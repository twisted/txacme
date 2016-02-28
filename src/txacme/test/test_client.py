import json
from contextlib import contextmanager
from operator import attrgetter, methodcaller

from acme import errors, jose, jws, messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from fixtures import Fixture
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing, Equals, Is, IsInstance, MatchesAll, MatchesListwise,
    MatchesPredicate, MatchesStructure, Mismatch)
from testtools.twistedsupport import failed, succeeded
from treq.client import HTTPClient
from treq.testing import RequestSequence as treq_RequestSequence
from treq.testing import (
    _SynchronousProducer, HasHeaders, RequestTraversalAgent,
    StringStubbingResource)
from twisted.internet import reactor
from twisted.python.compat import _PY3
from twisted.python.url import URL
from twisted.test.proto_helpers import MemoryReactor
from twisted.web import http

from txacme.client import _default_client, Client, JWSClient
from txacme.util import generate_private_key


def failed_with(matcher):
    return failed(AfterPreprocessing(attrgetter('value'), matcher))


# from cryptography:

RSA_KEY_512 = jose.JWKRSA(key=rsa.RSAPrivateNumbers(
    p=int(
        "d57846898d5c0de249c08467586cb458fa9bc417cdf297f73cfc52281b787cd9", 16
    ),
    q=int(
        "d10f71229e87e010eb363db6a85fd07df72d985b73c42786191f2ce9134afb2d", 16
    ),
    d=int(
        "272869352cacf9c866c4e107acc95d4c608ca91460a93d28588d51cfccc07f449"
        "18bbe7660f9f16adc2b4ed36ca310ef3d63b79bd447456e3505736a45a6ed21", 16
    ),
    dmp1=int(
        "addff2ec7564c6b64bc670d250b6f24b0b8db6b2810099813b7e7658cecf5c39", 16
    ),
    dmq1=int(
        "463ae9c6b77aedcac1397781e50e4afc060d4b216dc2778494ebe42a6850c81", 16
    ),
    iqmp=int(
        "54deef8548f65cad1d411527a32dcb8e712d3e128e4e0ff118663fae82a758f4", 16
    ),
    public_numbers=rsa.RSAPublicNumbers(
        e=65537,
        n=int(
            "ae5411f963c50e3267fafcf76381c8b1e5f7b741fdb2a544bcf48bd607b10c991"
            "90caeb8011dc22cf83d921da55ec32bd05cac3ee02ca5e1dbef93952850b525",
            16
        ),
    )
).private_key(default_backend()))


class Always(object):
    """Always matches."""

    def __str__(self):
        return 'Always()'

    def match(self, value):
        return None


class Never(object):
    """Never matches."""

    def __str__(self):
        return 'Never()'

    def match(self, value):
        return Mismatch(
            u'Inevitable mismatch on %r' % (value,))


class ClientFixture(Fixture):
    """
    Create a :class:`~txacme.client.Client` for testing.
    """
    def __init__(self, sequence, directory=None, key=None, alg=jose.RS256):
        super(ClientFixture, self).__init__()
        self._sequence = sequence
        if directory is None:
            self._directory = messages.Directory({
                messages.NewRegistration:
                u'https://example.org/acme/new-reg',
                messages.Revocation:
                u'https://example.org/acme/revoke-cert',
                messages.NewAuthorization:
                u'https://example.org/acme/new-authz',
                })
        else:
            self._directory = directory
        if key is None:
            key = jose.JWKRSA(key=generate_private_key('rsa'))
        self._key = key
        self._alg = alg

    def _setUp(self):  # noqa
        treq_client = HTTPClient(
            agent=RequestTraversalAgent(
                StringStubbingResource(self._sequence)),
            data_to_body_producer=_SynchronousProducer)
        self.client = Client(
            reactor, self._directory, self._key, self._alg,
            jws_client=JWSClient(treq_client, self._key, self._alg))


def _nonce_response(url, nonce):
    """
    Construct an expected request for an initial nonce check.

    :param bytes url: The url being requested.
    :param bytes nonce: The nonce to return.

    :return: A request/response tuple suitable for use with
        :class:`~treq.testing.RequestSequence`.
    """
    return (
        MatchesListwise([
            Equals(b'HEAD'),
            Equals(url),
            Equals({}),
            Equals(HasHeaders({b'user-agent': [b'txacme']})),
            Equals(b'')]),
        (http.NOT_ALLOWED,
         {b'content-type': b'application/json',
          b'replay-nonce': jose.b64encode(nonce)},
         b'{}'))


def _json_dumps(j):
    s = json.dumps(j)
    if _PY3:
        s = s.encode('utf-8')
    return s


class RequestSequence(treq_RequestSequence):
    @contextmanager
    def consume(self, sync_failure_reporter):
        yield
        if not self.consumed():
            sync_failure_reporter("\n".join(
                ["Not all expected requests were made.  Still expecting:"] +
                ["- {0!r})".format(e) for e, _ in self._sequence]))

    def __call__(self, method, url, params, headers, data):
        """
        :return: the next response in the sequence, provided that the
            parameters match the next in the sequence.
        """
        req = (method, url, params, headers, data)
        if len(self._sequence) == 0:
            self._async_reporter(
                None, Never(),
                "No more requests expected, but request {0!r} made.".format(
                    req))
            return (500, {}, "StubbingError")
        matcher, response = self._sequence[0]
        self._async_reporter(req, matcher)
        self._sequence = self._sequence[1:]
        return response


def on_json(matcher):
    def _loads(s):
        if isinstance(s, bytes):
            s = s.decode('utf-8')
        return json.loads(s)
    return AfterPreprocessing(_loads, matcher)


def on_jws(matcher):
    return on_json(
        AfterPreprocessing(
            jws.JWS.from_json,
            MatchesAll(
                MatchesPredicate(
                    methodcaller('verify'), 'JWS message does not verify'),
                AfterPreprocessing(
                    attrgetter('payload'),
                    on_json(matcher)))))


class ClientTests(TestCase):
    """
    :class:`.Client` provides a client interface for the ACME API.
    """
    def test_register_missing_next(self):
        """
        If the directory does not return a ``"next"`` link, a
        :exc:`~acme.errors.ClientError` failure occurs.
        """
        sequence = RequestSequence(
            [_nonce_response(
                u'https://example.org/acme/new-reg',
                b'Nonce'),
             (MatchesListwise([
                 Equals(b'POST'),
                 Equals(u'https://example.org/acme/new-reg'),
                 Equals({}),
                 Always(),
                 Always()]),
              (http.CREATED,
               {b'content-type': b'application/json',
                b'replay-nonce': jose.b64encode(b'Nonce2')},
               b'{}'))],
            self.expectThat)
        client = self.useFixture(ClientFixture(sequence)).client
        with sequence.consume(self.fail):
            d = client.register()
        self.expectThat(
            d, failed_with(MatchesAll(
                IsInstance(errors.ClientError),
                AfterPreprocessing(str, Equals('"next" link missing')))))

    def test_unexpected_update(self):
        """
        If the server does not return the registration we expected, an
        :exc:`~acme.errors.UnexpectedUpdate` failure occurs.
        """
        sequence = RequestSequence(
            [_nonce_response(
                u'https://example.org/acme/new-reg',
                b'Nonce'),
             (MatchesListwise([
                 Equals(b'POST'),
                 Equals(u'https://example.org/acme/new-reg'),
                 Equals({}),
                 Always(),
                 Always()]),
              (http.CREATED,
               {b'content-type': b'application/json',
                b'replay-nonce': jose.b64encode(b'Nonce2'),
                b'location': b'https://example.org/acme/reg/1',
                b'link': b','.join([
                    b'<https://example.org/acme/new-authz>;rel="next"',
                    b'<https://example.org/acme/recover-reg>;rel="recover"',
                    b'<https://example.org/acme/terms>;rel="terms-of-service"',
                ])},
               _json_dumps({
                   u'key': {
                       u'n': u'alQR-WPFDjJn-vz3Y4HIseX3t0H9sqVEvPSL1gexDJkZDK6'
                             u'4AR3CLPg9kh2lXsMr0FysPuAspeHb75OVKFC1JQ',
                       u'e': u'AQAB',
                       u'kty': u'RSA'},
                   u'contact': [u'mailto:example@example.com'],
               })))],
            self.expectThat)
        client = self.useFixture(
            ClientFixture(sequence, key=RSA_KEY_512)).client
        reg = messages.NewRegistration.from_data(email=u'example@example.com')
        with sequence.consume(self.fail):
            d = client.register(reg)
            self.assertThat(
                d, failed_with(IsInstance(errors.UnexpectedUpdate)))

    def test_register(self):
        """
        If the registration succeeds, the new registration is returned.
        """
        sequence = RequestSequence(
            [_nonce_response(
                u'https://example.org/acme/new-reg',
                b'Nonce'),
             (MatchesListwise([
                 Equals(b'POST'),
                 Equals(u'https://example.org/acme/new-reg'),
                 Equals({}),
                 Always(),
                 on_jws(Equals({
                     u'resource': u'new-reg',
                     u'contact': [u'mailto:example@example.com']}))]),
              (http.CREATED,
               {b'content-type': b'application/json',
                b'replay-nonce': jose.b64encode(b'Nonce2'),
                b'location': b'https://example.org/acme/reg/1',
                b'link': b','.join([
                    b'<https://example.org/acme/new-authz>;rel="next"',
                    b'<https://example.org/acme/recover-reg>;rel="recover"',
                    b'<https://example.org/acme/terms>;rel="terms-of-service"',
                ])},
               _json_dumps({
                   u'key': {
                       u'n': u'rlQR-WPFDjJn-vz3Y4HIseX3t0H9sqVEvPSL1gexDJkZDK6'
                             u'4AR3CLPg9kh2lXsMr0FysPuAspeHb75OVKFC1JQ',
                       u'e': u'AQAB',
                       u'kty': u'RSA'},
                   u'contact': [u'mailto:example@example.com'],
               })))],
            self.expectThat)
        client = self.useFixture(
            ClientFixture(sequence, key=RSA_KEY_512)).client
        reg = messages.NewRegistration.from_data(email=u'example@example.com')
        with sequence.consume(self.fail):
            d = client.register(reg)
            self.assertThat(
                d, succeeded(MatchesStructure(
                    body=MatchesStructure(
                        key=Equals(RSA_KEY_512.public_key()),
                        contact=Equals(reg.contact)),
                    uri=Equals(
                        URL.fromText(u'https://example.org/acme/reg/1')),
                    new_authzr_uri=Equals(
                        URL.fromText(u'https://example.org/acme/new-authz')),
                    terms_of_service=Equals(
                        URL.fromText(u'https://example.org/acme/terms')),
                )))

    def test_from_directory(self):
        """
        :func:`txacme.client.Client.from_url` constructs a client with a
        directory retrieved from the given URL.
        """
        new_reg = u'https://example.org/acme/new-reg'
        sequence = RequestSequence(
            [(MatchesListwise([
                Equals(b'GET'),
                Equals(u'https://example.org/acme/'),
                Always(),
                Always(),
                Always()]),
             (http.OK,
              {b'content-type': b'application/json',
               b'replay-nonce': jose.b64encode(b'Nonce')},
              _json_dumps({
                  u'new-reg': new_reg,
                  u'revoke-cert': u'https://example.org/acme/revoke-cert',
                  u'new-authz': u'https://example.org/acme/new-authz',
              })))],
            self.expectThat)
        treq_client = HTTPClient(
            agent=RequestTraversalAgent(
                StringStubbingResource(sequence)),
            data_to_body_producer=_SynchronousProducer)
        with sequence.consume(self.fail):
            d = Client.from_url(
                reactor, URL.fromText(u'https://example.org/acme/'),
                key=RSA_KEY_512, alg=jose.RS256,
                jws_client=JWSClient(
                    treq_client, key=RSA_KEY_512, alg=jose.RS256))
            self.assertThat(
                d,
                succeeded(
                    AfterPreprocessing(
                        lambda client:
                        client.directory[messages.NewRegistration()],
                        Equals(new_reg))))

    def test_default_client(self):
        """
        :func:`txacme.client._default_client` constructs a client if one was
        not provided.
        """
        reactor = MemoryReactor()
        client = _default_client(None, reactor, RSA_KEY_512, jose.RS384)
        self.assertThat(client, IsInstance(JWSClient))
        # We should probably assert some stuff about the treq.HTTPClient, but
        # it's hard without doing awful mock stuff.

__all__ = ['ClientTests']
