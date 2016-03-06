import json
import time
from contextlib import contextmanager
from operator import attrgetter, methodcaller

import attr
from acme import challenges, errors, jose, jws, messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from fixtures import Fixture
from hypothesis import strategies as s
from hypothesis import assume, example, given
from testtools import ExpectedException, TestCase
from testtools.matchers import (
    AfterPreprocessing, ContainsDict, Equals, IsInstance,
    MatchesAll, MatchesListwise, MatchesPredicate, MatchesStructure,
    Mismatch, Not, StartsWith)
from testtools.twistedsupport import failed, succeeded
from treq.client import HTTPClient
from treq.testing import RequestSequence as treq_RequestSequence
from treq.testing import (
    _SynchronousProducer, HasHeaders, RequestTraversalAgent,
    StringStubbingResource)
from twisted.internet import reactor
from twisted.internet.defer import fail, succeed
from twisted.python.compat import _PY3
from twisted.python.url import URL
from twisted.test.proto_helpers import MemoryReactor
from twisted.web import http
from twisted.web.http_headers import Headers

from txacme.client import (
    _default_client, _parse_header_links, Client, fqdn_identifier,
    JSON_CONTENT_TYPE, JSON_ERROR_CONTENT_TYPE, JWSClient, ServerError)
from txacme.test.strategies import dns_name, urls
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


class Nearly(object):
    """Within a certain threshold."""
    def __init__(self, expected, epsilon=0.001):
        self.expected = expected
        self.epsilon = epsilon

    def __str__(self):
        return 'Nearly(%r, %r)' % (self.expected, self.epsilon)

    def match(self, value):
        if abs(value - self.expected) > self.epsilon:
            return Mismatch(
                u'%r more than %r from %r' % (
                    value, self.epsilon, self.expected))


class ClientFixture(Fixture):
    """
    Create a :class:`~txacme.client.Client` for testing.
    """
    def __init__(self, sequence, key=None, alg=jose.RS256):
        super(ClientFixture, self).__init__()
        self._sequence = sequence
        self._directory = messages.Directory({
            messages.NewRegistration:
            u'https://example.org/acme/new-reg',
            messages.Revocation:
            u'https://example.org/acme/revoke-cert',
            messages.NewAuthorization:
            u'https://example.org/acme/new-authz',
            })
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
            self._directory, reactor, self._key,
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
         {b'content-type': JSON_CONTENT_TYPE,
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


@attr.s
class TestResponse(object):
    """
    Test response implementation for various bad response cases.
    """
    code = attr.ib(default=http.OK)
    content_type = attr.ib(default=JSON_CONTENT_TYPE)
    nonce = attr.ib(default=None)
    json = attr.ib(default=lambda: succeed({}))
    links = attr.ib(default=None)

    @property
    def headers(self):
        h = Headers({b'content-type': [self.content_type]})
        if self.nonce is not None:
            h.setRawHeaders(b'replay-nonce', [self.nonce])
        if self.links is not None:
            h.setRawHeaders(b'link', self.links)
        return h


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
               {b'content-type': JSON_CONTENT_TYPE,
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
        update = (
            MatchesListwise([
                Equals(b'POST'),
                Equals(u'https://example.org/acme/new-reg'),
                Equals({}),
                ContainsDict({b'Content-Type': Equals([JSON_CONTENT_TYPE])}),
                Always()]),
            (http.CREATED,
             {b'content-type': JSON_CONTENT_TYPE,
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
             })))
        sequence = RequestSequence(
            [_nonce_response(
                u'https://example.org/acme/new-reg',
                b'Nonce'),
             update,
             update],
            self.expectThat)
        client = self.useFixture(
            ClientFixture(sequence, key=RSA_KEY_512)).client
        reg = messages.NewRegistration.from_data(email=u'example@example.com')
        reg2 = messages.NewRegistration.from_data(email=u'foo@example.com')
        with sequence.consume(self.fail):
            self.assertThat(
                client.register(reg),
                failed_with(IsInstance(errors.UnexpectedUpdate)))
            self.assertThat(
                client.register(reg2),
                failed_with(IsInstance(errors.UnexpectedUpdate)))

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
                 ContainsDict({b'Content-Type': Equals([JSON_CONTENT_TYPE])}),
                 on_jws(Equals({
                     u'resource': u'new-reg',
                     u'contact': [u'mailto:example@example.com']}))]),
              (http.CREATED,
               {b'content-type': JSON_CONTENT_TYPE,
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
                    uri=Equals(u'https://example.org/acme/reg/1'),
                    new_authzr_uri=Equals(
                        u'https://example.org/acme/new-authz'),
                    terms_of_service=Equals(u'https://example.org/acme/terms'),
                )))

    def test_register_existing(self):
        """
        If registration fails due to our key already being registered, the
        existing registration is returned.
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
              (http.CONFLICT,
               {b'content-type': JSON_ERROR_CONTENT_TYPE,
                b'replay-nonce': jose.b64encode(b'Nonce2'),
                b'location': b'https://example.org/acme/reg/1',
                },
               _json_dumps(
                   {u'status': http.CONFLICT,
                    u'type': u'urn:acme:error:malformed',
                    u'detail': u'Registration key is already in use'}
               ))),
             (MatchesListwise([
                 Equals(b'POST'),
                 Equals(u'https://example.org/acme/reg/1'),
                 Equals({}),
                 Always(),
                 on_jws(Equals({u'resource': u'reg'}))]),
              (http.ACCEPTED,
               {b'content-type': JSON_CONTENT_TYPE,
                b'replay-nonce': jose.b64encode(b'Nonce3'),
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
                   u'agreement': u'https://example.org/acme/terms',
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
                    uri=Equals(u'https://example.org/acme/reg/1'),
                    new_authzr_uri=Equals(
                        u'https://example.org/acme/new-authz'),
                    terms_of_service=Equals(u'https://example.org/acme/terms'),
                )))

    def test_register_error(self):
        """
        If some other error occurs during registration, a
        :exc:`txacme.client.ServerError` results.
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
              (http.SERVICE_UNAVAILABLE,
               {b'content-type': JSON_ERROR_CONTENT_TYPE,
                b'replay-nonce': jose.b64encode(b'Nonce2'),
                },
               _json_dumps(
                   {u'status': http.SERVICE_UNAVAILABLE,
                    u'type': u'urn:acme:error:rateLimited',
                    u'detail': u'The request exceeds a rate limit'}
               )))],
            self.expectThat)
        client = self.useFixture(
            ClientFixture(sequence, key=RSA_KEY_512)).client
        reg = messages.NewRegistration.from_data(email=u'example@example.com')
        with sequence.consume(self.fail):
            d = client.register(reg)
            self.assertThat(
                d, failed_with(MatchesAll(
                    IsInstance(ServerError),
                    MatchesStructure(
                        message=MatchesStructure(
                            typ=Equals(u'urn:acme:error:rateLimited'),
                            detail=Equals(u'The request exceeds a rate limit'),
                            )))))

    def test_agree_to_tos(self):
        """
        Agreeing to the TOS returns a registration with the agreement updated.
        """
        tos = u'https://example.org/acme/terms'
        sequence = RequestSequence(
            [_nonce_response(
                u'https://example.org/acme/reg/1',
                b'Nonce'),
             (MatchesListwise([
                 Equals(b'POST'),
                 Equals(u'https://example.org/acme/reg/1'),
                 Equals({}),
                 ContainsDict({b'Content-Type': Equals([JSON_CONTENT_TYPE])}),
                 on_jws(ContainsDict({
                     u'resource': Equals(u'reg'),
                     u'agreement': Equals(tos)}))]),
              (http.ACCEPTED,
               {b'content-type': JSON_CONTENT_TYPE,
                b'replay-nonce': jose.b64encode(b'Nonce2'),
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
                   u'agreement': tos,
               })))],
            self.expectThat)
        client = self.useFixture(
            ClientFixture(sequence, key=RSA_KEY_512)).client
        reg = messages.RegistrationResource(
            body=messages.Registration(
                contact=(u'mailto:example@example.com',),
                key=RSA_KEY_512.public_key()),
            uri=u'https://example.org/acme/reg/1',
            new_authzr_uri=u'https://example.org/acme/new-authz',
            terms_of_service=tos)
        with sequence.consume(self.fail):
            d = client.agree_to_tos(reg)
            self.assertThat(
                d, succeeded(MatchesStructure(
                    body=MatchesStructure(
                        key=Equals(RSA_KEY_512.public_key()),
                        contact=Equals(reg.body.contact),
                        agreement=Equals(tos)),
                    uri=Equals(u'https://example.org/acme/reg/1'),
                    new_authzr_uri=Equals(
                        u'https://example.org/acme/new-authz'),
                    terms_of_service=Equals(tos),
                )))

    def test_from_directory(self):
        """
        :func:`~txacme.client.Client.from_url` constructs a client with a
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
              {b'content-type': JSON_CONTENT_TYPE,
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
                    MatchesAll(
                        AfterPreprocessing(
                            lambda client:
                            client.directory[messages.NewRegistration()],
                            Equals(new_reg)))))

    def test_default_client(self):
        """
        ``~txacme.client._default_client`` constructs a client if one was not
        provided.
        """
        reactor = MemoryReactor()
        client = _default_client(None, reactor, RSA_KEY_512, jose.RS384)
        self.assertThat(client, IsInstance(JWSClient))
        # We should probably assert some stuff about the treq.HTTPClient, but
        # it's hard without doing awful mock stuff.

    def test_request_challenges(self):
        """
        :meth:`~txacme.client.Client.request_challenges` creates a new
        authorization, and returns the authorization resource with a list of
        possible challenges to proceed with.
        """
        name = u'example.com'
        identifier_json = {u'type': u'dns',
                           u'value': name}
        identifier = messages.Identifier.from_json(identifier_json)
        challenges = [
            {u'type': u'http-01',
             u'uri': u'https://example.org/acme/authz/1/0',
             u'token': u'IlirfxKKXAsHtmzK29Pj8A'},
            {u'type': u'dns',
             u'uri': u'https://example.org/acme/authz/1/1',
             u'token': u'DGyRejmCefe7v4NfDGDKfA'},
            ]
        sequence = RequestSequence(
            [_nonce_response(
                u'https://example.org/acme/new-authz',
                b'Nonce'),
             (MatchesListwise([
                 Equals(b'POST'),
                 Equals(u'https://example.org/acme/new-authz'),
                 Equals({}),
                 ContainsDict({b'Content-Type': Equals([JSON_CONTENT_TYPE])}),
                 on_jws(Equals({
                     u'resource': u'new-authz',
                     u'identifier': identifier_json,
                     }))]),
              (http.CREATED,
               {b'content-type': JSON_CONTENT_TYPE,
                b'replay-nonce': jose.b64encode(b'Nonce2'),
                b'location': b'https://example.org/acme/authz/1',
                b'link': b'<https://example.org/acme/new-cert>;rel="next"',
                },
               _json_dumps({
                   u'status': u'pending',
                   u'identifier': identifier_json,
                   u'challenges': challenges,
                   u'combinations': [[0], [1]],
               })))],
            self.expectThat)
        client = self.useFixture(
            ClientFixture(sequence, key=RSA_KEY_512)).client
        with sequence.consume(self.fail):
            self.assertThat(
                client.request_challenges(identifier),
                succeeded(MatchesStructure(
                    body=MatchesStructure(
                        identifier=Equals(identifier),
                        challenges=Equals(
                            tuple(map(
                                messages.ChallengeBody.from_json,
                                challenges))),
                        combinations=Equals(((0,), (1,))),
                        status=Equals(messages.STATUS_PENDING)),
                    new_cert_uri=Equals(
                        u'https://example.org/acme/new-cert'),
                )))

    @example(http.CREATED, http.FOUND)
    @given(s.sampled_from(http.RESPONSES.keys()),
           s.sampled_from(http.RESPONSES.keys()))
    def test_expect_response_wrong_code(self, expected, actual):
        """
        ``_expect_response`` raises `~acme.errors.ClientError` if the response
        code does not match the expected code.
        """
        assume(expected != actual)
        response = TestResponse(code=actual)
        with ExpectedException(errors.ClientError):
            Client._expect_response(response, expected)

    def test_authorization_missing_link(self):
        """
        ``_parse_authorization`` raises `~acme.errors.ClientError` if the
        ``"next"`` link is missing.
        """
        response = TestResponse()
        with ExpectedException(errors.ClientError, '"next" link missing'):
            Client._parse_authorization(response)

    def test_authorization_unexpected_identifier(self):
        """
        ``_check_authorization`` raises `~acme.errors.UnexpectedUpdate` if the
        return identifier doesn't match.
        """
        with ExpectedException(errors.UnexpectedUpdate):
            Client._check_authorization(
                messages.AuthorizationResource(
                    body=messages.Authorization()),
                messages.Identifier(
                    typ=messages.IDENTIFIER_FQDN, value=u'example.org'))

    @example(u'example.com')
    @given(dns_name())
    def test_fqdn_identifier(self, name):
        """
        `~txacme.client.fqdn_identifier` constructs an
        `~acme.messages.Identifier` of the right type.
        """
        self.assertThat(
            fqdn_identifier(name),
            MatchesStructure(
                typ=Equals(messages.IDENTIFIER_FQDN),
                value=Equals(name)))

    def test_answer_challenge(self):
        """
        `~txacme.client.Client.answer_challenge` responds to a challenge and
        returns the updated challenge.
        """
        key_authorization = u'blahblahblah'
        uri = u'https://example.org/acme/authz/1/0'
        sequence = RequestSequence(
            [_nonce_response(
                u'https://example.org/acme/authz/1/0',
                b'Nonce'),
             (MatchesListwise([
                 Equals(b'POST'),
                 Equals(uri),
                 Equals({}),
                 ContainsDict({b'Content-Type': Equals([JSON_CONTENT_TYPE])}),
                 on_jws(Equals({
                     u'resource': u'challenge',
                     u'type': u'http-01',
                     u'keyAuthorization': key_authorization,
                     }))]),
              (http.OK,
               {b'content-type': JSON_CONTENT_TYPE,
                b'replay-nonce': jose.b64encode(b'Nonce2'),
                b'link': b'<https://example.org/acme/authz/1>;rel="up"',
                },
               _json_dumps({
                   u'uri': uri,
                   u'type': u'http-01',
                   u'status': u'processing',
                   u'token': u'DGyRejmCefe7v4NfDGDKfA',
               })))],
            self.expectThat)
        client = self.useFixture(
            ClientFixture(sequence, key=RSA_KEY_512)).client
        with sequence.consume(self.fail):
            self.assertThat(
                client.answer_challenge(
                    messages.ChallengeBody(
                        uri=uri,
                        chall=challenges.HTTP01(token=b'blahblah'),
                        status=messages.STATUS_PENDING),
                    challenges.HTTP01Response(
                        key_authorization=key_authorization)),
                succeeded(MatchesStructure(
                    body=MatchesStructure(),
                    authzr_uri=Equals(
                        u'https://example.org/acme/authz/1'),
                )))

    def test_challenge_missing_link(self):
        """
        ``_parse_challenge`` raises `~acme.errors.ClientError` if the ``"up"``
        link is missing.
        """
        response = TestResponse()
        with ExpectedException(errors.ClientError, '"up" link missing'):
            Client._parse_challenge(response)

    @example(URL.fromText(u'https://example.org/'),
             URL.fromText(u'https://example.com/'))
    @given(urls(), urls())
    def test_challenge_unexpected_uri(self, url1, url2):
        """
        ``_check_challenge`` raises `~acme.errors.UnexpectedUpdate` if the
        challenge does not have the expected URI.
        """
        url1 = url1.asURI().asText()
        url2 = url2.asURI().asText()
        assume(url1 != url2)
        with ExpectedException(errors.UnexpectedUpdate):
            Client._check_challenge(
                messages.ChallengeResource(
                    body=messages.ChallengeBody(chall=None, uri=url1)),
                messages.ChallengeBody(chall=None, uri=url2))

    @example(name=u'example.com', retry_after=60, date_string=False)
    @example(name=u'example.org', retry_after=60, date_string=True)
    @given(name=dns_name(),
           retry_after=s.none() | s.integers(min_value=0, max_value=1000000),
           date_string=s.booleans())
    def test_poll(self, name, retry_after, date_string):
        """
        `~txacme.client.Client.poll` retrieves the latest state of an
        authorization resource, as well as the minimum time to wait before
        polling the state again.
        """
        now = time.time()
        if retry_after is None:
            retry_after_encoded = None
            retry_after = 5
        elif date_string:
            retry_after /= 1000.
            retry_after_encoded = http.datetimeToString(retry_after)
            retry_after = retry_after - now
        else:
            retry_after_encoded = u'{}'.format(retry_after).encode('ascii')
        identifier_json = {u'type': u'dns',
                           u'value': name}
        identifier = messages.Identifier.from_json(identifier_json)
        challenges = [
            {u'type': u'http-01',
             u'status': u'invalid',
             u'uri': u'https://example.org/acme/authz/1/0',
             u'token': u'IlirfxKKXAsHtmzK29Pj8A'},
            {u'type': u'dns',
             u'status': u'pending',
             u'uri': u'https://example.org/acme/authz/1/1',
             u'token': u'DGyRejmCefe7v4NfDGDKfA'},
            ]
        authzr = messages.AuthorizationResource(
            uri=u'https://example.org/acme/authz/1',
            body=messages.Authorization(
                identifier=identifier))
        response_headers = {
            b'content-type': JSON_CONTENT_TYPE,
            b'replay-nonce': jose.b64encode(b'Nonce2'),
            b'location': b'https://example.org/acme/authz/1',
            b'link': b'<https://example.org/acme/new-cert>;rel="next"',
            }
        if retry_after_encoded is not None:
            response_headers[b'retry-after'] = retry_after_encoded
        sequence = RequestSequence(
            [(MatchesListwise([
                Equals(b'GET'),
                Equals(u'https://example.org/acme/authz/1'),
                Equals({}),
                Always(),
                Always()]),
              (http.OK,
               response_headers,
               _json_dumps({
                   u'status': u'invalid',
                   u'identifier': identifier_json,
                   u'challenges': challenges,
                   u'combinations': [[0], [1]],
               })))],
            self.expectThat)
        client = self.useFixture(
            ClientFixture(sequence, key=RSA_KEY_512)).client
        with sequence.consume(self.fail):
            self.assertThat(
                client.poll(authzr, _now=lambda: now),
                succeeded(MatchesListwise([
                    MatchesStructure(
                        body=MatchesStructure(
                            identifier=Equals(identifier),
                            challenges=Equals(
                                tuple(map(
                                    messages.ChallengeBody.from_json,
                                    challenges))),
                            combinations=Equals(((0,), (1,))),
                            status=Equals(messages.STATUS_INVALID)),
                        new_cert_uri=Equals(
                            u'https://example.org/acme/new-cert')),
                    Nearly(retry_after, 1.0),
                ])))


class JWSClientTests(TestCase):
    """
    :class:`.JWSClient` implements JWS-signed requests over HTTP.
    """
    def test_check_invalid_json(self):
        """
        If a JSON response is expected, but a response is received with a
        non-JSON Content-Type, :exc:`~acme.errors.ClientError` is raised.
        """
        self.assertThat(
            JWSClient._check_response(
                TestResponse(content_type=b'application/octet-stream')),
            failed_with(IsInstance(errors.ClientError)))

    def test_check_invalid_error_type(self):
        """
        If an error response is received with a non-JSON-problem Content-Type,
        :exc:`~acme.errors.ClientError` is raised.
        """
        self.assertThat(
            JWSClient._check_response(
                TestResponse(
                    code=http.FORBIDDEN,
                    content_type=b'application/octet-stream')),
            failed_with(IsInstance(errors.ClientError)))

    def test_check_invalid_error(self):
        """
        If an error response is received but cannot be parse,
        :exc:`~acme.errors.ClientError` is raised.
        """
        self.assertThat(
            JWSClient._check_response(
                TestResponse(
                    code=http.FORBIDDEN,
                    content_type=JSON_ERROR_CONTENT_TYPE)),
            failed_with(IsInstance(errors.ClientError)))

    def test_check_valid_error(self):
        """
        If an error response is received but cannot be parse,
        :exc:`~acme.errors.ClientError` is raised.
        """
        self.assertThat(
            JWSClient._check_response(
                TestResponse(
                    code=http.FORBIDDEN,
                    content_type=JSON_ERROR_CONTENT_TYPE,
                    json=lambda: succeed({
                        u'type': u'unauthorized',
                        u'detail': u'blah blah blah'}))),
            failed_with(
                MatchesAll(
                    IsInstance(ServerError),
                    AfterPreprocessing(repr, StartsWith('ServerError')))))

    def test_check_expected_bad_json(self):
        """
        If a JSON response was expected, but could not be parse,
        :exc:`~acme.errors.ClientError` is raised.
        """
        self.assertThat(
            JWSClient._check_response(
                TestResponse(json=lambda: fail(ValueError()))),
            failed_with(IsInstance(errors.ClientError)))

    def test_missing_nonce(self):
        """
        If the response from the server does not have a nonce,
        :exc:`~acme.errors.MissingNonce` is raised.
        """
        client = JWSClient(None, None, None)
        with ExpectedException(errors.MissingNonce):
            client._add_nonce(TestResponse())

    def test_bad_nonce(self):
        """
        If the response from the server has an unparseable nonce,
        :exc:`~acme.errors.BadNonce` is raised.
        """
        client = JWSClient(None, None, None)
        with ExpectedException(errors.BadNonce):
            client._add_nonce(TestResponse(nonce=b'a!_'))

    def test_already_nonce(self):
        """
        No request is made if we already have a nonce.
        """
        client = JWSClient(None, None, None)
        client._nonces.add(u'nonce')
        self.assertThat(client._get_nonce(b''), succeeded(Equals(u'nonce')))


class ExtraCoverageTests(TestCase):
    """
    Tests to get coverage on some test helpers that we don't really want to
    maintain ourselves.
    """
    def test_always_never(self):
        self.assertThat(Always(), AfterPreprocessing(str, Equals('Always()')))
        self.assertThat(Never(), AfterPreprocessing(str, Equals('Never()')))
        self.assertThat(None, Not(Never()))
        self.assertThat(
            Nearly(1.0, 2.0),
            AfterPreprocessing(str, Equals('Nearly(1.0, 2.0)')))
        self.assertThat(2.0, Not(Nearly(1.0)))

    def test_unexpected_number_of_request_causes_failure(self):
        """
        If there are no more expected requests, making a request causes a
        failure.
        """
        async_failures = []
        sequence = RequestSequence(
            [],
            async_failure_reporter=lambda *a: async_failures.append(a))
        client = HTTPClient(
            agent=RequestTraversalAgent(
                StringStubbingResource(sequence)),
            data_to_body_producer=_SynchronousProducer)
        d = client.get('https://anything', data=b'what', headers={b'1': b'1'})
        self.assertThat(
            d,
            succeeded(MatchesStructure(code=Equals(500))))
        self.assertEqual(1, len(async_failures))
        self.assertIn("No more requests expected, but request",
                      async_failures[0][2])

        # the expected requests have all been made
        self.assertTrue(sequence.consumed())

    def test_consume_context_manager_fails_on_remaining_requests(self):
        """
        If the ``consume`` context manager is used, if there are any remaining
        expecting requests, the test case will be failed.
        """
        sequence = RequestSequence(
            [(Always(), (418, {}, b'body'))] * 2,
            async_failure_reporter=self.assertThat)
        client = HTTPClient(
            agent=RequestTraversalAgent(
                StringStubbingResource(sequence)),
            data_to_body_producer=_SynchronousProducer)

        consume_failures = []
        with sequence.consume(sync_failure_reporter=consume_failures.append):
            self.assertThat(
                client.get('https://anything', data=b'what',
                           headers={b'1': b'1'}),
                succeeded(Always()))

        self.assertEqual(1, len(consume_failures))
        self.assertIn(
            "Not all expected requests were made.  Still expecting:",
            consume_failures[0])


class LinkParsingTests(TestCase):
    """
    ``_parse_header_links`` parses the links from a response with Link: header
    fields.  This implementation is ... actually not very good, which is why
    there aren't many tests.

    ..  seealso: RFC 5988
    """
    def test_rfc_example1(self):
        """
        The first example from the RFC.
        """
        self.assertThat(
            _parse_header_links(
                TestResponse(
                    links=[b'<http://example.com/TheBook/chapter2>; '
                           b'rel="previous"; '
                           b'title="previous chapter"'])),
            Equals({
                u'previous':
                {u'rel': u'previous',
                 u'title': u'previous chapter',
                 u'url': u'http://example.com/TheBook/chapter2'}
            }))


__all__ = ['ClientTests', 'ExtraCoverageTests', 'LinkParsingTests']
