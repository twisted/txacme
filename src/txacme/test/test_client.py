import json
from contextlib import contextmanager
from operator import attrgetter, methodcaller

import attr

from josepy.jwa import RS256, RS384
from josepy.jwk import JWKRSA
from josepy.jws import JWS
from josepy.b64 import b64encode, b64decode

from acme import challenges, errors, messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fixtures import Fixture
from hypothesis import strategies as s
from hypothesis import assume, example, given, settings
from testtools import ExpectedException, TestCase
from testtools.matchers import (
    AfterPreprocessing, Always, ContainsDict, Equals, Is, IsInstance,
    MatchesAll, MatchesListwise, MatchesPredicate, MatchesStructure, Mismatch,
    Never, Not, StartsWith, HasLength)
from testtools.twistedsupport import failed, succeeded, has_no_result
from treq.client import HTTPClient
from treq.testing import RequestSequence as treq_RequestSequence
from treq.testing import (
    _SynchronousProducer, RequestTraversalAgent, StringStubbingResource)
from twisted.internet import reactor
from twisted.internet.defer import Deferred, CancelledError, fail, succeed
from twisted.internet.error import ConnectionClosed
from twisted.internet.task import Clock
from twisted.python.url import URL
from twisted.test.proto_helpers import MemoryReactor
from twisted.web import http, server
from twisted.web.resource import Resource
from twisted.web.http_headers import Headers
from zope.interface import implementer

from txacme.client import (
    _default_client, _find_supported_challenge, _parse_header_links,
    answer_challenge, AuthorizationFailed, Client, DER_CONTENT_TYPE,
    fqdn_identifier, JSON_CONTENT_TYPE, JOSE_CONTENT_TYPE,
    JSON_ERROR_CONTENT_TYPE, JWSClient, NoSupportedChallenges, ServerError,
    get_certificate
)
from txacme.interfaces import IResponder
from txacme.messages import CertificateRequest
from txacme.test import strategies as ts
from txacme.testing import NullResponder
from txacme.util import (
    csr_for_names, generate_private_key
)


def failed_with(matcher):
    return failed(AfterPreprocessing(attrgetter('value'), matcher))


# from cryptography:

RSA_KEY_512_RAW = rsa.RSAPrivateNumbers(
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
).private_key(default_backend())

RSA_KEY_512 = JWKRSA(key=RSA_KEY_512_RAW)


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


@attr.s(auto_attribs=True)
class ConnectionPoolFixture:
    _deferred: Deferred = attr.Factory(Deferred)
    _closing: bool = False

    def started_closing(self):
        return self._closing

    def finish_closing(self):
        self._deferred.callback(None)


@attr.s(auto_attribs=True)
class FakePool:
    _fixture_pool: ConnectionPoolFixture

    def closeCachedConnections(self):  # noqa
        self._fixture_pool._closing = True
        return self._fixture_pool._deferred


class ClientFixture(Fixture):
    """
    Create a :class:`~txacme.client.Client` for testing.
    """
    def __init__(
        self, sequence, key=None, alg=RS256, use_connection_pool=False
    ):
        super(ClientFixture, self).__init__()
        self._sequence = sequence
        if isinstance(sequence, treq_RequestSequence):
            self._agent = RequestTraversalAgent(
                StringStubbingResource(self._sequence)
            )
        else:
            self._agent = RequestTraversalAgent(sequence)
        if use_connection_pool:
            self.pool = ConnectionPoolFixture()
            self._agent._pool = FakePool(self.pool)
        self._directory = messages.Directory({
            messages.NewRegistration:
            u'https://example.org/acme/new-reg',
            messages.Revocation:
            u'https://example.org/acme/revoke-cert',
            messages.NewAuthorization:
            u'https://example.org/acme/new-authz',
            messages.CertificateRequest:
            u'https://example.org/acme/new-cert',
            "newAccount":
            u"https://example.org/acme/new-account",
            })
        if key is None:
            key = JWKRSA(key=generate_private_key('rsa'))
        self._key = key
        self._alg = alg

    def _setUp(self):  # noqa
        self.clock = Clock()
        jws_client = JWSClient(self._agent, self._key, self._alg, "https://example.org/acme/authz/1/1", None)
        jws_client._treq._data_to_body_producer = _SynchronousProducer
        self.client = Client(
            self._directory, self.clock, self._key,
            jws_client=jws_client)

    def flush(self):
        self._agent.flush()


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
            ContainsDict({b'User-Agent':
                          MatchesListwise([StartsWith(b'txacme/')])}),
            Equals(b'')]),
        (http.NOT_ALLOWED,
         {b'content-type': JSON_CONTENT_TYPE,
          b'replay-nonce': b64encode(nonce)},
         b'{}'))


def _json_dumps(j):
    return json.dumps(j).encode("utf-8")


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
        assert isinstance(s, bytes)
        s = s.decode('utf-8')
        return json.loads(s)
    return AfterPreprocessing(_loads, matcher)


def on_jws(matcher, nonce=None):
    nonce_matcher = Always()
    if nonce is not None:
        def extract_nonce(j):
            protected = json.loads(j.signatures[0].protected)
            return b64decode(protected[u'nonce'])
        nonce_matcher = AfterPreprocessing(extract_nonce, Equals(nonce))
    return on_json(
        AfterPreprocessing(
            JWS.from_json,
            MatchesAll(
                MatchesPredicate(
                    methodcaller('verify'), '%r does not verify'),
                AfterPreprocessing(
                    attrgetter('payload'),
                    on_json(matcher)),
                nonce_matcher)))


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


@implementer(IResponder)
@attr.s
class RecordingResponder(object):
    challenges = attr.ib()
    challenge_type = attr.ib()

    def start_responding(self, server_name, challenge, response):
        self.challenges.add(challenge)

    def stop_responding(self, server_name, challenge, response):
        self.challenges.discard(challenge)


class ClientTests(TestCase):
    """
    :class:`.Client` provides a client interface for the ACME API.
    """
    def test_directory_url_type(self):
        """
        `~txacme.client.Client.from_url` expects a ``twisted.python.url.URL``
        instance for the ``url`` argument.
        """
        with ExpectedException(TypeError):
            Client.from_url(
                reactor, '/wrong/kind/of/directory', key=RSA_KEY_512)

    def stop_in_progress(self, use_pool=False):
        requested = []

        class NoAnswerResource(Resource):
            isLeaf = True       # noqa

            def render(self, request):
                requested.append(request.notifyFinish())
                return server.NOT_DONE_YET

        self.client_fixture = self.useFixture(
            ClientFixture(
                NoAnswerResource(),
                key=RSA_KEY_512,
                use_connection_pool=use_pool,
            )
        )
        client = self.client_fixture.client
        reg = messages.NewRegistration.from_data(email=u'example@example.com')
        register_call = client.start()
        self.expectThat(requested, HasLength(1))
        self.expectThat(register_call, has_no_result())
        self.expectThat(requested[0], has_no_result())
        stop_deferred = client.stop()
        self.assertThat(register_call, succeeded(Equals(None)))
        self.client_fixture.flush()
        self.assertThat(
            requested[0],
            failed_with(IsInstance(ConnectionClosed)),
        )
        return stop_deferred

    def test_stop_in_progress(self):
        """
        If we stop the client while an operation is in progress, it's
        cancelled.
        """
        self.assertThat(self.stop_in_progress(), succeeded(Equals(None)))

    def test_stop_in_progress_with_pool(self):
        """
        If we stop the client while an operation is in progress, it will stop.
        """
        stopped = self.stop_in_progress(True)
        self.assertThat(stopped, has_no_result())
        self.assertThat(
            self.client_fixture.pool.started_closing(),
            Equals(True),
        )
        self.client_fixture.pool.finish_closing()
        self.assertThat(stopped, succeeded(Equals(None)))

    @example(u'example.com')
    @given(ts.dns_names())
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

    @example(URL.fromText(u'https://example.org/'),
             URL.fromText(u'https://example.com/'))
    @given(ts.urls(), ts.urls())
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

    def _make_poll_response(self, uri, identifier_json):
        """
        Return a factory for a poll response.
        """
        def rr(status, error=None):
            chall = {
                u'type': u'http-01',
                u'status': status,
                u'uri': uri + u'/0',
                u'token': u'IlirfxKKXAsHtmzK29Pj8A'}
            if error is not None:
                chall[u'error'] = error
            return (
                MatchesListwise([
                    Equals(b'GET'),
                    Equals(uri),
                    Equals({}),
                    Always(),
                    Always()]),
                (http.ACCEPTED,
                 {b'content-type': JSON_CONTENT_TYPE,
                  b'replay-nonce': b64encode(b'nonce2'),
                  b'location': uri.encode('ascii'),
                  b'link': b'<https://example.org/acme/new-cert>;rel="next"'},
                 _json_dumps({
                     u'status': status,
                     u'identifier': identifier_json,
                     u'challenges': [chall],
                     u'combinations': [[0]],
                 })))
        return rr

    def _make_cert_sequence(self, cert_urls):
        """
        Build a sequence for fetching a list of certificates.
        """
        return RequestSequence([
            (MatchesListwise([
                Equals(b'GET'),
                Equals(url),
                Equals({}),
                ContainsDict({b'Accept': Equals([DER_CONTENT_TYPE])}),
                Always()]),
             (http.OK,
              {b'content-type': DER_CONTENT_TYPE,
               b'location': url.encode('utf-8'),
               b'link':
               u'<{!s}>;rel="up"'.format(
                   issuer_url).encode('utf-8')
               if issuer_url is not None else b''},
              b''))
            for url, issuer_url
            in cert_urls
            ], self.expectThat)


class JWSClientTests(TestCase):
    """
    :class:`.JWSClient` implements JWS-signed requests over HTTP.
    """
    def test_check_invalid_error(self):
        """
        If an error response is received but cannot be parsed,
        :exc:`~acme.errors.ServerError` is raised.
        """
        self.assertThat(
            JWSClient._check_response(
                TestResponse(
                    code=http.FORBIDDEN,
                    content_type=JSON_ERROR_CONTENT_TYPE)),
            failed_with(IsInstance(ServerError)))

    def test_check_valid_error(self):
        """
        If an error response is received but cannot be parsed,
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
