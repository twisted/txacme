import os
import json
import unittest
from contextlib import contextmanager
from operator import attrgetter, methodcaller

import attr

from josepy.jwa import RS256
from josepy.jwk import JWKRSA
from josepy.jws import JWS
from josepy.b64 import b64decode

from acme import errors, messages
from cryptography.hazmat.primitives.asymmetric import rsa
from treq.testing import RequestSequence as treq_RequestSequence
from twisted.internet import defer, reactor
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator
from twisted.python.url import URL
from twisted.web import http
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from twisted.web.http_headers import Headers
from twisted.trial.unittest import TestCase
from zope.interface import implementer
from OpenSSL import SSL

from txacme.client import (
    _parse_header_links,
    Client,
    fqdn_identifier,
    JSON_CONTENT_TYPE,
    JSON_ERROR_CONTENT_TYPE,
    JWSClient,
    ServerError,
)
from txacme.interfaces import IResponder


# URL to the pebble directory.
PEBBLE_URL = os.environ.get('PEBBLE_URL', '')
if PEBBLE_URL:
    PEBBLE_URL = URL.from_text(PEBBLE_URL)


def failed_with(matcher):
    return failed(AfterPreprocessing(attrgetter('value'), matcher))


# We generate a new RSA key for each test run.
# This will make sure that we don't already have an account on the
# ACME server.
# Let's Encrypt staging only supports keys of minimum 2048
RSA_TEST_KEY = JWKRSA(key=rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    ))


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
    json = attr.ib(default=lambda: defer.succeed({}))
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

    @defer.inlineCallbacks
    def test_directory_url_type(self):
        """
        `~txacme.client.Client.from_url` expects a ``twisted.python.url.URL``
        instance for the ``url`` argument.
        """
        with self.assertRaises(TypeError):
            yield Client.from_url(
                reactor, '/wrong/kind/of/directory', key=RSA_TEST_KEY)

    def test_fqdn_identifier(self):
        """
        `~txacme.client.fqdn_identifier` constructs an
        `~acme.messages.Identifier` of the right type.
        """
        name = u'example.com'
        result = fqdn_identifier(name)
        self.assertEqual(messages.IDENTIFIER_FQDN, result.typ)
        self.assertEqual(name, result.value)

    def test_challenge_unexpected_uri(self):
        """
        ``_check_challenge`` raises `~acme.errors.UnexpectedUpdate` if the
        challenge does not have the expected URI.
        """
        # Crazy dance that was used in previous test.
        url1 = URL.fromText(u'https://example.org/').asURI().asText()
        url2 = URL.fromText(u'https://example.com/').asURI().asText()

        with self.assertRaises(errors.UnexpectedUpdate):
            Client._check_challenge(
                challenge=messages.ChallengeResource(
                    body=messages.ChallengeBody(chall=None, uri=url1)),
                challenge_body=messages.ChallengeBody(chall=None, uri=url2),
                )


class JWSClientTests(TestCase):
    """
    :class:`.JWSClient` implements JWS-signed requests over HTTP.
    """
    @defer.inlineCallbacks
    def test_check_invalid_error(self):
        """
        If an error response is received but cannot be parsed,
        :exc:`~acme.errors.ServerError` is raised.
        """
        response = TestResponse(
            code=http.FORBIDDEN,
            content_type=JSON_ERROR_CONTENT_TYPE)

        with self.assertRaises(ServerError):
            yield JWSClient._check_response(response)

    @defer.inlineCallbacks
    def test_check_valid_error(self):
        """
        If an error response is received but cannot be parsed,
        :exc:`~acme.errors.ClientError` is raised.
        """
        response = TestResponse(
            code=http.FORBIDDEN,
            content_type=JSON_ERROR_CONTENT_TYPE,
            json=lambda: defer.succeed({
                u'type': u'unauthorized',
                u'detail': u'blah blah blah'}))

        with self.assertRaises(ServerError):
            yield JWSClient._check_response(response)


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
        response = TestResponse(links=[
            b'<http://example.com/TheBook/chapter2>; '
           b'rel="previous"; '
           b'title="previous chapter"'])
        result = _parse_header_links(response)
        self.assertEqual({
            u'previous':
            {u'rel': u'previous',
             u'title': u'previous chapter',
             u'url': u'http://example.com/TheBook/chapter2'}
            },
            result)


@unittest.skipIf(not PEBBLE_URL, 'Pebble tests enabled')
class PebbleTests(TestCase):
    """
    :class:`.Client` end to end test using Pebble over localhost.
    """

    @defer.inlineCallbacks
    def test_directory_lets_encrypt_staging(self):
        """
        Can start the client with the public Let's Encrypt staging URL.
        """
        client = yield Client.from_url(
            reactor,
            URL.from_text('https://acme-staging-v02.api.letsencrypt.org/directory'),
            key=RSA_TEST_KEY,
            )
        registration = yield client.start()

        self.assertIn(
            'https://acme-staging-v02.api.letsencrypt.org/acme/acct/',
            registration.uri)

        # Close any cached connection.
        yield client.stop()

    @defer.inlineCallbacks
    def test_directory_pebble_testing(self):
        """
        Can start the client with the public Let's Encrypt staging URL.
        """
        agent = Agent(reactor, contextFactory=UnsafePolicyForHTTPS())
        jws_client = JWSClient(agent, key=RSA_TEST_KEY, alg=RS256)
        client = yield Client.from_url(
            reactor,
            PEBBLE_URL,
            key=RSA_TEST_KEY,
            jws_client=jws_client,
            )
        # This will register the new account.
        registration = yield client.start()

        # Minimal checks for the new account.
        account_uri = registration.uri
        self.assertIn('/my-account/', registration.uri)

        # Stop can be triggered multiple times.
        yield client.stop()
        yield client.stop()

        agent = Agent(reactor, contextFactory=UnsafePolicyForHTTPS())
        jws_client = JWSClient(agent, key=RSA_TEST_KEY, alg=RS256)
        client = yield Client.from_url(
            reactor,
            PEBBLE_URL,
            key=RSA_TEST_KEY,
            jws_client=jws_client,
            )

        registration = yield client.start()
        self.assertEqual(account_uri, registration.uri)

        # Trigger the closing of TCP connections.
        yield client.stop()


class UnsafePolicyForHTTPS(BrowserLikePolicyForHTTPS):
    """
    Policy to help with testing.
    Doesn't validated the server certificate.

    This is to be used with the pebble server.
    """
    def __init__(self):
        self._ssl_context = SSL.Context(SSL.SSLv23_METHOD)

    def creatorForNetloc(self, hostname, port):
        """
        Create a L{client connection creator
        <twisted.internet.interfaces.IOpenSSLClientConnectionCreator>} for a
        given network location.
        """
        return UnsafeClientTLSOptions(
            hostname=hostname.decode("ascii"),
            ctx=self._ssl_context,
            )


@implementer(IOpenSSLClientConnectionCreator)
class UnsafeClientTLSOptions:
    """
    Client creator for TLS with SNI but without server validation
    """

    def __init__(self, hostname, ctx):
        self._hostname = hostname
        self._ctx = ctx

    def clientConnectionForTLS(self, tlsProtocol):
        """
        Create a TLS connection for a client.
        """
        connection = SSL.Connection(self._ctx, None)
        server_name = self._hostname.encode('utf-8')
        connection.set_tlsext_host_name(server_name)
        return connection
