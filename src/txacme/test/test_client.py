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
from treq.client import HTTPClient
from treq.testing import RequestSequence as treq_RequestSequence
from treq.testing import (
    _SynchronousProducer, RequestTraversalAgent, StringStubbingResource)
from twisted.internet import defer, reactor
from twisted.internet.defer import Deferred, CancelledError, fail, succeed
from twisted.internet.error import ConnectionClosed
from twisted.internet.task import Clock
from twisted.python.url import URL
from twisted.test.proto_helpers import MemoryReactor
from twisted.web import http, server
from twisted.web.resource import Resource
from twisted.web.http_headers import Headers
from twisted.trial.unittest import TestCase
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

    @defer.inlineCallbacks
    def test_directory_url_type(self):
        """
        `~txacme.client.Client.from_url` expects a ``twisted.python.url.URL``
        instance for the ``url`` argument.
        """
        with self.assertRaises(TypeError):
            yield Client.from_url(
                reactor, '/wrong/kind/of/directory', key=RSA_KEY_512)

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
            json=lambda: succeed({
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


__all__ = ['ClientTests', 'ExtraCoverageTests', 'LinkParsingTests']
