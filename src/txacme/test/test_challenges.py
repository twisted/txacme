"""
Tests for `txacme.challenges`.
"""
from operator import methodcaller
from unittest import TestCase

from acme import challenges
from josepy.b64 import b64encode
from treq.testing import StubTreq
from twisted._threads import createMemoryWorker
from twisted.internet import defer

from twisted.python.url import URL
from twisted.web.resource import Resource
from zope.interface.verify import verifyObject

from txacme.challenges import HTTP01Responder
from txacme.errors import NotInZone, ZoneNotFound
from txacme.interfaces import IResponder
from txacme.test.test_client import RSA_KEY_512, RSA_KEY_512_RAW


# A random example token for the challenge tests that need one
EXAMPLE_TOKEN = b'BWYcfxzmOha7-7LoxziqPZIUr99BCz3BfbN9kzSFnrU'


class HTTPResponderTests(TestCase):
    """
    `.HTTP01Responder` is a responder for http-01 challenges.
    """

    def test_interface(self):
        """
        The `.IResponder` interface is correctly implemented.
        """
        responder = HTTP01Responder()
        verifyObject(IResponder, responder)
        self.assertEqual(u'http-01', responder.challenge_type)

    @defer.inlineCallbacks
    def test_stop_responding_already_stopped(self):
        """
        Calling ``stop_responding`` when we are not responding for a server
        name does nothing.
        """
        token = EXAMPLE_TOKEN
        challenge = challenges.HTTP01(token=token)
        response = challenge.response(RSA_KEY_512)
        responder = HTTP01Responder()

        yield responder.stop_responding(
            u'example.com',
            challenge,
            response)

    @defer.inlineCallbacks
    def test_start_responding(self):
        """
        Calling ``start_responding`` makes an appropriate resource available.
        """
        token = b'BWYcfxzmOha7-7LoxziqPZIUr99BCz3BfbN9kzSFnrU'
        challenge = challenges.HTTP01(token=token)
        response = challenge.response(RSA_KEY_512)

        responder = HTTP01Responder()

        challenge_resource = Resource()
        challenge_resource.putChild(b'acme-challenge', responder.resource)
        root = Resource()
        root.putChild(b'.well-known', challenge_resource)
        client = StubTreq(root)

        encoded_token = challenge.encode('token')
        challenge_url = URL(host=u'example.com', path=[
            u'.well-known', u'acme-challenge', encoded_token]).asText()

        # We got page not found while the challenge is not yet active.
        result = yield client.get(challenge_url)
        self.assertEqual(404, result.code)

        # Once we enable the response.
        responder.start_responding(u'example.com', challenge, response)
        result = yield client.get(challenge_url)
        self.assertEqual(200, result.code)
        self.assertEqual(
            ['text/plain'], result.headers.getRawHeaders('content-type'))

        result = yield result.content()
        self.assertEqual(response.key_authorization.encode('utf-8'), result)

        # Starting twice before stopping doesn't break things
        responder.start_responding(u'example.com', challenge, response)

        result = yield client.get(challenge_url)
        self.assertEqual(200, result.code)

        yield responder.stop_responding(u'example.com', challenge, response)

        result = yield client.get(challenge_url)
        self.assertEqual(404, result.code)



__all__ = [
    'HTTPResponderTests', 'TLSResponderTests', 'MergingProxyTests',
    ]
