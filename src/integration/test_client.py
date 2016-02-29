"""
Integration tests for :mod:`acme.client`.
"""
from __future__ import print_function
from acme.jose import JWKRSA
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.python.url import URL
from twisted.trial.unittest import TestCase

from txacme.client import Client
from txacme.util import generate_private_key


STAGING_DIRECTORY = URL.fromText(
    u'https://acme-staging.api.letsencrypt.org/directory')


class ClientTests(TestCase):
    @inlineCallbacks
    def test_registration(self):
        key = JWKRSA(key=generate_private_key('rsa'))
        client = yield Client.from_url(reactor, STAGING_DIRECTORY, key=key)
        reg = yield client.register()
        # Re-registering just fetches the old registration
        reg2 = yield client.register()
        self.assertEqual(reg, reg2)
        yield client.agree_to_tos(reg2)
        yield client._client._treq._agent._pool.closeCachedConnections()
