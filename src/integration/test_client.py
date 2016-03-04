"""
Integration tests for :mod:`acme.client`.
"""
from __future__ import print_function

from acme.jose import JWKRSA
from acme.messages import STATUS_PENDING
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import serverFromString
from twisted.internet.task import deferLater
from twisted.python.url import URL
from twisted.trial.unittest import TestCase
from twisted.web.resource import Resource
from twisted.web.server import Site
from txsni.snimap import SNIMap
from txsni.tlsendpoint import TLSEndpoint

from txacme.challenges import TLSSNI01Responder
from txacme.client import Client, fqdn_identifier
from txacme.util import generate_private_key


STAGING_DIRECTORY = URL.fromText(
    u'https://acme-staging.api.letsencrypt.org/directory')
HOST = u'acme-testing.mithrandi.net'


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

        auth = yield client.request_challenges(fqdn_identifier(HOST))
        for challbs in auth.body.resolved_combinations:
            if tuple(challb.typ for challb in challbs) == (u'tls-sni-01',):
                challb = challbs[0]
                break
        else:
            raise RuntimeError('No supported challenges found!')

        responder = TLSSNI01Responder()
        host_map = responder.wrap_host_map({})
        site = Site(Resource())
        endpoint = TLSEndpoint(
            endpoint=serverFromString(reactor, 'tcp:4433'),
            contextFactory=SNIMap(host_map))
        port = yield endpoint.listen(site)

        response = challb.response(key)
        responder.start_responding(response.z_domain.decode('ascii'))

        print(challb.uri)
        challr = yield client.answer_challenge(challb, response)
        print(challr.body.status)

        auth = yield client.poll(auth)
        while auth.body.status == STATUS_PENDING:
            yield deferLater(reactor, 5.0, lambda: None)
            auth = yield client.poll(auth)
            print(auth.body.status)

        yield port.stopListening()

        # Close idle connections left over
        yield client._client._treq._agent._pool.closeCachedConnections()
