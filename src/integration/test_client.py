"""
Integration tests for :mod:`acme.client`.
"""
from __future__ import print_function

from functools import partial

from acme.jose import JWKRSA
from acme.messages import STATUS_PENDING, STATUS_PROCESSING, STATUS_VALID
from eliot import start_action
from eliot.twisted import DeferredContext
from twisted.internet import reactor
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
from txacme.util import generate_private_key, tap


STAGING_DIRECTORY = URL.fromText(
    u'https://acme-staging.api.letsencrypt.org/directory')
HOST = u'acme-testing.mithrandi.net'


class ClientTests(TestCase):
    def _cleanup_client(self):
        return self.client._client._treq._agent._pool.closeCachedConnections()

    def _test_create_client(self):
        with start_action(action_type=u'integration:create_client').context():
            self.key = JWKRSA(key=generate_private_key('rsa'))
            return (
                DeferredContext(
                    Client.from_url(reactor, STAGING_DIRECTORY, key=self.key))
                .addActionFinish())

    def _test_register(self):
        with start_action(action_type=u'integration:register').context():
            return DeferredContext(self.client.register()).addActionFinish()

    def _test_agree_to_tos(self, reg):
        with start_action(action_type=u'integration:agree_to_tos').context():
            return (
                DeferredContext(self.client.agree_to_tos(reg))
                .addActionFinish())

    def _test_request_challenges(self, host):
        def _find_tls(auth):
            self.auth = auth
            for challbs in auth.body.resolved_combinations:
                if tuple(challb.typ for challb in challbs) == (u'tls-sni-01',):
                    return challbs[0]
            else:
                raise RuntimeError('No supported challenges found!')

        action = start_action(
            action_type=u'integration:request_challenges',
            host=host)
        with action.context():
            return (
                DeferredContext(
                   self. client.request_challenges(fqdn_identifier(host)))
                .addCallback(_find_tls)
                .addActionFinish())

    def _create_response(self):
        self.response = self.challb.response(self.key)

    def _create_responder(self):
        action = start_action(action_type=u'integration:create_responder')
        with action.context():
            responder = TLSSNI01Responder()
            host_map = responder.wrap_host_map({})
            site = Site(Resource())
            endpoint = TLSEndpoint(
                endpoint=serverFromString(reactor, 'tcp:4433'),
                contextFactory=SNIMap(host_map))
            return (
                DeferredContext(endpoint.listen(site))
                .addCallback(lambda port: self.addCleanup(port.stopListening))
                .addCallback(lambda _: responder)
                .addActionFinish())

    def _test_answer_challenge(self, challb, response):
        action = start_action(action_type=u'integration:answer_challenge')
        with action.context():
            return (
                DeferredContext(self.client.answer_challenge(challb, response))
                .addActionFinish())

    def _test_poll(self, auth):
        def repoll(result):
            auth, retry_after = result
            if auth.body.status in {STATUS_PENDING, STATUS_PROCESSING}:
                return (
                    deferLater(reactor, retry_after, lambda: None)
                    .addCallback(lambda _: self.client.poll(auth))
                    .addCallback(repoll)
                    )
            self.assertEqual(
                auth.body.status, STATUS_VALID,
                'Unexpected response received: {!r}'.format(auth.body))
            return auth

        action = start_action(action_type=u'integration:poll')
        with action.context():
            return (
                DeferredContext(self.client.poll(auth))
                .addCallback(repoll)
                .addActionFinish())

    def _test_registration(self):
        return (
            DeferredContext(self._test_create_client())
            .addCallback(partial(setattr, self, 'client'))
            .addCallback(lambda _: self.addCleanup(self._cleanup_client))
            .addCallback(lambda _: self._test_register())
            .addCallback(tap(
                lambda reg1:
                self._test_register()
                .addCallback(lambda reg2: self.assertEqual(reg1, reg2))))
            .addCallback(self._test_agree_to_tos)
            .addCallback(
                lambda _: self._test_request_challenges(HOST))
            .addCallback(partial(setattr, self, 'challb'))
            .addCallback(lambda _: self._create_response())
            .addCallback(lambda _: self._create_responder())
            .addCallback(
                lambda responder: responder.start_responding(
                    self.response.z_domain.decode('ascii')))
            .addCallback(
                lambda _: self._test_answer_challenge(
                    self.challb, self.response))
            .addCallback(lambda _: self._test_poll(self.auth))
            .addActionFinish())

    def test_registration(self):
        action = start_action(action_type=u'integration')
        with action.context():
            return self._test_registration()
