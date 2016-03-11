"""
Integration tests for :mod:`acme.client`.
"""
from __future__ import print_function

from functools import partial

from acme.jose import JWKRSA
from cryptography.hazmat.primitives import serialization
from eliot import start_action
from eliot.twisted import DeferredContext
from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString
from twisted.python.filepath import FilePath
from twisted.python.url import URL
from twisted.trial.unittest import TestCase
from twisted.web.resource import Resource
from twisted.web.server import Site
from txsni.snimap import SNIMap
from txsni.tlsendpoint import TLSEndpoint

from txacme.challenges import TLSSNI01Responder
from txacme.client import (
    answer_tls_sni_01_challenge, Client, fqdn_identifier, poll_until_valid)
from txacme.messages import CertificateRequest
from txacme.util import csr_for_names, generate_private_key, tap


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
        action = start_action(
            action_type=u'integration:request_challenges',
            host=host)
        with action.context():
            return (
                DeferredContext(
                   self. client.request_challenges(fqdn_identifier(host)))
                .addActionFinish())

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

    def _test_answer_challenge(self, responder):
        action = start_action(action_type=u'integration:answer_challenge')
        with action.context():
            return (
                DeferredContext(
                    answer_tls_sni_01_challenge(
                        self.client, self.authzr, responder))
                .addActionFinish())

    def _test_poll(self, auth):
        action = start_action(action_type=u'integration:poll')
        with action.context():
            return (
                DeferredContext(poll_until_valid(reactor, self.client, auth))
                .addActionFinish())

    def _test_issue(self, name):
        def got_cert(certr):
            key_bytes = self.issued_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())
            FilePath('issued.crt').setContent(certr.body)
            FilePath('issued.key').setContent(key_bytes)
            return certr

        action = start_action(action_type=u'integration:issue')
        with action.context():
            self.issued_key = generate_private_key('rsa')
            csr = csr_for_names([name], self.issued_key)
            return (
                DeferredContext(
                    self.client.request_issuance(CertificateRequest(csr=csr)))
                .addCallback(got_cert)
                .addActionFinish())

    def _test_chain(self, certr):
        action = start_action(action_type=u'integration:chain')
        with action.context():
            return (
                DeferredContext(self.client.fetch_chain(certr))
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
            .addCallback(partial(setattr, self, 'authzr'))
            .addCallback(lambda _: self._create_responder())
            .addCallback(self._test_answer_challenge)
            .addCallback(lambda _: self._test_poll(self.authzr))
            .addCallback(lambda _: self._test_issue(HOST))
            .addCallback(self._test_chain)
            .addActionFinish())

    def test_registration(self):
        action = start_action(action_type=u'integration')
        with action.context():
            return self._test_registration()
