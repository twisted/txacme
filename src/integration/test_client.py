"""
Integration tests for :mod:`acme.client`.
"""
from __future__ import print_function

from functools import partial
from os import getenv

from acme.jose import JWKRSA
from acme.messages import NewRegistration, STATUS_PENDING
from cryptography.hazmat.primitives import serialization
from eliot import start_action
from eliot.twisted import DeferredContext
from twisted.internet import reactor
from twisted.internet.defer import succeed
from twisted.internet.endpoints import serverFromString
from twisted.python.compat import _PY3
from twisted.python.filepath import FilePath
from twisted.trial.unittest import TestCase
from twisted.web.resource import Resource
from twisted.web.server import Site
from txsni.snimap import SNIMap
from txsni.tlsendpoint import TLSEndpoint

from txacme.challenges import LibcloudDNSResponder, TLSSNI01Responder
from txacme.client import (
    answer_challenge, Client, fqdn_identifier, LETSENCRYPT_STAGING_DIRECTORY,
    poll_until_valid)
from txacme.messages import CertificateRequest
from txacme.testing import FakeClient, NullResponder
from txacme.util import csr_for_names, generate_private_key, tap


class ClientTestsMixin(object):
    """
    Integration tests for the ACME client.
    """
    def _test_create_client(self):
        with start_action(action_type=u'integration:create_client').context():
            self.key = JWKRSA(key=generate_private_key('rsa'))
            return (
                DeferredContext(self._create_client(self.key))
                .addActionFinish())

    def _test_register(self, new_reg=None):
        with start_action(action_type=u'integration:register').context():
            return (
                DeferredContext(self.client.register(new_reg))
                .addActionFinish())

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
                    self.client.request_challenges(fqdn_identifier(host)))
                .addActionFinish())

    def _test_poll_pending(self, auth):
        action = start_action(action_type=u'integration:poll_pending')
        with action.context():
            return (
                DeferredContext(self.client.poll(auth))
                .addCallback(
                    lambda auth:
                    self.assertEqual(auth[0].body.status, STATUS_PENDING))
                .addActionFinish())

    def _test_answer_challenge(self, responder):
        action = start_action(action_type=u'integration:answer_challenge')
        with action.context():
            self.responder = responder
            return (
                DeferredContext(
                    answer_challenge(
                        self.authzr, self.client, [responder]))
                .addActionFinish())

    def _test_poll(self, auth):
        action = start_action(action_type=u'integration:poll')
        with action.context():
            return (
                DeferredContext(poll_until_valid(auth, reactor, self.client))
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
            .addCallback(lambda _: self._test_register())
            .addCallback(tap(
                lambda reg1:
                self._test_register(
                    NewRegistration.from_data(email=u'example@example.com'))
                .addCallback(
                    lambda reg2: self.assertEqual(reg1.uri, reg2.uri))))
            .addCallback(self._test_agree_to_tos)
            .addCallback(
                lambda _: self._test_request_challenges(self.HOST))
            .addCallback(partial(setattr, self, 'authzr'))
            .addCallback(lambda _: self._create_responder())
            .addCallback(tap(lambda _: self._test_poll_pending(self.authzr)))
            .addCallback(self._test_answer_challenge)
            .addCallback(tap(lambda _: self._test_poll(self.authzr)))
            .addCallback(lambda stop_responding: stop_responding())
            .addCallback(lambda _: self._test_issue(self.HOST))
            .addCallback(self._test_chain)
            .addActionFinish())

    def test_issuing(self):
        action = start_action(action_type=u'integration')
        with action.context():
            return self._test_registration()


def _getenv(name, default=None):
    """
    Sigh.
    """
    if not _PY3:
        name = name.encode('utf-8')
    value = getenv(name)
    if value is None:
        return default
    if not _PY3:
        value = value.decode('utf-8')
    return value


class LetsEncryptStagingTLSSNI01Tests(ClientTestsMixin, TestCase):
    """
    Tests using the real ACME client against the Let's Encrypt staging
    environment, and the tls-sni-01 challenge.

    You must set $ACME_HOST to a hostname that will, when connected to on port
    443, reach a listening socket opened by the tests on $ACME_ENDPOINT.
    """
    HOST = _getenv(u'ACME_HOST')
    ENDPOINT = _getenv(u'ACME_ENDPOINT', u'tcp:443')
    if not _PY3:
        ENDPOINT = ENDPOINT.encode('utf-8')

    if HOST is None:
        skip = 'Must provide $ACME_HOST'

    def _create_client(self, key):
        return (
            Client.from_url(reactor, LETSENCRYPT_STAGING_DIRECTORY, key=key)
            .addCallback(tap(
                lambda client: self.addCleanup(
                    client._client._treq._agent._pool.closeCachedConnections)))
            )

    def _create_responder(self):
        action = start_action(action_type=u'integration:create_responder')
        with action.context():
            responder = TLSSNI01Responder()
            host_map = responder.wrap_host_map({})
            site = Site(Resource())
            endpoint = TLSEndpoint(
                endpoint=serverFromString(reactor, self.ENDPOINT),
                contextFactory=SNIMap(host_map))
            return (
                DeferredContext(endpoint.listen(site))
                .addCallback(lambda port: self.addCleanup(port.stopListening))
                .addCallback(lambda _: responder)
                .addActionFinish())


class LetsEncryptStagingLibcloudTests(ClientTestsMixin, TestCase):
    """
    Tests using the real ACME client against the Let's Encrypt staging
    environment, and the dns-01 challenge.

    You must set $ACME_HOST to a hostname that will be used for the challenge,
    and $LIBCLOUD_PROVIDER, $LIBCLOUD_USERNAME, $LIBCLOUD_PASSWORD, and
    $LIBCLOUD_ZONE to the appropriate values for the DNS provider to complete
    the challenge with.
    """
    HOST = _getenv(u'ACME_HOST')
    PROVIDER = _getenv(u'LIBCLOUD_PROVIDER')
    USERNAME = _getenv(u'LIBCLOUD_USERNAME')
    PASSWORD = _getenv(u'LIBCLOUD_PASSWORD')
    ZONE = _getenv(u'LIBCLOUD_ZONE')

    if None in (HOST, PROVIDER, USERNAME, PASSWORD, ZONE):
        skip = 'Must provide $ACME_HOST and $LIBCLOUD_*'

    def _create_client(self, key):
        return (
            Client.from_url(reactor, LETSENCRYPT_STAGING_DIRECTORY, key=key)
            .addCallback(tap(
                lambda client: self.addCleanup(
                    client._client._treq._agent._pool.closeCachedConnections)))
            )

    def _create_responder(self):
        with start_action(action_type=u'integration:create_responder'):
            return LibcloudDNSResponder.create(
                reactor,
                self.PROVIDER,
                self.USERNAME,
                self.PASSWORD,
                self.ZONE)


class FakeClientTests(ClientTestsMixin, TestCase):
    """
    Tests against our verified fake.
    """
    HOST = u'example.com'

    def _create_client(self, key):
        return succeed(FakeClient(key, reactor))

    def _create_responder(self):
        return succeed(NullResponder(u'tls-sni-01'))


__all__ = ['LetsEncryptStagingTLSSNI01Tests', 'FakeClientTests']
