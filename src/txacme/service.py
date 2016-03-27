from datetime import timedelta
from functools import partial

import attr
from acme import messages
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from pem import Certificate, Key
from twisted.application.internet import TimerService
from twisted.application.service import Service
from twisted.internet.defer import Deferred, gatherResults, succeed
from twisted.logger import Logger

from txacme.client import answer_tls_sni_01_challenge, poll_until_valid
from txacme.util import csr_for_names, generate_private_key, tap


log = Logger()


def _default_panic(failure, server_name):
    log.failure(
        u'PANIC! Unable to renew certificate for: {server_name!r}',
        failure, server_name=server_name)


@attr.s
class AcmeIssuingService(Service):
    """
    A service for keeping certificates up to date by using an ACME server.
    """
    cert_store = attr.ib()
    _client = attr.ib()
    _clock = attr.ib()
    _now = attr.ib()
    _tls_sni_01_responder = attr.ib()
    check_interval = attr.ib(default=24 * 60 * 60)  # default is 1 day
    reissue_interval = attr.ib(default=timedelta(days=30))
    panic_interval = attr.ib(default=timedelta(days=15))
    _panic = attr.ib(default=_default_panic)
    _generate_key = attr.ib(default=partial(generate_private_key, u'rsa'))

    def _check_certs(self):
        """
        Check all of the certs in the store, and reissue any that are expired
        or close to expiring.
        """
        def check(certs):
            panicing = set()
            expiring = set()
            for server_name, objects in certs.items():
                for o in filter(lambda o: isinstance(o, Certificate), objects):
                    cert = x509.load_pem_x509_certificate(
                        o.as_bytes(), default_backend())
                    until_expiry = cert.not_valid_after - self._now()
                    if until_expiry <= self.panic_interval:
                        panicing.add(server_name)
                    elif until_expiry <= self.reissue_interval:
                        expiring.add(server_name)
            d1 = (
                gatherResults(
                    [self._issue_cert(server_name)
                     .addErrback(self._panic, server_name)
                     for server_name in panicing],
                    consumeErrors=True)
                .addCallback(done_panicing))
            d2 = gatherResults(
                [self._issue_cert(server_name)
                 .addErrback(
                     lambda f: log.failure(
                         u'Error issuing certificate for: {server_name!r}',
                         f, server_name=server_name))
                 for server_name in expiring],
                consumeErrors=True)
            return gatherResults([d1, d2], consumeErrors=True)

        def done_panicing(ignored):
            self.ready = True
            for d in self._waiting:
                d.callback(None)
            self._waiting = []

        return self.cert_store.as_dict().addCallback(check)

    def _issue_cert(self, server_name):
        """
        Issue a new cert for a particular name.
        """
        key = self._generate_key()
        objects = [
            Key(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))]

        def got_cert(certr):
            objects.append(
                Certificate(
                    x509.load_der_x509_certificate(
                        certr.body, default_backend())
                    .public_bytes(serialization.Encoding.PEM)))
            return certr

        def got_chain(chain):
            for certr in chain:
                got_cert(certr)
            return objects

        return (
            self._client.request_challenges(server_name)
            .addCallback(
                tap(answer_tls_sni_01_challenge),
                self._client,
                self._tls_sni_01_responder)
            .addCallback(poll_until_valid, self._clock, self._client)
            .addCallback(lambda ign: self._client.request_issuance(
                messages.CertificateRequest(
                    csr=csr_for_names([server_name], key))))
            .addCallback(got_cert)
            .addCallback(self._client.fetch_chain)
            .addCallback(got_chain)
            .addCallback(partial(self.cert_store.store, server_name)))

    def when_certs_valid(self):
        """
        Get a notification once all certificates are valid.

        When the service starts, an initial check is made for certs that are
        already inside the panic threshold; the deferred returned by this
        function will only fire once reissue has been attempted for any such
        certificates.

        :rtype: ``Deferred``
        :return: A deferred that fires once the initial check has resolved.
        """
        if not self.running:
            raise RuntimeError('Service not started')
        if self.ready:
            return succeed(None)
        d = Deferred()
        self._waiting.append(d)
        return d

    def startService(self):
        Service.startService(self)
        self.ready = False
        self._waiting = []

        def _registered(registration):
            self._timer_service = TimerService(
                self.check_interval, self._check_certs)
            self._timer_service.clock = self._clock
            self._timer_service.startService()
            self.registering = None

        self.registering = (
            self._client.register()
            .addCallback(self._client.agree_to_tos)
            .addCallback(_registered))
        return self.registering

    def stopService(self):
        Service.stopService(self)
        if self.registering is None:
            return self._timer_service.stopService()
        else:
            self.registering.cancel()
            for d in self._waiting:
                d.cancel()
            self._waiting = []


__all__ = ['AcmeIssuingService']
