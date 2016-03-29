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
from txacme.util import clock_now, csr_for_names, generate_private_key, tap


log = Logger()


def _default_panic(failure, server_name):
    log.failure(
        u'PANIC! Unable to renew certificate for: {server_name!r}',
        failure, server_name=server_name)


@attr.s(cmp=False, hash=False)
class AcmeIssuingService(Service):
    """
    A service for keeping certificates up to date by using an ACME server.

    :param .ICertificateStore cert_store: The certificate store containing the
        certificates to manage.
    :param ~txacme.client.Client client: The ACME client to use.  Typically
        constructed with `Client.from_url <txacme.client.Client.from_url>`.
    :param clock: ``IReactorTime`` provider; usually the reactor, when not
        testing.
    :param .ITLSSNI01Responder tls_sni_01_responder: Responder for
        ``tls-sni-01`` challenges.
    :param int check_seconds: How often to check for expiring certificates, in
        seconds.
    :param ~datetime.timedelta reissue_interval: If a certificate is expiring
        in less time than this interval, it will be reissued.
    :param ~datetime.timedelta panic_interval: If a certificate is expiring in
        less time than this interval, and reissuing fails, the panic callback
        will be invoked.

    :type panic: ``Callable[[Failure, str], Deferred]``
    :param panic: A callable invoked with the failure and server name when
        reissuing fails for a certificate expiring in the ``panic_interval``.
        For example, you could generate a monitoring alert.  The default
        callback logs a message at *CRITICAL* level.
    :param generate_key: A 0-arg callable that generates a new private key.
        Normally you would not pass this unless you have specialized key
        generation requirements.
    """
    cert_store = attr.ib()
    _client = attr.ib()
    _clock = attr.ib()
    _tls_sni_01_responder = attr.ib()
    check_seconds = attr.ib(default=24 * 60 * 60)  # default is 1 day
    reissue_interval = attr.ib(default=timedelta(days=30))
    panic_interval = attr.ib(default=timedelta(days=15))
    _panic = attr.ib(default=_default_panic)
    _generate_key = attr.ib(default=partial(generate_private_key, u'rsa'))
    _waiting = attr.ib(default=attr.Factory(list))
    ready = False

    def _now(self):
        """
        Get the current time.
        """
        return clock_now(self._clock)

    def _check_certs(self):
        """
        Check all of the certs in the store, and reissue any that are expired
        or close to expiring.
        """
        def check(certs):
            panicing = set()
            expiring = set()
            for server_name, objects in certs.items():
                if len(objects) == 0:
                    panicing.add(server_name)
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
            for d in list(self._waiting):
                d.callback(None)
            self._waiting = []

        return (
            self._register()
            .addCallback(lambda _: self.cert_store.as_dict())
            .addCallback(check))

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

    def _register(self):
        """
        Register if needed.
        """
        def _registered(ign):
            self._registered = True
        if self._registered:
            return succeed(None)
        else:
            return (
                self._client.register()
                .addCallback(self._client.agree_to_tos)
                .addCallback(_registered))

    def when_certs_valid(self):
        """
        Get a notification once the startup check has completed.

        When the service starts, an initial check is made immediately; the
        deferred returned by this function will only fire once reissue has been
        attempted for any certificates within the panic interval.

        ..  note:: The reissue for any of these certificates may not have been
            successful; the panic callback will be invoked for any certificates
            in the panic interval that failed reissue.

        :rtype: ``Deferred``
        :return: A deferred that fires once the initial check has resolved.
        """
        if self.ready:
            return succeed(None)
        d = Deferred()
        self._waiting.append(d)
        return d

    def startService(self):
        Service.startService(self)
        self._registered = False
        self._timer_service = TimerService(
            self.check_seconds, self._check_certs)
        self._timer_service.clock = self._clock
        self._timer_service.startService()

    def stopService(self):
        Service.stopService(self)
        self.ready = False
        self._registered = False
        for d in list(self._waiting):
            d.cancel()
        self._waiting = []
        return self._timer_service.stopService()


__all__ = ['AcmeIssuingService']
