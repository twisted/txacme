from datetime import timedelta
from functools import partial

import attr
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import pem
from twisted.application.internet import TimerService
from twisted.application.service import Service
from twisted.internet import defer
from twisted.logger import Logger

from txacme.client import answer_challenge, get_certificate
from txacme.util import clock_now, generate_private_key, tap


log = Logger()


def _default_panic(failure, server_name):
    log.failure(
        u'PANIC! Unable to renew certificate for: {server_name!r}',
        failure, server_name=server_name)


@attr.s(cmp=False, hash=False)
class AcmeIssuingService(Service):
    """
    A service for keeping certificates up to date by using an ACME server.

    :type cert_store: `~txacme.interfaces.ICertificateStore`
    :param cert_store: The certificate store containing the certificates to
        manage.

    :type client: `txacme.client.Client`
    :param client: A client which is already set to be used for an
        environment.  For example, ``Client.from_url(reactor=reactor,
        url=LETSENCRYPT_STAGING_DIRECTORY, key=acme_key, alg=RS256)``.
        When the service is stopped, it will automatically call the stop
        method on the client.

    :param clock: ``IReactorTime`` provider; usually the reactor, when not
        testing.

    :type responders: List[`~txacme.interfaces.IResponder`]
    :param responders: Challenge responders.  Usually only one responder is
        needed; if more than one responder for the same type is provided, only
        the first will be used.
    :param str email: An (optional) email address to use during registration.
    :param ~datetime.timedelta check_interval: How often to check for expiring
        certificates.
    :param ~datetime.timedelta reissue_interval: If a certificate is expiring
        in less time than this interval, it will be reissued.
    :param ~datetime.timedelta panic_interval: If a certificate is expiring in
        less time than this interval, and reissuing fails, the panic callback
        will be invoked.

    :type panic: Callable[[Failure, `str`], Deferred]
    :param panic: A callable invoked with the failure and server name when
        reissuing fails for a certificate expiring in the ``panic_interval``.
        For example, you could generate a monitoring alert.  The default
        callback logs a message at *CRITICAL* level.
    :param generate_key: A 0-arg callable used to generate a private key for a
        new cert.  Normally you would not pass this unless you have specialized
        key generation requirements.
    """
    cert_store = attr.ib()
    _client = attr.ib(
        converter=lambda maybe_callable: (
            maybe_callable() if callable(maybe_callable) else maybe_callable
        )
    )
    _clock = attr.ib()
    _responders = attr.ib()
    _email = attr.ib(default=None)
    check_interval = attr.ib(default=timedelta(days=1))
    reissue_interval = attr.ib(default=timedelta(days=30))
    panic_interval = attr.ib(default=timedelta(days=15))
    _panic = attr.ib(default=_default_panic)
    _generate_key = attr.ib(default=partial(generate_private_key, u'rsa'))

    _waiting = attr.ib(default=attr.Factory(list), init=False)
    _issuing = attr.ib(default=attr.Factory(dict), init=False)
    ready = False
    # Service used to repeatedly call the certificate check and renewal.
    _timer_service = None
    # Deferred of the current certificates check.
    # Added to help the automated testing.
    _ongoing_check = None

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
        log.info('Starting scheduled check for expired certificates.')

        def check(certs):
            panicing = set()
            expiring = set()
            for server_names, objects in certs.items():
                if len(objects) == 0:
                    panicing.add(server_names)
                for o in filter(
                        lambda o: isinstance(o, pem.Certificate), objects):
                    cert = x509.load_pem_x509_certificate(
                        o.as_bytes(), default_backend())
                    until_expiry = cert.not_valid_after - self._now()
                    if until_expiry <= self.panic_interval:
                        panicing.add(server_names)
                    elif until_expiry <= self.reissue_interval:
                        expiring.add(server_names)

            log.info(
                'Found {panicing_count:d} overdue / expired and '
                '{expiring_count:d} expiring certificates.',
                panicing_count=len(panicing),
                expiring_count=len(expiring))

            d1 = (
                defer.gatherResults(
                    [self._issue_cert(server_names)
                     .addErrback(self._panic, server_names)
                     for server_names in panicing],
                    consumeErrors=True)
                .addCallback(done_panicing))
            d2 = defer.gatherResults(
                [self.issue_cert(server_names)
                 .addErrback(
                     lambda f: log.failure(
                         u'Error issuing certificate for: {server_names!r}',
                         f, server_names=server_names))
                 for server_names in expiring],
                consumeErrors=True)
            return defer.gatherResults([d1, d2], consumeErrors=True)

        def done_panicing(ignored):
            self.ready = True
            for d in list(self._waiting):
                d.callback(None)
            self._waiting = []

        self._ongoing_check = (
            self.cert_store.as_dict()
            .addCallback(check)
            .addErrback(
                lambda f: log.failure(
                    u'Error in scheduled certificate check.', f)))
        return self._ongoing_check

    def issue_cert(self, server_names):
        """
        Issue a new cert for a particular list of FQDNs.

        If an existing cert exists, it will be replaced with the new cert.  If
        issuing is already in progress for the given name, a second issuing
        process will *not* be started.

        :param str server_names: The comma separated list of names to issue a
            cert for.

        :rtype: ``Deferred``
        :return: A deferred that fires when issuing is complete.
        """
        canonical_names = self._canonicalNames(server_names)

        def finish(result):
            _, waiting = self._issuing.pop(canonical_names)
            for d in waiting:
                d.callback(result)

        # d_issue is assigned below, in the conditional, since we may be
        # creating it or using the existing one.
        d = defer.Deferred(lambda _: d_issue.cancel())
        if canonical_names in self._issuing:
            d_issue, waiting = self._issuing[canonical_names]
            waiting.append(d)
        else:
            d_issue = self._issue_cert(canonical_names)
            waiting = [d]
            self._issuing[canonical_names] = (d_issue, waiting)
            # Add the callback afterwards in case we're using a client
            # implementation that isn't actually async
            d_issue.addBoth(finish)
        return d

    @staticmethod
    def _canonicalNames(server_names):
        """
        Return the canonical representation for `server_names`.
        """
        names = [n.strip() for n in server_names.split(',')]
        return ','.join(names)

    def _issue_cert(self, server_names):
        """
        Issue a new cert for the list of server_names.

        `server_names` is already canonized.
        """
        names = [n.strip() for n in server_names.split(',')]

        log.info(
            'Requesting a certificate for {server_names!r}.',
            server_names=server_names)
        key = self._generate_key()
        objects = [
            pem.Key(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))]

        @defer.inlineCallbacks
        def answer_to_order(orderr):
            """
            Answer the challenges associated with the order.
            """
            for authorization in orderr.authorizations:
                yield answer_challenge(
                    authorization,
                    self._client,
                    self._responders,
                    clock=self._clock,
                )
            certificate = yield get_certificate(
                orderr, self._client, clock=self._clock)
            defer.returnValue(certificate)

        def got_cert(certr):
            """
            Called when we got a certificate.
            """
            # The certificate is returned as chain.
            objects.extend(pem.parse(certr.body))
            self.cert_store.store(','.join(names), objects)

        return (
            self._client.submit_order(key, names)
            .addCallback(answer_to_order)
            .addCallback(got_cert)
            )

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
            return defer.succeed(None)
        d = defer.Deferred()
        self._waiting.append(d)
        return d

    def start(self):
        """
        Like startService, but will return a deferred once the service was
        started and operational.
        """
        Service.startService(self)

        def cb_start(result):
            """
            Called when the client is ready for operation.
            """
            self._timer_service = TimerService(
                self.check_interval.total_seconds(), self._check_certs)
            self._timer_service.clock = self._clock
            self._timer_service.startService()

        return self._client.start(email=self._email).addCallback(cb_start)

    def startService(self):
        """
        Start operating the service.

        See `when_certs_valid` if you want to be notified when all the
        certificate from the storage were validated after startup.
        """
        self.start().addErrback(self._panic, 'FAIL-TO-START')

    def stopService(self):
        Service.stopService(self)
        self.ready = False
        for d in list(self._waiting):
            d.cancel()
        self._waiting = []

        def stop_timer(ignored):
            if not self._timer_service:
                return
            return self._timer_service.stopService()

        def cleanup(ignored):
            self._timer_service = None

        return (
            self._client.stop()
            .addBoth(tap(stop_timer))
            .addBoth(tap(cleanup))
            )


__all__ = ['AcmeIssuingService']
