from datetime import timedelta
from functools import partial

from acme import messages
import attr
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from pem import Certificate, Key
from twisted.application.internet import TimerService
from twisted.application.service import Service
from twisted.internet.defer import Deferred, gatherResults, succeed
from twisted.logger import Logger

from txacme.client import answer_challenge, fqdn_identifier, poll_until_valid
from txacme.messages import CertificateRequest
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

    :type cert_store: `~txacme.interfaces.ICertificateStore`
    :param cert_store: The certificate store containing the certificates to
        manage.

    :type client_creator: Callable[[], Deferred[`txacme.client.Client`]]
    :param client_creator: A callable called with no arguments for creating the
        ACME client.  For example, ``partial(Client.from_url, reactor=reactor,
        url=LETSENCRYPT_STAGING_DIRECTORY, key=acme_key, alg=RS256)``.
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
    _client_creator = attr.ib()
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

            log.info(
                'Found {panicing_count:d} overdue / expired and '
                '{expiring_count:d} expiring certificates.',
                panicing_count=len(panicing),
                expiring_count=len(expiring))

            d1 = (
                gatherResults(
                    [self._with_client(self._issue_cert, server_name)
                     .addErrback(self._panic, server_name)
                     for server_name in panicing],
                    consumeErrors=True)
                .addCallback(done_panicing))
            d2 = gatherResults(
                [self.issue_cert(server_name)
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
            self._ensure_registered()
            .addCallback(lambda _: self.cert_store.as_dict())
            .addCallback(check)
            .addErrback(
                lambda f: log.failure(
                    u'Error in scheduled certificate check.', f)))

    def issue_cert(self, server_name):
        """
        Issue a new cert for a particular name.

        If an existing cert exists, it will be replaced with the new cert.  If
        issuing is already in progress for the given name, a second issuing
        process will *not* be started.

        :param str server_name: The name to issue a cert for.

        :rtype: ``Deferred``
        :return: A deferred that fires when issuing is complete.
        """
        def finish(result):
            _, waiting = self._issuing.pop(server_name)
            for d in waiting:
                d.callback(result)

        # d_issue is assigned below, in the conditional, since we may be
        # creating it or using the existing one.
        d = Deferred(lambda _: d_issue.cancel())
        if server_name in self._issuing:
            d_issue, waiting = self._issuing[server_name]
            waiting.append(d)
        else:
            d_issue = self._with_client(self._issue_cert, server_name)
            waiting = [d]
            self._issuing[server_name] = (d_issue, waiting)
            # Add the callback afterwards in case we're using a client
            # implementation that isn't actually async
            d_issue.addBoth(finish)
        return d

    def _with_client(self, f, *a, **kw):
        """
        Construct a client, and perform an operation with it.
        """
        return self._client_creator().addCallback(f, *a, **kw)

    def _issue_cert(self, client, server_name):
        """
        Issue a new cert for a particular name.
        """
        log.info(
            'Requesting a certificate for {server_name!r}.',
            server_name=server_name)
        key = self._generate_key()
        objects = [
            Key(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))]

        def answer_and_poll(authzr):
            def got_challenge(stop_responding):
                return (
                    poll_until_valid(authzr, self._clock, client)
                    .addBoth(tap(lambda _: stop_responding())))
            return (
                answer_challenge(authzr, client, self._responders)
                .addCallback(got_challenge))

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
            log.info(
                'Received certificate for {server_name!r}.',
                server_name=server_name)
            self.cert_store.store(server_name, objects)

        names = [n.strip() for n in server_name.split(',')]

        challenges = []
        for name in names:
            deferred = self._client.request_challenges(fqdn_identifier(name))
            deferred.addCallback(answer_and_poll)
            challenges.append(deferred)

        return (
            gatherResults(challenges, consumeErrors=True)
            .addCallback(lambda ign: self._client.request_issuance(
                CertificateRequest(
                    csr=csr_for_names(names, key))))
            .addCallback(got_cert)
            .addCallback(self._client.fetch_chain)
            .addCallback(got_chain)
            )

    def _ensure_registered(self):
        """
        Register if needed.
        """
        if self._registered:
            return succeed(None)
        else:
            return self._with_client(self._register)

    def _register(self, client):
        """
        Register and agree to the TOS.
        """
        def _registered(regr):
            self._regr = regr
            self._registered = True
        regr = messages.NewRegistration.from_data(email=self._email)
        return (
            client.register(regr)
            .addCallback(client.agree_to_tos)
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
            self.check_interval.total_seconds(), self._check_certs)
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
