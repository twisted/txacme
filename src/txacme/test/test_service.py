import uuid
from datetime import datetime, timedelta
from operator import methodcaller

from unittest import TestCase

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from pem import Certificate, RSAPrivateKey
from twisted.internet import defer
from twisted.internet.defer import CancelledError, Deferred, fail
from twisted.internet.task import Clock
from twisted.python.failure import Failure

from txacme.service import _default_panic, AcmeIssuingService
from txacme.test.test_client import (
    failed_with, RecordingResponder, RSA_KEY_512, RSA_KEY_512_RAW)
from txacme.testing import FakeClient, FakeClientController, MemoryStore


def _generate_cert(server_name, not_valid_before, not_valid_after,
                   key=RSA_KEY_512_RAW):
    """
    Generate a self-signed certificate for test purposes.

    :param str server_name: The SAN the certificate should have.
    :param ~datetime.datetime not_valid_before: Valid from this moment.
    :param ~datetime.datetime not_valid_after: Expiry time.
    :param key: The private key.

    :rtype: `str`
    :return: The certificate in PEM format.
    """
    common_name = (
        u'san.too.long.invalid' if len(server_name) > 64 else server_name)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .serial_number(int(uuid.uuid4()))
        .public_key(key.public_key())
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(server_name)]),
            critical=False)
        .sign(
            private_key=key,
            algorithm=hashes.SHA256(),
            backend=default_backend())
        )
    return [
        Certificate(
            cert.public_bytes(serialization.Encoding.PEM)),
        RSAPrivateKey(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())),
        ]


def _match_certificate(matcher):
    return MatchesAny(
        Not(IsInstance(Certificate)),
        AfterPreprocessing(
            lambda c: x509.load_pem_x509_certificate(
                c.as_bytes(), default_backend()),
            matcher))


class HangingClient(object):
    """
    Test client that always hangs.
    """
    def __getattr__(self, name):
        return lambda *a, **kw: Deferred()


class FailingClient(object):
    """
    Test client that always fails.
    """
    def __getattr__(self, name):
        return lambda *a, **kw: fail(
            RuntimeError('Failing at "%s".' % (name,)))


class AcmeFixture(object):
    """
    A fixture for setting up an `~txacme.service.AcmeIssuingService`.
    """
    def __init__(self, test_case, now=datetime(2000, 1, 1, 0, 0, 0), certs=None,
                 panic_interval=None, panic=None, client=None, email=None):
        self.now = now
        self._certs = certs
        self._panic_interval = panic_interval
        self._panic = panic
        self._email = email
        self.acme_client = client
        self.controller = FakeClientController()

        self.cert_store = MemoryStore(self._certs)
        self.clock = Clock()
        self.clock.rightNow = (
            self.now - datetime(1970, 1, 1)).total_seconds()
        if self.acme_client is None:
            acme_client = FakeClient(
                RSA_KEY_512, clock=self.clock, ca_key=RSA_KEY_512_RAW,
                controller=self.controller)
        else:
            acme_client = self.acme_client
        self.responder = RecordingResponder(set(), u'http-01')
        args = dict(
            cert_store=self.cert_store,
            client=acme_client,
            clock=self.clock,
            responders=[self.responder],
            email=self._email,
            panic_interval=self._panic_interval,
            panic=self._panic,
            generate_key=lambda: RSA_KEY_512_RAW)
        self.service = AcmeIssuingService(
            **{k: v for k, v in args.items() if v is not None})
        test_case.addCleanup(
            lambda: self.service.running and self.service.stopService())



def panicing_cert(draw, now, panic):
    # @s.composite
    server_name = draw(ts.dns_names())
    offset = timedelta(seconds=draw(
        s.integers(
                min_value=-1000,
                max_value=int(panic.total_seconds()))))
    return (server_name,
            _generate_cert(
                server_name,
                not_valid_before=now + offset - timedelta(seconds=1),
                not_valid_after=now + offset))


def panicing_certs_fixture(draw):
    # @s.composite
    now = draw(datetimes(
        min_value=datetime(1971, 1, 1), max_value=datetime(2030, 1, 1)))
    panic = timedelta(seconds=draw(
        s.integers(min_value=60, max_value=60 * 60 * 24)))
    certs = dict(
        draw(
            s.lists(
                panicing_cert(now, panic),
                min_size=1,
                max_size=5,
                unique_by=lambda i: i[0])))
    return AcmeFixture(now=now, panic_interval=panic, certs=certs)



class AcmeIssuingServiceTests(TestCase):
    """
    Tests for `txacme.service.AcmeIssuingService`.
    """

    @defer.inlineCallbacks
    def test_when_certs_valid_no_certs(self):
        """
        The deferred returned by ``when_certs_valid`` fires immediately if
        there are no certs in the store.
        """
        service = AcmeFixture(self).service
        service.startService()

        result = yield service.when_certs_valid()

        self.assertIsNone(result)

    @defer.inlineCallbacks
    def test_when_certs_valid_all_certs_valid(self):
        """
        The deferred returned by ``when_certs_valid`` fires immediately if
        none of the certs in the store are expired.
        """
        now = datetime(2000, 1, 1, 0, 0, 0)
        certs = [
            (timedelta(seconds=60), u'example.com'),
            (timedelta(seconds=90), u'example.org'),
            ]

        certs = {
            server_name: _generate_cert(
                server_name,
                not_valid_before=now - timedelta(seconds=1),
                not_valid_after=now + offset)
            for offset, server_name in certs}

        fixture = AcmeFixture(self, now=now, certs=certs)

        service = fixture.service
        service.startService()

        result = yield service.when_certs_valid()
        self.assertIsNone(result)

        self.assertEqual(0, len(fixture.responder.challenges))

    def test_when_certs_valid_certs_expired(self, fixture):
        """
        The deferred returned by ``when_certs_valid`` only fires once all
        panicing and expired certs have been renewed.
        """
        #     @given(fixture=panicing_certs_fixture())

        with fixture:
            service = fixture.service
            d = service.when_certs_valid()
            self.assertThat(d, has_no_result())
            service.startService()
            self.assertThat(d, succeeded(Is(None)))
            max_expiry = fixture.now + service.panic_interval
            self.assertThat(
                fixture.cert_store.as_dict(),
                succeeded(AfterPreprocessing(
                    methodcaller('values'),
                    AllMatch(AllMatch(
                        _match_certificate(
                            MatchesStructure(
                                not_valid_after=GreaterThan(max_expiry))))))))
            self.assertThat(fixture.responder.challenges, HasLength(0))

    @defer.inlineCallbacks
    def test_time_marches_on(self):
        """
        Any certs that have exceeded the panic or reissue intervals will be
        reissued at the next check.
        """
        now = datetime(2000, 1, 1, 0, 0, 0)
        certs = {
            u'example.com': _generate_cert(
                u'example.com',
                not_valid_before=now - timedelta(seconds=1),
                not_valid_after=now + timedelta(days=31)),
            u'example.org': _generate_cert(
                u'example.org',
                not_valid_before=now - timedelta(seconds=1),
                not_valid_after=now + timedelta(days=32)),
            }
        fixture = AcmeFixture(self, now=now, certs=certs)
        fixture.service.startService()

        result = yield fixture.service.when_certs_valid()
        self.assertIsNone(result)

        result = yield fixture.cert_store.as_dict()
        self.assertEqual(certs, result)

        fixture.clock.advance(36 * 60 * 60)

        result = yield fixture.cert_store.as_dict()
        self.assertEqual([u'example.com', u'example.org'], result.keys())
        # The .org is not updated  yet.
        self.assertEqual(certs[u'example.org'], result[u'example.org'])
        # The .com is updated.
        self.assertNotEqual(certs[u'example.com'], result[u'example.com'])
        # No pending challenges.
        self.assertEqual(0, len(fixture.responder.challenges))


        fixture.clock.advance(36 * 60 * 60)
        result = yield fixture.cert_store.as_dict()

        self.assertEqual([u'example.com', u'example.org'], result.keys())
        # The .org is not updated  yet.
        self.assertNotEqual(certs[u'example.org'], result[u'example.org'])
        # The .com is updated.
        self.assertNotEqual(certs[u'example.com'], result[u'example.com'])
        # No pending challenges.
        self.assertEqual(0, len(fixture.responder.challenges))

    @defer.inlineCallbacks
    def test_errors(self):
        """
        If a cert renewal fails within the panic interval, the panic callback
        is invoked; otherwise the error is logged normally.
        """
        # @run_test_with(AsynchronousDeferredRunTest)
        now = datetime(2000, 1, 1, 0, 0, 0)
        certs = {
            u'example.com': _generate_cert(
                u'example.com',
                not_valid_before=now - timedelta(seconds=1),
                not_valid_after=now + timedelta(days=31)),
            }
        panics = []
        fixture = AcmeFixture(test_case, now=now, certs=certs,
                         panic=lambda *a: panics.append(a))
        fixture.service.startService()

        result = yield fixture.service.when_certs_valid()
        self.assertIsNone(result)
        # No pending challenges.
        self.assertEqual(0, len(fixture.responder.challenges))

        fixture.controller.pause()
        fixture.clock.advance(36 * 60 * 60)
        # Resume the client.request_issuance deferred with an exception.
        fixture.controller.resume(Failure(Exception()))

        self.assertEqual(1, len(flush_logged_errors()))

        self.assertThat(flush_logged_errors(), HasLength(1))
        self.assertThat(panics, Equals([]))
        self.assertThat(fixture.responder.challenges, HasLength(0))

        fixture.controller.pause()
        fixture.clock.advance(15 * 24 * 60 * 60)
        # Resume the client.request_issuance deferred with an exception.
        fixture.controller.resume(Failure(Exception()))
        self.assertThat(
            panics,
            MatchesListwise([
                MatchesListwise([IsInstance(Failure),
                                 Equals(u'example.com')]),
                ]))
        self.assertThat(fixture.responder.challenges, HasLength(0))

    def test_timer_errors(self):
        """
        If the timed check fails (for example, because registration fails), the
        error should be caught and logged.
        """
        fixture = AcmeFixture(self)
        # @run_test_with(AsynchronousDeferredRunTest)

        # Registration is triggered with service starts.
        fixture.service.startService()
        latest_logs = flush_logged_errors()
        self.assertThat(latest_logs, HasLength(1))
        self.assertThat(
            str(latest_logs[0]), Contains('Failing at "start".'))

        # Manually stop the service to not stop it from the fixture
        # and trigger another failure.
        self.assertThat(
            fixture.service.stopService(),
            failed(AfterPreprocessing(
                lambda f: f.value.args[0], Equals('Failing at "stop".'))))
        latest_logs = flush_logged_errors()

    def test_starting_stopping_cancellation(self):
        """
        Test the starting and stopping behaviour.
        """
        with AcmeFixture(client=HangingClient()) as fixture:
            d = fixture.service.when_certs_valid()
            self.assertThat(d, has_no_result())
            fixture.service.startService()
            self.assertThat(d, has_no_result())
            fixture.service.stopService()
            self.assertThat(d, failed(Always()))

    def test_default_panic(self):
        """
        The default panic callback logs a message via ``twisted.logger``.
        """
        # @run_test_with(AsynchronousDeferredRunTest)
        try:
            1 / 0
        except BaseException:
            f = Failure()
        _default_panic(f, u'server_name')
        self.assertThat(flush_logged_errors(), Equals([f]))

    def test_blank_cert(self):
        """
        An empty certificate file will be treated like an expired certificate.
        """
        server_name = 'server_name'

        with AcmeFixture(certs={server_name: []}) as fixture:
            fixture.service.startService()
            self.assertThat(
                fixture.service.when_certs_valid(),
                succeeded(Always()))
            self.assertThat(
                fixture.cert_store.as_dict(),
                succeeded(
                    MatchesDict({server_name: Not(Equals([]))})))
            self.assertThat(fixture.responder.challenges, HasLength(0))

    def test_issue_one_cert(self):
        """
        ``issue_cert`` will (re)issue a single certificate unconditionally.
        """
        server_name = u'example.com'
        with AcmeFixture() as fixture:
            fixture.service.startService()
            self.assertThat(
                fixture.cert_store.as_dict(),
                succeeded(
                    Not(Contains(server_name))))
            self.assertThat(
                fixture.service.issue_cert(server_name),
                succeeded(Always()))
            self.assertThat(
                fixture.cert_store.as_dict(),
                succeeded(
                    MatchesDict({server_name: Not(Equals([]))})))

    def test_issue_concurrently(self):
        """
        Invoking ``issue_cert`` multiple times concurrently for the same name
        will not start multiple issuing processes, only wait for the first
        process to complete.
        """
        server_name = u'example.com'
        with AcmeFixture() as fixture:
            fixture.service.startService()
            self.assertThat(
                fixture.cert_store.as_dict(),
                succeeded(
                    Not(Contains(server_name))))

            fixture.controller.pause()
            d1 = fixture.service.issue_cert(server_name)
            self.assertThat(d1, has_no_result())
            d2 = fixture.service.issue_cert(server_name)
            self.assertThat(d2, has_no_result())
            self.assertThat(fixture.controller.count(), Equals(1))

            fixture.controller.resume()
            self.assertThat(d1, succeeded(Always()))
            self.assertThat(d2, succeeded(Always()))

            self.assertThat(
                fixture.cert_store.as_dict(),
                succeeded(
                    MatchesDict({server_name: Not(Equals([]))})))

    def test_cancellation(self):
        """
        Cancelling the deferred returned by ``issue_cert`` cancels the actual
        issuing process.
        """
        server_name = u'example.com'
        with AcmeFixture() as fixture:
            fixture.service.startService()
            self.assertThat(
                fixture.cert_store.as_dict(),
                succeeded(
                    Not(Contains(server_name))))

            fixture.controller.pause()
            d1 = fixture.service.issue_cert(server_name)
            self.assertThat(d1, has_no_result())
            d2 = fixture.service.issue_cert(server_name)
            self.assertThat(d2, has_no_result())
            self.assertThat(fixture.controller.count(), Equals(1))
            d2.cancel()

            fixture.controller.resume()
            self.assertThat(d1, failed_with(IsInstance(CancelledError)))
            self.assertThat(d2, failed_with(IsInstance(CancelledError)))
            self.assertThat(
                fixture.cert_store.as_dict(),
                succeeded(
                    Not(Contains(server_name))))


__all__ = ['AcmeIssuingServiceTests']
