import uuid
from datetime import datetime, timedelta
from operator import methodcaller

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from fixtures import Fixture
from hypothesis import strategies as s
from hypothesis import example, given
from hypothesis.strategies import datetimes
from pem import Certificate, RSAPrivateKey
from testtools import run_test_with, TestCase
from testtools.matchers import (
    AfterPreprocessing, AllMatch, Always, Contains, Equals, GreaterThan,
    HasLength, Is, IsInstance, MatchesAny, MatchesDict, MatchesListwise,
    MatchesStructure, Not)
from testtools.twistedsupport import (
    AsynchronousDeferredRunTest, failed, flush_logged_errors,
    has_no_result, succeeded)
from twisted.internet.defer import CancelledError, Deferred, fail
from twisted.internet.task import Clock
from twisted.python.failure import Failure

from txacme.service import _default_panic, AcmeIssuingService
from txacme.test import strategies as ts
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


class AcmeFixture(Fixture):
    """
    A fixture for setting up an `~txacme.service.AcmeIssuingService`.
    """
    def __init__(self, now=datetime(2000, 1, 1, 0, 0, 0), certs=None,
                 panic_interval=None, panic=None, client=None, email=None):
        super(AcmeFixture, self).__init__()
        self.now = now
        self._certs = certs
        self._panic_interval = panic_interval
        self._panic = panic
        self._email = email
        self.acme_client = client
        self.controller = FakeClientController()

    def _setUp(self):
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
        self.addCleanup(
            lambda: self.service.running and self.service.stopService())


@s.composite
def panicing_cert(draw, now, panic):
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


@s.composite
def panicing_certs_fixture(draw):
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
    def test_when_certs_valid_no_certs(self):
        """
        The deferred returned by ``when_certs_valid`` fires immediately if
        there are no certs in the store.
        """
        service = self.useFixture(AcmeFixture()).service
        service.startService()
        self.assertThat(
            service.when_certs_valid(),
            succeeded(Is(None)))

    @run_test_with(AsynchronousDeferredRunTest)
    def test_timer_errors(self):
        """
        If the timed check fails (for example, because registration fails), the
        error should be caught and logged.
        """
        with AcmeFixture(client=FailingClient()) as fixture:
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

    @run_test_with(AsynchronousDeferredRunTest)
    def test_default_panic(self):
        """
        The default panic callback logs a message via ``twisted.logger``.
        """
        try:
            1 / 0
        except BaseException:
            f = Failure()
        _default_panic(f, u'server_name')
        self.assertThat(flush_logged_errors(), Equals([f]))

__all__ = ['AcmeIssuingServiceTests']
