import uuid
from datetime import datetime, timedelta
from operator import methodcaller

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from fixtures import Fixture
from hypothesis import strategies as s
from hypothesis import given
from hypothesis.extra.datetime import datetimes
from pem import Certificate, RSAPrivateKey
from testtools import ExpectedException, TestCase
from testtools.matchers import (
    AfterPreprocessing, AllMatch, GreaterThan, Is, IsInstance, MatchesAny,
    MatchesStructure, Not)
from testtools.twistedsupport import succeeded
from twisted.internet.task import Clock

from txacme.service import AcmeIssuingService
from txacme.test import strategies as ts
from txacme.test.test_client import Always, RSA_KEY_512, RSA_KEY_512_RAW
from txacme.testing import FakeClient, MemoryStore, NullResponder


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
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, server_name)])
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
        Certificate(cert.public_bytes(serialization.Encoding.PEM)),
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
                bytes(c), default_backend()),
            matcher))


class AcmeFixture(Fixture):
    """
    A fixture for setting up an `~txacme.service.AcmeIssuingService`.
    """
    def __init__(self, now=None, certs=None,
                 panic_interval=timedelta(days=15)):
        super(AcmeFixture, self).__init__()
        if now is None:
            now = datetime(2000, 1, 1, 0, 0, 0)
        self.now = now
        self._certs = certs
        self._panic_interval = panic_interval

    def _setUp(self):
        self.cert_store = MemoryStore(self._certs)
        self.clock = Clock()
        self.acme_client = FakeClient(RSA_KEY_512, lambda: self.now)
        self.responder = NullResponder()
        self.service = AcmeIssuingService(
            cert_store=self.cert_store,
            client=self.acme_client,
            clock=self.clock,
            now=lambda: self.now,
            tls_sni_01_responder=self.responder,
            panic_interval=self._panic_interval,
            generate_key=lambda: RSA_KEY_512_RAW)


class AcmeIssuingServiceTests(TestCase):
    """
    Tests for `txacme.service.AcmeIssuingService`.
    """
    def test_when_certs_valid_stopped(self):
        """
        ``when_certs_valid`` raises `RuntimeError` if called on a stopped
        service.
        """
        service = self.useFixture(AcmeFixture()).service
        with ExpectedException(RuntimeError, 'Service not started'):
            service.when_certs_valid()

    def test_when_certs_valid_no_certs(self):
        """
        The deferred returned by ``when_certs_valid`` fires immediately if
        there are no certs in the store.
        """
        service = self.useFixture(AcmeFixture()).service
        self.assertThat(
            service.startService(),
            succeeded(Always()))
        self.assertThat(
            service.when_certs_valid(),
            succeeded(Is(None)))

    @given(now=datetimes(min_year=1971, timezones=[]),
           certs=s.lists(
               s.tuples(
                   s.integers(min_value=0, max_value=1000)
                   .map(lambda s: timedelta(seconds=s)),
                   ts.dns_names().filter(lambda n: len(n) < 50))))
    def test_when_certs_valid_all_certs_valid(self, now, certs):
        """
        The deferred returned by ``when_certs_valid`` fires immediately if
        none of the certs in the store are expired.
        """
        certs = {
            server_name: _generate_cert(
                server_name,
                not_valid_before=now - timedelta(seconds=1),
                not_valid_after=now + offset)
            for offset, server_name in certs}
        with AcmeFixture(now=now, certs=certs) as fixture:
            service = fixture.service
            self.assertThat(
                service.startService(),
                succeeded(Always()))
            self.assertThat(
                service.when_certs_valid(),
                succeeded(Is(None)))

    @given(now=datetimes(min_year=1971, timezones=[]),
           panic=s.builds(
               timedelta,
               seconds=s.integers(min_value=60, max_value=60 * 60 * 24)),
           data=s.data())
    def test_when_certs_valid_certs_expired(self, now, panic, data):
        """
        The deferred returned by ``when_certs_valid`` only fires once all
        panicing and expired certs have been renewed.
        """
        certs = data.draw(
            s.lists(
                s.builds(
                    lambda server_name, offset:
                    (server_name,
                     _generate_cert(
                         server_name,
                         not_valid_before=now + offset - timedelta(seconds=1),
                         not_valid_after=now + offset)),
                    ts.dns_names().filter(lambda n: len(n) < 50),
                    s.builds(
                        timedelta,
                        seconds=s.integers(
                            min_value=-1000,
                            max_value=int(panic.total_seconds())))),
                min_size=1,
                unique_by=lambda i: i[0])
            .map(dict))
        with AcmeFixture(
                now=now, panic_interval=panic, certs=certs) as fixture:
            service = fixture.service
            self.assertThat(
                service.startService(),
                succeeded(Always()))
            self.assertThat(
                service.when_certs_valid(),
                succeeded(Is(None)))
            self.assertThat(
                fixture.cert_store.as_dict(),
                succeeded(AfterPreprocessing(
                    methodcaller('values'),
                    AllMatch(AllMatch(
                        _match_certificate(
                            MatchesStructure(
                                not_valid_after=GreaterThan(now + panic))))))))


__all__ = ['AcmeIssuingServiceTests']
