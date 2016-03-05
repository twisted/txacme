import attr
from acme import challenges
from acme.jose import b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import strategies as s
from hypothesis import example, given
from service_identity.pyopenssl import verify_hostname
from testtools import ExpectedException, TestCase
from testtools.matchers import Equals, IsInstance, Not

from txacme.test.test_client import RSA_KEY_512
from txacme.util import (
    cert_cryptography_to_pyopenssl, generate_private_key,
    generate_tls_sni_01_cert, key_cryptography_to_pyopenssl)


class GeneratePrivateKeyTests(TestCase):
    """
    `.generate_private_key` generates private keys of various types using
    sensible parameters.
    """
    @example(u'not-a-real-key-type')
    @given(s.text().filter(lambda t: t not in [u'rsa']))
    def test_unknown_key_type(self, key_type):
        """
        Passing an unknown key type results in :exc:`.ValueError`.
        """
        with ExpectedException(ValueError):
            generate_private_key(key_type)

    def test_rsa_key(self):
        """
        Passing ``u'rsa'`` results in an RSA private key.
        """
        key1 = generate_private_key(u'rsa')
        self.assertThat(key1, IsInstance(rsa.RSAPrivateKey))
        key2 = generate_private_key(u'rsa')
        self.assertThat(key2, IsInstance(rsa.RSAPrivateKey))
        self.assertThat(
            key1.public_key().public_numbers(),
            Not(Equals(key2.public_key().public_numbers())))


@attr.s
class NotAConnection(object):
    """
    Pretend to be an ``OpenSSL.Connection`` object as far as
    ``service_identity`` cares.
    """
    _cert = attr.ib()

    def get_peer_certificate(self):
        """
        Return the certificate.
        """
        return self._cert


class GenerateCertTests(TestCase):
    """
    `.generate_tls_sni_01_cert` generates a cert and key suitable for
    responding for the given challenge SAN.
    """
    @given(token=s.binary(min_size=32, max_size=32).map(b64encode))
    def test_cert_verifies(self, token):
        """
        The certificates generated verify using
        `~acme.challenges.TLSSNI01Response.verify_cert`.
        """
        ckey = RSA_KEY_512.key._wrapped
        challenge = challenges.TLSSNI01(token=token)
        response = challenge.response(RSA_KEY_512)
        server_name = response.z_domain.decode('ascii')
        cert, pkey = generate_tls_sni_01_cert(
            server_name, _generate_private_key=lambda key_type: ckey)

        ocert = cert_cryptography_to_pyopenssl(cert)
        self.assertThat(
            ocert.digest('sha256').replace(':', '').decode('hex'),
            Equals(cert.fingerprint(hashes.SHA256())))
        okey = key_cryptography_to_pyopenssl(pkey)
        # TODO: Can we assert more here?
        self.assertThat(okey.bits(), Equals(pkey.key_size))

        self.assertThat(
            response.verify_cert(ocert),
            Equals(True))
        verify_hostname(NotAConnection(ocert), server_name)


__all__ = ['GeneratePrivateKeyTests', 'GenerateCertTests']
