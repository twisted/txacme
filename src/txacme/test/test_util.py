from codecs import decode

import attr
from acme import challenges
from acme.jose import b64encode
from acme.jose.errors import DeserializationError
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from hypothesis import strategies as s
from hypothesis import assume, example, given
from service_identity.pyopenssl import verify_hostname
from testtools import ExpectedException, TestCase
from testtools.matchers import (
    Equals, IsInstance, MatchesAll, MatchesStructure, Not)

from txacme.test import strategies as ts
from txacme.test.matchers import ValidForName
from txacme.test.test_client import RSA_KEY_512, RSA_KEY_512_RAW
from txacme.util import (
    cert_cryptography_to_pyopenssl, const, csr_for_names, decode_csr,
    encode_csr, generate_private_key, generate_tls_sni_01_cert,
    key_cryptography_to_pyopenssl)


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
    @example(token=b'BWYcfxzmOha7-7LoxziqPZIUr99BCz3BfbN9kzSFnrU')
    @given(token=s.binary(min_size=32, max_size=32).map(b64encode))
    def test_cert_verifies(self, token):
        """
        The certificates generated verify using
        `~acme.challenges.TLSSNI01Response.verify_cert`.
        """
        ckey = RSA_KEY_512_RAW
        challenge = challenges.TLSSNI01(token=token)
        response = challenge.response(RSA_KEY_512)
        server_name = response.z_domain.decode('ascii')
        cert, pkey = generate_tls_sni_01_cert(
            server_name, _generate_private_key=lambda key_type: ckey)

        self.assertThat(cert, ValidForName(server_name))

        ocert = cert_cryptography_to_pyopenssl(cert)
        self.assertThat(
            decode(ocert.digest('sha256').replace(b':', b''), 'hex'),
            Equals(cert.fingerprint(hashes.SHA256())))
        okey = key_cryptography_to_pyopenssl(pkey)
        # TODO: Can we assert more here?
        self.assertThat(okey.bits(), Equals(pkey.key_size))

        self.assertThat(
            response.verify_cert(ocert),
            Equals(True))
        verify_hostname(NotAConnection(ocert), server_name)


class CSRTests(TestCase):
    """
    `~txacme.util.encode_csr` and `~txacme.util.decode_csr` serialize CSRs in
    JOSE Base64 DER encoding.
    """
    @example(names=[u'example.com', u'example.org'])
    @given(names=s.lists(ts.dns_names(), min_size=1))
    def test_roundtrip(self, names):
        """
        The encoding roundtrips.
        """
        assume(len(names[0]) <= 64)
        csr = csr_for_names(names, RSA_KEY_512_RAW)
        self.assertThat(decode_csr(encode_csr(csr)), Equals(csr))

    def test_decode_garbage(self):
        """
        If decoding fails, `~txacme.util.decode_csr` raises
        `~acme.jose.errors.DeserializationError`.
        """
        with ExpectedException(DeserializationError):
            decode_csr(u'blah blah not a valid CSR')

    def test_empty_names_invalid(self):
        """
        `~txacme.util.csr_for_names` raises `ValueError` if given an empty list
        of names.
        """
        with ExpectedException(ValueError):
            csr_for_names([], RSA_KEY_512_RAW)

    @example(names=[u'example.com', u'example.org'], key=RSA_KEY_512_RAW)
    @given(names=s.lists(ts.dns_names(), min_size=1),
           key=s.just(RSA_KEY_512_RAW))
    def test_valid_for_names(self, names, key):
        """
        `~txacme.util.csr_for_names` returns a CSR that is actually valid for
        the given names.
        """
        assume(len(names[0]) <= 64)

        self.assertThat(
            csr_for_names(names, key),
            MatchesAll(*[ValidForName(name) for name in names]))

    def test_common_name_too_long(self):
        """
        If the first name provided is too long, `~txacme.util.csr_for_names`
        uses a dummy value for the common name.
        """
        self.assertThat(
            csr_for_names([u'aaaa.' * 16], RSA_KEY_512_RAW),
            MatchesStructure(
                subject=Equals(x509.Name([
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        u'san.too.long.invalid')]))))


class ConstTests(TestCase):
    """
    `~txacme.util.const` returns a function that always returns a constant
    value.
    """
    @given(s.integers())
    def test_const(self, x):
        self.assertThat(const(x)(), Equals(x))


__all__ = [
    'GeneratePrivateKeyTests', 'GenerateCertTests', 'CSRTests', 'ConstTests']
