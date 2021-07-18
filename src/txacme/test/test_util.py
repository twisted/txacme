from codecs import decode

import attr
from OpenSSL import crypto
from acme import challenges
from josepy.b64 import b64encode
from josepy.errors import DeserializationError
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
    const, csr_for_names, decode_csr, encode_csr,
    generate_private_key
)


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
        `~josepy.errors.DeserializationError`.
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
