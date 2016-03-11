from codecs import decode
from functools import partial

import attr
from acme import challenges
from acme.jose import b64encode
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID
from hypothesis import strategies as s
from hypothesis import assume, example, given
from service_identity._common import (
    DNS_ID, DNSPattern, verify_service_identity)
from service_identity.exceptions import VerificationError
from service_identity.pyopenssl import verify_hostname
from testtools import ExpectedException, TestCase
from testtools.matchers import (
    Equals, IsInstance, MatchesAll, MatchesPredicate, Not)

from txacme.test import strategies as ts
from txacme.test.test_client import RSA_KEY_512, RSA_KEY_512_RAW
from txacme.util import (
    cert_cryptography_to_pyopenssl, csr_for_names, decode_csr, encode_csr,
    generate_private_key, generate_tls_sni_01_cert,
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

        def _verify(name, csr):
            # This is really terrible. Probably can be better after
            # pyca/service_identity#14 is resolved.
            csr_ids = [
                DNSPattern(csr_name.encode('utf-8'))
                for csr_name
                in (
                    csr.extensions
                    .get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    .value
                    .get_values_for_type(x509.DNSName)
                )]
            ids = [DNS_ID(name)]
            try:
                verify_service_identity(
                    cert_patterns=csr_ids, obligatory_ids=ids, optional_ids=[])
            except VerificationError:
                return False
            else:
                return True

        self.assertThat(
            csr_for_names(names, key),
            MatchesAll(*[
                MatchesPredicate(
                    partial(_verify, name),
                    '%r not valid for {!r}'.format(name))
                for name in names]))


__all__ = ['GeneratePrivateKeyTests', 'GenerateCertTests', 'CSRTests']
