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
from service_identity.pyopenssl import verify_hostname
from twisted.trial.unittest import TestCase

from txacme.test.test_client import RSA_KEY_512, RSA_KEY_512_RAW
from txacme.util import (
    const, csr_for_names, decode_csr, encode_csr,
    generate_private_key)


class GeneratePrivateKeyTests(TestCase):
    """
    `.generate_private_key` generates private keys of various types using
    sensible parameters.
    """

    def test_unknown_key_type(self):
        """
        Passing an unknown key type results in :exc:`.ValueError`.
        """
        with self.assertRaises(ValueError):
            generate_private_key(u'not-a-real-key-type')

    def test_rsa_key(self):
        """
        Passing ``u'rsa'`` results in an RSA private key.
        """
        key1 = generate_private_key(u'rsa')
        self.assertIsInstance(key1,rsa.RSAPrivateKey)
        key2 = generate_private_key(u'rsa')
        self.assertIsInstance(key2, rsa.RSAPrivateKey)
        self.assertNotEqual(
            key1.public_key().public_numbers(),
            key2.public_key().public_numbers()
            )
