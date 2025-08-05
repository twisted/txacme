from cryptography.hazmat.primitives.asymmetric import rsa
from twisted.trial.unittest import TestCase

from txacme.util import (generate_private_key)


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
