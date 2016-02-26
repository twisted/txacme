from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import strategies as s
from hypothesis import given
from testtools import ExpectedException, TestCase
from testtools.matchers import Equals, IsInstance, Not

from txacme.util import generate_private_key


class GeneratePrivateKeyTests(TestCase):
    """
    :func:`.generate_private_key` generates private keys of various types using
    sensible parameters.
    """
    @given(s.text().filter(lambda t: t not in ['rsa']))
    def test_unknown_key_type(self, key_type):
        """
        Passing an unknown key type results in :exc:`ValueError`.
        """
        with ExpectedException(ValueError):
            generate_private_key(key_type)

    def test_rsa_key(self):
        """
        Passing ``'rsa'`` results in an RSA private key.
        """
        key1 = generate_private_key('rsa')
        self.assertThat(key1, IsInstance(rsa.RSAPrivateKey))
        key2 = generate_private_key('rsa')
        self.assertThat(key2, IsInstance(rsa.RSAPrivateKey))
        self.assertThat(
            key1.public_key().public_numbers(),
            Not(Equals(key2.public_key().public_numbers())))
