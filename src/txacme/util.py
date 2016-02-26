"""
Utility functions that may prove useful when writing an ACME client.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_private_key(key_type):
    """
    Generate a random private key using sensible parameters.

    :param str key_type: The type of key to generate. One of: ``'rsa'``.
    """
    if key_type == 'rsa':
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
    raise ValueError(key_type)
