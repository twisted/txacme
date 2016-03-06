"""
Utility functions that may prove useful when writing an ACME client.
"""
import uuid
from datetime import datetime, timedelta
from functools import wraps

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto
from twisted.internet.defer import maybeDeferred


def generate_private_key(key_type):
    """
    Generate a random private key using sensible parameters.

    :param str key_type: The type of key to generate. One of: ``rsa``.
    """
    if key_type == u'rsa':
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
    raise ValueError(key_type)


def generate_tls_sni_01_cert(server_name, key_type=u'rsa',
                             _generate_private_key=None):
    """
    Generate a certificate/key pair for responding to a tls-sni-01 challenge.

    :param str server_name: The SAN the certificate should have.
    :param str key_type: The type of key to generate; usually not necessary.

    :rtype: ``Tuple[`~cryptography.x509.Certificate`, PrivateKey]``
    :return: A tuple of the certificate and private key.
    """
    key = (_generate_private_key or generate_private_key)(key_type)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'acme.invalid')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .not_valid_before(datetime.now() - timedelta(seconds=3600))
        .not_valid_after(datetime.now() + timedelta(seconds=3600))
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
    return (cert, key)


def cert_cryptography_to_pyopenssl(cert):
    """
    Convert a `cryptography.x509.Certificate` object to an
    ``OpenSSL.crypto.X509`` object.
    """
    return crypto.load_certificate(
        crypto.FILETYPE_PEM,
        cert.public_bytes(serialization.Encoding.PEM))


def key_cryptography_to_pyopenssl(key):
    """
    Convert a Cryptography private key object to an ``OpenSSL.crypto.PKey``
    object.
    """
    return crypto.load_privatekey(
        crypto.FILETYPE_PEM,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))


def tap(f):
    """
    "Tap" a Deferred callback chain with a function whose return value is
    ignored.
    """
    @wraps(f)
    def _cb(res, *a, **kw):
        d = maybeDeferred(f, res, *a, **kw)
        d.addCallback(lambda ignored: res)
        return d
    return _cb


__all__ = [
    'generate_private_key', 'generate_tls_sni_01_cert',
    'cert_cryptography_to_pyopenssl', 'key_cryptography_to_pyopenssl', 'tap']
