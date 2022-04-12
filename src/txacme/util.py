"""
Utility functions that may prove useful when writing an ACME client.
"""
import uuid
from datetime import datetime, timedelta
from functools import wraps

from josepy.errors import DeserializationError
from josepy.json_util import encode_b64jose, decode_b64jose

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from twisted.internet.defer import maybeDeferred
from twisted.python.url import URL


def generate_private_key(key_type):
    """
    Generate a random private key using sensible parameters.

    :param str key_type: The type of key to generate. One of: ``rsa``.
    """
    if key_type == u'rsa':
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
    raise ValueError(key_type)


def load_or_create_client_key(pem_path):
    """
    Load the client key from a directory, creating it if it does not exist.

    .. note:: The client key that will be created will be a 2048-bit RSA key.

    :type pem_path: ``twisted.python.filepath.FilePath``
    :param pem_path: The certificate directory
        to use, as with the endpoint.
    """
    acme_key_file = pem_path.asTextMode().child(u'client.key')
    if acme_key_file.exists():
        key = serialization.load_pem_private_key(
            acme_key_file.getContent(),
            password=None,
            backend=default_backend())
    else:
        key = generate_private_key(u'rsa')
        acme_key_file.setContent(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
    return JWKRSA(key=key)


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


def encode_csr(csr):
    """
    Encode CSR as JOSE Base-64 DER.

    :param cryptography.x509.CertificateSigningRequest csr: The CSR.

    :rtype: str
    """
    return encode_b64jose(csr.public_bytes(serialization.Encoding.DER))


def decode_csr(b64der):
    """
    Decode JOSE Base-64 DER-encoded CSR.

    :param str b64der: The encoded CSR.

    :rtype: `cryptography.x509.CertificateSigningRequest`
    :return: The decoded CSR.
    """
    try:
        return x509.load_der_x509_csr(
            decode_b64jose(b64der), default_backend())
    except ValueError as error:
        raise DeserializationError(error)


def csr_for_names(names, key):
    """
    Generate a certificate signing request for the given names and private key.

    ..  seealso:: `acme.client.Client.request_issuance`

    ..  seealso:: `generate_private_key`

    :param ``List[str]``: One or more names (subjectAltName) for which to
        request a certificate.
    :param key: A Cryptography private key object.

    :rtype: `cryptography.x509.CertificateSigningRequest`
    :return: The certificate request message.
    """
    if len(names) == 0:
        raise ValueError('Must have at least one name')
    if len(names[0]) > 64:
        common_name = u'san.too.long.invalid'
    else:
        common_name = names[0]
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(
            x509.SubjectAlternativeName(list(map(x509.DNSName, names))),
            critical=False)
        .sign(key, hashes.SHA256(), default_backend()))


def clock_now(clock):
    """
    Get a datetime representing the current time.

    :param clock: An ``IReactorTime`` provider.

    :rtype: `~datetime.datetime`
    :return: A datetime representing the current time.
    """
    return datetime.utcfromtimestamp(clock.seconds())


def check_directory_url_type(url):
    """
    Check that ``url`` is a ``twisted.python.url.URL`` instance, raising
    `TypeError` if it isn't.
    """
    if not isinstance(url, URL):
        raise TypeError(
            'ACME directory URL should be a twisted.python.url.URL, '
            'got {!r} instead'.format(url))


def const(x):
    """
    Return a constant function.
    """
    return lambda: x


__all__ = [
    'generate_private_key', 'generate_tls_sni_01_cert',
    'encode_csr', 'decode_csr', 'csr_for_names', 'clock_now',
    'check_directory_url_type', 'const', 'tap']
