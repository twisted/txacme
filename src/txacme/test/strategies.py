"""
Miscellaneous strategies for Hypothesis testing.
"""
try:
    from base64 import encodebytes
except ImportError:
    from base64 import encodestring as encodebytes

from hypothesis import strategies as s
from pem import Certificate, RSAPrivateKey
from twisted.python.url import URL


def dns_labels():
    """
    Strategy for generating limited charset DNS labels.
    """
    # This is too limited, but whatever
    return (
        s.text(
            u'abcdefghijklmnopqrstuvwxyz0123456789-',
            min_size=1, max_size=25)
        .filter(
            lambda s: not any([
                s.startswith(u'-'),
                s.endswith(u'-'),
                s.isdigit(),
                s[2:4] == u'--',
            ])))


def dns_names():
    """
    Strategy for generating limited charset DNS names.
    """
    return (
        s.lists(dns_labels(), min_size=1, max_size=10)
        .map(u'.'.join))


def urls():
    """
    Strategy for generating ``twisted.python.url.URL``\s.
    """
    return s.builds(
        URL,
        scheme=s.just(u'https'),
        host=dns_names(),
        path=s.lists(s.text(max_size=64), min_size=1, max_size=10))


@s.composite
def pem_objects(draw):
    """
    Strategy for generating ``pem`` objects.
    """
    key = RSAPrivateKey((
        b'-----BEGIN RSA PRIVATE KEY-----\n' +
        encodebytes(draw(s.binary(min_size=1))) +
        b'-----END RSA PRIVATE KEY-----\n'))
    return [key] + [
        Certificate((
            b'-----BEGIN CERTIFICATE-----\n' +
            encodebytes(cert) +
            b'-----END CERTIFICATE-----\n'))
        for cert in draw(s.lists(s.binary(min_size=1), min_size=1))]


__all__ = ['dns_labels', 'dns_names', 'urls', 'pem_objects']
