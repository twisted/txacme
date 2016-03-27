import pem
from fixtures import TempDir
from hypothesis import example, given
from testtools import TestCase
from testtools.matchers import ContainsDict, Equals, Is, IsInstance
from testtools.twistedsupport import succeeded
from twisted.python.filepath import FilePath

from txacme.store import DirectoryStore
from txacme.test import strategies as ts
from txacme.test.test_client import failed_with
from txacme.testing import MemoryStore


EXAMPLE_PEM_OBJECTS = [
    pem.RSAPrivateKey(
        b'-----BEGIN RSA PRIVATE KEY-----\n'
        b'iq63EP+H3w==\n'
        b'-----END RSA PRIVATE KEY-----\n'),
    pem.Certificate(
        b'-----BEGIN CERTIFICATE-----\n'
        b'yns=\n'
        b'-----END CERTIFICATE-----\n'),
    pem.Certificate(
        b'-----BEGIN CERTIFICATE-----\n'
        b'pNaiqhAT\n'
        b'-----END CERTIFICATE-----\n'),
    ]

EXAMPLE_PEM_OBJECTS2 = [
    pem.RSAPrivateKey(
        b'-----BEGIN RSA PRIVATE KEY-----\n'
        b'fQ==\n'
        b'-----END RSA PRIVATE KEY-----\n'),
    pem.Certificate(
        b'-----BEGIN CERTIFICATE-----\n'
        b'xUg=\n'
        b'-----END CERTIFICATE-----\n'),
    ]


class _StoreTestsMixin(object):
    """
    Tests for `txacme.interfaces.ICertificateStore` implementations.
    """
    @example(u'example.com', EXAMPLE_PEM_OBJECTS)
    @given(ts.dns_names(), ts.pem_objects())
    def test_insert(self, server_name, pem_objects):
        """
        Inserting an entry causes the same entry to be returned by ``get`` and
        ``as_dict``.
        """
        self.assertThat(
            self.cert_store.store(server_name, pem_objects),
            succeeded(Is(None)))
        self.assertThat(
            self.cert_store.get(server_name),
            succeeded(Equals(pem_objects)))
        self.assertThat(
            self.cert_store.as_dict(),
            succeeded(ContainsDict(
                {server_name: Equals(pem_objects)})))

    @example(u'example.com', EXAMPLE_PEM_OBJECTS, EXAMPLE_PEM_OBJECTS2)
    @given(ts.dns_names(), ts.pem_objects(), ts.pem_objects())
    def test_insert_twice(self, server_name, pem_objects, pem_objects2):
        """
        Inserting an entry a second time overwrites the first entry.
        """
        self.assertThat(
            self.cert_store.store(server_name, pem_objects),
            succeeded(Is(None)))
        self.assertThat(
            self.cert_store.store(server_name, pem_objects2),
            succeeded(Is(None)))
        self.assertThat(
            self.cert_store.get(server_name),
            succeeded(Equals(pem_objects2)))
        self.assertThat(
            self.cert_store.as_dict(),
            succeeded(ContainsDict({server_name: Equals(pem_objects2)})))

    @example(u'example.com')
    @given(ts.dns_names())
    def test_get_missing(self, server_name):
        """
        Getting a non-existent entry results in `KeyError`.
        """
        self.assertThat(
            self.cert_store.get(server_name),
            failed_with(IsInstance(KeyError)))


class DirectoryStoreTests(_StoreTestsMixin, TestCase):
    """
    Tests for `txacme.store.DirectoryStore`.
    """
    def setUp(self):
        super(DirectoryStoreTests, self).setUp()
        temp_dir = self.useFixture(TempDir())
        self.cert_store = DirectoryStore(FilePath(temp_dir.path))


class MemoryStoreTests(_StoreTestsMixin, TestCase):
    """
    Tests for `txacme.testing.MemoryStore`.
    """
    def setUp(self):
        super(MemoryStoreTests, self).setUp()
        self.cert_store = MemoryStore()


__all__ = ['DirectoryStoreTests', 'MemoryStoreTests']
