from operator import methodcaller
import os
import tempfile
import shutil

import pem
from twisted.internet import defer
from twisted.python.compat import unicode
from twisted.python.filepath import FilePath
from twisted.trial.unittest import TestCase

from txacme.store import DirectoryStore
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

    @defer.inlineCallbacks
    def test_insert(self):
        """
        Inserting an entry causes the same entry to be returned by ``get`` and
        ``as_dict``.
        """
        server_name = 'example.com'
        pem_objects = EXAMPLE_PEM_OBJECTS
        cert_store = self.getCertStore()

        result = yield cert_store.store(server_name, pem_objects)
        self.assertIsNone(result)

        result = yield cert_store.get(server_name)
        self.assertEqual(pem_objects, result)

        result = yield cert_store.as_dict()
        self.assertEqual({'example.com': pem_objects}, result)

    @defer.inlineCallbacks
    def test_insert_twice(self):
        """
        Inserting an entry a second time overwrites the first entry.
        """
        server_name = u'example.com'
        pem_objects = EXAMPLE_PEM_OBJECTS
        pem_objects2 = EXAMPLE_PEM_OBJECTS2
        cert_store = self.getCertStore()

        result = yield cert_store.store(server_name, pem_objects)
        self.assertIsNone(result)

        result = yield cert_store.store(server_name, pem_objects2)
        self.assertIsNone(result)

        result = yield cert_store.get(server_name)
        self.assertEqual(result, pem_objects2)

        result = yield cert_store.as_dict()
        self.assertEqual({'example.com': pem_objects2}, result)

    @defer.inlineCallbacks
    def test_get_missing(self):
        """
        Getting a non-existent entry results in `KeyError`.
        """
        cert_store = self.getCertStore()

        with self.assertRaises(KeyError):
            yield cert_store.get(u'example.com')

    @defer.inlineCallbacks
    def test_unicode_keys(self):
        """
        The keys of the dict returned by ``as_dict`` are ``unicode``.
        """
        cert_store = self.getCertStore()

        result = yield cert_store.store(
            u'example.com', EXAMPLE_PEM_OBJECTS)
        self.assertIsNone(result)

        result = yield cert_store.as_dict()
        self.assertEqual(['example.com'], list(result.keys()))


class DirectoryStoreTests(_StoreTestsMixin, TestCase):
    """
    Tests for `txacme.store.DirectoryStore`.
    """

    def getCertStore(self):
        """
        Return the certificate store for these tests.
        """
        # FIXME
        # rever to trial mktemp.
        tmpdir = tempfile.mkdtemp()
        subdir = os.path.join(tmpdir, self._testMethodName)
        os.mkdir(subdir)
        self.addCleanup(shutil.rmtree, tmpdir)

        return DirectoryStore(FilePath(tmpdir))

    def test_filepath_mode(self):
        """
        The given ``FilePath`` is always converted to text mode.
        """
        store = DirectoryStore(FilePath(b'bytesbytesbytes'))
        self.assertIsInstance(store.path.path, unicode)


class MemoryStoreTests(_StoreTestsMixin, TestCase):
    """
    Tests for `txacme.testing.MemoryStore`.
    """

    def getCertStore(self):
        """
        Return the certificate store for these tests.
        """
        return MemoryStore()


__all__ = ['DirectoryStoreTests', 'MemoryStoreTests']
