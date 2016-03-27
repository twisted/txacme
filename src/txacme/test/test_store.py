from operator import attrgetter

from fixtures import TempDir
from hypothesis import given
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing, ContainsDict, Equals, Is, IsInstance, MatchesListwise)
from testtools.twistedsupport import succeeded
from twisted.python.filepath import FilePath

from txacme.store import DirectoryStore
from txacme.test import strategies as ts
from txacme.test.test_client import failed_with
from txacme.testing import MemoryStore


class _StoreTestsMixin(object):
    """
    Tests for `txacme.interfaces.ICertificateStore` implementations.
    """
    @given(ts.dns_names(), ts.pem_objects())
    def test_insert(self, server_name, pem_objects):
        """
        Inserting an entry causes the same entry to be returned by ``get`` and
        ``as_dict``.
        """
        self.assertThat(
            self.cert_store.store(server_name, pem_objects),
            succeeded(Is(None)))
        match_objects = MatchesListwise([
            AfterPreprocessing(attrgetter('_pem_str'), Equals(o._pem_str))
            for o in pem_objects])
        self.assertThat(
            self.cert_store.get(server_name),
            succeeded(match_objects))
        self.assertThat(
            self.cert_store.as_dict(),
            succeeded(ContainsDict({server_name: match_objects})))

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
        match_objects = MatchesListwise([
            AfterPreprocessing(attrgetter('_pem_str'), Equals(o._pem_str))
            for o in pem_objects2])
        self.assertThat(
            self.cert_store.get(server_name),
            succeeded(match_objects))
        self.assertThat(
            self.cert_store.as_dict(),
            succeeded(ContainsDict({server_name: match_objects})))

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
