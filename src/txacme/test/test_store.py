import pem
from fixtures import TempDir
from hypothesis import strategies as s
from hypothesis import example, given
from testtools import TestCase
from testtools.matchers import (
    ContainsDict, Equals, FileExists, Is, IsInstance, Not)
from testtools.twistedsupport import (
    AsynchronousDeferredRunTestForBrokenTwisted, succeeded)
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


class _DirectoryStoreTestsMixin(object):
    def setUp(self):
        super(_DirectoryStoreTestsMixin, self).setUp()
        self.temp_dir = FilePath(self.useFixture(TempDir()).path)

    @given(ts.dns_names(), ts.pem_objects(), s.integers())
    def test_onstore_script(self, server_name, pem_objects, nonce):
        """
        .onstore scripts will be run after something is stored, but only if the
        setting is enabled.
        """
        script = self.temp_dir.child(server_name + '.onstore')
        script.setContent("""\
#!/bin/sh
echo >output "%s" "$1"
        """.strip(' ') % nonce)
        script.chmod(0o700)
        d = self.cert_store.store(server_name, pem_objects)
        return self._check_onstore_script(d, server_name, nonce)


class DirectoryStoreTests(
        _StoreTestsMixin, _DirectoryStoreTestsMixin, TestCase):
    """
    Tests for `txacme.store.DirectoryStore`.
    """
    def setUp(self):
        super(DirectoryStoreTests, self).setUp()
        self.cert_store = DirectoryStore(self.temp_dir)

    def _check_onstore_script(self, d, server_name, nonce):
        self.expectThat(d, succeeded(Is(None)))
        self.expectThat(self.temp_dir.child('output').path, Not(FileExists()))


class DirectoryStoreWithOnstoreScriptsTests(
        _StoreTestsMixin, _DirectoryStoreTestsMixin, TestCase):
    """
    Tests for `txacme.store.DirectoryStore` with onstore_scripts=True.
    """
    def setUp(self):
        super(DirectoryStoreWithOnstoreScriptsTests, self).setUp()
        self.cert_store = DirectoryStore(self.temp_dir, onstore_scripts=True)
        self.example_result = self.defaultTestResult()

    def execute_example(self, f):
        runtest_fac = AsynchronousDeferredRunTestForBrokenTwisted.make_factory(
            timeout=2)

        class Case(TestCase):
            def test_example(self):
                result = f()
                if callable(result):
                    result = result()
                return result

        runtest_fac(Case('test_example')).run(self.example_result)

    def _check_output(self, ign, expected_content):
        self.assertThat(
            self.temp_dir.child('output').getContent(),
            Equals(expected_content))

    def _check_onstore_script(self, d, server_name, nonce):
        d.addCallback(self._check_output, '%s %s\n' % (nonce, server_name))
        return d


class MemoryStoreTests(_StoreTestsMixin, TestCase):
    """
    Tests for `txacme.testing.MemoryStore`.
    """
    def setUp(self):
        super(MemoryStoreTests, self).setUp()
        self.cert_store = MemoryStore()


__all__ = ['DirectoryStoreTests', 'MemoryStoreTests']
