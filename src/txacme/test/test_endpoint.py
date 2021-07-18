"""
Tests for `txacme.endpoint`.
"""
from datetime import datetime

from josepy.jwk import JWKRSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fixtures import TempDir
from testtools import ExpectedException, TestCase
from testtools.matchers import (
    Always, Equals, Is, IsInstance, MatchesAll, MatchesPredicate,
    MatchesStructure)
from testtools.twistedsupport import succeeded
from twisted.internet.defer import succeed
from twisted.internet.interfaces import (
    IListeningPort, IStreamServerEndpoint, IStreamServerEndpointStringParser)
from twisted.internet.protocol import Factory
from twisted.internet.task import Clock
from twisted.plugin import IPlugin
from twisted.plugins import txacme_endpoint
from twisted.python.filepath import FilePath
from twisted.python.url import URL
from twisted.test.proto_helpers import MemoryReactorClock
from txsni.snimap import HostDirectoryMap
from zope.interface import implementer
from zope.interface.verify import verifyObject

from txacme._endpoint_parser import _AcmeParser
from txacme.endpoint import AutoTLSEndpoint, load_or_create_client_key
from txacme.store import DirectoryStore
from txacme.test.test_client import RSA_KEY_512
from txacme.testing import FakeClient, MemoryStore, TXACMETestCase
from txacme.urls import LETSENCRYPT_DIRECTORY, LETSENCRYPT_STAGING_DIRECTORY


@implementer(IListeningPort)
class DummyPort(object):
    """
    Port implementation that does nothing.
    """
    def stopListening(self):  # noqa
        pass


@implementer(IStreamServerEndpoint)
class DummyEndpoint(object):
    """
    Endpoint implementation that does nothing.
    """
    def listen(self, factory):
        return succeed(DummyPort())


class TXAcmeTestCaseTestCase(TestCase):
    def test_tear_down(self):
        from twisted.internet import reactor

        def no_op():
            pass

        no_op()

        garbage_delayed_call = None

        class TestTest(TXACMETestCase):
            def test_test(self):
                nonlocal garbage_delayed_call
                garbage_delayed_call = reactor.callLater(1.0, no_op)

        test_case_under_test = TestTest("test_test")
        result = test_case_under_test.run()
        self.assertThat(len(result.failures), Equals(1))
        self.assertThat(garbage_delayed_call.active(), Equals(False))
        self.assertThat(reactor.getDelayedCalls(), Equals([]))


class EndpointTests(TXACMETestCase):
    """
    Tests for `~txacme.endpoint.AutoTLSEndpoint`.
    """
    def setUp(self):
        super(EndpointTests, self).setUp()
        clock = Clock()
        clock.rightNow = (
            datetime.now() - datetime(1970, 1, 1)).total_seconds()
        client = FakeClient(RSA_KEY_512, clock)
        self.endpoint = AutoTLSEndpoint(
            reactor=clock,
            directory=URL.fromText(u'https://example.com/'),
            client=client,
            cert_store=MemoryStore(),
            cert_mapping={},
            sub_endpoint=DummyEndpoint())

    def test_directory_url_type(self):
        """
        `~txacme.endpoint.AutoTLSEndpoint` expects a ``twisted.python.url.URL``
        instance for the ``directory`` argument.
        """
        with ExpectedException(TypeError):
            AutoTLSEndpoint(
                reactor=Clock(),
                directory='/wrong/kind/of/directory',
                client=None,
                cert_store=None,
                cert_mapping={},
                sub_endpoint=DummyEndpoint())

    def test_listen_starts_service(self):
        """
        ``AutoTLSEndpoint.listen`` starts an ``AcmeIssuingService``.  Stopping
        the port stops the service.
        """
        factory = Factory()
        d = self.endpoint.listen(factory)
        self.assertThat(
            d,
            succeeded(
                MatchesPredicate(
                    IListeningPort.providedBy,
                    '%r does not provide IListeningPort')))
        port = d.result
        self.assertThat(
            self.endpoint.service,
            MatchesStructure(running=Equals(True)))
        self.assertThat(port.stopListening(), succeeded(Always()))
        self.assertThat(
            self.endpoint.service,
            MatchesStructure(running=Equals(False)))


class PluginTests(TXACMETestCase):
    """
    Tests for the plugins.
    """

    def test_le_parser(self):
        """
        The ``le:`` parser uses the Let's Encrypt production directory, and
        provides the relevant interfaces.
        """
        verifyObject(
            IPlugin, txacme_endpoint.le_parser)
        verifyObject(
            IStreamServerEndpointStringParser, txacme_endpoint.le_parser)
        self.assertThat(
            txacme_endpoint.le_parser,
            MatchesStructure(
                prefix=Equals('le'),
                directory=Equals(LETSENCRYPT_DIRECTORY)))

    def test_lets_parser(self):
        """
        The ``lets:`` parser uses the Let's Encrypt staging directory, and
        provides the relevant interfaces.
        """
        verifyObject(
            IPlugin, txacme_endpoint.lets_parser)
        verifyObject(
            IStreamServerEndpointStringParser, txacme_endpoint.lets_parser)
        self.assertThat(
            txacme_endpoint.lets_parser,
            MatchesStructure(
                prefix=Equals('lets'),
                directory=Equals(LETSENCRYPT_STAGING_DIRECTORY)))



class LoadClientKeyTests(TXACMETestCase):
    """
    Tests for `~txacme.endpoint.load_or_create_client_key`.
    """
    def test_create_key(self):
        """
        `~txacme.endpoint.load_or_create_client_key` creates a new key if one
        does not exist.
        """
        tempdir = self.useFixture(TempDir()).path
        temp_path = FilePath(tempdir)
        key_path = temp_path.child('client.key')
        self.assertThat(key_path.isfile(), Equals(False))
        self.assertThat(
            load_or_create_client_key(temp_path),
            Equals(JWKRSA(key=load_pem_private_key(
                    key_path.getContent(),
                    password=None,
                    backend=default_backend()))))

    def test_idempotent(self):
        """
        Loading the key twice loads the same key the second time as was created
        the first time.
        """
        tempdir = self.useFixture(TempDir()).path
        temp_path = FilePath(tempdir)
        key_path = temp_path.child('client.key')
        self.assertThat(key_path.isfile(), Equals(False))
        key = load_or_create_client_key(temp_path)
        self.assertThat(load_or_create_client_key(temp_path), Equals(key))


__all__ = ['EndpointTests', 'PluginTests']
