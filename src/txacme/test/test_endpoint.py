"""
Tests for `txacme.endpoint`.
"""
from fixtures import TempDir
from testtools import TestCase
from testtools.matchers import (
    Equals, Is, IsInstance, MatchesAll, MatchesPredicate, MatchesStructure)
from twisted.internet.interfaces import (
    IStreamServerEndpoint, IStreamServerEndpointStringParser)
from twisted.plugin import IPlugin
from twisted.plugins import txacme_endpoint
from twisted.python.filepath import FilePath
from twisted.python.url import URL
from txsni.snimap import HostDirectoryMap
from zope.interface.verify import verifyObject

from txacme.client import LETSENCRYPT_DIRECTORY, LETSENCRYPT_STAGING_DIRECTORY
from txacme.endpoint import _AcmeParser, AutoTLSEndpoint
from txacme.store import DirectoryStore


class EndpointTests(TestCase):
    """
    Tests for `~txacme.endpoint.AutoTLSEndpoint`.
    """


class PluginTests(TestCase):
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

    def test_parser(self):
        """
        ``AcmeParser`` creates an endpoint with the specified ACME directory
        and directory store.
        """
        directory = URL.fromText(u'https://example.com/acme')
        parser = _AcmeParser(u'prefix', directory)
        tempdir = self.useFixture(TempDir()).path
        temppath = FilePath(tempdir)
        reactor = object()
        self.assertThat(
            parser.parseStreamServer(reactor, tempdir, 'tcp', '443'),
            MatchesAll(
                IsInstance(AutoTLSEndpoint),
                MatchesStructure(
                    reactor=Is(reactor),
                    directory=Equals(directory),
                    cert_store=MatchesAll(
                        IsInstance(DirectoryStore),
                        MatchesStructure(
                            path=Equals(temppath))),
                    cert_mapping=MatchesAll(
                        IsInstance(HostDirectoryMap),
                        MatchesStructure(
                            directoryPath=Equals(temppath))),
                    sub_endpoint=MatchesPredicate(
                        IStreamServerEndpoint.providedBy,
                        '%r is not a stream server endpoint'))))


__all__ = ['EndpointTests', 'PluginTests']
