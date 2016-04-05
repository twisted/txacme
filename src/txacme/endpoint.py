"""
A TLS endpoint that supports SNI automatically issues / renews certificates via
an ACME CA (eg. Let's Encrypt).
"""
import attr
from twisted.internet.endpoints import serverFromString
from twisted.internet.interfaces import (
    IStreamServerEndpoint, IStreamServerEndpointStringParser)
from twisted.plugin import IPlugin
from twisted.python.filepath import FilePath
from txsni.snimap import HostDirectoryMap
from zope.interface import implementer

from txacme.store import DirectoryStore


@implementer(IStreamServerEndpoint)
@attr.s
class AutoTLSEndpoint(object):
    """
    A server endpoint that does TLS SNI, with certificates automatically
    (re)issued from an ACME certificate authority.
    """
    reactor = attr.ib()
    directory = attr.ib()
    cert_store = attr.ib()
    cert_mapping = attr.ib()
    sub_endpoint = attr.ib()


def _parse(reactor, directory, pemdir, *args, **kwargs):
    """
    Parse a txacme endpoint description.

    :param reactor: The Twisted reactor.
    :param directory: ``twisted.python.url.URL`` for the ACME directory to use
        for issuing certs.
    :param str pemdir: The path to the certificate directory to use.
    """
    def colon_join(items):
        return ':'.join([item.replace(':', '\\:') for item in items])
    sub = colon_join(list(args) + ['='.join(item) for item in kwargs.items()])
    pem_path = FilePath(pemdir)
    return AutoTLSEndpoint(
        reactor=reactor,
        directory=directory,
        cert_store=DirectoryStore(pem_path),
        cert_mapping=HostDirectoryMap(pem_path),
        sub_endpoint=serverFromString(reactor, sub))


@implementer(IPlugin, IStreamServerEndpointStringParser)
@attr.s
class _AcmeParser(object):
    """
    txacme endpoint parser.

    Connects an `AutoTLSEndpoint` to the an ACME certificate authority and a
    directory certificate store.
    """
    prefix = attr.ib()
    directory = attr.ib()

    def parseStreamServer(self, reactor, *args, **kwargs):
        """
        .. seealso:: `_parse`
        """
        return _parse(reactor, self.directory, *args, **kwargs)


__all__ = ['AutoTLSEndpoint', '_AcmeParser']
