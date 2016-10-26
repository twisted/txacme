"""
Standalone module for the endpoint parser to avoid eagerly importing a bunch of
things which will install a reactor.
"""
import attr
from twisted.internet.interfaces import IStreamServerEndpointStringParser
from twisted.plugin import IPlugin
from zope.interface import implementer


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

    def parseStreamServer(self, reactor, *args, **kwargs):  # noqa
        """
        .. seealso:: `txacme.endpoint._parse`
        """
        from txacme.endpoint import _parse
        return _parse(reactor, self.directory, *args, **kwargs)


__all___ = ['_AcmeParser']
