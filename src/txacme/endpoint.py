"""
A TLS endpoint that supports SNI automatically issues / renews certificates via
an ACME CA (eg. Let's Encrypt).
"""
from functools import partial

import attr
from acme.jose import JWKRSA, RS256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from twisted.internet.defer import gatherResults, maybeDeferred
from twisted.internet.endpoints import serverFromString
from twisted.internet.interfaces import (
    IListeningPort, IStreamServerEndpoint, IStreamServerEndpointStringParser)
from twisted.plugin import IPlugin
from twisted.protocols.tls import TLSMemoryBIOFactory
from twisted.python.filepath import FilePath
from txsni.snimap import HostDirectoryMap, SNIMap
from zope.interface import implementer

from txacme.challenges import TLSSNI01Responder
from txacme.client import Client
from txacme.service import AcmeIssuingService
from txacme.store import DirectoryStore
from txacme.util import generate_private_key


@implementer(IListeningPort)
@attr.s(cmp=False, hash=False)
class _WrapperPort(object):
    """
    Wrapper for the underlying port to stop the issuing service when the port
    is stopped.
    """
    _port = attr.ib()
    _service = attr.ib()

    def stopListening(self):  # noqa
        return (
            maybeDeferred(self._port.stopListening)
            .addCallback(lambda _: self._service.stopService()))


@implementer(IStreamServerEndpoint)
@attr.s(cmp=False, hash=False)
class AutoTLSEndpoint(object):
    """
    A server endpoint that does TLS SNI, with certificates automatically
    (re)issued from an ACME certificate authority.
    """
    reactor = attr.ib()
    directory = attr.ib()
    client_creator = attr.ib()
    cert_store = attr.ib()
    cert_mapping = attr.ib()
    sub_endpoint = attr.ib()

    def listen(self, protocolFactory):  # noqa
        """
        Start an issuing service, and wait until initial issuing is complete.
        """
        def _got_client_and_port(cp):
            client, port = cp
            self.service = AcmeIssuingService(
                cert_store=self.cert_store,
                client=client,
                clock=self.reactor,
                responders=[responder])
            self.service.startService()
            return (
                self.service.when_certs_valid()
                .addCallback(
                    lambda _: _WrapperPort(port=port, service=self.service)))

        responder = TLSSNI01Responder()
        sni_map = SNIMap(responder.wrap_host_map(self.cert_mapping))
        return (
            gatherResults([
                self.client_creator(self.reactor, self.directory),
                maybeDeferred(
                    self.sub_endpoint.listen,
                    TLSMemoryBIOFactory(
                        contextFactory=sni_map,
                        isClient=False,
                        wrappedFactory=protocolFactory)),
                ], consumeErrors=True)
            .addCallback(_got_client_and_port))


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
    pem_path = FilePath(pemdir).asTextMode()
    acme_key_file = pem_path.child(u'client.key')
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
    acme_key = JWKRSA(key=key)
    return AutoTLSEndpoint(
        reactor=reactor,
        directory=directory,
        client_creator=partial(Client.from_url, key=acme_key, alg=RS256),
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
