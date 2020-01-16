"""
A TLS endpoint that supports SNI automatically issues / renews certificates via
an ACME CA (eg. Let's Encrypt).
"""
from datetime import timedelta
from functools import partial

import attr
from josepy.jwk import JWKRSA
from josepy.jwa import RS256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from twisted.internet.defer import maybeDeferred
from twisted.internet.endpoints import serverFromString
from twisted.internet.interfaces import IListeningPort, IStreamServerEndpoint
from twisted.protocols.tls import TLSMemoryBIOFactory
from twisted.python.filepath import FilePath
from txsni.snimap import HostDirectoryMap, SNIMap
from zope.interface import implementer

from txacme.challenges import TLSSNI01Responder
from txacme.client import Client, _DEFAULT_TIMEOUT
from txacme.service import _default_panic, AcmeIssuingService
from txacme.store import DirectoryStore
from txacme.util import check_directory_url_type, generate_private_key


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

    :param reactor: The Twisted reactor.
    :param directory: ``twisted.python.url.URL`` for the ACME directory to use
        for issuing certs.

    :type client_creator: Callable[[reactor, ``twisted.python.url.URL``],
        Deferred[`txacme.client.Client`]]
    :param client_creator: A callable called with the reactor and directory URL
        for creating the ACME client.  For example, ``partial(Client.from_url,
        key=acme_key, alg=RS256)``.
    :type cert_store: `txacme.interfaces.ICertificateStore`
    :param cert_store: The certificate
        store containing the certificates to manage.  For example,
        `txacme.store.DirectoryStore`.
    :param dict cert_mapping: The certificate mapping to use for SNI; for
        example, ``txsni.snimap.HostDirectoryMap``.  Usually this should
        correspond to the same underlying storage as ``cert_store``.
    :param ~datetime.timedelta check_interval: How often to check for expiring
        certificates.
    :param ~datetime.timedelta reissue_interval: If a certificate is expiring
        in less time than this interval, it will be reissued.
    :param ~datetime.timedelta panic_interval: If a certificate is expiring in
        less time than this interval, and reissuing fails, the panic callback
        will be invoked.

    :type panic: Callable[[Failure, `str`], Deferred]
    :param panic: A callable invoked with the failure and server name when
        reissuing fails for a certificate expiring in the ``panic_interval``.
        For example, you could generate a monitoring alert.  The default
        callback logs a message at *CRITICAL* level.
    :param generate_key: A 0-arg callable used to generate a private key for a
        new cert.  Normally you would not pass this unless you have specialized
        key generation requirements.
    """
    reactor = attr.ib()
    directory = attr.ib(
        validator=lambda inst, a, value: check_directory_url_type(value))
    client = attr.ib()
    cert_store = attr.ib()
    cert_mapping = attr.ib()
    sub_endpoint = attr.ib()
    check_interval = attr.ib(default=timedelta(days=1))
    reissue_interval = attr.ib(default=timedelta(days=30))
    panic_interval = attr.ib(default=timedelta(days=15))
    _panic = attr.ib(default=_default_panic)
    _generate_key = attr.ib(default=partial(generate_private_key, u'rsa'))

    def listen(self, protocolFactory):  # noqa
        """
        Start an issuing service, and wait until initial issuing is complete.
        """
        def _got_port(port):
            self.service = AcmeIssuingService(
                cert_store=self.cert_store,
                client=self.client,
                clock=self.reactor,
                responders=[responder],
                check_interval=self.check_interval,
                reissue_interval=self.reissue_interval,
                panic_interval=self.panic_interval,
                panic=self._panic,
                generate_key=self._generate_key)
            self.service.startService()
            return (
                self.service.when_certs_valid()
                .addCallback(
                    lambda _: _WrapperPort(port=port, service=self.service)))

        responder = TLSSNI01Responder()
        sni_map = SNIMap(responder.wrap_host_map(self.cert_mapping))
        return (
            maybeDeferred(
                self.sub_endpoint.listen,
                TLSMemoryBIOFactory(
                    contextFactory=sni_map,
                    isClient=False,
                    wrappedFactory=protocolFactory))
            .addCallback(_got_port))


def load_or_create_client_key(pem_path):
    """
    Load the client key from a directory, creating it if it does not exist.

    .. note:: The client key that will be created will be a 2048-bit RSA key.

    :type pem_path: ``twisted.python.filepath.FilePath``
    :param pem_path: The certificate directory
        to use, as with the endpoint.
    """
    acme_key_file = pem_path.asTextMode().child(u'client.key')
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
    return JWKRSA(key=key)


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

    timeout = kwargs.pop('timeout', _DEFAULT_TIMEOUT)
    sub = colon_join(list(args) + ['='.join(item) for item in kwargs.items()])

    pem_path = FilePath(pemdir).asTextMode()
    acme_key = load_or_create_client_key(pem_path)
    return AutoTLSEndpoint(
        reactor=reactor,
        directory=directory,
        client=Client.from_url(
            reactor, directory, key=acme_key, alg=RS256, timeout=timeout),
        cert_store=DirectoryStore(pem_path),
        cert_mapping=HostDirectoryMap(pem_path),
        sub_endpoint=serverFromString(reactor, sub))


__all__ = ['AutoTLSEndpoint', 'load_or_create_client_key']
