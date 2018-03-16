"""
``tls-sni-01`` challenge implementation.
"""
from collections import Mapping

import attr
from OpenSSL import crypto
from twisted.internet.ssl import CertificateOptions
from zope.interface import implementer

from txacme.interfaces import IResponder
from txacme.util import generate_tls_sni_01_cert


@attr.s(hash=False)
class _MergingMappingProxy(Mapping):
    """
    Merges two mappings together.

    The proxy is immutable, even if the underlying mappings are mutable.
    """
    underlay = attr.ib()
    overlay = attr.ib()

    def __getitem__(self, key):
        try:
            return self.overlay[key]
        except KeyError:
            return self.underlay[key]

    def __iter__(self):
        return iter(set(self.underlay.keys()) | set(self.overlay.keys()))

    def __len__(self):
        return sum(1 for _ in self)

    def __contains__(self, key):
        return key in self.underlay or key in self.overlay


@implementer(IResponder)
class TLSSNI01Responder(object):
    """
    A ``tls-sni-01`` challenge responder for txsni.
    """
    challenge_type = u'tls-sni-01'

    _generate_private_key = None

    def __init__(self):
        self._challenge_options = {}

    def wrap_host_map(self, host_map):
        """
        Wrap a txsni host mapping.

        The wrapper should be passed to ``txsni.snimap.SNIMap``; any active
        challenge server names will override entries in the wrapped map, but
        this scenario is unlikely to occur due to the invalid nature of these
        names.
        """
        return _MergingMappingProxy(
            underlay=host_map, overlay=self._challenge_options)

    def start_responding(self, server_name, challenge, response):
        """
        Put a context into the mapping.
        """
        server_name = response.z_domain.decode('ascii')
        cert, pkey = generate_tls_sni_01_cert(
            server_name, _generate_private_key=self._generate_private_key)
        server_name = server_name.encode('utf-8')
        self._challenge_options[server_name] = CertificateOptions(
            certificate=crypto.X509.from_cryptography(cert),
            privateKey=crypto.PKey.from_cryptography_key(pkey))

    def stop_responding(self, server_name, challenge, response):
        """
        Remove a context from the mapping.
        """
        server_name = response.z_domain.decode('ascii')
        self._challenge_options.pop(server_name, None)


__all__ = ['TLSSNI01Responder']
