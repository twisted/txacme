"""
Implementations of ACME challenge mechanisms.

.. seealso:: `acme.challenges`
"""
from collections import Mapping

import attr
from twisted.internet.ssl import CertificateOptions
from zope.interface import implementer

from txacme.interfaces import ITLSSNI01Responder
from txacme.util import (
    cert_cryptography_to_pyopenssl, generate_tls_sni_01_cert,
    key_cryptography_to_pyopenssl)


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


@implementer(ITLSSNI01Responder)
class TLSSNI01Responder(object):
    """
    A tls-sni-01 challenge responder for txsni.
    """
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

    def start_responding(self, server_name):
        """
        Put a context into the mapping.
        """
        cert, pkey = generate_tls_sni_01_cert(
            server_name, _generate_private_key=self._generate_private_key)
        server_name = server_name.encode('utf-8')
        self._challenge_options[server_name] = CertificateOptions(
            certificate=cert_cryptography_to_pyopenssl(cert),
            privateKey=key_cryptography_to_pyopenssl(pkey))

    def stop_responding(self, server_name):
        """
        Remove a context from the mapping.
        """
        self._challenge_options.pop(server_name, None)
