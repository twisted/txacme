"""
TLS challenge implementations.

Formerly tls-sni-01, hopefully tls-alpn-01 at some point in the future.
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
