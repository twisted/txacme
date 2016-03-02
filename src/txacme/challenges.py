"""
Implementations of ACME challenge mechanisms.

.. seealso:: `acme.challenges`
"""
from zope.interface import implementer

from txacme.interfaces import ITLSSNI01Responder


@implementer(ITLSSNI01Responder)
class TLSSNI01Responder(object):
    """
    A tls-sni-01 challenge responder for txsni.
    """
