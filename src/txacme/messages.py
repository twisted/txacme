"""
ACME protocol messages.

This module provides supplementary message implementations that are not already
provided by the `acme` library.

..  seealso:: `acme.messages`
"""
from acme.fields import Resource
from acme.jose import Field, JSONObjectWithFields

from txacme.util import decode_csr, encode_csr


class CertificateRequest(JSONObjectWithFields):
    """
    ACME new-cert request.

    Differs from the upstream version because it wraps a Cryptography CSR
    object instead of a PyOpenSSL one.

    ..  seealso:: `acme.messages.CertificateRequest`,
        `cryptography.x509.CertificateSigningRequest`
    """
    resource_type = 'new-cert'
    resource = Resource(resource_type)
    csr = Field('csr', decoder=decode_csr, encoder=encode_csr)


__all__ = ['CertificateRequest']
