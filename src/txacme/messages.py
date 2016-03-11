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

    ..  seealso: `acme.messages.CertificateRequest`

    :ivar cryptography.x509.CertificateSigningRequest csr: A CSR.
    """
    resource_type = 'new-cert'
    resource = Resource(resource_type)
    csr = Field('csr', decoder=decode_csr, encoder=encode_csr)
