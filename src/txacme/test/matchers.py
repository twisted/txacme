from cryptography import x509
from testtools.matchers import Mismatch
from cryptography.x509.oid import ExtensionOID
from service_identity._common import (
    DNS_ID, DNSPattern, verify_service_identity)
from service_identity.exceptions import VerificationError


class ValidForName(object):
    """
    Matches when the matchee object (must be a `~cryptography.x509.Certificate`
    or `~cryptography.x509.CertificateSigningRequest`) is valid for the given
    name.
    """
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return 'ValidForName({0.name!r})'.format(self)

    def match(self, value):
        # This is somewhat terrible. Probably can be better after
        # pyca/service_identity#14 is resolved.
        target_ids = [
            DNSPattern(target_name.encode('utf-8'))
            for target_name
            in (
                value.extensions
                .get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                .value
                .get_values_for_type(x509.DNSName)
            )]
        ids = [DNS_ID(self.name)]
        try:
            verify_service_identity(
                cert_patterns=target_ids, obligatory_ids=ids, optional_ids=[])
        except VerificationError:
            return Mismatch(
                '{!r} is not valid for {!r}'.format(value, self.name))

__all__ = ['ValidForName']
