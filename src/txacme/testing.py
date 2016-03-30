"""
Utilities for testing with txacme.
"""
from collections import OrderedDict
from datetime import timedelta
from uuid import uuid4

import attr
from acme import challenges, messages
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, NameOID
from twisted.internet.defer import fail, succeed
from twisted.python.compat import unicode
from zope.interface import implementer

from txacme.interfaces import ICertificateStore, IResponder
from txacme.util import clock_now, generate_private_key


class FakeClient(object):
    """
    Provides the same API as `~txacme.client.Client`, but performs no network
    operations and issues certificates signed by its own fake CA.
    """
    _challenge_types = [challenges.TLSSNI01]

    def __init__(self, key, clock, ca_key=None):
        self.key = key
        self._clock = clock
        self._registered = False
        self._tos_agreed = None
        self._authorizations = {}
        self._challenges = {}
        self._ca_key = ca_key
        self._generate_ca_cert()

    def _now(self):
        """
        Get the current time.
        """
        return clock_now(self._clock)

    def _generate_ca_cert(self):
        """
        Generate a CA cert/key.
        """
        if self._ca_key is None:
            self._ca_key = generate_private_key(u'rsa')
        self._ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'ACME Snake Oil CA')])
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(self._ca_name)
            .issuer_name(self._ca_name)
            .not_valid_before(self._now() - timedelta(seconds=3600))
            .not_valid_after(self._now() + timedelta(days=3650))
            .public_key(self._ca_key.public_key())
            .serial_number(int(uuid4()))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    self._ca_key.public_key()),
                critical=False)
            .sign(
                private_key=self._ca_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()))
        self._ca_aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            self._ca_key.public_key())

    def register(self, new_reg=None):
        self._registered = True
        if new_reg is None:
            new_reg = messages.NewRegistration()
        self.regr = messages.RegistrationResource(
            body=messages.Registration(
                contact=new_reg.contact,
                agreement=new_reg.agreement))
        return succeed(self.regr)

    def agree_to_tos(self, regr):
        self._tos_agreed = True
        self.regr = self.regr.update(
            body=regr.body.update(
                agreement=regr.terms_of_service))
        return succeed(self.regr)

    def request_challenges(self, identifier):
        self._authorizations[identifier] = challenges = OrderedDict()
        for chall_type in self._challenge_types:
            uuid = unicode(uuid4())
            challb = messages.ChallengeBody(
                chall=chall_type(token=b'token'),
                uri=uuid,
                status=messages.STATUS_PENDING)
            challenges[chall_type] = uuid
            self._challenges[uuid] = challb
        return succeed(
            messages.AuthorizationResource(
                body=messages.Authorization(
                    identifier=identifier,
                    status=messages.STATUS_PENDING,
                    challenges=[
                        self._challenges[u] for u in challenges.values()],
                    combinations=[[n] for n in range(len(challenges))])))

    def answer_challenge(self, challenge_body, response):
        challb = self._challenges[challenge_body.uri]
        challb = challb.update(status=messages.STATUS_VALID)
        self._challenges[challenge_body.uri] = challb
        return succeed(challb)

    def poll(self, authzr):
        challenges = [
            self._challenges[u] for u
            in self._authorizations[authzr.body.identifier].values()]
        status = (
            messages.STATUS_VALID
            if any(c.status == messages.STATUS_VALID for c in challenges)
            else messages.STATUS_PENDING)
        return succeed(
            (messages.AuthorizationResource(
                body=messages.Authorization(
                    status=status,
                    challenges=challenges,
                    combinations=[[n] for n in range(len(challenges))])),
             1.0))

    def request_issuance(self, csr):
        csr = csr.csr
        # TODO: Only in Cryptography 1.3
        # assert csr.is_signature_valid
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._ca_name)
            .not_valid_before(self._now() - timedelta(seconds=3600))
            .not_valid_after(self._now() + timedelta(days=90))
            .serial_number(int(uuid4()))
            .public_key(csr.public_key())
            .add_extension(
                csr.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value,
                critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False)
            .add_extension(self._ca_aki, critical=False)
            .sign(
                private_key=self._ca_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()))
        return succeed(
            messages.CertificateResource(
                body=cert.public_bytes(encoding=serialization.Encoding.DER)))

    def fetch_chain(self, certr, max_length=10):
        return succeed([
            messages.CertificateResource(
                body=self._ca_cert.public_bytes(
                    encoding=serialization.Encoding.DER))])


@implementer(IResponder)
@attr.s
class NullResponder(object):
    """
    A responder that does absolutely nothing.
    """
    challenge_type = attr.ib()

    def start_responding(self, challenge):
        pass

    def stop_responding(self, challenge):
        pass


@implementer(ICertificateStore)
class MemoryStore(object):
    """
    A certificate store that keeps certificates in memory only.
    """
    def __init__(self, certs=None):
        if certs is None:
            self._store = {}
        else:
            self._store = dict(certs)

    def get(self, server_name):
        try:
            return succeed(self._store[server_name])
        except KeyError:
            return fail()

    def store(self, server_name, pem_objects):
        self._store[server_name] = pem_objects
        return succeed(None)

    def as_dict(self):
        return succeed(self._store)


__all__ = ['FakeClient', 'MemoryStore', 'NullResponder']
