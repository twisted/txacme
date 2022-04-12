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
from testtools import TestCase
from twisted.internet import reactor
from twisted.internet.defer import Deferred, fail, succeed
from twisted.python.compat import unicode
from zope.interface import implementer

from txacme.interfaces import ICertificateStore, IResponder
from txacme.util import clock_now, generate_private_key


class TXACMETestCase(TestCase):
    """
    Common code for all tests for the txacme project.
    """

    def tearDown(self):
        super(TXACMETestCase, self).tearDown()

        # Make sure the main reactor is clean after each test.
        junk = []
        for delayed_call in reactor.getDelayedCalls():
            junk.append(delayed_call.func)
            delayed_call.cancel()
        if junk:
            raise AssertionError(
                'Reactor is not clean. DelayedCalls: %s' % (junk,))



@implementer(IResponder)
@attr.s
class NullResponder(object):
    """
    A responder that does absolutely nothing.
    """
    challenge_type = attr.ib()

    def start_responding(self, server_name, challenge, response):
        pass

    def stop_responding(self, server_name, challenge, response):
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


__all__ = ['MemoryStore', 'NullResponder']
