from functools import partial
from operator import attrgetter

from acme import jose, messages
from acme.errors import ClientError
from fixtures import Fixture
from testtools import TestCase
from testtools.matchers import AfterPreprocessing, IsInstance, Mismatch
from testtools.twistedsupport import failed
from treq.client import HTTPClient
from treq.testing import (
    _SynchronousProducer, HasHeaders, RequestSequence, RequestTraversalAgent,
    StringStubbingResource)
from twisted.internet import reactor

from txacme.client import Client
from txacme.util import generate_private_key


def failed_with(matcher):
    return failed(AfterPreprocessing(attrgetter('value'), matcher))


class Never(object):
    """Never matches."""

    def __str__(self):
        return 'Never()'

    def match(self, value):
        return Mismatch(
            u'Inevitable mismatch on %r' % (value,))


class ClientFixture(Fixture):
    """
    Create a :class:`.Client` for testing.
    """
    def __init__(self, sequence, directory=None, key=None, alg=jose.RS256):
        super(ClientFixture, self).__init__()
        self._sequence = sequence
        if directory is None:
            self._directory = messages.Directory({
                messages.NewRegistration:
                'https://www.letsencrypt-demo.org/acme/new-reg',
                messages.Revocation:
                'https://www.letsencrypt-demo.org/acme/revoke-cert',
                messages.NewAuthorization:
                'https://www.letsencrypt-demo.org/acme/new-authz',
                })
        else:
            self._directory = directory
        if key is None:
            self._key = jose.JWKRSA(key=generate_private_key('rsa'))
        else:
            self._key = key
        self._alg = alg

    def _setUp(self):  # noqa
        treq_client = HTTPClient(
            agent=RequestTraversalAgent(
                StringStubbingResource(self._sequence)),
            data_to_body_producer=_SynchronousProducer)
        self.client = Client(
            reactor, self._directory, self._key, self._alg,
            treq_client=treq_client)


class ClientTests(TestCase):
    """
    :class:`.Client` provides a client interface for the ACME API.
    """
    def test_register_missing_next(self):
        """
        If the directory does not return a ``"next"`` link, a
        :exc:`~acme.errors.ClientError` failure occurs.
        """
        sequence = RequestSequence(
            [((b'head',
               b'https://www.letsencrypt-demo.org/acme/new-reg',
               {},
               HasHeaders({'user-agent': ['txacme']}),
               b''),
              (0, {}, b''))],
            partial(self.expectThat, None, Never()))
        client = self.useFixture(ClientFixture(sequence, None, None)).client
        with sequence.consume(self.fail):
            d = client.register()
        self.assertThat(d, failed_with(IsInstance(ClientError)))
