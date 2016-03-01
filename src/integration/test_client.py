"""
Integration tests for :mod:`acme.client`.
"""
from __future__ import print_function

from acme.jose import JWKRSA
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.python.url import URL
from twisted.trial.unittest import TestCase

from txacme.client import Client, fqdn_identifier
from txacme.util import generate_private_key


STAGING_DIRECTORY = URL.fromText(
    u'https://acme-staging.api.letsencrypt.org/directory')
HOST = u'acme-testing.mithrandi.net'


class ClientTests(TestCase):
    @inlineCallbacks
    def test_registration(self):
        key = JWKRSA(key=generate_private_key('rsa'))
        client = yield Client.from_url(reactor, STAGING_DIRECTORY, key=key)

        reg = yield client.register()

        # Re-registering just fetches the old registration
        reg2 = yield client.register()
        self.assertEqual(reg, reg2)

        yield client.agree_to_tos(reg2)

        auth = yield client.request_challenges(fqdn_identifier(HOST))

        # AuthorizationResource(
        #     body=Authorization(
        #         status=Status(pending),
        #         challenges=(
        #             ChallengeBody(
        #                 chall=UnrecognizedChallenge(),
        #                 status=Status(pending),
        #                 validated=None,
        #                 uri=u'https://acme-staging.api.letsencrypt.org/acme/challenge/9j78Tc9U5YJfvSjmYfi1MC4zi7l-r7sAQUSnjYiOuiY/1478888',
        #                 error=None),
        #             ChallengeBody(
        #                 chall=HTTP01(token='B\x1c2\x88\x01\xc1\xc4Fn\x1c\xb1\x9af\xf6\x938\xa6\xd6}a\xd5&\x19\xf1\xd1N1w\xd2\xa5R\x0f'),
        #                 status=Status(pending),
        #                 validated=None,
        #                 uri=u'https://acme-staging.api.letsencrypt.org/acme/challenge/9j78Tc9U5YJfvSjmYfi1MC4zi7l-r7sAQUSnjYiOuiY/1478889',
        #                 error=None),
        #             ChallengeBody(
        #                 chall=TLSSNI01(token='r\x8e\x9aZ\xafC\xe1L\x84\xc0WQMB\xd8:\x01\xa2D\xc1z\xcf\xc7\x1a\x9aM\xd5\xd5c\xfc&\xee'),
        #                 status=Status(pending),
        #                 validated=None,
        #                 uri=u'https://acme-staging.api.letsencrypt.org/acme/challenge/9j78Tc9U5YJfvSjmYfi1MC4zi7l-r7sAQUSnjYiOuiY/1478890',
        #                 error=None)),
        #         identifier=Identifier(typ=IdentifierType(dns),
        #                               value=u'acme-testing.mithrandi.net'),
        #         expires=datetime.datetime(2016, 3, 7, 20, 4, 17, 775010),
        #         combinations=((0,), (2,),
        #                       (1,))),
        #     new_cert_uri=u'https://acme-staging.api.letsencrypt.org/acme/new-cert',
        #     uri=u'https://acme-staging.api.letsencrypt.org/acme/authz/9j78Tc9U5YJfvSjmYfi1MC4zi7l-r7sAQUSnjYiOuiY')

        # Close idle connections left over
        yield client._client._treq._agent._pool.closeCachedConnections()
