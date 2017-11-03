import attr
import treq

from txacme.interfaces import IResponder
from txacme.challenges._libcloud import _validation, _split_zone
from zope.interface import implementer
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import deferLater

@attr.s(hash=False)
@implementer(IResponder)
class GandiV5Responder(object):
    """
    Gandi V5 API responder.
    """

    _api_key = attr.ib()
    _zone_name = attr.ib()
    _settle_delay=attr.ib(default=60.0)

    challenge_type = u'dns-01'

    def _headers(self):
        return {
            # b"Content-Type": [b"application/json"],
            b"X-API-Key": [self._api_key.encode("ascii")]
        }

    @inlineCallbacks
    def start_responding(self, server_name, challenge, response):
        from twisted.internet import reactor
        validation = _validation(response)
        full_name = challenge.validation_domain_name(server_name)
        subdomain = _split_zone(full_name, self._zone_name)
        if subdomain == '':
            subdomain = '@'

        url = (
            'https://dns.api.gandi.net/api/v5/domains/'
            '{zone}/records'
        ).format(
            zone=self._zone_name, subdomain=subdomain, type='TXT',
        )
        body = {"rrset_name": subdomain,
                "rrset_type": "TXT",
                "rrset_ttl": 300,
                "rrset_values": [
                    validation
                ]}
        print(body)
        response = yield treq.post(url, json=body, headers=self._headers())
        print((yield treq.json_content(response)))
        yield deferLater(reactor, self._settle_delay, lambda: None)
        print("start settled")

    def stop_responding(self, server_name, challenge, response):
        from twisted.internet import reactor
        full_name = challenge.validation_domain_name(server_name)
        subdomain = _split_zone(full_name, self._zone_name)
        url = (
            'https://dns.api.gandi.net/api/v5/domains/'
            '{zone}/records/{subdomain}/{type}'
        ).format(
            zone=self._zone_name, subdomain=subdomain, type='TXT',
        )
        if subdomain == '':
            subdomain = '@'
        response = yield treq.delete(url, headers=self._headers())
        print((yield treq.json_content(response)))
        yield deferLater(reactor, self._settle_delay, lambda: None)
        print("stop settled")
