"""
Tests for `txacme.challenges`.
"""
from operator import methodcaller

from acme import challenges
from acme.jose import b64encode
from hypothesis import strategies as s
from hypothesis import assume, example, given
from testtools import skipIf, TestCase
from testtools.matchers import (
    AfterPreprocessing, Always, Contains, EndsWith, Equals, HasLength,
    Is, IsInstance, MatchesAll, MatchesListwise, MatchesPredicate,
    MatchesStructure, Not)
from testtools.twistedsupport import succeeded
from treq.testing import StubTreq
from twisted._threads import createMemoryWorker
from twisted.internet.defer import maybeDeferred
from twisted.python.url import URL
from twisted.web.resource import Resource
from zope.interface.verify import verifyObject

from txacme.challenges import HTTP01Responder, TLSSNI01Responder
from txacme.challenges._tls import _MergingMappingProxy
from txacme.errors import NotInZone, ZoneNotFound
from txacme.interfaces import IResponder
from txacme.test import strategies as ts
from txacme.test.doubles import SynchronousReactorThreads
from txacme.test.test_client import failed_with, RSA_KEY_512, RSA_KEY_512_RAW


try:
    from txacme.challenges import LibcloudDNSResponder
    from txacme.challenges._libcloud import _daemon_thread
except ImportError:
    LibcloudDNSResponder = None


# A random example token for the challenge tests that need one
EXAMPLE_TOKEN = b'BWYcfxzmOha7-7LoxziqPZIUr99BCz3BfbN9kzSFnrU'


class _CommonResponderTests(object):
    """
    Common properties which every responder implementation should satisfy.
    """
    def _do_one_thing(self):
        """
        Make the underlying fake implementation do one thing (eg.  simulate one
        network request, one threaded task execution).
        """

    def test_interface(self):
        """
        The `.IResponder` interface is correctly implemented.
        """
        responder = self._responder_factory()
        verifyObject(IResponder, responder)
        self.assertThat(responder.challenge_type, Equals(self._challenge_type))

    @example(token=EXAMPLE_TOKEN)
    @given(token=s.binary(min_size=32, max_size=32).map(b64encode))
    def test_stop_responding_already_stopped(self, token):
        """
        Calling ``stop_responding`` when we are not responding for a server
        name does nothing.
        """
        challenge = self._challenge_factory(token=token)
        response = challenge.response(RSA_KEY_512)
        responder = self._responder_factory()
        d = maybeDeferred(
            responder.stop_responding,
            u'example.com',
            challenge,
            response)
        self._do_one_thing()
        self.assertThat(d, succeeded(Always()))


class TLSResponderTests(_CommonResponderTests, TestCase):
    """
    `.TLSSNI01Responder` is a responder for tls-sni-01 challenges that works
    with txsni.
    """
    _challenge_factory = challenges.TLSSNI01
    _responder_factory = TLSSNI01Responder
    _challenge_type = u'tls-sni-01'

    @example(token=b'BWYcfxzmOha7-7LoxziqPZIUr99BCz3BfbN9kzSFnrU')
    @given(token=s.binary(min_size=32, max_size=32).map(b64encode))
    def test_start_responding(self, token):
        """
        Calling ``start_responding`` makes an appropriate entry appear in the
        host map.
        """
        ckey = RSA_KEY_512_RAW
        challenge = challenges.TLSSNI01(token=token)
        response = challenge.response(RSA_KEY_512)
        server_name = response.z_domain.decode('ascii')
        host_map = {}
        responder = TLSSNI01Responder()
        responder._generate_private_key = lambda key_type: ckey
        wrapped_host_map = responder.wrap_host_map(host_map)

        self.assertThat(wrapped_host_map, Not(Contains(server_name)))
        responder.start_responding(u'example.com', challenge, response)
        self.assertThat(
            wrapped_host_map.get(server_name.encode('utf-8')).certificate,
            MatchesPredicate(response.verify_cert, '%r does not verify'))

        # Starting twice before stopping doesn't break things
        responder.start_responding(u'example.com', challenge, response)
        self.assertThat(
            wrapped_host_map.get(server_name.encode('utf-8')).certificate,
            MatchesPredicate(response.verify_cert, '%r does not verify'))

        responder.stop_responding(u'example.com', challenge, response)
        self.assertThat(wrapped_host_map, Not(Contains(server_name)))


class MergingProxyTests(TestCase):
    """
    ``_MergingMappingProxy`` merges two mappings together.
    """
    @example(underlay={}, overlay={}, key=u'foo')
    @given(underlay=s.dictionaries(s.text(), s.builds(object)),
           overlay=s.dictionaries(s.text(), s.builds(object)),
           key=s.text())
    def test_get_overlay(self, underlay, overlay, key):
        """
        Getting an key that only exists in the overlay returns the value from
        the overlay.
        """
        underlay.pop(key, None)
        overlay[key] = object()
        proxy = _MergingMappingProxy(
            overlay=overlay, underlay=underlay)
        self.assertThat(proxy[key], Is(overlay[key]))

    @example(underlay={}, overlay={}, key=u'foo')
    @given(underlay=s.dictionaries(s.text(), s.builds(object)),
           overlay=s.dictionaries(s.text(), s.builds(object)),
           key=s.text())
    def test_get_underlay(self, underlay, overlay, key):
        """
        Getting an key that only exists in the underlay returns the value from
        the underlay.
        """
        underlay[key] = object()
        overlay.pop(key, None)
        proxy = _MergingMappingProxy(
            overlay=overlay, underlay=underlay)
        self.assertThat(proxy[key], Is(underlay[key]))

    @example(underlay={}, overlay={}, key=u'foo')
    @given(underlay=s.dictionaries(s.text(), s.builds(object)),
           overlay=s.dictionaries(s.text(), s.builds(object)),
           key=s.text())
    def test_get_both(self, underlay, overlay, key):
        """
        Getting an key that exists in both the underlay and the overlay returns
        the value from the overlay.
        """
        underlay[key] = object()
        overlay[key] = object()
        proxy = _MergingMappingProxy(
            overlay=overlay, underlay=underlay)
        self.assertThat(proxy[key], Not(Is(underlay[key])))
        self.assertThat(proxy[key], Is(overlay[key]))

    @example(underlay={u'foo': object(), u'bar': object()},
             overlay={u'bar': object(), u'baz': object()})
    @given(underlay=s.dictionaries(s.text(), s.builds(object)),
           overlay=s.dictionaries(s.text(), s.builds(object)))
    def test_len(self, underlay, overlay):
        """
        ``__len__`` of the proxy does not count duplicates.
        """
        proxy = _MergingMappingProxy(
            overlay=overlay, underlay=underlay)
        self.assertThat(len(proxy), Equals(len(list(proxy))))

    @example(underlay={u'foo': object(), u'bar': object()},
             overlay={u'bar': object(), u'baz': object()})
    @given(underlay=s.dictionaries(s.text(), s.builds(object)),
           overlay=s.dictionaries(s.text(), s.builds(object)))
    def test_iter(self, underlay, overlay):
        """
        ``__iter__`` of the proxy does not produce duplicate keys.
        """
        proxy = _MergingMappingProxy(
            overlay=overlay, underlay=underlay)
        keys = sorted(list(proxy))
        self.assertThat(keys, Equals(sorted(list(set(keys)))))

    @example(underlay={u'foo': object()}, overlay={}, key=u'foo')
    @example(underlay={}, overlay={}, key=u'bar')
    @given(underlay=s.dictionaries(s.text(), s.builds(object)),
           overlay=s.dictionaries(s.text(), s.builds(object)),
           key=s.text())
    def test_contains(self, underlay, overlay, key):
        """
        The mapping only contains a key if it can be gotten.
        """
        proxy = _MergingMappingProxy(
            overlay=overlay, underlay=underlay)
        self.assertThat(
            key in proxy,
            Equals(proxy.get(key) is not None))


class HTTPResponderTests(_CommonResponderTests, TestCase):
    """
    `.HTTP01Responder` is a responder for http-01 challenges.
    """
    _challenge_factory = challenges.HTTP01
    _responder_factory = HTTP01Responder
    _challenge_type = u'http-01'

    @example(token=b'BWYcfxzmOha7-7LoxziqPZIUr99BCz3BfbN9kzSFnrU')
    @given(token=s.binary(min_size=32, max_size=32).map(b64encode))
    def test_start_responding(self, token):
        """
        Calling ``start_responding`` makes an appropriate resource available.
        """
        challenge = challenges.HTTP01(token=token)
        response = challenge.response(RSA_KEY_512)

        responder = HTTP01Responder()

        challenge_resource = Resource()
        challenge_resource.putChild(b'acme-challenge', responder.resource)
        root = Resource()
        root.putChild(b'.well-known', challenge_resource)
        client = StubTreq(root)

        encoded_token = challenge.encode('token')
        challenge_url = URL(host=u'example.com', path=[
            u'.well-known', u'acme-challenge', encoded_token]).asText()

        self.assertThat(client.get(challenge_url),
                        succeeded(MatchesStructure(code=Equals(404))))

        responder.start_responding(u'example.com', challenge, response)
        self.assertThat(client.get(challenge_url), succeeded(MatchesAll(
            MatchesStructure(
                code=Equals(200),
                headers=AfterPreprocessing(
                    methodcaller('getRawHeaders', b'content-type'),
                    Equals([b'text/plain']))),
            AfterPreprocessing(methodcaller('content'), succeeded(
                Equals(response.key_authorization.encode('utf-8'))))
        )))

        # Starting twice before stopping doesn't break things
        responder.start_responding(u'example.com', challenge, response)
        self.assertThat(client.get(challenge_url),
                        succeeded(MatchesStructure(code=Equals(200))))

        responder.stop_responding(u'example.com', challenge, response)
        self.assertThat(client.get(challenge_url),
                        succeeded(MatchesStructure(code=Equals(404))))


@skipIf(LibcloudDNSResponder is None, 'libcloud not available')
class LibcloudResponderTests(_CommonResponderTests, TestCase):
    """
    `.LibcloudDNSResponder` implements a responder for dns-01 challenges using
    libcloud on the backend.
    """
    _challenge_factory = challenges.DNS01
    _challenge_type = u'dns-01'

    def _responder_factory(self, zone_name=u'example.com'):
        responder = LibcloudDNSResponder.create(
            reactor=SynchronousReactorThreads(),
            driver_name='dummy',
            username='ignored',
            password='ignored',
            zone_name=zone_name,
            settle_delay=0.0)
        if zone_name is not None:
            responder._driver.create_zone(zone_name)
        responder.thread_pool, self._perform = createMemoryWorker()
        return responder

    def _do_one_thing(self):
        return self._perform()

    def test_daemon_threads(self):
        """
        ``_daemon_thread`` creates thread objects with ``daemon`` set.
        """
        thread = _daemon_thread()
        self.assertThat(thread, MatchesStructure(daemon=Equals(True)))

    @example(token=EXAMPLE_TOKEN,
             subdomain=u'acme-testing',
             zone_name=u'example.com')
    @given(token=s.binary(min_size=32, max_size=32).map(b64encode),
           subdomain=ts.dns_names(),
           zone_name=ts.dns_names())
    def test_start_responding(self, token, subdomain, zone_name):
        """
        Calling ``start_responding`` causes an appropriate TXT record to be
        created.
        """
        challenge = self._challenge_factory(token=token)
        response = challenge.response(RSA_KEY_512)
        responder = self._responder_factory(zone_name=zone_name)
        server_name = u'{}.{}'.format(subdomain, zone_name)
        zone = responder._driver.list_zones()[0]

        self.assertThat(zone.list_records(), HasLength(0))
        d = responder.start_responding(server_name, challenge, response)
        self._perform()
        self.assertThat(d, succeeded(Always()))
        self.assertThat(
            zone.list_records(),
            MatchesListwise([
                MatchesStructure(
                    name=EndsWith(u'.' + subdomain),
                    type=Equals('TXT'),
                    )]))

        # Starting twice before stopping doesn't break things
        d = responder.start_responding(server_name, challenge, response)
        self._perform()
        self.assertThat(d, succeeded(Always()))
        self.assertThat(zone.list_records(), HasLength(1))

        d = responder.stop_responding(server_name, challenge, response)
        self._perform()
        self.assertThat(d, succeeded(Always()))
        self.assertThat(zone.list_records(), HasLength(0))

    @example(token=EXAMPLE_TOKEN,
             subdomain=u'acme-testing',
             zone_name=u'example.com')
    @given(token=s.binary(min_size=32, max_size=32).map(b64encode),
           subdomain=ts.dns_names(),
           zone_name=ts.dns_names())
    def test_wrong_zone(self, token, subdomain, zone_name):
        """
        Trying to respond for a domain not in the configured zone results in a
        `.NotInZone` exception.
        """
        challenge = self._challenge_factory(token=token)
        response = challenge.response(RSA_KEY_512)
        responder = self._responder_factory(zone_name=zone_name)
        server_name = u'{}.{}.junk'.format(subdomain, zone_name)
        d = maybeDeferred(
            responder.start_responding, server_name, challenge, response)
        self._perform()
        self.assertThat(
            d,
            failed_with(MatchesAll(
                IsInstance(NotInZone),
                MatchesStructure(
                    server_name=EndsWith(u'.' + server_name),
                    zone_name=Equals(zone_name)))))

    @example(token=EXAMPLE_TOKEN,
             subdomain=u'acme-testing',
             zone_name=u'example.com')
    @given(token=s.binary(min_size=32, max_size=32).map(b64encode),
           subdomain=ts.dns_names(),
           zone_name=ts.dns_names())
    def test_missing_zone(self, token, subdomain, zone_name):
        """
        `.ZoneNotFound` is raised if the configured zone cannot be found at the
        configured provider.
        """
        challenge = self._challenge_factory(token=token)
        response = challenge.response(RSA_KEY_512)
        responder = self._responder_factory(zone_name=zone_name)
        server_name = u'{}.{}'.format(subdomain, zone_name)
        for zone in responder._driver.list_zones():
            zone.delete()
        d = maybeDeferred(
            responder.start_responding, server_name, challenge, response)
        self._perform()
        self.assertThat(
            d,
            failed_with(MatchesAll(
                IsInstance(ZoneNotFound),
                MatchesStructure(
                    zone_name=Equals(zone_name)))))

    @example(token=EXAMPLE_TOKEN,
             subdomain=u'acme-testing',
             extra=u'extra',
             zone_name1=u'example.com',
             suffix1=u'.',
             zone_name2=u'example.org',
             suffix2=u'')
    @given(token=s.binary(min_size=32, max_size=32).map(b64encode),
           subdomain=ts.dns_names(),
           extra=ts.dns_names(),
           zone_name1=ts.dns_names(),
           suffix1=s.sampled_from([u'', u'.']),
           zone_name2=ts.dns_names(),
           suffix2=s.sampled_from([u'', u'.']))
    def test_auto_zone(self, token, subdomain, extra, zone_name1, suffix1,
                       zone_name2, suffix2):
        """
        If the configured zone_name is ``None``, the zone will be guessed by
        finding the longest zone that is a suffix of the server name.
        """
        zone_name3 = extra + u'.' + zone_name1
        zone_name4 = extra + u'.' + zone_name2
        server_name = u'{}.{}.{}'.format(subdomain, extra, zone_name1)
        assume(
            len({server_name, zone_name1, zone_name2, zone_name3, zone_name4})
            == 5)
        challenge = self._challenge_factory(token=token)
        response = challenge.response(RSA_KEY_512)
        responder = self._responder_factory(zone_name=None)
        zone1 = responder._driver.create_zone(zone_name1 + suffix1)
        zone2 = responder._driver.create_zone(zone_name2 + suffix2)
        zone3 = responder._driver.create_zone(zone_name3 + suffix1)
        zone4 = responder._driver.create_zone(zone_name4 + suffix2)
        self.assertThat(zone1.list_records(), HasLength(0))
        self.assertThat(zone2.list_records(), HasLength(0))
        self.assertThat(zone3.list_records(), HasLength(0))
        self.assertThat(zone4.list_records(), HasLength(0))
        d = responder.start_responding(server_name, challenge, response)
        self._perform()
        self.assertThat(d, succeeded(Always()))
        self.assertThat(zone1.list_records(), HasLength(0))
        self.assertThat(zone2.list_records(), HasLength(0))
        self.assertThat(
            zone3.list_records(),
            MatchesListwise([
                MatchesStructure(
                    name=AfterPreprocessing(
                        methodcaller('rstrip', u'.'),
                        EndsWith(u'.' + subdomain)),
                    type=Equals('TXT'),
                    )]))
        self.assertThat(zone4.list_records(), HasLength(0))

    @example(token=EXAMPLE_TOKEN,
             subdomain=u'acme-testing',
             zone_name1=u'example.com',
             zone_name2=u'example.org')
    @given(token=s.binary(min_size=32, max_size=32).map(b64encode),
           subdomain=ts.dns_names(),
           zone_name1=ts.dns_names(),
           zone_name2=ts.dns_names())
    def test_auto_zone_missing(self, token, subdomain, zone_name1, zone_name2):
        """
        If the configured zone_name is ``None``, and no matching zone is found,
        ``NotInZone`` is raised.
        """
        server_name = u'{}.{}'.format(subdomain, zone_name1)
        assume(not server_name.endswith(zone_name2))
        challenge = self._challenge_factory(token=token)
        response = challenge.response(RSA_KEY_512)
        responder = self._responder_factory(zone_name=None)
        zone = responder._driver.create_zone(zone_name2)
        self.assertThat(zone.list_records(), HasLength(0))
        d = maybeDeferred(
            responder.start_responding, server_name, challenge, response)
        self._perform()
        self.assertThat(
            d,
            failed_with(MatchesAll(
                IsInstance(NotInZone),
                MatchesStructure(
                    server_name=EndsWith(u'.' + server_name),
                    zone_name=Is(None)))))


__all__ = [
    'HTTPResponderTests', 'TLSResponderTests', 'MergingProxyTests',
    'LibcloudResponderTests']
