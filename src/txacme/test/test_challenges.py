"""
Tests for `txacme.challenges`.
"""
from acme import challenges
from acme.jose import b64encode
from hypothesis import strategies as s
from hypothesis import example, given
from testtools import TestCase
from testtools.matchers import Contains, Equals, Is, MatchesPredicate, Not

from txacme.challenges import _MergingMappingProxy, TLSSNI01Responder
from txacme.test.strategies import dns_names
from txacme.test.test_client import RSA_KEY_512, RSA_KEY_512_RAW


class ResponderTests(TestCase):
    """
    `.TLSSNI01Responder` is a responder for tls-sni-01 challenges that works
    with txsni.
    """
    @example(u'example.com')
    @given(dns_names())
    def test_stop_responding_already_stopped(self, server_name):
        """
        Calling ``stop_responding`` when we are not responding for a server
        name does nothing.
        """
        responder = TLSSNI01Responder()
        responder.stop_responding(server_name)

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
        responder.start_responding(server_name)
        self.assertThat(
            wrapped_host_map.get(server_name.encode('utf-8')).certificate,
            MatchesPredicate(response.verify_cert, '%r does not verify'))

        # Starting twice before stopping doesn't break things
        responder.start_responding(server_name)
        self.assertThat(
            wrapped_host_map.get(server_name.encode('utf-8')).certificate,
            MatchesPredicate(response.verify_cert, '%r does not verify'))

        responder.stop_responding(server_name)
        self.assertThat(wrapped_host_map, Not(Contains(server_name)))


class MergingProxyTests(TestCase):
    """
    `._MergingMappingProxy` merges two mappings together.
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


__all__ = ['ResponderTests']
