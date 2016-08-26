import hashlib
import time

import attr
from acme import jose
from libcloud.dns.providers import get_driver
from twisted.internet.threads import deferToThreadPool
from twisted.python.threadpool import ThreadPool
from zope.interface import implementer

from txacme.errors import NotInZone, ZoneNotFound
from txacme.interfaces import IResponder


def _split_zone(server_name, zone_name):
    """
    Split the zone portion off from a DNS label.

    :param str server_name: The full DNS label.
    :param str zone_name: The zone name suffix.
    """
    if not (server_name == zone_name or
            server_name.endswith(u'.' + zone_name)):
        raise NotInZone(server_name=server_name, zone_name=zone_name)
    return server_name[:-len(zone_name)].rstrip(u'.')


def _get_existing(driver, zone_name, subdomain, validation):
    """
    Get existing validation records.
    """
    zones = [
        z for z
        in driver.list_zones()
        if z.domain == zone_name]
    if len(zones) == 0:
        raise ZoneNotFound(zone_name=zone_name)
    else:
        zone = zones[0]
    existing = [
        record for record
        in zone.list_records()
        if record.name == subdomain and
        record.type == 'TXT' and
        record.data == validation]
    return zone, existing


def _validation(response):
    """
    Get the validation value for a challenge response.
    """
    h = hashlib.sha256(response.key_authorization.encode("utf-8"))
    return jose.b64encode(h.digest()).decode()


@attr.s(hash=False)
@implementer(IResponder)
class LibcloudDNSResponder(object):
    """
    A ``dns-01`` challenge responder using libcloud.

    ..  note:: This implementation relies on invoking libcloud in a thread, so
        may not be entirely production quality.
    """
    challenge_type = u'dns-01'

    _reactor = attr.ib()
    _thread_pool = attr.ib()
    _driver = attr.ib()
    zone_name = attr.ib()
    settle_delay = attr.ib()

    @classmethod
    def create(cls, reactor, driver_name, username, password, zone_name,
               settle_delay=60.0):
        """
        Create a responder.

        :param reactor: The Twisted reactor to use for threading support.
        :param str driver_name: The name of the libcloud DNS driver to use.
        :param str username: The username to authenticate with (the meaning of
            this is driver-specific).
        :param str password: The username to authenticate with (the meaning of
            this is driver-specific).
        :param str zone_name: The zone name to respond in.
        :param float settle_delay: The time, in seconds, to allow for the DNS
            provider to propagate record changes.
        """
        return cls(
            reactor=reactor,
            thread_pool=ThreadPool(minthreads=1, maxthreads=1),
            driver=get_driver(driver_name)(username, password),
            zone_name=zone_name,
            settle_delay=settle_delay)

    def _defer(self, f):
        """
        Run a function in our private thread pool.
        """
        return deferToThreadPool(self._reactor, self._thread_pool, f)

    def _subdomain(self, server_name, challenge):
        """
        Get the validation domain name for a challenge.
        """
        return _split_zone(
            challenge.validation_domain_name(server_name),
            self.zone_name)

    def _ensure_thread_pool_started(self):
        """
        Start the thread pool if it isn't already started.
        """
        if not self._thread_pool.started:
            self._thread_pool.start()
            self._reactor.addSystemEventTrigger(
                'after', 'shutdown', self._thread_pool.stop)

    def start_responding(self, server_name, challenge, response):
        """
        Install a TXT challenge response record.
        """
        self._ensure_thread_pool_started()
        validation = _validation(response)
        subdomain = self._subdomain(server_name, challenge)
        _driver = self._driver

        def _go():
            zone, existing = _get_existing(
                _driver, self.zone_name, subdomain, validation)
            if len(existing) == 0:
                zone.create_record(name=subdomain, type='TXT', data=validation)
                time.sleep(self.settle_delay)
        return self._defer(_go)

    def stop_responding(self, server_name, challenge, response):
        """
        Remove a TXT challenge response record.
        """
        validation = _validation(response)
        subdomain = self._subdomain(server_name, challenge)
        _driver = self._driver

        def _go():
            zone, existing = _get_existing(
                _driver, self.zone_name, subdomain, validation)
            for record in existing:
                record.delete()
        return self._defer(_go)


__all__ = ['LibcloudDNSResponder']
