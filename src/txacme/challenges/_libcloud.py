import hashlib
import time
from threading import Thread

import attr
from josepy.b64 import b64encode
from libcloud.dns.providers import get_driver
from twisted._threads import pool
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure
from zope.interface import implementer

from txacme.errors import NotInZone, ZoneNotFound
from txacme.interfaces import IResponder
from txacme.util import const


def _daemon_thread(*a, **kw):
    """
    Create a `threading.Thread`, but always set ``daemon``.
    """
    thread = Thread(*a, **kw)
    thread.daemon = True
    return thread


def _defer_to_worker(deliver, worker, work, *args, **kwargs):
    """
    Run a task in a worker, delivering the result as a ``Deferred`` in the
    reactor thread.
    """
    deferred = Deferred()

    def wrapped_work():
        try:
            result = work(*args, **kwargs)
        except BaseException:
            f = Failure()
            deliver(lambda: deferred.errback(f))
        else:
            deliver(lambda: deferred.callback(result))
    worker.do(wrapped_work)
    return deferred


def _split_zone(server_name, zone_name):
    """
    Split the zone portion off from a DNS label.

    :param str server_name: The full DNS label.
    :param str zone_name: The zone name suffix.
    """
    server_name = server_name.rstrip(u'.')
    zone_name = zone_name.rstrip(u'.')
    if not (server_name == zone_name or
            server_name.endswith(u'.' + zone_name)):
        raise NotInZone(server_name=server_name, zone_name=zone_name)
    return server_name[:-len(zone_name)].rstrip(u'.')


def _get_existing(driver, zone_name, server_name, validation):
    """
    Get existing validation records.
    """
    if zone_name is None:
        zones = sorted(
            (z for z
             in driver.list_zones()
             if server_name.rstrip(u'.')
                .endswith(u'.' + z.domain.rstrip(u'.'))),
            key=lambda z: len(z.domain),
            reverse=True)
        if len(zones) == 0:
            raise NotInZone(server_name=server_name, zone_name=None)
    else:
        zones = [
            z for z
            in driver.list_zones()
            if z.domain == zone_name]
        if len(zones) == 0:
            raise ZoneNotFound(zone_name=zone_name)
    zone = zones[0]
    subdomain = _split_zone(server_name, zone.domain)
    existing = [
        record for record
        in zone.list_records()
        if record.name == subdomain and
        record.type == 'TXT' and
        record.data == validation]
    return zone, existing, subdomain


def _validation(response):
    """
    Get the validation value for a challenge response.
    """
    h = hashlib.sha256(response.key_authorization.encode("utf-8"))
    return b64encode(h.digest()).decode()


@attr.s(hash=False)
@implementer(IResponder)
class LibcloudDNSResponder(object):
    """
    A ``dns-01`` challenge responder using libcloud.

    ..  warning:: Some libcloud backends are broken with regard to TXT records
        at the time of writing; the Route 53 backend, for example. This makes
        them unusable with this responder.

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
    def create(cls, reactor, driver_name, username, password, zone_name=None,
               settle_delay=60.0):
        """
        Create a responder.

        :param reactor: The Twisted reactor to use for threading support.
        :param str driver_name: The name of the libcloud DNS driver to use.
        :param str username: The username to authenticate with (the meaning of
            this is driver-specific).
        :param str password: The username to authenticate with (the meaning of
            this is driver-specific).
        :param str zone_name: The zone name to respond in, or ``None`` to
            automatically detect zones.  Usually auto-detection should be fine,
            unless restricting responses to a single specific zone is desired.
        :param float settle_delay: The time, in seconds, to allow for the DNS
            provider to propagate record changes.
        """
        return cls(
            reactor=reactor,
            thread_pool=pool(const(1), threadFactory=_daemon_thread),
            driver=get_driver(driver_name)(username, password),
            zone_name=zone_name,
            settle_delay=settle_delay)

    def _defer(self, f):
        """
        Run a function in our private thread pool.
        """
        return _defer_to_worker(
            self._reactor.callFromThread, self._thread_pool, f)

    def start_responding(self, server_name, challenge, response):
        """
        Install a TXT challenge response record.
        """
        validation = _validation(response)
        full_name = challenge.validation_domain_name(server_name)
        _driver = self._driver

        def _go():
            zone, existing, subdomain = _get_existing(
                _driver, self.zone_name, full_name, validation)
            if len(existing) == 0:
                zone.create_record(name=subdomain, type='TXT', data=validation)
                time.sleep(self.settle_delay)
        return self._defer(_go)

    def stop_responding(self, server_name, challenge, response):
        """
        Remove a TXT challenge response record.
        """
        validation = _validation(response)
        full_name = challenge.validation_domain_name(server_name)
        _driver = self._driver

        def _go():
            zone, existing, subdomain = _get_existing(
                _driver, self.zone_name, full_name, validation)
            for record in existing:
                record.delete()
        return self._defer(_go)


__all__ = ['LibcloudDNSResponder']
