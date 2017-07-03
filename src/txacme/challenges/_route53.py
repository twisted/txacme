import hashlib

import attr

from acme import jose
from txaws import AWSServiceRegion
from txaws.route53.model import (
    RRSetKey, RRSet, Name, TXT, create_rrset, upsert_rrset, delete_rrset
)
from zope.interface import implementer

from txacme.errors import ZoneNotFound
from txacme.interfaces import IResponder


def _validation(response):
    """
    Get the validation value for a challenge response.
    """
    # TODO: This is just duplicated directly from _libcloud.py. Should we hoist
    # this out to a common utility module?
    h = hashlib.sha256(response.key_authorization.encode("utf-8"))
    return jose.b64encode(h.digest()).decode()


def _add_txt_record(args, full_name, validation, client):
    """
    Adds a TXT record for full_name to the appropriate resource record set in
    Route 53, with the value set to validation.

    This is implemented by doing an UPSERT of the RR set if it already exists:
    otherwise, we'll need to create a new one.
    """
    zone_id, rr_sets = args

    # Right off the bat we can create the record we're going to insert. A
    # quirk of Route53 is that these need to be surrounded by dquotes.
    resource_record = TXT(texts=(u'"%s"' % validation,))

    # We're interested only in the TXT RR Set. If it exists, we're going to
    # update ('upsert') it. If it does not exist, we're going to create it.
    key = RRSetKey(label=Name(full_name), type=u'TXT')

    try:
        rr_set = rr_sets[key]
    except KeyError:
        rr_set = RRSet(
            name=full_name, type=u'TXT', ttl=300, records=set(resource_record))

    rr_set.records.add(resource_record)
    rr_set_update = upsert_rrset(rr_set)

    return client.change_resource_record_sets(zone_id, rr_set_update)


def _delete_txt_record(args, full_name, validation, client):
    """
    Deletes a TXT record for full_name from the appropriate resource record set
    in Route 53, with the value set to validation.

    This is implemented by doing an UPSERT of any RR set with multiple values,
    or by deleting a complete RR set if there are no other values.
    """
    zone_id, rr_sets = args

    # Right off the bat we can create the record we're going to remove. A
    # quirk of Route53 is that these need to be surrounded by dquotes.
    resource_record = TXT(texts=(u'"%s"' % validation,))

    # We're interested only in the TXT RR Set. We expect this to exist: if it
    # doesn't, we'll just quietly exit as we have no work to do.
    key = RRSetKey(label=Name(full_name), type=u'TXT')

    try:
        rr_set = rr_sets[key]
    except KeyError:
        return

    # Now we want to check that the record is in the RR set. If it isn't, we
    # again quietly exit.
    if resource_record not in rr_set:
        return

    if len(rr_set) == 1:
        rr_set_update = delete_rrset(rr_set)
    else:
        rr_set.records.remove(resource_record)
        rr_set_update = upsert_rrset(rr_set)

    return client.change_resource_record_sets(zone_id, rr_set_update)


def _get_rr_sets_for_zone(zone_id, client):
    """
    Given a single zone ID, returns a tuple of that zone ID and the RRSets for
    that zone.
    """
    d = client.list_resource_record_sets(zone_id)
    d.addCallback(lambda rr_sets: (zone_id, rr_sets))
    return d


def _get_zone_id(zones, server_name):
    """
    Given the collection of zones in Route53, returns the zone ID of the one
    that is appropriate for use with this challenge. If no zones are, then this
    raises a ZoneNotFound error.
    """
    for zone in zones:
        if server_name.endswith(zone.name):
            return zone.identifier

    raise ZoneNotFound(u"Unable to find zone for %s" % server_name)


@attr.s(hash=False)
@implementer(IResponder)
class Route53DNSResponder(object):
    """
    A ``dns-01`` challenge responder using txaws and Route53.
    """
    challenge_type = u'dns-01'

    _client = attr.ib()
    access_key = attr.ib()
    secret_key = attr.ib()
    settle_delay = attr.ib()

    @classmethod
    def create(cls, access_key, secret_key, settle_delay=60.0):
        """
        Create a responder.

        :param str access_key: The AWS IAM access key to use.
        :param str secret_key: The AWS IAM secret key to use.
        :param float settle_delay: The time, in seconds, to allow for the DNS
            provider to propagate record changes.
        """
        region = AWSServiceRegion(access_key=access_key, secret_key=secret_key)
        return cls(
            client=region.get_route53_client(),
            settle_delay=settle_delay)

    def start_responding(self, server_name, challenge, response):
        """
        Install a TXT challenge response record.
        """
        validation = _validation(response)
        full_name = challenge.validation_domain_name(server_name)

        d = self._client.list_hosted_zones()
        d.addCallback(_get_zone_id, server_name=full_name)
        d.addCallback(_get_rr_sets_for_zone, client=self._client)
        d.addCallback(
            _add_txt_record,
            full_name=full_name,
            validation=validation,
            client=self._client
        )

        return d

    def stop_responding(self, server_name, challenge, response):
        """
        Remove a TXT challenge response record.
        """
        validation = _validation(response)
        full_name = challenge.validation_domain_name(server_name)

        d = self._client.list_hosted_zones()
        d.addCallback(_get_zone_id, server_name=full_name)
        d.addCallback(_get_rr_sets_for_zone, client=self._client)
        d.addCallback(
            _delete_txt_record,
            full_name=full_name,
            validation=validation,
            client=self._client
        )


__all__ = ['Route53DNSResponder']
