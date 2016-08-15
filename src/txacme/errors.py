"""
Exception types for txacme.
"""
import attr


@attr.s
class NotInZone(ValueError):
    """
    The given domain name is not in the configured zone.
    """
    server_name = attr.ib()
    zone_name = attr.ib()


@attr.s
class ZoneNotFound(ValueError):
    """
    The configured zone was not found in the zones at the configured provider.
    """
    zone_name = attr.ib()


__all__ = ['NotInZone', 'ZoneNotFound']
