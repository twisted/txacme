"""
Miscellaneous strategies for Hypothesis testing.
"""
from hypothesis import strategies as s
from twisted.python.url import URL


def dns_label():
    """
    Strategy for generating limited charset DNS labels.
    """
    # This is too limited, but whatever
    return s.text(
        u'abcdefghijklmnopqrstuvwxyz0123456789_-',
        min_size=1, max_size=25)


def dns_name():
    """
    Strategy for generating limited charset DNS names.
    """
    return (
        s.lists(dns_label(), min_size=1, max_size=10)
        .map(u'.'.join))


def urls():
    """
    Strategy for generating ``twisted.python.url.URL``\s.
    """
    return s.builds(
        URL,
        scheme=s.just(u'https'),
        host=dns_name(),
        path=s.lists(s.text(max_size=64), min_size=1, max_size=10))


__all__ = ['dns_label', 'dns_name', 'urls']
