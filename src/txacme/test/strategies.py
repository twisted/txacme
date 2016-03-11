"""
Miscellaneous strategies for Hypothesis testing.
"""
from hypothesis import strategies as s
from twisted.python.url import URL


def dns_labels():
    """
    Strategy for generating limited charset DNS labels.
    """
    # This is too limited, but whatever
    return (
        s.text(
            u'abcdefghijklmnopqrstuvwxyz0123456789-',
            min_size=1, max_size=25)
        .filter(
            lambda s: not any([
                s.startswith(u'-'),
                s.endswith(u'-'),
                s.isdigit(),
                s[2:4] == u'--',
            ])))


def dns_names():
    """
    Strategy for generating limited charset DNS names.
    """
    return (
        s.lists(dns_labels(), min_size=1, max_size=10)
        .map(u'.'.join))


def urls():
    """
    Strategy for generating ``twisted.python.url.URL``\s.
    """
    return s.builds(
        URL,
        scheme=s.just(u'https'),
        host=dns_names(),
        path=s.lists(s.text(max_size=64), min_size=1, max_size=10))


__all__ = ['dns_labels', 'dns_names', 'urls']
