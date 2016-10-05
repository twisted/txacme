"""
Test doubles.
"""
from twisted.internet.interfaces import IReactorFromThreads
from zope.interface import implementer


@implementer(IReactorFromThreads)
class SynchronousReactorThreads(object):
    """
    An implementation of ``IReactorFromThreads`` that calls things
    synchronously in the same thread.
    """
    def callFromThread(self, f, *args, **kwargs):  # noqa
        f(*args, **kwargs)
