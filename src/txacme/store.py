"""
`txacme.interfaces.ICertificateStore` implementations.
"""
import attr
from pem import parse
from twisted.internet.defer import maybeDeferred, succeed
from twisted.python.compat import unicode
from zope.interface import implementer

from txacme.interfaces import ICertificateStore


@attr.s
@implementer(ICertificateStore)
class DirectoryStore(object):
    """
    A certificate store that keeps certificates in a directory on disk.
    """
    _path = attr.ib()

    def _get(self, server_name):
        """
        Synchronously retrieve an entry.
        """
        p = self._path.child(server_name.encode('utf-8'))
        if p.isfile():
            return parse(p.getContent().decode('utf-8'))
        else:
            raise KeyError(server_name)

    def get(self, server_name):
        return maybeDeferred(self._get, server_name)

    def store(self, server_name, pem_objects):
        p = self._path.child(server_name.encode('utf-8'))
        p.setContent(u''.join(map(unicode, pem_objects)).encode('utf-8'))
        return succeed(None)

    def as_dict(self):
        return succeed(
            {server_name: self._get(server_name)
             for server_name in self._path.listdir()})


__all__ = ['DirectoryStore']
