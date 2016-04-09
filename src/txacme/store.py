"""
``txacme.interfaces.ICertificateStore`` implementations.
"""
import attr
from pem import parse
from twisted.internet.defer import maybeDeferred, succeed
from zope.interface import implementer

from txacme.interfaces import ICertificateStore


@attr.s
@implementer(ICertificateStore)
class DirectoryStore(object):
    """
    A certificate store that keeps certificates in a directory on disk.
    """
    path = attr.ib()

    def _get(self, server_name):
        """
        Synchronously retrieve an entry.
        """
        p = self.path.child(server_name + u'.pem')
        if p.isfile():
            return parse(p.getContent())
        else:
            raise KeyError(server_name)

    def get(self, server_name):
        return maybeDeferred(self._get, server_name)

    def store(self, server_name, pem_objects):
        p = self.path.child(server_name + u'.pem')
        p.setContent(b''.join(o.as_bytes() for o in pem_objects))
        return succeed(None)

    def as_dict(self):
        return succeed(
            {fn[:-4]: self._get(fn[:-4])
             for fn in self.path.listdir()
             if fn.endswith(u'.pem')})


__all__ = ['DirectoryStore']
