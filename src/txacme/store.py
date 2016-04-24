"""
``txacme.interfaces.ICertificateStore`` implementations.
"""
import os

import attr
from pem import parse
from twisted.internet.defer import maybeDeferred, succeed
from twisted.internet.utils import getProcessValue
from zope.interface import implementer

from txacme.interfaces import ICertificateStore


@attr.s
@implementer(ICertificateStore)
class DirectoryStore(object):
    """
    A certificate store that keeps certificates in a directory on disk.
    """
    path = attr.ib()
    onstore_scripts = attr.ib(default=False)
    reactor = attr.ib(default=None)

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
        if not self.onstore_scripts:
            return succeed(None)
        onstore_script = self.path.child(server_name + u'.onstore')
        if not onstore_script.exists():
            return succeed(None)
        d = getProcessValue(
            onstore_script.path.encode(), args=[server_name.encode()],
            env=os.environ, path=self.path.path.encode(), reactor=self.reactor)
        d.addCallback(lambda ign: None)
        return d

    def as_dict(self):
        return succeed(
            {fn[:-4]: self._get(fn[:-4])
             for fn in self.path.listdir()
             if fn.endswith(u'.pem')})


__all__ = ['DirectoryStore']
