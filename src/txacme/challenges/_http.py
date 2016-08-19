"""
``http-01`` challenge implementation.
"""
from twisted.web.http import OK
from twisted.web.resource import Resource

from zope.interface import implementer

from txacme.interfaces import IResponder


@implementer(IResponder)
class HTTP01Responder(object):
    """
    An ``http-01`` challenge responder for txsni.
    """
    challenge_type = u'http-01'

    def __init__(self):
        self.resource = Resource()

    def start_responding(self, server_name, challenge, response):
        """
        Add the child resource.
        """
        self.resource.putChild(challenge.path, _HTTP01Resource(response))

    def stop_responding(self, server_name, challenge, response):
        """
        Remove the child resource.
        """
        if self.resource.getStaticEntity(challenge.path) is not None:
            self.resource.delEntity(challenge.path)


class _HTTP01Resource(Resource):
    isLeaf = True

    def __init__(self, response):
        self.response = response

    def render_GET(self, request):
        request.setResponseCode(OK)
        return self.response.key_authorization.encode()


__all__ = ['HTTP01Responder']
