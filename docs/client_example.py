"""
This wants to be a complex example demonstrating all the txacme client
capabilities.

Each time it starts, if one is not defined, it will generate a new
private key and register a new account.

It can also start a pebble ACME server and run tests against it... or you can
use your one ACME server.

It uses `.tox` as the build directory.

https://www.rfc-editor.org/rfc/rfc8555.html

Example usage:

# Copy pebble binary to the following path: /tmp/pebble_linux-amd64
# Update /etc/hosts and add test.local and www.test.local as names for
  127.0.0.1

# Make sure all python txacme dependencies are installed.
$ python docs/client_example.py test.local

# After it starts and all is fine you could connect to https://test.local:5003
# and see the new certificate.
"""
from __future__ import unicode_literals, print_function
from threading import Thread
import os
import socket
import sys
import time

from acme.errors import ClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from eliot import add_destinations
from eliot.parse import Parser
from eliottree import render_tasks

from josepy.jwa import RS256
from josepy.jwk import JWKRSA
from twisted.internet import reactor, defer, ssl, task
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.web import http
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.python.url import URL
from zope.interface import implementer

from txacme.client import (
    answer_challenge,
    Client,
    get_certificate,
    )
from txacme.interfaces import IResponder
from txacme.util import generate_private_key

# WARNING. THIS DISABLES SSL validation in twisted client.
# Is here to make the example easier to read.
import twisted.internet._sslverify as v
v.platformTrust = lambda: None

# Update it to the path of your pebble executable.
# Download it from https://github.com/letsencrypt/pebble/releases
# This script can automatically start a pebble instance, but in that case
# already registered accounts are not persisted.
PEBBLE = "/tmp/pebble_linux-amd64 --config docs/pebble-config.json"

# Copy inside an exiting private key and check that account is reused.
# Or leave it empty to have the key automatically generated.
ACCOUNT_KEY_PEM = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAqJc17HS3PftQZzharEnOpdW1eCxJvqHuiciolx6qtu1X3YIa
PlG/e36oL4ENqMekJ/caEISMr0y1OUi6NVvjWisZpJXCg1RHwrSAw8/pYaE8IIrs
ffPd6Y8R/sTSDGVCKFkx5R4e4VRmimfrZlnNPFeAFXvfgKM3ZmavN1KUoaghQktr
/NpmKCzSaBViMv1LpqsXh6xCyRRbT3hbRcxDNK+m5rgq7Xg6XSkV4eKYtZYrGHyU
lydKEmxmrDawk71YRgSsAWGDLro/tsCUMIKPQoz+cQwwaWdbABAHStUPwARCiuHG
wIa2slAckbPOgwzCLL/mt+sBXQnATtIrukci/QIDAQABAoIBAQCI5pExO+349PTr
fMWUljKqU4oS1dPka1ZqqHjOjmaOONla1GU/Kd7WB5nHSYKwBb31fiC6PQiI6T9Y
Dwi2f7F07P7buYjEYFINd8oAN/sJ/oX23xj/hmIzYKx6N5Vh33ADl7p+lSD6VTEX
Px/WcyHH2D34NCjgKqm4C7ZItFRhl/ZAbSs1GNuN3TvlBhUfR/nr3pYxhZ/7cY1k
LozhARbT74Xsa8layl5cs2r2jXQRfBRXF8D1dSxp0zhiI3V1ywmHsTWYtEjofTgN
iJI5e+e5csl/ZlbQVJCx6oIxDumymZ+cwEQN4NB95g2mX2qfmmBlB2uuFaEldCx7
hnKvBc35AoGBANQqaWX1GwgOti279ezfyIELTgT2CBsWqxOAtC+p9Jb5e9Pkvuo0
wreVgf+lcgCQNr972MmNWYtQoFgP8VDfUT6+RdVClmoglAjbUbSlPSXiJ8AGOOqD
XxwB0RhZTdhXUsu9L+QDpDF4+kpPQNEZTUHpL7TLMhvM80c2cgTnmSQPAoGBAMts
FkQrdatIoWY2fUoQNhWe/PhSpSOGpgDE2PcmDhuseeI1dzCzOfvaQqgqI5iVgxrS
AYdDdeXwELhB1hAk8d7jUA8HBG4b7PfHkCmQ9NdYb8YoBOpVilL0OYuSf4kQJYdI
Ody+Tfa6DxnYjrZW24uyQGMUa8ex1MrG/R00Z8wzAoGBAKh4pQjZAIX9aJwYTMez
SzttBp7Z3sXj0iTCZlIS2q2nnbQ8R30iOBwfFAM0FLptyYtzhElHfHsroqdKwYw+
R/1SiZE2Nso+5E3EGbUgINYcJwRL7JYLi1Jp/ucewrmvXYd6yrR8T70ZG2Y2WHmx
Za+YwtEFKNz6eZNqoE9UuD3xAoGBAJwE3ZsRXiGuBiRYHIYmouS4WTu4X3I8/qtO
Tz5X0LBG/ACUk0Ml444YG9HQ6BZKbhCvC38MLavbEWfRDva4703NOIUeE7bD8l8k
j5xh0ngsGyZ3YTW9v+bZ7BzxkqG0YaQ9sCtvRmq6z4Q6RVLykVa2s42KhxPVf+i6
8D1rCUVjAoGAc8kja8SUE5uxQZHfBlD7MXS7wNqRsginnI0+gZrmOQLAM2fUTcP9
aLhPkFOG4jTZGg3TwV5XNk+f/nh4Ps+GKYng6MneKzN9+mcZ30T54e+1gd+chz9X
yLwHm1esy/txlB27jQ26/8LabbLRQkFCiXxdJ9W1+TEWoq0YT25Awek=
-----END RSA PRIVATE KEY-----
""".strip()
# Uncomment this to have a new account key generated at each run.
# ACCOUNT_KEY_PEM = ''


class EliotTreeDestination:
    def __init__(self, out=sys.stdout.write, **opts):
        self.out = out
        self.opts = opts
        self._parser = Parser()

    def __call__(self, message):
        tasks, self._parser = self._parser.add(message)

        if tasks:
            render_tasks(self.out, tasks, **self.opts)


def _get_account_key():
    """
    Return the private key to be used for ACME interaction.
    """
    if ACCOUNT_KEY_PEM:
        return serialization.load_pem_private_key(
            ACCOUNT_KEY_PEM.encode('ascii'),
            password=None,
            backend=default_backend(),
            )
    # We don't have a key...so generate one.
    key = generate_private_key('rsa')
    account_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
        )
    print('New account key generated:\n%s' % (account_key))
    return key


class StaticTextResource(Resource, object):
    """
    A resource returning a static page... is a placeholder page.
    """
    def __init__(self, content='', content_type='text/plain', code=http.OK):
        self._content = content.encode('utf-8')
        self._content_type = content_type.encode('ascii')
        self._code = code
        super(StaticTextResource, self).__init__()

    def getChild(self, name, request):
        """
        Called when no other resources are attached.
        """
        return self

    def render(self, request):
        """
        Return the same content.
        """
        request.setHeader(b'Content-Type', self._content_type)
        request.setResponseCode(self._code)
        return self._content


@implementer(IResponder)
class HTTP01Responder(StaticTextResource):
    """
    Web resource for ``http-01`` challenge responder.

    Beside the challenge pages, it displays empty pages.
    """
    challenge_type = u'http-01'

    def __init__(self):
        super(HTTP01Responder, self).__init__('')
        # Add a static response to help with connection troubleshooting.
        self.putChild(b'test.txt', StaticTextResource('Let\'s Encrypt Ready'))

    def start_responding(self, ignored, challenge, response):
        """
        Prepare for the ACME server to validate the challenge.
        """
        self.putChild(
            challenge.encode('token').encode('utf-8'),
            StaticTextResource(response.key_authorization),
            )

    def stop_responding(self, ignored, challenge, ignored1):
        """
        Remove the child resource once the process is done.
        """
        encoded_token = challenge.encode('token').encode('utf-8')
        if self.getStaticEntity(encoded_token) is not None:
            self.delEntity(encoded_token)


def start_http01_server(port=5002):
    """
    Start an HTTP server which handles HTTP-01 changeless.
    """
    responder = HTTP01Responder()
    root = StaticTextResource(
        'Just a test server. Main thing in: '
        '.well-known/acme-challenge/test.txt'
        )
    well_known = StaticTextResource('')
    root.putChild('.well-known', well_known)
    well_known.putChild('acme-challenge', responder)

    endpoint = TCP4ServerEndpoint(
        reactor=reactor,
        interface='0.0.0.0',
        port=port,
        )
    deferred = endpoint.listen(Site(root))
    deferred.addCallback(lambda result: (result, responder))
    return deferred


def start_https_demo_server(key, certificate_chain, port=5003):
    """
    Start a demo HTTPS server which uses the generate certificate.
    """
    wait = 60
    root = StaticTextResource('Hello ACME!')
    certificate = ssl.PrivateCertificate.loadPEM(key + certificate_chain)
    reactor.listenSSL(port, Site(root), certificate.options())
    print('New HTTPS server listening on port %s for the next %s seconds' % (
        port, wait))
    return task.deferLater(reactor, wait, lambda: None)


def start_acme_server():
    """
    Start a local pebble ACME v2 server.
    """
    # Pebble testing files from
    # https://github.com/letsencrypt/pebble/tree/master/test/certs/localhost
    key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAmxTFtw113RK70H9pQmdKs9AxhFmnQ6BdDtp3jOZlWlUO0Blt
MXOUML5905etgtCbcC6RdKRtgSAiDfgx3VWiFMJH++4gUtnaB9SN8GhNSPBpFfSa
2JhWPo9HQNUsAZqlGTV4SzcGRqtWvdZxUiOfQ2TcvyXIqsaD19ivvqI1NhT6bl3t
redTZlzLLM6Wvkw6hfyHrJAPQP8LOlCIeDM4YIce6Gstv6qo9iCD4wJiY4u95HVL
7RK8t8JpZAb7VR+dPhbHEvVpjwuYd5Q05OZ280gFyrhbrKLbqst104GOQT4kQMJG
WxGONyTX6np0Dx6O5jU7dvYvjVVawbJwGuaL6wIDAQABAoIBAGW9W/S6lO+DIcoo
PHL+9sg+tq2gb5ZzN3nOI45BfI6lrMEjXTqLG9ZasovFP2TJ3J/dPTnrwZdr8Et/
357YViwORVFnKLeSCnMGpFPq6YEHj7mCrq+YSURjlRhYgbVPsi52oMOfhrOIJrEG
ZXPAwPRi0Ftqu1omQEqz8qA7JHOkjB2p0i2Xc/uOSJccCmUDMlksRYz8zFe8wHuD
XvUL2k23n2pBZ6wiez6Xjr0wUQ4ESI02x7PmYgA3aqF2Q6ECDwHhjVeQmAuypMF6
IaTjIJkWdZCW96pPaK1t+5nTNZ+Mg7tpJ/PRE4BkJvqcfHEOOl6wAE8gSk5uVApY
ZRKGmGkCgYEAzF9iRXYo7A/UphL11bR0gqxB6qnQl54iLhqS/E6CVNcmwJ2d9pF8
5HTfSo1/lOXT3hGV8gizN2S5RmWBrc9HBZ+dNrVo7FYeeBiHu+opbX1X/C1HC0m1
wJNsyoXeqD1OFc1WbDpHz5iv4IOXzYdOdKiYEcTv5JkqE7jomqBLQk8CgYEAwkG/
rnwr4ThUo/DG5oH+l0LVnHkrJY+BUSI33g3eQ3eM0MSbfJXGT7snh5puJW0oXP7Z
Gw88nK3Vnz2nTPesiwtO2OkUVgrIgWryIvKHaqrYnapZHuM+io30jbZOVaVTMR9c
X/7/d5/evwXuP7p2DIdZKQKKFgROm1XnhNqVgaUCgYBD/ogHbCR5RVsOVciMbRlG
UGEt3YmUp/vfMuAsKUKbT2mJM+dWHVlb+LZBa4pC06QFgfxNJi/aAhzSGvtmBEww
xsXbaceauZwxgJfIIUPfNZCMSdQVIVTi2Smcx6UofBz6i/Jw14MEwlvhamaa7qVf
kqflYYwelga1wRNCPopLaQKBgQCWsZqZKQqBNMm0Q9yIhN+TR+2d7QFjqeePoRPl
1qxNejhq25ojE607vNv1ff9kWUGuoqSZMUC76r6FQba/JoNbefI4otd7x/GzM9uS
8MHMJazU4okwROkHYwgLxxkNp6rZuJJYheB4VDTfyyH/ng5lubmY7rdgTQcNyZ5I
majRYQKBgAMKJ3RlII0qvAfNFZr4Y2bNIq+60Z+Qu2W5xokIHCFNly3W1XDDKGFe
CCPHSvQljinke3P9gPt2HVdXxcnku9VkTti+JygxuLkVg7E0/SWwrWfGsaMJs+84
fK+mTZay2d3v24r9WKEKwLykngYPyZw5+BdWU0E+xx5lGUd3U4gG
-----END RSA PRIVATE KEY-----
"""
    cert = """
-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIIbEfayDFsBtwwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgMjRlMmRiMCAXDTE3MTIwNjE5NDIxMFoYDzIxMDcx
MjA2MTk0MjEwWjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCbFMW3DXXdErvQf2lCZ0qz0DGEWadDoF0O2neM5mVa
VQ7QGW0xc5Qwvn3Tl62C0JtwLpF0pG2BICIN+DHdVaIUwkf77iBS2doH1I3waE1I
8GkV9JrYmFY+j0dA1SwBmqUZNXhLNwZGq1a91nFSI59DZNy/JciqxoPX2K++ojU2
FPpuXe2t51NmXMsszpa+TDqF/IeskA9A/ws6UIh4Mzhghx7oay2/qqj2IIPjAmJj
i73kdUvtEry3wmlkBvtVH50+FscS9WmPC5h3lDTk5nbzSAXKuFusotuqy3XTgY5B
PiRAwkZbEY43JNfqenQPHo7mNTt29i+NVVrBsnAa5ovrAgMBAAGjYzBhMA4GA1Ud
DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0T
AQH/BAIwADAiBgNVHREEGzAZgglsb2NhbGhvc3SCBnBlYmJsZYcEfwAAATANBgkq
hkiG9w0BAQsFAAOCAQEAYIkXff8H28KS0KyLHtbbSOGU4sujHHVwiVXSATACsNAE
D0Qa8hdtTQ6AUqA6/n8/u1tk0O4rPE/cTpsM3IJFX9S3rZMRsguBP7BSr1Lq/XAB
7JP/CNHt+Z9aKCKcg11wIX9/B9F7pyKM3TdKgOpqXGV6TMuLjg5PlYWI/07lVGFW
/mSJDRs8bSCFmbRtEqc4lpwlrpz+kTTnX6G7JDLfLWYw/xXVqwFfdengcDTHCc8K
wtgGq/Gu6vcoBxIO3jaca+OIkMfxxXmGrcNdseuUCa3RMZ8Qy03DqGu6Y6XQyK4B
W8zIG6H9SVKkAznM2yfYhW8v2ktcaZ95/OBHY97ZIw==
-----END CERTIFICATE-----
"""
    try:
        os.makedirs('.tox/pebble/certs/localhost')
    except OSError:
        pass

    with open('.tox/pebble/certs/localhost/key.pem', 'w') as stream:
        stream.write(key)
    with open('.tox/pebble/certs/localhost/cert.pem', 'w') as stream:
        stream.write(cert)

    thread = Thread(target=lambda: os.system(PEBBLE))
    thread.start()

    # Wait for pebble to start.
    wait = 0.5
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for _ in range(5):
        try:
            s.connect(('127.0.0.1', 14000))
        except Exception as error:
            time.sleep(wait)
            wait += wait
        else:
            s.close()
            return thread

    raise error


@defer.inlineCallbacks
def start_responders():
    port, http01_responder = yield start_http01_server()
    defer.returnValue([http01_responder])


@defer.inlineCallbacks
def get_things_done():
    """
    Here is where the client part is setup and action is done.
    """
    responders = yield start_responders()

    # We first validate the directory.
    account_key = _get_account_key()
    try:
        client = yield Client.from_url(
            reactor,
            URL.fromText(acme_url.decode('utf-8')),
            key=JWKRSA(key=account_key),
            alg=RS256,
            )
    except Exception as error:
        print('\n\nFailed to connect to ACME directory. %s' % (error,))
        yield reactor.stop()
        defer.returnValue(None)

    # Then we register a new account or update an existing account.
    # First register a new account with a contact set, then using the same
    # key call register with a different contact and see that it was updated.
    response = yield client.start(
        email='txacme-test1@twstedmatrix.org,txacme-test2@twstedmatrix.org')

    print('Account URI: %s' % (response.uri,))
    print('Account contact: %s' % (response.body.contact,))

    # We request a single certificate for a list of domains and get an "order"
    cert_key = generate_private_key('rsa')
    orderr = yield client.submit_order(cert_key, requested_domains)

    # Each order had a list of "authorizations" for which the challenge needs
    # to be validated.
    for authorization in orderr.authorizations:
        try:
            # Make sure all ACME server requests are sequential.
            # For now, answering to the challenges in parallel will not work.
            yield answer_challenge(
                authorization, client, responders, clock=reactor)
        except Exception as error:
            print('\n\nFailed to validate a challenge. %s' % (error,))
            yield reactor.stop()
            defer.returnValue(None)

    certificate = yield get_certificate(orderr, client, clock=reactor)

    print('Got a new cert:\n')
    print(certificate.body)

    cert_key_pem = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
        )

    # Cleanup the client and disconnect any persistent connection to the
    # ACME server.
    yield client.stop()

    # The new certificate is available and we can start a demo HTTPS server
    # using it.
    yield start_https_demo_server(cert_key_pem, certificate.body)
    print('txacme demo done.')


def stop():
    """
    Stop and cleanup the whole shebang.
    """
    if pebble_thread:
        pebble_thread.join(5)
    print('Press Ctrl+C to end the process.')


def eb_client_failure(failure):
    """
    Called when any of the client operation fails.
    """
    failure.trap(ClientError)
    print (failure.value)


def eb_general_failure(failure):
    """
    Called when any operation fails.
    """
    print(failure)


def show_usage():
    """
    Show the help on how to use the command.
    """
    print('Usage: %s REQUSTED_DOMAINS [API_ENDPOINT]\n' % (sys.argv[0],))
    print('REQUSTED_DOMAINS -> comma separated list of domains')
    print('It will start a local PEBBLE if API_ENDPOINT is not provided.')

    print('\nACME v2 endpoints:')
    print('[Production] https://acme-v02.api.letsencrypt.org/directory')
    print('[Staging] https://acme-staging-v02.api.letsencrypt.org/directory')
    sys.exit(1)


for arg in sys.argv:
    if arg.lower().strip() in ['-h', '--help']:
        show_usage()


if len(sys.argv) < 2:
    show_usage()


pebble_thread = None
try:
    acme_url = sys.argv[2]
except IndexError:
    pebble_thread = start_acme_server()
    acme_url = 'https://localhost:14000/dir'


requested_domains = [d.strip().decode('utf-8') for d in sys.argv[1].split(',')]

print('\n\n')
print('-' * 70)
print('Using ACME at %s' % (acme_url,))
print('Requesting a single certificate for %s' % (requested_domains,))
print(
    'HTTP-01 responser at '
    'http://localhost:5002/.well-known/acme-challenge/test.txt'
    )
print('-' * 70)
print('\n\n')

add_destinations(EliotTreeDestination(
    colorize=True, colorize_tree=True, human_readable=True))


def main(reactor):
    d = get_things_done()
    d.addErrback(eb_client_failure)
    d.addErrback(eb_general_failure)
    d.addBoth(lambda _: stop())
    return d


if __name__ == '__main__':
    task.react(main)
