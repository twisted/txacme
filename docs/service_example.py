"""
This wants to be a simple example demonstrating all the txacme service
capabilities.

Each time it starts, if one is not defined, it will generate a new
private key and register a new account.

It uses `.tox` as the build directory.

You will need to have a TXACME v2 server available and point the script to
use that server.

Example usage:

# Start pebble in a separate process.
$ /tmp/pebble_linux-amd64 --config docs/pebble-config.json

# Update /etc/hosts to have test.local and www.test.local
# Make sure all python txacme dependencies are installed.
$ python docs/service_example.py \
    test.local,www.test.local \
    https://127.0.0.1:14000/dir

"""
from __future__ import unicode_literals, print_function
from subprocess import Popen, PIPE
from threading import Thread
import os
import socket
import sys
import time

import pem

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from eliot import add_destinations, to_file
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

from txacme.client import Client
from txacme.service import AcmeIssuingService
from txacme.interfaces import ICertificateStore, IResponder
from txacme.util import generate_private_key

# WARNING. THIS DISABLES SSL validation in twisted client.
# Is here to make the example easier to read.
import twisted.internet._sslverify as v
v.platformTrust = lambda : None

HTTP_O1_PORT = 5002

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

    def start_responding(self, challenge, response):
        """
        Prepare for the ACME server to validate the challenge.
        """
        self.putChild(
            challenge.encode('token').encode('utf-8'),
            StaticTextResource(response.key_authorization),
            )

    def stop_responding(self, challenge):
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


@defer.inlineCallbacks
def start_responders():
    port, http01_responder = yield start_http01_server(port=HTTP_O1_PORT)
    defer.returnValue([http01_responder])


@implementer(ICertificateStore)
class MemoryStore(object):
    """
    A certificate store that keeps certificates in memory only and shows
    when a new certificate was added.
    """
    def __init__(self, certs=None):
        if certs is None:
            self._store = {}
        else:
            self._store = dict(certs)

        # This is a certificate which is expired
        self._store['localhost'] = pem.parse("""
-----BEGIN CERTIFICATE-----
MIICPzCCAaigAwIBAgIBBzANBgkqhkiG9w0BAQUFADBGMQswCQYDVQQGEwJHQjEP
MA0GA1UEChMGQ2hldmFoMRIwEAYDVQQLEwlDaGV2YWggQ0ExEjAQBgNVBAMTCUNo
ZXZhaCBDQTAeFw0xNjAyMTAyMzE5MDBaFw0xNjA0MTEyMzE5MDBaMDIxCzAJBgNV
BAYTAkdCMQ8wDQYDVQQKEwZDaGV2YWgxEjAQBgNVBAMMCXRlc3RfdXNlcjCBnzAN
BgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAoGWApc109GKTaN5kgdx0jK+6qFx84lgT
UZuTcYAmn4WEMBtV/B3BFgjIlq5ubYCosu56rNnItbH1/a4voYiWdoq2zErABkg5
slEYRx66f7EocFAQwakzl0vxKLMn5X84uefZSPPUvac40KoudJn1Ys+cQSVfNOcm
8rUNELEi7IUCAwEAAaNRME8wEwYDVR0lBAwwCgYIKwYBBQUHAwIwOAYDVR0fBDEw
LzAtoCugKYYnaHR0cDovL2xvY2FsaG9zdDo4MDgwL3NvbWUtY2hpbGQvY2EuY3Js
MA0GCSqGSIb3DQEBBQUAA4GBADWigcPHP+SF6n7pmAxV4DSt6CBQ+Z8RL7G1f43Z
rW3pcIZkcFhc+2YccGdoiP1DfJhQKyuH+oQgTSp2w3eiNX/t/CaWw4XDHeE0C7kQ
+yMG/FpuVQaZ2uXDqvACGhLCPRkoHjUdi5ZyXzdtqSrm0MqYv48wR8/xV+sUCHTB
9Ze9
-----END CERTIFICATE-----
""")



    def get(self, server_name):
        try:
            return defer.succeed(self._store[server_name])
        except KeyError:
            return fail()

    def store(self, server_name, pem_objects):
        self._store[server_name] = pem_objects
        print('Got a new certificate for "%s":\n\n%s' % (
            server_name, pem_objects))
        return defer.succeed(None)

    def as_dict(self):
        return defer.succeed(self._store)


def on_panic(failure, certificate_name):
    """
    Called when (re)issuing of a certificate failes.
    """
    print('Failed to get certificate for %s: %s' % (
        certificate_name, failure))


@defer.inlineCallbacks
def get_things_done():
    """
    Here is where the service part is setup and action is done.
    """
    responders = yield start_responders()

    store = MemoryStore()

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

    service = AcmeIssuingService(
        email='txacme-test1@twstedmatrix.org,txacme-test2@twstedmatrix.org',
        cert_store=store,
        client=client,
        clock=reactor,
        responders=responders,
        panic=on_panic,
        )

    # Service to start.
    service.startService()

    # Wait for the existing certificate from the storage to be available.
    yield service.when_certs_valid()

    # Request single CN cert and wait for it to be available.
    yield service.issue_cert(requested_domains[0])

    # Request a SAN ... if passed via command line.
    yield service.issue_cert(','.join(requested_domains))

    yield service.stopService()


def stop():
    """
    Stop and cleanup the whole shebang.
    """
    print('Press Ctrl+C to end the process.')


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
    print('It will use the staging server if API_ENDPOINT is not provided.')

    print('\nACME v2 endpoints:')
    print('[Production] https://acme-v02.api.letsencrypt.org/directory')
    print('[Staging] https://acme-staging-v02.api.letsencrypt.org/directory')
    sys.exit(1)


for arg in sys.argv:
    if arg.lower().strip() in ['-h', '--help']:
        show_usage()

if len(sys.argv) < 2:
    show_usage()

try:
    acme_url = sys.argv[2]
except IndexError:
    # Fallback to Let's Encrypt staging server.
    acme_url = 'https://acme-staging-v02.api.letsencrypt.org/directory'

requested_domains = [d.strip().decode('utf-8') for d in sys.argv[1].split(',')]

print('\n\n')
print('-' * 70)
print('Using ACME at %s' % (acme_url,))
print('Managing a single certificate for %s' % (requested_domains,))
print(
    'HTTP-01 responser at '
    'http://localhost:%s/.well-known/acme-challenge/test.txt' % (HTTP_O1_PORT,)
    )
print('-' * 70)
print('\n\n')

#to_file(sys.stdout)
add_destinations(EliotTreeDestination(
    colorize=True, colorize_tree=True, human_readable=True))


def main(reactor):
    d = get_things_done()
    d.addErrback(eb_general_failure)
    d.addBoth(lambda _: stop())
    return d

if __name__ == '__main__':
    task.react(main)
