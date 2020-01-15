"""
This tried to be a complex example demonstrating all the txacme client
capabilities.

Each time it starts, it will generate a new private key and register a new
account if one is not defined.
"""
from __future__ import unicode_literals, print_function
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from eliot import to_file
from eliottree._cli import parse_messages, render_tasks
from josepy.jwa import RS256
from josepy.jwk import JWKRSA
from twisted.internet import reactor, defer
from twisted.python.url import URL

from txacme.client import Client


# Copy inside an exiting private key and check that account is reused.
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

LOG_PATH = 'eliot-log.json'

def _get_key():
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
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
        )
    account_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
        )
    print('New account key generated:\n%s' % (account_key))
    return key


@defer.inlineCallbacks
def work():
    # We first validate the directory.
    key = _get_key()
    client = yield Client.from_url(
        reactor,
        URL.fromText(acme_url.decode('utf-8')),
        key=JWKRSA(key=key),
        alg=RS256,
        )

    # Then we register a new account or update an existing account.
    # First register a new account with a contact set, then using the same
    # key call register with a different contact and see that it was updated.
    response = yield client.register(
        email='txacme-test1@twstedmatrix.org,txacme-test2@twstedmatrix.org')

    print('Account URI: %s' % (response.uri,))
    print('Account contact: %s' % (response.body.contact,))

    # Cleanup the client and disconnect any persistent connection to the
    # ACME server.
    client.stop()

def stop():
    """
    """
    reactor.stop()
    _, tasks = parse_messages([open(LOG_PATH, 'r')])
    render_tasks(sys.stdout.write, tasks)


if len(sys.argv) < 3:
    print('Usage: %s API_ENDPOINT REQUSTED_DOMAIN\n' % (sys.argv[0],))
    print('ACME v2 endpoints:')
    print('[Production] https://acme-v02.api.letsencrypt.org/directory')
    print('[Staging] https://acme-staging-v02.api.letsencrypt.org/directory')
    sys.exit(1)

acme_url = sys.argv[1]

to_file(open(LOG_PATH, 'w'))
#to_file(sys.stdout)

d = work()
d.addErrback(lambda failure: print(failure))
d.addBoth(lambda _: stop())
reactor.run()
