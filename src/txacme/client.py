"""
ACME client API (like :mod:`acme.client`) implementation for Twisted.

Extracted from RFC 8555

                              directory
                                  |
                                  +--> newNonce
                                  |
      +----------+----------+-----+-----+------------+
      |          |          |           |            |
      |          |          |           |            |
      V          V          V           V            V
 newAccount   newAuthz   newOrder   revokeCert   keyChange
      |          |          |
      |          |          |
      V          |          V
   account       |        order --+--> finalize
                 |          |     |
                 |          |     +--> cert
                 |          V
                 +---> authorization
                           | ^
                           | | "up"
                           V |
                         challenge

                 ACME Resources and Relationships

   The following table illustrates a typical sequence of requests
   required to establish a new account with the server, prove control of
   an identifier, issue a certificate, and fetch an updated certificate
   some time after issuance.  The "->" is a mnemonic for a Location
   header field pointing to a created resource.

   +-------------------+--------------------------------+--------------+
   | Action            | Request                        | Response     |
   +-------------------+--------------------------------+--------------+
   |1.Get directory     | GET  directory                 | 200          |
   |                   |                                |              |
   |2.Get nonce         | HEAD newNonce                  | 200          |
   |                   |                                |              |
   |3.Create account    | POST newAccount                | 201 ->       |
   |                   |                                | account      |
   |                   |                                |              |
   |4.Submit order      | POST newOrder                  | 201 -> order |
   |                   |                                |              |
   |5.Fetch challenges  | POST-as-GET order's            | 200          |
   |                   | authorization urls             |              |
   |                   |                                |              |
   |6.Respond to        | POST authorization challenge   | 200          |
   | challenges        | urls                           |              |
   |                   |                                |              |
   |7.Poll for status   | POST-as-GET order              | 200          |
   |                   |                                |              |
   |8.Finalize order    | POST order's finalize url      | 200          |
   |                   |                                |              |
   |9.Poll for status   | POST-as-GET order              | 200          |
   |                   |                                |              |
   |10.Download          | POST-as-GET order's            | 200          |
   | certificate       | certificate url                |              |
   +-------------------+--------------------------------+--------------+

1. client = Client.from_url(DIRECTORY_URL)
2. done as part of Client.from_url() call and automatically for each request
3. client.start() - creates or updates an account.
4. order = client.submit_order(new_cert_key, [list,domains])
5. list(order.authorizations) - fetch done as part of client.submit_order()
6. client.check_authoriztion(order.authorizations[0]) and for each
   authorization
7. poll as part of answer_challenge
8. client.finalize(order)
9. client.check_order(order)
10.

"""
import re

from acme import errors, messages
from acme.crypto_util import make_csr
from acme.jws import JWS, Header
from acme.messages import (
    STATUS_PENDING,
    STATUS_VALID,
    STATUS_INVALID,
    )

import josepy as jose
from josepy.jwa import RS256
from josepy.errors import DeserializationError

import OpenSSL
from cryptography.hazmat.primitives import serialization

from eliot.twisted import DeferredContext
from treq import json_content
from treq.client import HTTPClient
from twisted.internet import defer
from twisted.internet.task import deferLater
from twisted.web import http
from twisted.web.client import Agent, HTTPConnectionPool
from twisted.web.http_headers import Headers

from txacme import __version__
from txacme.logging import (
    LOG_ACME_ANSWER_CHALLENGE,
    LOG_ACME_CONSUME_DIRECTORY,
    LOG_ACME_REGISTER,
    LOG_HTTP_PARSE_LINKS,
    LOG_JWS_ADD_NONCE,
    LOG_JWS_CHECK_RESPONSE,
    LOG_JWS_GET,
    LOG_JWS_GET_NONCE,
    LOG_JWS_HEAD,
    LOG_JWS_POST,
    LOG_JWS_REQUEST,
    LOG_JWS_SIGN,
    )
from txacme.util import check_directory_url_type, tap

_DEFAULT_TIMEOUT = 40


# Borrowed from requests, with modifications.
def _parse_header_links(response):
    """
    Parse the links from a Link: header field.

    ..  todo:: Links with the same relation collide at the moment.

    :param bytes value: The header value.

    :rtype: `dict`
    :return: A dictionary of parsed links, keyed by ``rel`` or ``url``.
    """
    values = response.headers.getRawHeaders(b'link', [b''])
    value = b','.join(values).decode('ascii')
    with LOG_HTTP_PARSE_LINKS(raw_link=value) as action:
        links = {}
        replace_chars = u' \'"'
        for val in re.split(u', *<', value):
            try:
                url, params = val.split(u';', 1)
            except ValueError:
                url, params = val, u''

            link = {}
            link[u'url'] = url.strip(u'<> \'"')
            for param in params.split(u';'):
                try:
                    key, value = param.split(u'=')
                except ValueError:
                    break
                link[key.strip(replace_chars)] = value.strip(replace_chars)
            links[link.get(u'rel') or link.get(u'url')] = link
        action.add_success_fields(parsed_links=links)
        return links


def _default_client(jws_client, reactor, key, alg):
    """
    Make a client if we didn't get one.
    """
    if jws_client is None:
        pool = HTTPConnectionPool(reactor)
        agent = Agent(reactor, pool=pool)
        jws_client = JWSClient(agent, key, alg)
    return jws_client


def fqdn_identifier(fqdn):
    """
    Construct an identifier from an FQDN.

    Trivial implementation, just saves on typing.

    :param str fqdn: The domain name.

    :return: The identifier.
    :rtype: `~acme.messages.Identifier`
    """
    return messages.Identifier(
        typ=messages.IDENTIFIER_FQDN, value=fqdn)


@messages.Directory.register
class Finalize(jose.JSONObjectWithFields):
    """
    ACME order finalize request.

    This is here as acme.messages.CertificateRequest does not work with
    pebble in --strict mode.

    :ivar josepy.util.ComparableX509 csr:
        `OpenSSL.crypto.X509Req` wrapped in `.ComparableX509`
    """
    resource_type = 'finalize'
    csr = jose.Field('csr', decoder=jose.decode_csr, encoder=jose.encode_csr)


class Client(object):
    """
    ACME client interface.

    The current implementation does not support multiple parallel requests.
    This is due to the nonce handling.

    Should be initialized with 'Client.from_url'.
    """
    def __init__(self, directory, reactor, key, jws_client):
        self._client = jws_client
        self._clock = reactor
        self.directory = directory
        self.key = key
        self._kid = None

    @classmethod
    def from_url(
        cls, reactor, url, key, alg=RS256,
        jws_client=None, timeout=_DEFAULT_TIMEOUT,
            ):
        """
        Construct a client from an ACME directory at a given URL.

        At construct time, it validates the ACME directory.

        :param url: The ``twisted.python.url.URL`` to fetch the directory from.
            See `txacme.urls` for constants for various well-known public
            directories.
        :param reactor: The Twisted reactor to use.
        :param ~josepy.jwk.JWK key: The client key to use.
        :param alg: The signing algorithm to use.  Needs to be compatible with
            the type of key used.
        :param JWSClient jws_client: The underlying client to use, or ``None``
            to construct one.
        :param int timeout: Number of seconds to wait for an HTTP response
            during ACME server interaction.

        :return: The constructed client.
        :rtype: Deferred[`Client`]
        """
        action = LOG_ACME_CONSUME_DIRECTORY(
            url=url, key_type=key.typ, alg=alg.name)
        with action.context():
            check_directory_url_type(url)
            jws_client = _default_client(jws_client, reactor, key, alg)
            jws_client.timeout = timeout
            return (
                DeferredContext(jws_client.start(url.asText()))
                .addCallback(
                    tap(lambda d: action.add_success_fields(directory=d)))
                .addCallback(cls, reactor, key, jws_client)
                .addActionFinish())

    def start(self, email=None):
        """
        Create a new registration with the ACME server or update an existing
        account.

        :param str email: Comma separated contact emails used by the account.

        :return: The registration resource.
        :rtype: Deferred[`~acme.messages.RegistrationResource`]
        """
        uri = self.directory.newAccount
        new_reg = messages.Registration.from_data(
            email=email,
            terms_of_service_agreed=True,
        )
        action = LOG_ACME_REGISTER(registration=new_reg)
        with action.context():
            return (
                DeferredContext(
                    self._client.post(uri, new_reg))
                .addCallback(self._cb_check_existing_account, new_reg)
                .addCallback(self._cb_check_registration)
                .addCallback(
                    tap(lambda r: action.add_success_fields(registration=r)))
                .addActionFinish())

    def stop(self):
        """
        Stops the client operation.

        This cancels pending operations and does cleanup.

        :return: When operation is done.
        :rtype: Deferred[None]
        """
        return self._client.stop()

    @classmethod
    def _maybe_location(cls, response, uri=None):
        """
        Get the Location: if there is one.
        """
        location = response.headers.getRawHeaders(b'location', [None])[0]
        if location is not None:
            return location.decode('ascii')
        return uri

    def _cb_check_existing_account(self, response, request):
        """
        Get the response from the account registration and see if the
        account is already registered and do an update in that case.
        """
        if response.code == 200 and request.contact:
            # Account already exists and we email address to update.
            # I don't know how to remove a contact.
            uri = self._maybe_location(response)
            deferred = self._client.post(uri, request, kid=uri)
            deferred.addCallback(self._cb_parse_registration_response, uri=uri)
            return deferred

        return self._cb_parse_registration_response(response)

    def _cb_parse_registration_response(self, response, uri=None):
        """
        Parse a new or update registration response from the server.
        """
        links = _parse_header_links(response)
        terms_of_service = None
        if u'terms-of-service' in links:
            terms_of_service = links[u'terms-of-service'][u'url']
        return (
            response.json()
            .addCallback(
                lambda body:
                messages.RegistrationResource(
                    body=messages.Registration.from_json(body),
                    uri=self._maybe_location(response, uri),
                    terms_of_service=terms_of_service))
            )

    def _cb_check_registration(self, regr):
        """
        Check that a registration response contains the registration we were
        expecting.
        """
        if regr.body.key != self.key.public_key():
            # This is a response for another key.
            raise errors.UnexpectedUpdate(regr)

        if regr.body.status != 'valid':
            raise errors.UnexpectedUpdate(regr)

        self._client.kid = regr.uri

        return regr

    @defer.inlineCallbacks
    def submit_order(self, key, names):
        """
        Create a new order and return the OrderResource for that order with
        all the authorizations resolved.

        It will automatically create a new private key and CSR for the
        domain 'names'.

        :param list of str names: Sequence of DNS names for which to request
            a new certificate.
        :param key: Key for the future certificate.

        :return: The new authorization resource.
        :rtype: Deferred[`~acme.messages.Order`]
        """
        # certbot helper API needs PEM.
        pem_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
            )
        csr_pem = make_csr(pem_key, names)
        identifiers = [fqdn_identifier(name) for name in names]

        message = messages.NewOrder(identifiers=identifiers)
        response = yield self._client.post(self.directory.newOrder, message)
        self._expect_response(response, [http.CREATED])

        order_uri = self._maybe_location(response)

        authorizations = []
        order_body = yield response.json()
        for uri in order_body['authorizations']:
            # We do a POST-as-GET
            respose = yield self._client.post(uri, obj=None)
            self._expect_response(response, [http.CREATED])
            body = yield respose.json()
            authorizations.append(
                messages.AuthorizationResource(
                    body=messages.Authorization.from_json(body),
                    uri=uri,
                    ))

        order = messages.OrderResource(
            body=messages.Order.from_json(order_body),
            uri=order_uri,
            authorizations=authorizations,
            csr_pem=csr_pem,
            )

        # TODO: Not sure if all these sanity checks are required.
        for identifier in order.body.identifiers:
            if identifier not in identifiers:
                raise errors.UnexpectedUpdate(order)
        defer.returnValue(order)

    @classmethod
    def _expect_response(cls, response, codes):
        """
        Ensure we got one of the expected response codes`.
        """
        if response.code not in codes:
            return _fail_and_consume(response, errors.ClientError(
                'Expected {!r} response but got {!r}'.format(
                    codes, response.code)))
        return response

    def answer_challenge(self, challenge_body, response):
        """
        Respond to an authorization challenge.

        This send a POST with the empty object '{}' as the payload.

        :param ~acme.messages.ChallengeBody challenge_body: The challenge being
            responded to.
        :param ~acme.challenges.ChallengeResponse response: The response to the
            challenge.

        :return: The updated challenge resource.
        :rtype: Deferred[`~acme.messages.ChallengeResource`]
        """
        action = LOG_ACME_ANSWER_CHALLENGE(
            challenge_body=challenge_body, response=response)

        if challenge_body.status != STATUS_PENDING:
            # We already have an answer.
            return challenge_body

        with action.context():
            return (
                DeferredContext(
                    self._client.post(
                        challenge_body.uri, jose.JSONObjectWithFields()))
                .addCallback(self._parse_challenge)
                .addCallback(self._check_challenge, challenge_body)
                .addCallback(
                    tap(lambda c:
                        action.add_success_fields(challenge_resource=c)))
                .addActionFinish())

    @classmethod
    @defer.inlineCallbacks
    def _parse_challenge(cls, response):
        """
        Parse a challenge resource.
        """
        links = _parse_header_links(response)
        try:
            authzr_uri = links['up']['url']
        except KeyError:
            yield _fail_and_consume(
                response, errors.ClientError('"up" link missing'))

        body = yield response.json()
        defer.returnValue(messages.ChallengeResource(
            authzr_uri=authzr_uri,
            body=messages.ChallengeBody.from_json(body),
            ))

    @classmethod
    def _check_challenge(cls, challenge, challenge_body):
        """
        Check that the challenge resource we got is the one we expected.
        """
        if challenge.uri != challenge_body.uri:
            raise errors.UnexpectedUpdate(challenge.uri)
        return challenge

    def check_authorization(self, authzz):
        """
        Check the status of the authorization.

        Return an updated message.AuthorizationResource.
        """
        return self._poll(
            authzz.uri, messages.AuthorizationResource, messages.Authorization)

    def check_order(self, orderr):
        """
        Check the status of the authorization.

        Return an updated message.OrderResource.
        """
        return self._poll(orderr.uri, messages.OrderResource, messages.Order)

    @defer.inlineCallbacks
    def _poll(self, url, resource_class, body_class,):
        """
        Make a POST-as-GET for a resource.
        """
        response = yield self._client.post(url, obj=None)
        self._expect_response(response, [http.OK])
        body = yield response.json()
        defer.returnValue(resource_class(
            uri=url,
            body=body_class.from_json(body),
            ))

    @defer.inlineCallbacks
    def finalize(self, order):
        """
        Request order finalization.

        Authorizations should have already been completed for all of the names
        requested in the order.

        :param ~acme.messages.Order order: The order for which the certificate
            is requested.

        :rtype: Deferred[`acme.messages.OrderResource`]
        :return: The issued certificate.
        """
        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, order.csr_pem)
        request = Finalize(csr=jose.ComparableX509(csr))
        response = yield self._client.post(
            order.body.finalize, obj=request)
        self._expect_response(response, [http.OK])
        body = yield response.json()
        defer.returnValue(messages.OrderResource(
            uri=order.uri,
            body=messages.Order.from_json(body),
            ))

    @classmethod
    def _parse_certificate(cls, response):
        """
        Parse a response containing a certificate resource.
        """
        links = _parse_header_links(response)
        try:
            cert_chain_uri = links[u'up'][u'url']
        except KeyError:
            cert_chain_uri = None
        return (
            response.content()
            .addCallback(
                lambda body: messages.CertificateResource(
                    uri=cls._maybe_location(response),
                    cert_chain_uri=cert_chain_uri,
                    body=body))
            )

    @defer.inlineCallbacks
    def fetch_certificate(self, url):
        """
        Download the certificate for `order`.

        :rtype: acme.messages.CertificateResource
        :return: The certificate which was downloaded.
        """
        deferred = self._client.post(
            url,
            content_type=PEM_CHAIN_TYPE,
            response_type=PEM_CHAIN_TYPE,
            obj=None,
            )
        deferred.addCallback(self._parse_certificate)

        result = yield deferred
        defer.returnValue(result)


def _find_supported_challenge(authzr, responders):
    """
    Find a challenge combination that consists of a single challenge that the
    responder can satisfy.

    :param ~acme.messages.AuthorizationResource authzr:
        The authorization to examine.

    :type responder: List[`~txacme.interfaces.IResponder`]
    :param responder: The possible responders to use.

    :raises NoSupportedChallenges: When a suitable challenge combination is not
        found.

    :rtype: Tuple[`~txacme.interfaces.IResponder`,
            `~acme.messages.ChallengeBody`]
    :return: The responder and challenge that were found.
    """
    for responder in responders:
        r_type = responder.challenge_type
        for challenge in authzr.body.challenges:
            if r_type == challenge.chall.typ:
                return (responder, challenge)

    raise NoSupportedChallenges(authzr)


@defer.inlineCallbacks
def answer_challenge(authz, client, responders, clock, timeout=300.0):
    """
    Complete an authorization using a responder.

    It waits for the authorization to be completed (as valid or invliad)
    for a maximum of 'timeout' seconds.

                      pending --------------------+
                         |                        |
       Challenge failure |                        |
              or         |                        |
             Error       |  Challenge valid       |
               +---------+---------+              |
               |                   |              |
               V                   V              |
            invalid              valid            |
                                   |              |
                                   |              |
                                   |              |
                    +--------------+--------------+
                    |              |              |
                    |              |              |
             Server |       Client |   Time after |
             revoke |   deactivate |    "expires" |
                    V              V              V
                 revoked      deactivated      expired

    :param ~acme.messages.AuthorizationResource authz:
        The authorization answer the challenges for.
    :param .Client client: The ACME client.

    :type responders: List[`~txacme.interfaces.IResponder`]
    :param responders: A list of responders that can be used to complete the
        challenge with.
    :param clock: The ``IReactorTime`` implementation to use; usually the
        reactor, when not testing.
    :param float timeout: Maximum time to poll in seconds, before giving up.

    :raises AuthorizationFailed: If the challenge was not validated.

    :return: A deferred firing when the authorization is verified.
    """
    server_name = authz.body.identifier.value
    responder, challenge = _find_supported_challenge(authz, responders)
    response = challenge.response(client.key)
    yield defer.maybeDeferred(
        responder.start_responding, server_name, challenge.chall, response)

    resource = yield client.answer_challenge(challenge, response)

    now = clock.seconds()
    sleep = 0.5
    try:
        while True:
            resource = yield client.check_authorization(authz)
            status = resource.body.status

            if status == STATUS_INVALID:
                # No need to wait longer as we got a definitive answer.
                raise AuthorizationFailed(resource)

            if status == STATUS_VALID:
                # All good.
                defer.returnValue(resource)

            if clock.seconds() - now > timeout:
                raise AuthorizationFailed(resource)

            yield deferLater(clock, sleep, lambda: None)
            sleep += sleep
    finally:
        yield defer.maybeDeferred(
            responder.stop_responding, server_name, challenge.chall, response)


@defer.inlineCallbacks
def get_certificate(orderr, client, clock, timeout=300.0):
    """
    Finalize the order and return the associated certificate.

    It assumes all authorizations were already validated.

    It waits for the order to be 'valid' for a maximum of 'timeout'
    seconds.::

        pending --------------+
           |                  |
           | All authz        |
           | "valid"          |
           V                  |
         ready ---------------+
           |                  |
           | Receive          |
           | finalize         |
           | request          |
           V                  |
       processing ------------+
           |                  |
           | Certificate      | Error or
           | issued           | Authorization failure
           V                  V
         valid             invalid


    :param ~acme.messages.OrderResource orderr: The order to finalize.
    :param .Client client: The ACME client.

    :param clock: The ``IReactorTime`` implementation to use; usually the
        reactor, when not testing.
    :param float timeout: Maximum time to poll in seconds, before giving up.

    :raises ServerError: If a certificate could not be retrieved.

    :return: A deferred firing when the PEM certificate is retrieved.
    """
    orderr = yield client.finalize(orderr)

    now = clock.seconds()
    sleep = 0.5

    while True:
        status = orderr.body.status

        if status == STATUS_VALID:
            # All good.
            break

        if status == STATUS_INVALID:
            raise ServerError('Order is now invalid.')

        if clock.seconds() - now > timeout:
            raise ServerError('Timeout while waiting for order finalization.')

        yield deferLater(clock, sleep, lambda: None)
        sleep += sleep

        orderr = yield client.check_order(orderr)

    certificate = yield client.fetch_certificate(orderr.body.certificate)
    defer.returnValue(certificate)


JSON_CONTENT_TYPE = b'application/json'
JOSE_CONTENT_TYPE = b'application/jose+json'
JSON_ERROR_CONTENT_TYPE = b'application/problem+json'
DER_CONTENT_TYPE = b'application/pkix-cert'
PEM_CHAIN_TYPE = b'application/pem-certificate-chain'
REPLAY_NONCE_HEADER = b'Replay-Nonce'


class ServerError(Exception):
    """
    :exc:`acme.messages.Error` isn't usable as an asynchronous exception,
    because it doesn't allow setting the ``__traceback__`` attribute like
    Twisted wants to do when cleaning Failures.  This type exists to wrap such
    an error, as well as provide access to the original response.
    """
    def __init__(self, message, response):
        Exception.__init__(self, message, response)
        self.message = message
        self.response = response

    def __repr__(self):
        return 'ServerError({!r})'.format(self.message)


class AuthorizationFailed(Exception):
    """
    An attempt was made to complete an authorization, but it failed.
    """
    def __init__(self, authzr):
        self.status = authzr.body.status
        self.authzr = authzr
        self.errors = [
            challb.error
            for challb in authzr.body.challenges
            if challb.error is not None]

    def __repr__(self):
        return (
            'AuthorizationFailed(<'
            '{0.status!r} '
            '{0.authzr.body.identifier!r} '
            '{0.errors!r}>)'.format(self))

    def __str__(self):
        return repr(self)


class NoSupportedChallenges(Exception):
    """
    No supported challenges were found in an authorization.
    """


class JWSClient(object):
    """
    HTTP client using JWS-signed messages for ACME.
    """
    timeout = _DEFAULT_TIMEOUT

    def __init__(self, agent, key, alg,
                 user_agent=u'txacme/{}'.format(__version__).encode('ascii')):
        self._treq = HTTPClient(agent=agent)
        self._agent = agent
        self._current_request = None
        self._key = key
        self._alg = alg
        self._user_agent = user_agent

        self._nonces = set()
        # URL from where a new nonce can be obtained.
        self._new_nonce = None
        self._kid = None

    @property
    def kid(self):
        return self._kid

    @kid.setter
    def kid(self, value):
        self._kid = value

    def _cb_wrap_in_jws(self, nonce, obj, url, kid=None):
        """
        Callebacak to wrap ``JSONDeSerializable`` object in ACME JWS.

        :param ~josepy.interfaces.JSONDeSerializable obj:
        :param bytes nonce:
        :param bytes url: URL to the request for which we wrap the payload.

        :rtype: `bytes`
        :return: JSON-encoded data
        """
        if kid is None:
            kid = self._kid

        with LOG_JWS_SIGN(key_type=self._key.typ, alg=self._alg.name,
                          nonce=nonce, kid=kid):
            if obj is None:
                jobj = b''
            else:
                jobj = obj.json_dumps().encode()
            result = (
                JWS.sign(
                    payload=jobj,
                    key=self._key,
                    alg=self._alg,
                    nonce=nonce,
                    url=url,
                    kid=kid,
                    )
                .json_dumps()
                .encode())
            return result

    @classmethod
    def _check_response(cls, response, content_type=JSON_CONTENT_TYPE):
        """
        Check response content and its type.

        ..  note::

            Unlike :mod:content_type`acme.client`, checking is strict.

        :param bytes content_type: Expected Content-Type response header.  If
            the response Content-Type does not match, :exc:`ClientError` is
            raised.

        :raises .ServerError: If server response body carries HTTP Problem
            (draft-ietf-appsawg-http-problem-00).
        :raises ~acme.errors.ClientError: In case of other networking errors.
        """
        def _got_failure(f):
            f.trap(ValueError)
            return None

        def _got_json(jobj):
            if 400 <= response.code < 600:
                if (
                    response_ct.lower().startswith(JSON_ERROR_CONTENT_TYPE)
                    and jobj is not None
                        ):
                    raise ServerError(
                        messages.Error.from_json(jobj), response)
                else:
                    # response is not JSON object
                    return _fail_and_consume(
                        response, errors.ClientError('Response is not JSON.'))
            elif content_type not in response_ct.lower():
                return _fail_and_consume(response, errors.ClientError(
                    'Unexpected response Content-Type: {0!r}. '
                    'Expecting {1!r}.'.format(
                        response_ct, content_type)))
            elif JSON_CONTENT_TYPE in content_type.lower() and jobj is None:
                return _fail_and_consume(
                    response, errors.ClientError('Missing JSON body.'))
            return response

        response_ct = response.headers.getRawHeaders(
            b'Content-Type', [None])[0]
        action = LOG_JWS_CHECK_RESPONSE(
            expected_content_type=content_type,
            response_content_type=response_ct)
        with action.context():
            # TODO: response.json() is called twice, once here, and
            # once in _get and _post clients
            return (
                DeferredContext(response.json())
                .addErrback(_got_failure)
                .addCallback(_got_json)
                .addActionFinish())

    def _send_request(self, method, url, *args, **kwargs):
        """
        Send HTTP request.

        :param str method: The HTTP method to use.
        :param str url: The URL to make the request to.

        :return: Deferred firing with the HTTP response.
        """
        if self._current_request is not None:
            return defer.fail(RuntimeError('Overlapped HTTP request'))

        def cb_request_done(result):
            """
            Called when we got a response from the request.
            """
            self._current_request = None
            return result

        action = LOG_JWS_REQUEST(url=url)
        with action.context():
            headers = kwargs.setdefault('headers', Headers())
            headers.setRawHeaders(b'user-agent', [self._user_agent])
            kwargs.setdefault('timeout', self.timeout)
            self._current_request = self._treq.request(
                method, url, *args, **kwargs)
            return (
                DeferredContext(self._current_request)
                .addCallback(cb_request_done)
                .addCallback(
                    tap(lambda r: action.add_success_fields(
                        code=r.code,
                        content_type=r.headers.getRawHeaders(
                            b'content-type', [None])[0])))
                .addActionFinish())

    def start(self, directory):
        """
        Prepare for ACME operations based on 'directory' url.

        :param str directory: The URL to the ACME v2 directory.

        :return: When operation is done.
        :rtype: Deferred[None]
        """
        def cb_extract_new_nonce(directory):
            try:
                self._new_nonce = directory.newNonce
            except AttributeError:
                raise errors.ClientError(
                    'Directory has no newNonce URL', directory)

            return directory
        return (
            self.get(directory)
            .addCallback(json_content)
            .addCallback(messages.Directory.from_json)
            .addCallback(cb_extract_new_nonce)
            )

    def stop(self):
        """
        Stops the operation.

        This cancels pending operations and does cleanup.

        :return: A deferred which fires when the client is stopped.
        """
        if self._current_request is not None:
            self._current_request.addErrback(lambda _: None)
            self._current_request.cancel()
            self._current_request = None

        agent_pool = getattr(self._agent, '_pool', None)
        if agent_pool:
            return agent_pool.closeCachedConnections()
        return defer.succeed(None)

    def head(self, url, *args, **kwargs):
        """
        Send HEAD request without checking the response.

        Note that ``_check_response`` is not called, as there will be no
        response body to check.

        :param str url: The URL to make the request to.
        """
        with LOG_JWS_HEAD().context():
            return DeferredContext(
                self._send_request(u'HEAD', url, *args, **kwargs)
                ).addActionFinish()

    def get(self, url, content_type=JSON_CONTENT_TYPE, **kwargs):
        """
        Send GET request and check response.

        :param str method: The HTTP method to use.
        :param str url: The URL to make the request to.

        :raises txacme.client.ServerError: If server response body carries HTTP
            Problem (draft-ietf-appsawg-http-problem-00).
        :raises acme.errors.ClientError: In case of other protocol errors.

        :return: Deferred firing with the checked HTTP response.
        """
        with LOG_JWS_GET().context():
            return (
                DeferredContext(self._send_request(u'GET', url, **kwargs))
                .addCallback(self._check_response, content_type=content_type)
                .addActionFinish())

    def _add_nonce(self, response):
        """
        Store a nonce from a response we received.

        :param twisted.web.iweb.IResponse response: The HTTP response.

        :return: The response, unmodified.
        """
        nonce = response.headers.getRawHeaders(
            REPLAY_NONCE_HEADER, [None])[0]
        with LOG_JWS_ADD_NONCE(raw_nonce=nonce) as action:
            if nonce is None:
                return _fail_and_consume(
                    response,
                    errors.ClientError(str(errors.MissingNonce(response))),
                    )
            else:
                try:
                    decoded_nonce = Header._fields['nonce'].decode(
                        nonce.decode('ascii')
                    )
                    action.add_success_fields(nonce=decoded_nonce)
                except DeserializationError as error:
                    return _fail_and_consume(
                        response, errors.BadNonce(nonce, error))
                self._nonces.add(decoded_nonce)
                return response

    def _get_nonce(self, url):
        """
        Get a nonce to use in a request, removing it from the nonces on hand.
        """
        action = LOG_JWS_GET_NONCE()
        if len(self._nonces) > 0:
            with action:
                nonce = self._nonces.pop()
                action.add_success_fields(nonce=nonce)
                return defer.succeed(nonce)
        else:
            with action.context():
                return (
                    DeferredContext(self.head(self._new_nonce))
                    .addCallback(self._add_nonce)
                    .addCallback(lambda _: self._nonces.pop())
                    .addCallback(tap(
                        lambda nonce: action.add_success_fields(nonce=nonce)))
                    .addActionFinish())

    def _post(
        self, url, obj, content_type,
        response_type=JSON_CONTENT_TYPE, kid=None,
        **kwargs
            ):
        """
        POST an object and check the response.

        :param str url: The URL to request.
        :param ~josepy.interfaces.JSONDeSerializable obj: The serializable
            payload of the request.
        :param bytes content_type: The expected content type of the response.

        :raises txacme.client.ServerError: If server response body carries HTTP
            Problem (draft-ietf-appsawg-http-problem-00).
        :raises acme.errors.ClientError: In case of other protocol errors.
        """
        with LOG_JWS_POST().context():
            headers = kwargs.setdefault('headers', Headers())
            headers.setRawHeaders(b'content-type', [JOSE_CONTENT_TYPE])
            return (
                DeferredContext(self._get_nonce(url))
                .addCallback(self._cb_wrap_in_jws, obj, url, kid)
                .addCallback(
                    lambda data: self._send_request(
                        u'POST', url, data=data, **kwargs))
                .addCallback(self._add_nonce)
                .addCallback(self._check_response, content_type=response_type)
                .addActionFinish())

    def post(self, url, obj, content_type=JOSE_CONTENT_TYPE, **kwargs):
        """
        POST an object and check the response. Retry once if a badNonce error
        is received.

        :param str url: The URL to request.
        :param ~josepy.interfaces.JSONDeSerializable obj: The serializable
            payload of the request.
        :param bytes content_type: The expected content type of the response.
            By default, JSON.

        :raises txacme.client.ServerError: If server response body carries HTTP
            Problem (draft-ietf-appsawg-http-problem-00).
        :raises acme.errors.ClientError: In case of other protocol errors.
        """
        def retry_bad_nonce(f):
            f.trap(ServerError)
            # The current RFC draft defines the namespace as
            # urn:ietf:params:acme:error:<code>, but earlier drafts (and some
            # current implementations) use urn:acme:error:<code> instead. We
            # don't really care about the namespace here, just the error code.
            if f.value.message.typ.split(':')[-1] == 'badNonce':
                # If one nonce is bad, others likely are too. Let's clear them
                # and re-add the one we just got.
                self._nonces.clear()
                self._add_nonce(f.value.response)
                return self._post(url, obj, content_type, **kwargs)
            return f
        return (
            self._post(url, obj, content_type, **kwargs)
            .addErrback(retry_bad_nonce))


def _fail_and_consume(response, error):
    """
    Fail the deferred, but before the read all the pending data from the
    response.
    """
    def fail(_):
        raise error
    return response.text().addBoth(fail)


__all__ = [
    'Client', 'JWSClient', 'ServerError', 'JSON_CONTENT_TYPE',
    'JSON_ERROR_CONTENT_TYPE', 'REPLAY_NONCE_HEADER', 'fqdn_identifier',
    'answer_challenge', 'get_certificate', 'NoSupportedChallenges',
    'AuthorizationFailed', 'DER_CONTENT_TYPE']
