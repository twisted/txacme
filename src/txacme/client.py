"""
ACME client API (like :mod:`acme.client`) implementation for Twisted.
"""
import re
import time

from acme import errors, jose, jws, messages
from acme.messages import STATUS_PENDING, STATUS_PROCESSING, STATUS_VALID
from eliot.twisted import DeferredContext
from treq import json_content
from treq.client import HTTPClient
from twisted.internet.defer import maybeDeferred, succeed
from twisted.internet.task import deferLater
from twisted.web import http
from twisted.web.client import Agent, HTTPConnectionPool
from twisted.web.http_headers import Headers

from txacme import __version__
from txacme.logging import (
    LOG_ACME_ANSWER_CHALLENGE, LOG_ACME_CONSUME_DIRECTORY,
    LOG_ACME_CREATE_AUTHORIZATION, LOG_ACME_FETCH_CHAIN,
    LOG_ACME_POLL_AUTHORIZATION, LOG_ACME_REGISTER,
    LOG_ACME_REQUEST_CERTIFICATE, LOG_ACME_UPDATE_REGISTRATION,
    LOG_HTTP_PARSE_LINKS, LOG_JWS_ADD_NONCE, LOG_JWS_CHECK_RESPONSE,
    LOG_JWS_GET, LOG_JWS_GET_NONCE, LOG_JWS_HEAD, LOG_JWS_POST,
    LOG_JWS_REQUEST, LOG_JWS_SIGN)
from txacme.util import check_directory_url_type, tap


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
        jws_client = JWSClient(HTTPClient(agent=agent), key, alg)
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


class Client(object):
    """
    ACME client interface.
    """
    def __init__(self, directory, reactor, key, jws_client):
        self._client = jws_client
        self._clock = reactor
        self.directory = directory
        self.key = key

    @classmethod
    def from_url(cls, reactor, url, key, alg=jose.RS256, jws_client=None):
        """
        Construct a client from an ACME directory at a given URL.

        :param url: The ``twisted.python.url.URL`` to fetch the directory from.
            See `txacme.urls` for constants for various well-known public
            directories.
        :param reactor: The Twisted reactor to use.
        :param ~acme.jose.jwk.JWK key: The client key to use.
        :param alg: The signing algorithm to use.  Needs to be compatible with
            the type of key used.
        :param JWSClient jws_client: The underlying client to use, or ``None``
            to construct one.

        :return: The constructed client.
        :rtype: Deferred[`Client`]
        """
        action = LOG_ACME_CONSUME_DIRECTORY(
            url=url, key_type=key.typ, alg=alg.name)
        with action.context():
            check_directory_url_type(url)
            jws_client = _default_client(jws_client, reactor, key, alg)
            return (
                DeferredContext(jws_client.get(url.asText()))
                .addCallback(json_content)
                .addCallback(messages.Directory.from_json)
                .addCallback(
                    tap(lambda d: action.add_success_fields(directory=d)))
                .addCallback(cls, reactor, key, jws_client)
                .addActionFinish())

    def register(self, new_reg=None):
        """
        Create a new registration with the ACME server.

        :param ~acme.messages.NewRegistration new_reg: The registration message
            to use, or ``None`` to construct one.

        :return: The registration resource.
        :rtype: Deferred[`~acme.messages.RegistrationResource`]
        """
        if new_reg is None:
            new_reg = messages.NewRegistration()
        action = LOG_ACME_REGISTER(registration=new_reg)
        with action.context():
            return (
                DeferredContext(
                    self.update_registration(
                        new_reg, uri=self.directory[new_reg]))
                .addErrback(self._maybe_registered, new_reg)
                .addCallback(
                    tap(lambda r: action.add_success_fields(registration=r)))
                .addActionFinish())

    @classmethod
    def _maybe_location(cls, response, uri=None):
        """
        Get the Location: if there is one.
        """
        location = response.headers.getRawHeaders(b'location', [None])[0]
        if location is not None:
            return location.decode('ascii')
        return uri

    def _maybe_registered(self, failure, new_reg):
        """
        If the registration already exists, we should just load it.
        """
        failure.trap(ServerError)
        response = failure.value.response
        if response.code == http.CONFLICT:
            reg = new_reg.update(
                resource=messages.UpdateRegistration.resource_type)
            uri = self._maybe_location(response)
            return self.update_registration(reg, uri=uri)
        return failure

    def agree_to_tos(self, regr):
        """
        Accept the terms-of-service for a registration.

        :param ~acme.messages.RegistrationResource regr: The registration to
            update.

        :return: The updated registration resource.
        :rtype: Deferred[`~acme.messages.RegistrationResource`]
        """
        return self.update_registration(
            regr.update(
                body=regr.body.update(
                    agreement=regr.terms_of_service)))

    def update_registration(self, regr, uri=None):
        """
        Submit a registration to the server to update it.

        :param ~acme.messages.RegistrationResource regr: The registration to
            update.  Can be a :class:`~acme.messages.NewRegistration` instead,
            in order to create a new registration.
        :param str uri: The url to submit to.  Must be
            specified if a :class:`~acme.messages.NewRegistration` is provided.

        :return: The updated registration resource.
        :rtype: Deferred[`~acme.messages.RegistrationResource`]
        """
        if uri is None:
            uri = regr.uri
        if isinstance(regr, messages.RegistrationResource):
            message = messages.UpdateRegistration(**dict(regr.body))
        else:
            message = regr
        action = LOG_ACME_UPDATE_REGISTRATION(uri=uri, registration=message)
        with action.context():
            return (
                DeferredContext(self._client.post(uri, message))
                .addCallback(self._parse_regr_response, uri=uri)
                .addCallback(self._check_regr, regr)
                .addCallback(
                    tap(lambda r: action.add_success_fields(registration=r)))
                .addActionFinish())

    def _parse_regr_response(self, response, uri=None, new_authzr_uri=None,
                             terms_of_service=None):
        """
        Parse a registration response from the server.
        """
        links = _parse_header_links(response)
        if u'terms-of-service' in links:
            terms_of_service = links[u'terms-of-service'][u'url']
        if u'next' in links:
            new_authzr_uri = links[u'next'][u'url']
        if new_authzr_uri is None:
            raise errors.ClientError('"next" link missing')
        return (
            response.json()
            .addCallback(
                lambda body:
                messages.RegistrationResource(
                    body=messages.Registration.from_json(body),
                    uri=self._maybe_location(response, uri=uri),
                    new_authzr_uri=new_authzr_uri,
                    terms_of_service=terms_of_service))
            )

    def _check_regr(self, regr, new_reg):
        """
        Check that a registration response contains the registration we were
        expecting.
        """
        body = getattr(new_reg, 'body', new_reg)
        for k, v in body.items():
            if k == 'resource' or not v:
                continue
            if regr.body[k] != v:
                raise errors.UnexpectedUpdate(regr)
        if regr.body.key != self.key.public_key():
            raise errors.UnexpectedUpdate(regr)
        return regr

    def request_challenges(self, identifier):
        """
        Create a new authorization.

        :param ~acme.messages.Identifier identifier: The identifier to
            authorize.

        :return: The new authorization resource.
        :rtype: Deferred[`~acme.messages.AuthorizationResource`]
        """
        action = LOG_ACME_CREATE_AUTHORIZATION(identifier=identifier)
        with action.context():
            message = messages.NewAuthorization(identifier=identifier)
            return (
                DeferredContext(
                    self._client.post(self.directory[message], message))
                .addCallback(self._expect_response, http.CREATED)
                .addCallback(self._parse_authorization)
                .addCallback(self._check_authorization, identifier)
                .addCallback(
                    tap(lambda a: action.add_success_fields(authorization=a)))
                .addActionFinish())

    @classmethod
    def _expect_response(cls, response, code):
        """
        Ensure we got the expected response code.
        """
        if response.code != code:
            raise errors.ClientError(
                'Expected {!r} response but got {!r}'.format(
                    code, response.code))
        return response

    @classmethod
    def _parse_authorization(cls, response, uri=None):
        """
        Parse an authorization resource.
        """
        links = _parse_header_links(response)
        try:
            new_cert_uri = links[u'next'][u'url']
        except KeyError:
            raise errors.ClientError('"next" link missing')
        return (
            response.json()
            .addCallback(
                lambda body: messages.AuthorizationResource(
                    body=messages.Authorization.from_json(body),
                    uri=cls._maybe_location(response, uri=uri),
                    new_cert_uri=new_cert_uri))
            )

    @classmethod
    def _check_authorization(cls, authzr, identifier):
        """
        Check that the authorization we got is the one we expected.
        """
        if authzr.body.identifier != identifier:
            raise errors.UnexpectedUpdate(authzr)
        return authzr

    def answer_challenge(self, challenge_body, response):
        """
        Respond to an authorization challenge.

        :param ~acme.messages.ChallengeBody challenge_body: The challenge being
            responded to.
        :param ~acme.challenges.ChallengeResponse response: The response to the
            challenge.

        :return: The updated challenge resource.
        :rtype: Deferred[`~acme.messages.ChallengeResource`]
        """
        action = LOG_ACME_ANSWER_CHALLENGE(
            challenge_body=challenge_body, response=response)
        with action.context():
            return (
                DeferredContext(
                    self._client.post(challenge_body.uri, response))
                .addCallback(self._parse_challenge)
                .addCallback(self._check_challenge, challenge_body)
                .addCallback(
                    tap(lambda c:
                        action.add_success_fields(challenge_resource=c)))
                .addActionFinish())

    @classmethod
    def _parse_challenge(cls, response):
        """
        Parse a challenge resource.
        """
        links = _parse_header_links(response)
        try:
            authzr_uri = links['up']['url']
        except KeyError:
            raise errors.ClientError('"up" link missing')
        return (
            response.json()
            .addCallback(
                lambda body: messages.ChallengeResource(
                    authzr_uri=authzr_uri,
                    body=messages.ChallengeBody.from_json(body)))
            )

    @classmethod
    def _check_challenge(cls, challenge, challenge_body):
        """
        Check that the challenge resource we got is the one we expected.
        """
        if challenge.uri != challenge_body.uri:
            raise errors.UnexpectedUpdate(challenge.uri)
        return challenge

    def poll(self, authzr):
        """
        Update an authorization from the server (usually to check its status).
        """
        action = LOG_ACME_POLL_AUTHORIZATION(authorization=authzr)
        with action.context():
            return (
                DeferredContext(self._client.get(authzr.uri))
                # Spec says we should get 202 while pending, Boulder actually
                # sends us 200 always, so just don't check.
                # .addCallback(self._expect_response, http.ACCEPTED)
                .addCallback(
                    lambda res:
                    self._parse_authorization(res, uri=authzr.uri)
                    .addCallback(
                        self._check_authorization, authzr.body.identifier)
                    .addCallback(
                        lambda authzr:
                        (authzr,
                         self.retry_after(res, _now=self._clock.seconds)))
                )
                .addCallback(tap(
                    lambda a_r: action.add_success_fields(
                        authorization=a_r[0], retry_after=a_r[1])))
                .addActionFinish())

    @classmethod
    def retry_after(cls, response, default=5, _now=time.time):
        """
        Parse the Retry-After value from a response.
        """
        val = response.headers.getRawHeaders(b'retry-after', [default])[0]
        try:
            return int(val)
        except ValueError:
            return http.stringToDatetime(val) - _now()

    def request_issuance(self, csr):
        """
        Request a certificate.

        Authorizations should have already been completed for all of the names
        requested in the CSR.

        Note that unlike `acme.client.Client.request_issuance`, the certificate
        resource will have the body data as raw bytes.

        ..  seealso:: `txacme.util.csr_for_names`

        ..  todo:: Delayed issuance is not currently supported, the server must
                   issue the requested certificate immediately.

        :param csr: A certificate request message: normally
            `txacme.messages.CertificateRequest` or
            `acme.messages.CertificateRequest`.

        :rtype: Deferred[`acme.messages.CertificateResource`]
        :return: The issued certificate.
        """
        action = LOG_ACME_REQUEST_CERTIFICATE()
        with action.context():
            return (
                DeferredContext(
                    self._client.post(
                        self.directory[csr], csr,
                        content_type=DER_CONTENT_TYPE,
                        headers=Headers({b'Accept': [DER_CONTENT_TYPE]})))
                .addCallback(self._expect_response, http.CREATED)
                .addCallback(self._parse_certificate)
                .addActionFinish())

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

    def fetch_chain(self, certr, max_length=10):
        """
        Fetch the intermediary chain for a certificate.

        :param acme.messages.CertificateResource certr: The certificate to
            fetch the chain for.
        :param int max_length: The maximum length of the chain that will be
            fetched.

        :rtype: Deferred[List[`acme.messages.CertificateResource`]]
        :return: The issuer certificate chain, ordered with the trust anchor
                 last.
        """
        action = LOG_ACME_FETCH_CHAIN()
        with action.context():
            if certr.cert_chain_uri is None:
                return succeed([])
            elif max_length < 1:
                raise errors.ClientError('chain too long')
            return (
                DeferredContext(
                    self._client.get(
                        certr.cert_chain_uri,
                        content_type=DER_CONTENT_TYPE,
                        headers=Headers({b'Accept': [DER_CONTENT_TYPE]})))
                .addCallback(self._parse_certificate)
                .addCallback(
                    lambda issuer:
                    self.fetch_chain(issuer, max_length=max_length - 1)
                    .addCallback(lambda chain: [issuer] + chain))
                .addActionFinish())


def _find_supported_challenge(authzr, responders):
    """
    Find a challenge combination that consists of a single challenge that the
    responder can satisfy.

    :param ~acme.messages.AuthorizationResource auth: The authorization to
        examine.

    :type responder: List[`~txacme.interfaces.IResponder`]
    :param responder: The possible responders to use.

    :raises NoSupportedChallenges: When a suitable challenge combination is not
        found.

    :rtype: Tuple[`~txacme.interfaces.IResponder`,
            `~acme.messages.ChallengeBody`]
    :return: The responder and challenge that were found.
    """
    matches = [
        (responder, challbs[0])
        for challbs in authzr.body.resolved_combinations
        for responder in responders
        if [challb.typ for challb in challbs] == [responder.challenge_type]]
    if len(matches) == 0:
        raise NoSupportedChallenges(authzr)
    else:
        return matches[0]


def answer_challenge(authzr, client, responders):
    """
    Complete an authorization using a responder.

    :param ~acme.messages.AuthorizationResource auth: The authorization to
        complete.
    :param .Client client: The ACME client.

    :type responders: List[`~txacme.interfaces.IResponder`]
    :param responders: A list of responders that can be used to complete the
        challenge with.

    :return: A deferred firing when the authorization is verified.
    """
    responder, challb = _find_supported_challenge(authzr, responders)
    response = challb.response(client.key)

    def _stop_responding():
        return maybeDeferred(
            responder.stop_responding,
            authzr.body.identifier.value,
            challb.chall,
            response)
    return (
        maybeDeferred(
            responder.start_responding,
            authzr.body.identifier.value,
            challb.chall,
            response)
        .addCallback(lambda _: client.answer_challenge(challb, response))
        .addCallback(lambda _: _stop_responding)
        )


def poll_until_valid(authzr, clock, client, timeout=300.0):
    """
    Poll an authorization until it is in a state other than pending or
    processing.

    :param ~acme.messages.AuthorizationResource auth: The authorization to
        complete.
    :param clock: The ``IReactorTime`` implementation to use; usually the
        reactor, when not testing.
    :param .Client client: The ACME client.
    :param float timeout: Maximum time to poll in seconds, before giving up.

    :raises txacme.client.AuthorizationFailed: if the authorization is no
        longer in the pending, processing, or valid states.
    :raises: ``twisted.internet.defer.CancelledError`` if the authorization was
        still in pending or processing state when the timeout was reached.

    :rtype: Deferred[`~acme.messages.AuthorizationResource`]
    :return: A deferred firing when the authorization has completed/failed; if
             the authorization is valid, the authorization resource will be
             returned.
    """
    def repoll(result):
        authzr, retry_after = result
        if authzr.body.status in {STATUS_PENDING, STATUS_PROCESSING}:
            return (
                deferLater(clock, retry_after, lambda: None)
                .addCallback(lambda _: client.poll(authzr))
                .addCallback(repoll)
                )
        if authzr.body.status != STATUS_VALID:
            raise AuthorizationFailed(authzr)
        return authzr

    def cancel_timeout(result):
        if timeout_call.active():
            timeout_call.cancel()
        return result
    d = client.poll(authzr).addCallback(repoll)
    timeout_call = clock.callLater(timeout, d.cancel)
    d.addBoth(cancel_timeout)
    return d


JSON_CONTENT_TYPE = b'application/json'
JSON_ERROR_CONTENT_TYPE = b'application/problem+json'
DER_CONTENT_TYPE = b'application/pkix-cert'
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
    HTTP client using JWS-signed messages.
    """
    timeout = 30

    def __init__(self, treq_client, key, alg,
                 user_agent=u'txacme/{}'.format(__version__).encode('ascii')):
        self._treq = treq_client
        self._key = key
        self._alg = alg
        self._user_agent = user_agent

        self._nonces = set()

    def _wrap_in_jws(self, nonce, obj):
        """
        Wrap ``JSONDeSerializable`` object in JWS.

        ..  todo:: Implement ``acmePath``.

        :param ~acme.jose.interfaces.JSONDeSerializable obj:
        :param bytes nonce:

        :rtype: `bytes`
        :return: JSON-encoded data
        """
        with LOG_JWS_SIGN(key_type=self._key.typ, alg=self._alg.name,
                          nonce=nonce):
            jobj = obj.json_dumps().encode()
            return (
                jws.JWS.sign(
                    payload=jobj, key=self._key, alg=self._alg, nonce=nonce)
                .json_dumps()
                .encode())

    @classmethod
    def _check_response(cls, response, content_type=JSON_CONTENT_TYPE):
        """
        Check response content and its type.

        ..  note::

            Unlike :mod:`acme.client`, checking is strict.

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
                if response_ct == JSON_ERROR_CONTENT_TYPE and jobj is not None:
                    raise ServerError(
                        messages.Error.from_json(jobj), response)
                else:
                    # response is not JSON object
                    raise errors.ClientError(response)
            elif response_ct != content_type:
                raise errors.ClientError(
                    'Unexpected response Content-Type: {0!r}'.format(
                        response_ct))
            elif content_type == JSON_CONTENT_TYPE and jobj is None:
                raise errors.ClientError(response)
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
        action = LOG_JWS_REQUEST(url=url)
        with action.context():
            headers = kwargs.setdefault('headers', Headers())
            headers.setRawHeaders(b'user-agent', [self._user_agent])
            kwargs.setdefault('timeout', self.timeout)
            return (
                DeferredContext(
                    self._treq.request(method, url, *args, **kwargs))
                .addCallback(
                    tap(lambda r: action.add_success_fields(
                        code=r.code,
                        content_type=r.headers.getRawHeaders(
                            b'content-type', [None])[0])))
                .addActionFinish())

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
                raise errors.MissingNonce(response)
            else:
                try:
                    decoded_nonce = jws.Header._fields['nonce'].decode(
                        nonce.decode('ascii'))
                    action.add_success_fields(nonce=decoded_nonce)
                except jose.DeserializationError as error:
                    raise errors.BadNonce(nonce, error)
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
                return succeed(nonce)
        else:
            with action.context():
                return (
                    DeferredContext(self.head(url))
                    .addCallback(self._add_nonce)
                    .addCallback(lambda _: self._nonces.pop())
                    .addCallback(tap(
                        lambda nonce: action.add_success_fields(nonce=nonce)))
                    .addActionFinish())

    def _post(self, url, obj, content_type, **kwargs):
        """
        POST an object and check the response.

        :param str url: The URL to request.
        :param ~acme.jose.interfaces.JSONDeSerializable obj: The serializable
            payload of the request.
        :param bytes content_type: The expected content type of the response.

        :raises txacme.client.ServerError: If server response body carries HTTP
            Problem (draft-ietf-appsawg-http-problem-00).
        :raises acme.errors.ClientError: In case of other protocol errors.
        """
        with LOG_JWS_POST().context():
            headers = kwargs.setdefault('headers', Headers())
            headers.setRawHeaders(b'content-type', [JSON_CONTENT_TYPE])
            return (
                DeferredContext(self._get_nonce(url))
                .addCallback(self._wrap_in_jws, obj)
                .addCallback(
                    lambda data: self._send_request(
                        u'POST', url, data=data, **kwargs))
                .addCallback(self._add_nonce)
                .addCallback(self._check_response, content_type=content_type)
                .addActionFinish())

    def post(self, url, obj, content_type=JSON_CONTENT_TYPE, **kwargs):
        """
        POST an object and check the response. Retry once if a badNonce error
        is received.

        :param str url: The URL to request.
        :param ~acme.jose.interfaces.JSONDeSerializable obj: The serializable
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


__all__ = [
    'Client', 'JWSClient', 'ServerError', 'JSON_CONTENT_TYPE',
    'JSON_ERROR_CONTENT_TYPE', 'REPLAY_NONCE_HEADER', 'fqdn_identifier',
    'answer_challenge', 'poll_until_valid', 'NoSupportedChallenges',
    'AuthorizationFailed', 'DER_CONTENT_TYPE']
