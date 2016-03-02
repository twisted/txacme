"""
ACME client API (like :mod:`acme.client`) implementation for Twisted.
"""
import re

from acme import errors, jose, jws, messages
from treq import json_content
from treq.client import HTTPClient
from twisted.internet.defer import inlineCallbacks, returnValue, succeed
from twisted.logger import Logger
from twisted.web import http
from twisted.web.client import Agent, HTTPConnectionPool
from twisted.web.http_headers import Headers


logger = Logger()


# Borrowed from requests, with modifications.

def _parse_header_links(response):
    """
    Parse the links from a Link: header field.

    ..  todo: Links with the same relation collide at the moment.

    :param bytes value: The header value.

    :rtype: `dict`
    :return: A dictionary of parsed links, keyed by ``rel`` or ``url``.
    """
    values = response.headers.getRawHeaders(b'link', [b''])
    links = {}
    value = b','.join(values).decode('ascii')
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
        self.directory = directory
        self._key = key

    @classmethod
    def from_url(cls, reactor, url, key, alg=jose.RS256, jws_client=None):
        """
        Construct a client from an ACME directory at a given URL.

        :param url: The ``twisted.python.url.URL`` to fetch the directory from.
        :param reactor: The Twisted reactor to use.
        :param JWSClient jws_client: The underlying client to use, or ``None``
            to construct one.

        :return: The constructed client.
        :rtype: `Client`
        """
        jws_client = _default_client(jws_client, reactor, key, alg)
        return (
            jws_client.get(url.asText())
            .addCallback(json_content)
            .addCallback(messages.Directory.from_json)
            .addCallback(cls, reactor, key, jws_client))

    def register(self, new_reg=None):
        """
        Create a new registration with the ACME server.

        :param ~acme.messages.NewRegistration new_reg: The registration message
            to use, or ``None`` to construct one.

        :return: The registration resource.
        :rtype: `~acme.messages.RegistrationResource`
        """
        if new_reg is None:
            new_reg = messages.NewRegistration()
        return (
            self.update_registration(new_reg, uri=self.directory[new_reg])
            .addErrback(self._maybe_registered)
            )

    def _maybe_registered(self, failure):
        """
        If the registration already exists, we should just load it.
        """
        failure.trap(ServerError)
        response = failure.value.response
        if response.code == http.CONFLICT:
            location = response.headers.getRawHeaders(b'location')[0]
            uri = location.decode('ascii')
            return self.update_registration(
                messages.UpdateRegistration(), uri=uri)
        return failure

    def agree_to_tos(self, regr):
        """
        Accept the terms-of-service for a registration.

        :param ~acme.messages.RegistrationResource regr: The registration to
            update.

        :return: The updated registration resource.
        :rtype: `~acme.messages.RegistrationResource`
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
        :rtype: `~acme.messages.RegistrationResource`
        """
        if uri is None:
            uri = regr.uri
        if isinstance(regr, messages.RegistrationResource):
            message = messages.UpdateRegistration(**dict(regr.body))
        else:
            message = regr
        return (
            self._client.post(uri, message)
            .addCallback(self._parse_regr_response, uri=uri)
            .addCallback(self._check_regr, regr)
            )

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
        location = response.headers.getRawHeaders(b'location', [None])[0]
        if location is None:
            location = uri
        else:
            location = location.decode('ascii')
        return (
            response.json()
            .addCallback(
                lambda body:
                messages.RegistrationResource(
                    body=messages.Registration.from_json(body),
                    uri=location,
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
        if regr.body.key != self._key.public_key():
            raise errors.UnexpectedUpdate(regr)
        return regr

    def request_challenges(self, identifier):
        """
        Create a new authorization.

        :param ~acme.messages.Identifier identifier: The identifier to
            authorize.

        :return: The new authorization resource.
        :rtype: `~acme.messages.AuthorizationResource`
        """
        message = messages.NewAuthorization(identifier=identifier)
        return (
            self._client.post(
                self.directory[message], message)
            .addCallback(self._expect_response, http.CREATED)
            .addCallback(self._parse_authorization)
            .addCallback(self._check_authorization, identifier)
            )

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
    def _parse_authorization(cls, response):
        """
        Parse an authorization resource.
        """
        links = _parse_header_links(response)
        try:
            new_cert_uri = links['next']['url']
        except KeyError:
            raise errors.ClientError('"next" link missing')
        location = response.headers.getRawHeaders(b'location')[0]
        uri = location.decode('ascii')
        return (
            response.json()
            .addCallback(
                lambda body: messages.AuthorizationResource(
                    body=messages.Authorization.from_json(body),
                    uri=uri,
                    new_cert_uri=new_cert_uri))
            )

    @classmethod
    def _check_authorization(cls, auth, identifier):
        """
        Check that the authorization we got is the one we expected.
        """
        if auth.body.identifier != identifier:
            raise errors.UnexpectedUpdate(auth)
        return auth

    def answer_challenge(self, challenge_body, response):
        """
        Respond to an authorization challenge.

        :param ~acme.messages.ChallengeBody challenge_body: The challenge being
            responded to.
        :param ~acme.challenges.ChallengeResponse response: The response to the
            challenge.

        :return: The updated challenge resource.
        :rtype: `~acme.messages.ChallengeResource`
        """
        return (
            self._client.post(challenge_body.uri, response)
            .addCallback(self._parse_challenge)
            .addCallback(self._check_challenge, challenge_body)
            )

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


JSON_CONTENT_TYPE = b'application/json'
JSON_ERROR_CONTENT_TYPE = b'application/problem+json'
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


class JWSClient(object):
    """
    HTTP client using JWS-signed messages.
    """
    def __init__(self, treq_client, key, alg, user_agent=b'txacme'):
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
        jobj = obj.json_dumps().encode()
        logger.debug('Serialized JSON: {jobj}', jobj=jobj)
        return (
            jws.JWS.sign(
                payload=jobj, key=self._key, alg=self._alg, nonce=nonce)
            .json_dumps())

    @classmethod
    @inlineCallbacks
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
        logger.debug('Received response {response} '
                     '(headers: {response.headers})',
                     response=response)

        response_ct = response.headers.getRawHeaders(
            b'Content-Type', [None])[0]
        try:
            # TODO: response.json() is called twice, once here, and
            # once in _get and _post clients
            jobj = yield response.json()
        except ValueError:
            jobj = None

        if 400 <= response.code < 600:
            if response_ct == JSON_ERROR_CONTENT_TYPE and jobj is not None:
                try:
                    raise ServerError(messages.Error.from_json(jobj), response)
                except jose.DeserializationError as error:
                    # Couldn't deserialize JSON object
                    raise errors.ClientError((response, error))
            else:
                # response is not JSON object
                raise errors.ClientError(response)
        elif response_ct != content_type:
            raise errors.ClientError(
                'Unexpected response Content-Type: {0!r}'.format(response_ct))
        elif content_type == JSON_CONTENT_TYPE and jobj is None:
            raise errors.ClientError(response)

        returnValue(response)

    def _send_request(self, method, url, *args, **kwargs):
        """
        Send HTTP request.

        :param str method: The HTTP method to use.
        :param str url: The URL to make the request to.

        :return: Deferred firing with the HTTP response.
        """
        logger.debug('Sending {method} request to {url}. '
                     'args: {args!r}, kwargs: {kwargs!r}',
                     method=method, url=url, args=args, kwargs=kwargs)
        headers = kwargs.setdefault('headers', Headers())
        headers.setRawHeaders(b'user-agent', [self._user_agent])
        response = self._treq.request(
            method, url, *args, **kwargs)
        return response

    def head(self, url, *args, **kwargs):
        """
        Send HEAD request without checking the response.

        Note that ``_check_response`` is not called, as there will be no
        response body to check.

        :param str url: The URL to make the request to.
        """
        return self._send_request(u'HEAD', url, *args, **kwargs)

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
        return (
            self._send_request(u'GET', url, **kwargs)
            .addCallback(self._check_response, content_type=content_type))

    def _add_nonce(self, response):
        """
        Store a nonce from a response we received.

        :param twisted.web.iweb.IResponse response: The HTTP response.

        :return: The response, unmodified.
        """
        nonce = response.headers.getRawHeaders(
            REPLAY_NONCE_HEADER, [None])[0]
        if nonce is not None:
            try:
                decoded_nonce = jws.Header._fields['nonce'].decode(
                    nonce.decode('ascii'))
            except jose.DeserializationError as error:
                raise errors.BadNonce(nonce, error)
            logger.debug('Storing nonce: {nonce!r}', nonce=decoded_nonce)
            self._nonces.add(decoded_nonce)
            return response
        else:
            raise errors.MissingNonce(response)

    def _get_nonce(self, url):
        """
        Get a nonce to use in a request, removing it from the nonces on hand.
        """
        if len(self._nonces) > 0:
            return succeed(self._nonces.pop())
        else:
            return (
                self.head(url)
                .addCallback(self._add_nonce)
                .addCallback(lambda _: self._nonces.pop())
                )

    def post(self, url, obj, content_type=JSON_CONTENT_TYPE, **kwargs):
        """
        POST an object and check the response.

        :param str url: The URL to request.
        :param ~acme.jose.interfaces.JSONDeSerializable obj: The serializable
            payload of the request.
        :param bytes content_type: The expected content type of the response.
            By default, JSON.

        :raises txacme.client.ServerError: If server response body carries HTTP
            Problem (draft-ietf-appsawg-http-problem-00).
        :raises acme.errors.ClientError: In case of other protocol errors.
        """
        headers = kwargs.setdefault('headers', Headers())
        headers.setRawHeaders(b'content-type', [JSON_CONTENT_TYPE])
        return (
            self._get_nonce(url)
            .addCallback(self._wrap_in_jws, obj)
            .addCallback(
                lambda data: self._send_request(
                    u'POST', url, data=data, **kwargs))
            .addCallback(self._add_nonce)
            .addCallback(self._check_response, content_type=content_type)
            )

__all__ = [
    'Client', 'JWSClient', 'ServerError', 'JSON_CONTENT_TYPE',
    'JSON_ERROR_CONTENT_TYPE', 'REPLAY_NONCE_HEADER', 'fqdn_identifier']
