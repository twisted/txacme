"""
ACME client API (like :mod:`acme.client`) implementation for Twisted.
"""
import re

from acme import errors, jose, jws, messages
from treq.client import HTTPClient
from twisted.internet.defer import succeed
from twisted.logger import Logger
from twisted.web.client import Agent, HTTPConnectionPool
from twisted.web.http_headers import Headers


logger = Logger()


def parse_header_links(value):
    links = []
    replace_chars = " '\""
    for val in re.split(", *<", value):
        try:
            url, params = val.split(";", 1)
        except ValueError:
            url, params = val, ''

        link = {}
        link["url"] = url.strip("<> '\"")
        for param in params.split(";"):
            try:
                key, value = param.split("=")
            except ValueError:
                break
            link[key.strip(replace_chars)] = value.strip(replace_chars)
        links.append(link)
    return links


class Client(object):
    """
    ACME client interface.
    """
    def __init__(self, reactor, directory, key, alg=jose.RS256,
                 treq_client=None):
        if treq_client is None:
            pool = HTTPConnectionPool(reactor)
            agent = Agent(reactor, pool=pool)
            self._client = JWSClient(HTTPClient(agent=agent), key, alg)
        else:
            self._client = JWSClient(treq_client, key, alg)
        self.directory = directory

    def register(self, new_reg=None):
        """
        Register.

        :param ~acme.messages.NewRegistration new_reg: The registration message
            to use, or :const:`None` to construct one (the default).

        :return: The registration resource.
        :rtype: ~acme.messages.RegistrationResource
        """
        if new_reg is None:
            new_reg = messages.NewRegistration()

        d = self._client.post(self.directory[new_reg], new_reg)
        d.addCallback(self._parse_regr_response)
        return d

    def _parse_regr_response(self, response):
        link = response.headers.getRawHeaders('link', [''])[0]
        links = parse_header_links(link)
        if 'terms-of-service' in links:
            terms_of_service = links['terms-of-service']['url']
        if 'next' in response.links:
            new_authzr_uri = response.links['next']['url']
        if new_authzr_uri is None:
            raise errors.ClientError('"next" link missing')


JSON_CONTENT_TYPE = 'application/json'
JSON_ERROR_CONTENT_TYPE = 'application/problem+json'
REPLAY_NONCE_HEADER = 'Replay-Nonce'


class JWSClient(object):
    """
    HTTP client using JWS messaging.
    """
    def __init__(self, treq_client, key, alg, user_agent='txacme'):
        self._treq = treq_client
        self._key = key
        self._alg = alg
        self._user_agent = user_agent

        self._nonces = set()

    def _wrap_in_jws(self, obj, nonce):
        """Wrap `JSONDeSerializable` object in JWS.

        .. todo:: Implement ``acmePath``.

        :param .JSONDeSerializable obj:
        :param bytes nonce:
        :rtype: `.JWS`
        """
        jobj = obj.json_dumps().encode()
        logger.debug('Serialized JSON: {jobj}', jobj=jobj)
        return (
            jws.JWS.sign(
                payload=jobj, key=self._key, alg=self._alg, nonce=nonce)
            .json_dumps())

    @classmethod
    def _check_response(cls, response, content_type=None):
        """Check response content and its type.
        .. note::
           Checking is not strict: wrong server response ``Content-Type``
           HTTP header is ignored if response is an expected JSON object
           (c.f. Boulder #56).
        :param str content_type: Expected Content-Type response header.
            If JSON is expected and not present in server response, this
            function will raise an error. Otherwise, wrong Content-Type
            is ignored, but logged.
        :raises .messages.Error: If server response body
            carries HTTP Problem (draft-ietf-appsawg-http-problem-00).
        :raises .ClientError: In case of other networking errors.
        """
        logger.debug('Received response {response} '
                     '(headers: {response.headers}): {response.content!r}',
                     response=response)

        response_ct = response.headers.getRawHeaders(
            'Content-Type', [None])[0]
        try:
            # TODO: response.json() is called twice, once here, and
            # once in _get and _post clients
            jobj = response.json()
        except ValueError:
            jobj = None

        if not response.ok:
            if jobj is not None:
                if response_ct != JSON_ERROR_CONTENT_TYPE:
                    logger.debug(
                        'Ignoring wrong Content-Type ({res!r}) for JSON Error',
                        res=response_ct)
                try:
                    raise messages.Error.from_json(jobj)
                except jose.DeserializationError as error:
                    # Couldn't deserialize JSON object
                    raise errors.ClientError((response, error))
            else:
                # response is not JSON object
                raise errors.ClientError(response)
        else:
            if jobj is not None and response_ct != JSON_CONTENT_TYPE:
                logger.debug(
                    'Ignoring wrong Content-Type ({res!r}) for JSON decodable '
                    'response', res=response_ct)

            if content_type == JSON_CONTENT_TYPE and jobj is None:
                raise errors.ClientError(
                    'Unexpected response Content-Type: {0}'.format(response_ct))

        return response

    def _send_request(self, method, url, *args, **kwargs):
        """Send HTTP request.

        :param str method: method for the new `requests.Request` object
        :param str url: URL for the new `requests.Request` object
        :raises requests.exceptions.RequestException: in case of any problems
        :returns: HTTP Response
        :rtype: `requests.Response`
        """
        logger.debug('Sending {method} request to {url}. '
                     'args: {args!r}, kwargs: {kwargs!r}',
                     method=method, url=url, args=args, kwargs=kwargs)
        headers = kwargs.setdefault('headers', Headers())
        if not headers.hasHeader('user-agent'):
            headers.setRawHeaders('user-agent', [self._user_agent])
        response = self._treq.request(method, url, *args, **kwargs)
        #logger.debug('Received %s. Headers: %s. Content: %r',
        #              response, response.headers, response.content)
        return response

    def head(self, *args, **kwargs):
        """Send HEAD request without checking the response.
        Note, that `_check_response` is not called, as it is expected
        that status code other than successfully 2xx will be returned, or
        messages2.Error will be raised by the server.
        """
        return self._send_request(b'HEAD', *args, **kwargs)

    def get(self, url, content_type=JSON_CONTENT_TYPE, **kwargs):
        """Send GET request and check response."""
        return (
            self._send_request(b'GET', url, **kwargs)
            .addCallback(self._check_request, content_type=content_type))

    def _add_nonce(self, response):
        nonce = response.headers.getRawHeaders(
            REPLAY_NONCE_HEADER, [None])[0]
        if nonce is not None:
            try:
                decoded_nonce = jws.Header._fields['nonce'].decode(nonce)
            except jose.DeserializationError as error:
                raise errors.BadNonce(nonce, error)
            logger.debug('Storing nonce: {nonce!r}', nonce=decoded_nonce)
            self._nonces.add(decoded_nonce)
        else:
            raise errors.MissingNonce(response)

    def _get_nonce(self, url):
        d = succeed(None)
        d.addCallback(lambda _: self.head(url))
        d.addCallback(self._add_nonce)
        d.addCallback(lambda _: self._nonces.pop())
        return d

    def post(self, url, obj, content_type=JSON_CONTENT_TYPE, **kwargs):
        """POST object wrapped in `.JWS` and check response."""
        return (
            self._get_nonce(url)
            .addCallback(lambda nonce: self._wrap_in_jws(obj, nonce))
            .addCallback(
                lambda data: self._send_request(b'POST', url, data=data, **kwargs))
            .addCallback(self._add_nonce)
            .addCallback(
                lambda response:
                self._check_response(response, content_type=content_type))
            )
