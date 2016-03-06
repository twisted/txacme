"""
Eliot message and action definitions.
"""
from operator import methodcaller

from eliot import ActionType, Field, fields
from twisted.python.compat import unicode

NONCE = Field(
    u'nonce',
    lambda nonce: nonce.encode('hex').decode('ascii'),
    u'A nonce value')

LOG_JWS_SIGN = ActionType(
    u'txacme:jws:sign',
    fields(NONCE, key_type=unicode, alg=unicode),
    fields(),
    u'Signing a message with JWS')

LOG_JWS_HEAD = ActionType(
    u'txacme:jws:http:head',
    fields(),
    fields(),
    u'A JWSClient HEAD request')

LOG_JWS_GET = ActionType(
    u'txacme:jws:http:get',
    fields(),
    fields(),
    u'A JWSClient GET request')

LOG_JWS_POST = ActionType(
    u'txacme:jws:http:post',
    fields(),
    fields(),
    u'A JWSClient POST request')

LOG_JWS_REQUEST = ActionType(
    u'txacme:jws:http:request',
    fields(url=unicode),
    fields(Field.for_types(u'content_type',
                           [unicode, None],
                           u'Content-Type header field'),
           code=int),
    u'A JWSClient request')

LOG_JWS_CHECK_RESPONSE = ActionType(
    u'txacme:jws:http:check-response',
    fields(Field.for_types(u'response_content_type',
                           [unicode, None],
                           u'Content-Type header field'),
           expected_content_type=unicode),
    fields(),
    u'Checking a JWSClient response')

LOG_JWS_GET_NONCE = ActionType(
    u'txacme:jws:nonce:get',
    fields(),
    fields(NONCE),
    u'Consuming a nonce')

LOG_JWS_ADD_NONCE = ActionType(
    u'txacme:jws:nonce:add',
    fields(Field.for_types(u'raw_nonce',
                           [bytes, None],
                           u'Nonce header field')),
    fields(NONCE),
    u'Adding a nonce')

LOG_HTTP_PARSE_LINKS = ActionType(
    u'txacme:http:parse-links',
    fields(raw_link=unicode),
    fields(parsed_links=dict),
    u'Parsing HTTP Links')

DIRECTORY = Field(u'directory', methodcaller('to_json'), u'An ACME directory')

URL = Field(u'url', methodcaller('asText'), u'A URL object')

LOG_ACME_CONSUME_DIRECTORY = ActionType(
    u'txacme:acme:client:from-url',
    fields(URL, key_type=unicode, alg=unicode),
    fields(DIRECTORY),
    u'Creating an ACME client from a remote directory')

LOG_ACME_REGISTER = ActionType(
    u'txacme:acme:client:registration:create',
    fields(Field(u'registration',
                 methodcaller('to_json'),
                 u'An ACME registration')),
    fields(Field(u'registration',
                 methodcaller('to_json'),
                 u'The resulting registration')),
    u'Registering with an ACME server')

LOG_ACME_UPDATE_REGISTRATION = ActionType(
    u'txacme:acme:client:registration:update',
    fields(Field(u'registration',
                 methodcaller('to_json'),
                 u'An ACME registration'),
           uri=unicode),
    fields(Field(u'registration',
                 methodcaller('to_json'),
                 u'The updated registration')),
    u'Updating a registration')

LOG_ACME_CREATE_AUTHORIZATION = ActionType(
    u'txacme:acme:client:authorization:create',
    fields(Field(u'identifier',
                 methodcaller('to_json'),
                 u'An identifier')),
    fields(Field(u'authorization',
                 methodcaller('to_json'),
                 u'The authorization')),
    u'Creating an authorization')

LOG_ACME_ANSWER_CHALLENGE = ActionType(
    u'txacme:acme:client:challenge:answer',
    fields(Field(u'challenge_body',
                 methodcaller('to_json'),
                 u'The challenge body'),
           Field(u'response',
                 methodcaller('to_json'),
                 u'The challenge response')),
    fields(Field(u'challenge_resource',
                 methodcaller('to_json'),
                 u'The updated challenge')),
    u'Answering an authorization challenge')

LOG_ACME_POLL_AUTHORIZATION = ActionType(
    u'txacme:acme:client:authorization:poll',
    fields(Field(u'authorization',
                 methodcaller('to_json'),
                 u'The authorization resource')),
    fields(Field(u'authorization',
                 methodcaller('to_json'),
                 u'The updated authorization'),
           Field.for_types(u'retry_after',
                           [int, float],
                           u'How long before polling again?')),
    u'Polling an authorization')
