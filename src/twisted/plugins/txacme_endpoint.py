from txacme._endpoint_parser import _AcmeParser
from txacme.directory import (
    LETSENCRYPT_DIRECTORY, LETSENCRYPT_STAGING_DIRECTORY)


le_parser = _AcmeParser('le', LETSENCRYPT_DIRECTORY)

lets_parser = _AcmeParser('lets', LETSENCRYPT_STAGING_DIRECTORY)
