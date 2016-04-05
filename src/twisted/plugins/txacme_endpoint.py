from txacme.client import LETSENCRYPT_DIRECTORY, LETSENCRYPT_STAGING_DIRECTORY
from txacme.endpoint import _AcmeParser


le_parser = _AcmeParser('le', LETSENCRYPT_DIRECTORY)

lets_parser = _AcmeParser('lets', LETSENCRYPT_STAGING_DIRECTORY)
