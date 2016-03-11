from testtools import TestCase
from testtools.tests.matchers.helpers import TestMatchersInterface

from txacme.util import csr_for_names
from txacme.test.matchers import ValidForName
from txacme.test.test_client import RSA_KEY_512_RAW


class ValidForNameTests(TestMatchersInterface, TestCase):
    """
    `~txacme.test.matchers.ValidForName` matches if a CSR/cert is valid for the
    given name.
    """
    matches_matcher = ValidForName(u'example.com')
    matches_matches = [
        csr_for_names([u'example.com'], RSA_KEY_512_RAW),
        csr_for_names([u'example.invalid', u'example.com'], RSA_KEY_512_RAW),
        csr_for_names([u'example.com', u'example.invalid'], RSA_KEY_512_RAW),
        ]
    matches_mismatches = [
        csr_for_names([u'example.org'], RSA_KEY_512_RAW),
        csr_for_names([u'example.net', u'example.info'], RSA_KEY_512_RAW),
        ]

    str_examples = [
        ('ValidForName({!r})'.format(u'example.com'),
         ValidForName(u'example.com')),
        ]
    describe_examples = []
