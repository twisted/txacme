from os import getenv
from hypothesis import settings
from ._version import get_versions
__version__ = get_versions()['version']
del get_versions

settings.register_profile("light", settings(max_examples=10))
settings.register_profile("coverage", settings(max_examples=0))
settings.load_profile(getenv(u'HYPOTHESIS_PROFILE', 'default'))
del settings, getenv
