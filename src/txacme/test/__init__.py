from os import getenv

import eliot.twisted
from hypothesis import settings

eliot.twisted.redirectLogsForTrial()
del eliot

settings.register_profile("light", settings(max_examples=20))
settings.register_profile("coverage", settings(max_examples=0))
settings.load_profile(getenv(u'HYPOTHESIS_PROFILE', 'default'))
del settings, getenv
