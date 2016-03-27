from os import getenv

import eliot.twisted
from hypothesis import HealthCheck, settings


eliot.twisted.redirectLogsForTrial()
del eliot

settings.register_profile(
    "coverage",
    settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow]))
settings.load_profile(getenv(u'HYPOTHESIS_PROFILE', 'default'))
del HealthCheck, getenv, settings
