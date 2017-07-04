import hashlib

from acme import jose


def _validation(response):
    """
    Get the validation value for a challenge response.
    """
    # TODO: This is just duplicated directly from _libcloud.py. Should we hoist
    # this out to a common utility module?
    h = hashlib.sha256(response.key_authorization.encode("utf-8"))
    return jose.b64encode(h.digest()).decode()
