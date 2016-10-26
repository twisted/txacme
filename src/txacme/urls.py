from twisted.python.url import URL


LETSENCRYPT_DIRECTORY = URL.fromText(
    u'https://acme-v01.api.letsencrypt.org/directory')


LETSENCRYPT_STAGING_DIRECTORY = URL.fromText(
    u'https://acme-staging.api.letsencrypt.org/directory')


__all__ = ['LETSENCRYPT_DIRECTORY', 'LETSENCRYPT_STAGING_DIRECTORY']
