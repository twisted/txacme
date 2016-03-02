# -*- coding: utf-8 -*-
"""
Interface definitions for txacme.
"""
from zope.interface import Interface


class ITLSSNI01Responder(Interface):
    """
    Configuration for a tls-sni-01 challenge responder.

    The actual responder may exist somewhere else, this interface is merely for
    an object that knows how to configure it.
    """
    def start_responding(hostname, key_authorization):
        """
        Start responding for a particular challenge.

        .. seealso:: `txacme.util.generate_tls_sni_01_cert`

        :param str hostname: The hostname being challenged.
        :param str key_authorization: The "key authorization", as defined in
            draft-ietf-acme-acme-01 § 7.1.

        :rtype: `~twisted.internet.defer.Deferred`
        :return: A deferred firing when the given hostname is ready to respond
                 with the given authorization.
        """

    def stop_responding(hostname, key_authorization):
        """
        Stop responding for a particular challenge.

        May be a noop if a particular responder does not need or implement
        explicit cleanup; implementations should not rely on this method always
        being called.
        """
