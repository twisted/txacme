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
    def start_responding(server_name):
        """
        Start responding for a particular challenge.

        ..  seealso:: `txacme.util.generate_tls_sni_01_cert`

        :param str server_name: The server name to respond to: ie.
            `u'<hex>.<hex>.acme.invalid'`.

        :rtype: `~twisted.internet.defer.Deferred`
        :return: A deferred firing when the given hostname is ready to respond
                 with the given authorization.
        """

    def stop_responding(server_name):
        """
        Stop responding for a particular challenge.

        May be a noop if a particular responder does not need or implement
        explicit cleanup; implementations should not rely on this method always
        being called.

        :param str server_name: The server name to stop responding for: ie.
            `u'<hex>.<hex>.acme.invalid'`.
        """


class ICertificateStore(Interface):
    """
    A store of certificate/keys/chains.
    """
    def get(self, server_name):
        """
        Retrieve the current PEM objects for the given server name.

        :param str server_name: The server name.

        :raises KeyError: if the given name does not exist in the store.

        :return: ``Deferred[List[:ref:`pem-objects`]]``
        """

    def store(self, server_name, pem_objects):
        """
        Store PEM objects for the given server name.

        Implementations do not have to permit invoking this with a server name
        that was not already present in the store.

        :param str server_name: The server name to update.
        :param pem_objects: A list of :ref:`pem-objects`; must contain exactly
            one private key, a certificate corresponding to that private key,
            and zero or more chain certificates.

        :rtype: ``Deferred``
        """

    def as_dict(self):
        """
        Get all certificates in the store.

        :rtype: ``Deferred[Dict[str, List[:ref:`pem-objects`]]]``
        :return: A deferred firing with a dict mapping server names to
                 :ref:`pem-objects`.
        """


__all__ = ['ITLSSNI01Responder', 'ICertificateStore']
