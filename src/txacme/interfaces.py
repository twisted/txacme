# -*- coding: utf-8 -*-
"""
Interface definitions for txacme.
"""
from zope.interface import Attribute, Interface


class IResponder(Interface):
    """
    Configuration for a ACME challenge responder.

    The actual responder may exist somewhere else, this interface is merely for
    an object that knows how to configure it.
    """
    challenge_type = Attribute(
        """
        The type of challenge this responder is able to respond for.

        Must correspond to one of the types from `acme.challenges`; for
        example, ``u'tls-sni-01'``.
        """)

    def start_responding(response):
        """
        Start responding for a particular challenge.

        :param response: The `acme.challenges` response object; the exact type
            of this object depends on the challenge type.

        :rtype: ``Deferred``
        :return: A deferred firing when the challenge is ready to be verified.
        """

    def stop_responding(server_name):
        """
        Stop responding for a particular challenge.

        May be a noop if a particular responder does not need or implement
        explicit cleanup; implementations should not rely on this method always
        being called.

        :param response: The `acme.challenges` response object; the exact type
            of this object depends on the challenge type.
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


__all__ = ['IResponder', 'ICertificateStore']
