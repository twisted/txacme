txacme: A Twisted implementation of the ACME protocol
=====================================================

.. include:: ../README.rst
   :start-after: teaser-begin


API entry points
----------------

There are several possible starting points for making use of txacme.


Server endpoint string
~~~~~~~~~~~~~~~~~~~~~~

.. todo:: None of the stuff in this section actually exists yet.

The simplest part of txacme to use is the stream server endpoint. Two endpoint
parsers are provided, under the ``le:`` (Let's Encrypt) and ``lets:`` (Let's
Encrypt Test in Staging) prefixes. The endpoint takes as parameters a directory
to store certificates in, and the underlying endpoint to listen on.

.. note:: The Let's Encrypt staging environment generates certificates signed
   by *Fake LE Intermediate X1*, but does not have the stringent limits that
   the production environment has, so using it for testing before switching to
   the production environment is highly recommended.

A typical example::

  twistd -n web --port lets:/srv/www/certs:tcp:443 --path /srv/www/root

.. note:: The certificate directory must be writable by the user the
   application is running as.

The ACME client key will be stored in ``client.key`` in the cert directory. If
this file does not exist, a new key will automatically be generated.
Certificates (and chain certificates and keys) in PEM format will be stored in
files named like ``some.domain.name.pem`` in the certificate directory. The
appropriate certificate will be selected based on the servername that the
client sends by SNI, so clients that do not perform SNI will not be able to
connect.

In the event that there is no existing certificate available for a domain, an
empty file can be used. This will be treated the same way as an expired
certificate, and a new certificate will then be issued on startup. For
example::

  touch /srv/www/certs/example.com.pem

.. note:: This endpoint uses the ``tls-sni-01`` challenge type to perform
   authorization; this requires that the endpoint is reachable on port 443 for
   those domains (possibly via port forwarding).

.. note:: A certificate directored can be shared amongst multiple applications,
   using ``le:`` for the application running on port 443 to keep the
   certificates up to date, and ``txsni:`` for the other applications to make
   use of the same certificates.

At startup, and periodically (every 24 hours), a check will be performed for
expiring certificates; if a certificate will expire in less than 30 days' time,
it will be reissued. If the reissue fails, it will be retried at the next
check. If a certificate will expire in less than 15 days' time, and reissue
fails, a message will be logged at *CRITICAL* level.


Server endpoint API
~~~~~~~~~~~~~~~~~~~

The endpoint can be instantiated directly as well; this allows extra
customizations beyond what the string syntax provides for.

.. todo:: Actually implement and document this.


Issuing service
~~~~~~~~~~~~~~~

The endpoint is a simple wrapper that combines the functionality of the
`txsni`_ endpoint for handling SNI, and the issuing service which takes care of
(re)issuing certificates using an ACME service.

.. autoclass:: txacme.service.AcmeIssuingService
   :noindex:
   :members:

The `.ICertificateStore` and `.IResponder` interfaces are the main extension
points for using the issuing service directly. For example, a custom
implementation might manage the certificate configuration of a cloud load
balancer, implementing the ``dns-01`` challenge type by modifying DNS entries
in the cloud DNS configuration.

.. _txsni: https://github.com/glyph/txsni


API documentation
=================

.. toctree::
   :maxdepth: 2

   API documentation </api/modules>


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

