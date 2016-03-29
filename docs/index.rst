txacme: A Twisted implementation of the ACME protocol
=====================================================

.. include:: ../README.rst
   :start-after: teaser-begin


API entry points
----------------

There are several possible starting points for making use of txacme.


String endpoint parser
~~~~~~~~~~~~~~~~~~~~~~

..  todo:: None of the stuff in this section actually exists yet.

The simplest part of txacme to use is the stream server endpoint. Two endpoint
parsers are provided, under the ``le:`` (Let's Encrypt) and ``lets:`` (Let's
Encrypt Test in Staging) prefixes. You will need to pass a directory to store
certificates in, and the underlying endpoint to listen on.

A typical example::

  le:/srv/www/certs:tcp:443

The ACME client key will be stored in ``client.key`` in the cert directory; if
this file does not exist, a key will automatically be created for you.
Certificates (and chain certificates and keys) in PEM format will be stored in
files named like ``some.domain.name.pem`` in the certificate directory; the
appropriate certificate will be selected based on the servername that the
client sends by SNI, so ancient clients that do not perform SNI will not be
able to connect.

In the event where you do not have an existing certificate and wish to issue
one, simply place a blank file of the appropriate name in the certificate
directory. This will be treated the same way as an expired certificate, and a
new certificate will then be issued on startup. For example::

  touch /srv/www/certs/example.com.pem

This endpoint uses the ``tls-sni-01`` challenge type to perform authorization
for your domains; this requires that your server is reachable on port 443 for
those domains (the actual port you listen on can be different, as long as you
are forwarding port 443 connections to your listening port).

Periodically (at startup, and then every 24 hours) a check will be performed
for expiring certificates; if a certificate will expire in less than 30 days'
time, it will be reissued. If the reissue fails, it will just be retried at the
next check. If a certificate will expire in less than 15 days' time, and
reissue fails, a message will be logged at *CRITICAL* level.


String endpoint
~~~~~~~~~~~~~~~

If you need to customize the behaviour of the endpoint, or you are not using
endpoint strings, instantiating the endpoint directly is quite simple.

..  todo:: Actually implement and document this.


Issuing service
~~~~~~~~~~~~~~~

The endpoint is a simple wrapper that combines the functionality of the
`txsni`_ endpoint for handling SNI, and the issuing service which takes care of
(re)issuing certificates using an ACME service.

.. autoclass:: txacme.service.AcmeIssuingService
   :noindex:
   :members:

If you are not using the endpoint, then the `.ICertificateStore` and
`.ITLSSNI01Responder` implementations in txacme are likely insufficient for
your use case, so you will need to provide your own implementations of these.
For example, an implementation might manage the certificate configuration of a
cloud load balancer.

.. todo:: Currently, only the ``tls-sni-01`` challenge method is supported. An
   API change is planned that will allow providing responders for other
   challenge types, such as ``http-01`` or ``dns-01``.

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

