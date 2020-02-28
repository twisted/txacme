Using txacme
============

There are several possible ways to make use of txacme:

* An issuing service for keeping certificates in a certificate store up to date;

* Lowest-level public API for interacting with an ACME server.


Issuing service
---------------

The issuing service takes care of certificate issuance, renewal and retry on
errors.

The service is linked to an ICertificateStore which takes care of storing
the issued certificates.
The certificate store can be used to receive hooks get an update whenever a
new certificate was issued.

.. autoclass:: txacme.service.AcmeIssuingService
   :noindex:
   :members:

The `~txacme.interfaces.ICertificateStore` and `~txacme.interfaces.IResponder`
interfaces are the main extension points for using the issuing service
directly. For example, a custom implementation of
`~txacme.interfaces.ICertificateStore` might manage the certificate
configuration of a cloud load balancer, implementing the ``dns-01`` challenge
type by modifying DNS entries in the cloud DNS configuration.


Certificate storage
-------------------

.. autoclass:: txacme.interface.ICertificateStore
   :noindex:
   :members: