txacme changelog
~~~~~~~~~~~~~~~~

.. towncrier release notes start

Txacme 0.9.1 (2016-12-08)
=========================

Features
--------

- INCOMPATIBLE CHANGE: AcmeIssuingService now takes a client creator,
  rather than a client, and invokes it for every issuing attempt.
  (#21)
- INCOMPATIBLE CHANGE: The ``*_DIRECTORY`` constants are now in
  txacme.urls. (#28)
- INCOMPATIBLE CHANGE: ``IResponder.start_responding`` and
  ``IResponder.stop_responding`` now take the server_name and
  challenge object in addition to the challenge response object. (#60)
- AcmeIssuingService now logs info messages about what it is doing.
  (#38)
- txacme.challenges.LibcloudDNSResponder implements a dns-01 challenge
  responder using libcloud. Installing txacme[libcloud] is necessary
  to pull in the dependencies for this. (#59)
- ``txacme.challenges.HTTP01Responder``, an http-01 challenge
  responder that can be embedded into an existing twisted.web
  application. (#65)
- ``txacme.endpoint.load_or_create_client_key`` gets a client key from
  the certs directory, using the same logic as the endpoints. (#71)
- ``AcmeIssuingService`` now accepts an ``email`` parameter which it
  adds to the ACME registration. In addition, existing registrations
  are updated with this email address. (#72)
- ``AcmeIssuingService`` now has a public ``issue_cert`` method for
  safely issuing a new cert on demand. (#76)

Bugfixes
--------

- ``txacme.client.JWSClient`` now automatically retries a POST request
  that fails with a ``badNonce`` error. (#66)
- ``txacme.store.DirectoryStore`` now handles bytes mode paths
  correctly. (#68)
- The txacme endpoint plugin now lazily imports the rest of the code,
  avoiding ReactorAlreadyInstalled errors in various cases. (#79)

Improved Documentation
----------------------

- The contents of the certificates directory, and compatibility with
  txsni, is now documented. (#35)

Misc
----

- #67


Txacme 0.9.0 (2016-04-10)
=========================

Features
--------

- Initial release! (#23)
