API stability
=============

txacme is versioned according to `SemVer 2.0.0`_. In addition, since SemVer
does not make this explicit, versions following txacme 1.0.0 will have a
"rolling compatibility" guarantee: new major versions will not break behaviour
that did not already emit a deprecation warning in the latest minor version of
the previous major version series.

The current version number of 0.9.x is intended to reflect the
not-quite-finalized nature of the API. While it is not expected that the API
will change drastically, the 0.9 version series is intended to allow space for
users to experiment and identify any issues obstructing their use cases so that
these can be corrected before the API is finalized in the 1.0.0 release.

.. _SemVer 2.0.0: http://semver.org/spec/v2.0.0.html
