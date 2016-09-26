=====================================================
txacme: A Twisted implementation of the ACME protocol
=====================================================

.. image:: https://readthedocs.org/projects/txacme/badge/?version=stable
   :target: http://txacme.readthedocs.org/en/stable/?badge=stable
   :alt: Documentation Status

.. image:: https://travis-ci.org/mithrandi/txacme.svg?branch=master
   :target: https://travis-ci.org/mithrandi/txacme
   :alt: CI status

.. image:: https://codecov.io/github/mithrandi/txacme/coverage.svg?branch=master
   :target: https://codecov.io/github/mithrandi/txacme?branch=master
   :alt: Coverage

.. teaser-begin

`ACME`_ is Automatic Certificate Management Environment, a protocol that allows
clients and certificate authorities to automate verification and certificate
issuance. The ACME protocol is used by the free `Let's Encrypt`_ Certificate
Authority.

``txacme`` is an implementation of the protocol for `Twisted`_, the
event-driven networking engine for Python.

``txacme`` is still under heavy development, and currently only an
implementation of the client side of the protocol is planned; if you are
interested in implementing or have need of the server side, please get in
touch!

``txacme``\ ’s documentation lives at `Read the Docs`_, the code on `GitHub`_.
It’s rigorously tested on Python 2.7, 3.4+, and PyPy.

.. _ACME: https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md

.. _Let's Encrypt: https://letsencrypt.org/

.. _Twisted: https://twistedmatrix.com/trac/

.. _Read the Docs: https://txacme.readthedocs.io/

.. _GitHub: https://github.com/mithrandi/txacme


.. image:: https://badges.gitter.im/txacme/Lobby.svg
   :alt: Join the chat at https://gitter.im/txacme/Lobby
   :target: https://gitter.im/txacme/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge