Contributing to txacme
######################

We use `tox` to run the test in a controller environment.

Each change should consider covering the followings:

* Create a release notes fragment. See section below.
* Write automated tests to the point of having at least 100% code coverage.
* Documenting the API.
* Update the documentation with usage examples.


Documenting the changes
-----------------------

`towncrier <https://github.com/hawkowl/towncrier>`_
is used to manage the release notes.

Beside the normal docstring and API documentation,
each change which is visible to the users of txame should be documented in
the release notes.

To avoid merge conflict in the release notes files, each item of the release
notes is create in a separate file located in `src/txacme/newsfragments/`

The file will have the following format: ISSUE_ID.ITEM_TYPE.
`ISSUE_ID` is the GitHub Issue ID targeted by this branch.

`ITEM_TYPE` is one of the
`default types <https://github.com/hawkowl/towncrier#news-fragments>`_
supported by Towncrier.


Executing tests and checking coverage
-------------------------------------

You can run all tests in a specific environment, or just a single test::

    $ tox -e py27-twlatest txacme.test.test_service
    $ tox -e py27-twlatest \
          txacme.test.test_service.AcmeIssuingServiceTests.test_timer_errors

You can check the test coverage, and diff coverage by running the dedicated
`coverage-report` tox env::

    $ tox -e py27-twlatest,coverage-report

There is a tox environment dedicated to code style checks::

    $ tox -e flake8

If executing the `tox` environment is too slow for you, you can always enable
a specific environment and execute the test with `trial`::

    $ . .tox/py27-twlatest/bin/activate
    $ pip install -e .
    $ trial txacme.test.test_service.AcmeIssuingServiceTests.test_timer_errors
