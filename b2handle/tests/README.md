# B2HANDLE Testing

## Python 3 support

Currently it supports Python version 3.5, 3.6 , 3.7 , 3.9.

As of version 1.1.0 the B2HANDLE library supports Python 3.
Only for Python 3 users, the value of PYTHONHASHSEED variable should be set to 0 before running the tests.
This can be simply performed by:

    export PYTHONHASHSEED=0

## Testing with plain unittest/unittest2

Simply run:

    python -m b2handle.tests.main_test_script


## Testing with nose and/or coverage
Currently  Python version 3.5, 3.6 , 3.7 , 3.9 are supported. For Python 3.10 we are looking for a new version of testing tools. 

If you have installed the B2HANDLE module running `python setup.py install`, [nose](https://pypi.python.org/pypi/nose/) should already be available. Otherwise you can install it using your distribution's package manager or `pip` (recommended) as follows:

    pip install nose

Then run:

    nosetests --with-xunit --xunit-testsuite-name=b2handle --with-coverage --cover-erase --cover-package=b2handle --cover-branches --cover-inclusive --cover-xml main_test_script.py

The above will generate test results in the standard XUnit XML format and also provide an XML-formatted coverage report using Ned Batchelder's [Coverage.py](https://pypi.python.org/pypi/coverage). The latter can be installed using `pip` (recommended) as follows:

    pip install coverage

To generate test coverage reports without `nose`, run:

    coverage erase
    coverage run --branch -m b2handle.tests.main_test_script
    coverage xml -i

Alternatively you may run tests with nose and generate coverage reports as follows:

    python setup.py test

To configure the nosetests command see also nosetests section in setup.cfg.

### Notes for older versions of nose and coverage

* Support for branch coverage (`--branch` switch) is only available for Coverage.py version 3.2b1 and above.
* Sub-command syntax and generating reports in Cobertura-compatible XML format became available in Coverage.py version 3.1b1. With older versions run:

        coverage -e
        coverage -x main_test_script.py 

    or alternatively, using nose:

        nosetests --with-coverage --cover-erase --cover-inclusive main_test_script.py




## Testing with Docker

The [Dockerfile](Dockerfile) contains instructions for building a [Docker](https://www.docker.com/) image for running the B2HANDLE test suites.


### Base Docker Image

* [eudat-b2handle](../../Dockerfile)


### Installation

1. Install [Docker](https://www.docker.com/).

2. Build an image from parent Dockerfile: `cd /path/to/B2HANDLE && docker build -t eudat-b2handle .`

3. Build an image from this Dockerfile: `cd /path/to/B2HANDLE/b2handle/tests && docker build -t eudat-b2handle-tests .`


### Usage

This will run all B2HANDLE unit & integration tests and create an xml-formatted coverage report suitable for Jenkins/SonarQube:

    docker run -it --rm eudat-b2handle-tests

Using the `-v` flag you can also mount a directory from your Docker daemon’s host into the container and gain access to the generated coverage reports, e.g.: 

    docker run -it --rm -v /path/to/B2HANDLE/b2handle/tests:/opt/B2HANDLE/b2handle/tests eudat-b2handle-tests

The above command mounts the host directory, `/path/to/B2HANDLE/b2handle/tests`, into the container at `/opt/B2HANDLE/b2handle/tests`. The `/path/to/B2HANDLE/b2handle/tests` mount overlays but does not remove the pre-existing content. Once the mount is removed, the content is accessible again, including the generated `coverage.xml` file.
