# B2HANDLE [![Build Status](https://jenkins.argo.grnet.gr/job/B2HANDLE_devel/badge/icon)](https://jenkins.argo.grnet.gr/job/B2HANDLE_devel) [![Test Coverage](http://jenkins.argo.grnet.gr:9913/jenkins/c/http/jenkins.argo.grnet.gr/job/B2HANDLE_devel/PYTHON_VERSION=2.7)](https://jenkins.argo.grnet.gr/job/B2HANDLE_devel/PYTHON_VERSION=2.7/cobertura/)


The b2handle Python library is a client library for interaction with a [Handle System](https://handle.net) server, using the native REST interface introduced in Handle System 8. The library offers methods to create, update and delete Handles as well as advanced functionality such as searching over Handles using an additional search servlet and managing multiple location entries per Handle.

The library currently supports Python 2.6 and Python 2.7 and requires at least a Handle System server 8.1.

# Installation and use

Build an egg:

```bash
python setup.py bdist_egg
```

Install the library via pip:

```bash
pip install <egg file>
```

For more information on the methods offered by the library, please consult the [technical documentation](http://eudat-b2safe.github.io/B2HANDLE). The documentation also contains information on how to set up correct certificates for the Handle Server so it accepts modification REST requests and how to set up client authentication using public keys.

## Docker support
The library can also be used in combination with Docker. The [Dockerfile](Dockerfile) contains instructions for building a [Docker](https://www.docker.com/) image with the B2HANDLE library installed.

### Base Docker Image

* [debian:jessie](https://hub.docker.com/_/debian/)

### Installation

1. Install [Docker](https://www.docker.com/).

2. Build an image from Dockerfile: `docker build -t eudat-b2handle .`

### Running Python

    docker run -it --rm eudat-b2handle python

    Python 2.7.9 (default, Mar  1 2015, 12:57:24) 
    [GCC 4.9.2] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from b2handle.handleclient import EUDATHandleClient
    >>>

# Building the documentation

B2Handle uses [Sphinx](http://www.sphinx-doc.org) for documentation, requiring at least version 1.3. To build HTML documentation locally, run:
```bash
cd docs
make html
```

