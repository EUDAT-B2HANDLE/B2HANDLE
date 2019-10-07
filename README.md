# B2HANDLE

The b2handle Python library is a client library for interaction with a [Handle System](https://handle.net) server, using the native REST interface introduced in Handle System 8. The library offers methods to create, update and delete Handles as well as advanced functionality such as searching over Handles using an additional search servlet and managing multiple location entries per Handle.

The library currently supports Python 2.6, 2.7, 3.5, 3.6 and 3.7, and requires at least a Handle System server 8.1.
The library requires OpenSSL v1.0.1 or higher.

# Test Coverage and Continuous Integration

Test status of the devel branch:

[![Build Status](https://jenkins.argo.grnet.gr/job/B2HANDLE_devel/badge/icon)](https://jenkins.argo.grnet.gr/job/B2HANDLE_devel) [![(click here to check out test coverage)](http://jenkins.argo.grnet.gr:9913/jenkins/c/http/jenkins.argo.grnet.gr/job/B2HANDLE_devel/PYTHON_VERSION=2.7)](https://jenkins.argo.grnet.gr/job/B2HANDLE_devel/PYTHON_VERSION=2.7/cobertura/)

B2Handle has a unit test coverage of approximately 90%. Every addition to the devel branch is automatically unit tested. The test can be found in b2handle/tests and easily run using the command "python main_test_script.py". For the current test coverage, please click on the badge and link above.

In addition to the unit tests, integration tests cover the reading, writing and searching of handles. As these needs credentials and write access to a real server, these are not run on GitHub. However, every user with access to a handle server can add their own credentials and run the integration tests in his/her system (using the command "python main_test_script.py testtype write", or "read", or "search", or all three).


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

B2Handle uses [Sphinx](http://www.sphinx-doc.org) for documentation, requiring at least version 1.3. Sphinx can be installed via pip. To build HTML documentation locally, then run:
```bash
python setup.py build_sphinx
```

# Developer team

Machines don't write software, people do. Please refer to [CONTRIBUTORS.md](CONTRIBUTORS.md) to learn about those who spent effort in creating this product.

# License

Copyright 2015-2016, Deutsches Klimarechenzentrum GmbH, GRNET S.A., SURFsara

   The B2Handle library is licensed under the Apache License,
   Version 2.0 (the "License"); you may not use this product except in 
   compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.



