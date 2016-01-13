# B2HANDLE Testing

## Docker

The [Dockerfile](Dockerfile) contains instructions for building a [Docker](https://www.docker.com/) image for running the B2HANDLE test suites.


### Base Docker Image

* [eudat-b2handle](../../Dockerfile)


### Installation

1. Install [Docker](https://www.docker.com/).

2. Build an image from parent Dockerfile: `cd /path/to/B2HANDLE && docker build -t eudat-b2handle .`

3. Build an image from this Dockerfile: `cd /path/to/B2HANDLE/b2handle/tests && docker build -t eudat-b2handle-tests .`


#### Usage

This will run all B2HANDLE unit & integration tests and create an xml-formatted coverage report suitable for Jenkins/SonarQube:

    docker run -it --rm eudat-b2handle-tests

Using the `-v` flag you can also mount a directory from your Docker daemon’s host into the container and gain access to the generated coverage reports, e.g.: 

    docker run -it --rm -v /path/to/B2HANDLE/b2handle/tests:/opt/B2HANDLE/b2handle/tests eudat-b2handle-tests

The above command mounts the host directory, `/path/to/B2HANDLE/b2handle/tests`, into the container at `/opt/B2HANDLE/b2handle/tests`. The `/path/to/B2HANDLE/b2handle/tests` mount overlays but does not remove the pre-existing content. Once the mount is removed, the content is accessible again, including the generated `coverage.xml` file.
