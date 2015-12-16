# B2HANDLE Docs

## Docker

The [Dockerfile](Dockerfile) contains instructions for building a [Docker](https://www.docker.com/) image for building the B2HANDLE documentation using [Sphinx](http://sphinx-doc.org/).


### Base Docker Image

* [eudat-b2handle](../Dockerfile)


### Installation

1. Install [Docker](https://www.docker.com/).

2. Build an image from parent Dockerfile: `cd /path/to/B2HANDLE && docker build -t eudat-b2handle .`

3. Build an image from this Dockerfile: `cd /path/to/B2HANDLE/docs && docker build -t eudat-b2handle-docs .`


#### Usage

To build B2HANDLE docs in standalone HTML files:

    docker run -it --rm eudat-b2handle-docs html

To see all available build options (equivalent to running `make help`):

    docker run -it --rm eudat-b2handle-docs

Using the `-v` flag you can also mount a directory from your Docker daemon’s host into the container and gain access to the generated doc files, e.g.:

    docker run -it --rm -v /path/to/B2HANDLE/docs:/opt/B2HANDLE/docs eudat-b2handle-docs html

The above command mounts the host directory, `/path/to/B2HANDLE/docs`, into the container at `/opt/B2HANDLE/docs`. The `/path/to/B2HANDLE/docs` mount overlays but does not remove the pre-existing content. Once the mount is removed, the content is accessible again, including the generated HTML files under `/path/to/B2HANDLE/docs/build/html`.
