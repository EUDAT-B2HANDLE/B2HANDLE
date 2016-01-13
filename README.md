# B2HANDLE [![Build Status](https://jenkins.argo.grnet.gr/job/B2HANDLE_devel/badge/icon)](https://jenkins.argo.grnet.gr/job/B2HANDLE_devel) ![Test Coverage](http://jenkins.argo.grnet.gr:9913/jenkins/c/http/jenkins.argo.grnet.gr/job/B2HANDLE_devel)


## Docker
The [Dockerfile](Dockerfile) contains instructions for building a [Docker](https://www.docker.com/) image with the B2HANDLE library installed.


### Base Docker Image

* [debian:jessie](https://hub.docker.com/_/debian/)


### Installation

1. Install [Docker](https://www.docker.com/).

2. Build an image from Dockerfile: `docker build -t eudat-b2handle .`


#### Running `python`

    docker run -it --rm eudat-b2handle python

    Python 2.7.9 (default, Mar  1 2015, 12:57:24) 
    [GCC 4.9.2] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from b2handle.handleclient import EUDATHandleClient
    >>>
