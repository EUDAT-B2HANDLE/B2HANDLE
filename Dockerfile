# vim:set ft=dockerfile:
FROM       debian:jessie

RUN        apt-get update && apt-get install -y --no-install-recommends \
           ca-certificates \
           python \
           python-setuptools \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

ADD        . /opt/B2HANDLE

WORKDIR    /opt/B2HANDLE

RUN        python setup.py install
