# vim:set ft=dockerfile:
FROM       debian:jessie

RUN        apt-get update && apt-get install -y --no-install-recommends \
           ca-certificates \
           python \
           python-pip \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

RUN     pip install pip && \
        pip install -Iv setuptools==44.0.0 && \
        pip install -Iv requests==2.23.0

ADD        . /opt/B2HANDLE

WORKDIR    /opt/B2HANDLE

RUN        python setup.py install
