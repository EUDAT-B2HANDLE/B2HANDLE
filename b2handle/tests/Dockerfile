# vim:set ft=dockerfile:
FROM       python:2.7.9

RUN        pip install -U "pip < 21.0" && \
           pip install -U "setuptools < 45"
RUN        pip install \
           mock \
           coverage \
           nose

ADD        . /opt/B2HANDLE
RUN        cd /opt/B2HANDLE && \
           python setup.py install

WORKDIR    /opt/B2HANDLE/b2handle/tests

CMD ["./docker-entrypoint.sh", "coverage"]