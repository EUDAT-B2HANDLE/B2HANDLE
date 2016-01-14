# vim:set ft=dockerfile:
FROM       eudat-b2handle

RUN        easy_install pip
RUN        pip install coverage mock

VOLUME     /opt/B2HANDLE/b2handle/tests

WORKDIR    /opt/B2HANDLE/b2handle/tests

COPY       docker-entrypoint.sh ./

ENTRYPOINT ["./docker-entrypoint.sh"]

CMD        ["coverage"]
