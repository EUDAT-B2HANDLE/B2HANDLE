# vim:set ft=dockerfile:
FROM       eudat-b2handle

RUN        apt-get update && apt-get install -y --no-install-recommends \
           python-coverage \
           python-mock \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

VOLUME     /opt/B2HANDLE/b2handle/tests

WORKDIR    /opt/B2HANDLE/b2handle/tests

COPY       docker-entrypoint.sh ./

ENTRYPOINT ["./docker-entrypoint.sh"]

CMD        ["coverage"]
