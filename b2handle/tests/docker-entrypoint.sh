#!/bin/bash
set -e

if [ "$1" = 'coverage' ]; then
  nosetests --with-xunit --xunit-testsuite-name=b2handle --with-coverage --cover-erase --cover-package=b2handle --cover-branches --cover-inclusive --cover-xml main_test_script.py
else
  exec "$@"
fi
