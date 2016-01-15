#!/bin/bash
set -e

if [ "$1" = 'coverage' ]; then
  nosetests --with-xunit --xunit-testsuite-name=b2handle --cover-erase --cover-tests --cover-inclusive --cover-xml main_test_script.py
else
  exec "$@"
fi
