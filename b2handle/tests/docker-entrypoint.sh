#!/bin/bash
set -e

if [ "$1" = 'coverage' ]; then
  python -m coverage run main_test_script.py
  python -m coverage xml --include="*/b2handle/*" --omit="*/tests/*"
else
  exec "$@"
fi
