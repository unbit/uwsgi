#!/bin/bash
set -u

PYTHON_VERSION="$1"
. "./tests/gh-shared.sh"


for WSGI_FILE in tests/staticfile.py tests/testworkers.py tests/testrpc.py ; do
  test_python "${PYTHON_VERSION}" "${WSGI_FILE}"
done

results
