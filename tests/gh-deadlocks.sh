#!/bin/bash
set -u

PYTHON_VERSION="$1"
. "./tests/gh-shared.sh"


for INI_FILE in tests/deadlocks/*.ini ; do
  test_python_deadlocks "${PYTHON_VERSION}" "$INI_FILE"
done

results
