#!/bin/bash
set -u

RACK_VERSION="$1"
. "./tests/gh-shared.sh"


for RACK in examples/config2.ru ; do
  test_rack "${RACK_VERSION}" "${RACK}"
done

results
