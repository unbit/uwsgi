#!/usr/bin/env python
# Find functions in pymodule that are missing from uwsgi.py
# Compile both plugins, then run this script.

import os.path
import json
import subprocess

script = "import uwsgi, json; print(json.dumps(sorted(dir(uwsgi))))"
CFFI = ["./uwsgi", "--plugin", "cffi", "--socket", ":", "--cffi-eval", script]
PYMODULE = ["./uwsgi", "--plugin", "python", "--socket", ":", "--eval", script]

cffi = [
    line
    for line in subprocess.run(
        CFFI, cwd="../..", capture_output=True, encoding="utf-8"
    ).stdout.splitlines()
    if line.startswith("[")
][0]
pymodule = [
    line
    for line in subprocess.run(
        PYMODULE, cwd="../..", capture_output=True, encoding="utf-8"
    ).stderr.splitlines()
    if line.startswith("[")
][0]

cffi_api = set(json.loads(cffi))
pymodule_api = set(json.loads(pymodule))

print("Missing functions:")
print("\n".join(sorted(pymodule_api - cffi_api)))

print("\nExtra functions:")
print("\n".join(sorted(cffi_api - pymodule_api)))
