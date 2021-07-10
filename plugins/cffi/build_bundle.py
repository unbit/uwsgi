#!/usr/bin/env python
"""
Create bundle to be used as cffi init code.
"""

import os.path
import gzip
import base64
import sys
import pprint

BUNDLED = {"_init": "cffi_init.py", "uwsgi": "uwsgi.py"}
OUTPUT = {}


def bundler(out):
    for key, filename in BUNDLED.items():
        with open(filename, "rb") as file:
            data = file.read()
            data = gzip.compress(data)
            data = base64.b64encode(data).decode("latin1")
            OUTPUT[key] = data

    with open("module_bundle.py", "r") as loader:
        for line in loader:
            out.write(line)
            if line.startswith("# MODULES"):
                out.write("\nMODULES =")
                pprint.pprint(OUTPUT, out)


if __name__ == "__main__":
    bundler(sys.stdout)
