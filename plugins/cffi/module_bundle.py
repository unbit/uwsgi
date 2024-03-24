"""
Load Python modules from strings. You know, for tracebacks.

cffi can embed a single module for initialization. This lets us
have several, and shows good tracebacks with source code printouts
when there are errors in those modules.
"""

import sys
import os
import importlib.abc, importlib.util
import gzip
import base64


def unpack(data):
    return gzip.decompress(base64.b64decode(data))


class StringLoader(importlib.abc.SourceLoader):
    """
    Allow inspection of "built-in" modules that are embedded as strings.
    """

    def __init__(self, data):
        self.data = data

    def get_source(self, fullname):
        try:
            return unpack(self.data[fullname]).decode("utf-8")
        except KeyError:
            raise ImportError()

    def get_data(self, path):
        path = path.partition("/")[-1][:-3]
        try:
            return unpack(self.data[path])
        except KeyError:
            raise ImportError()

    def get_filename(self, fullname):
        return "<cffi plugin>/" + fullname + ".py"


# MODULES go here

loader = StringLoader(MODULES)

for module_name in MODULES:
    spec = importlib.util.spec_from_loader(module_name, loader, origin=module_name)
    # spec.has_location = True
    module = importlib.util.module_from_spec(spec)
    if module_name != "_init":
        sys.modules[module_name] = module
    spec.loader.exec_module(module)
