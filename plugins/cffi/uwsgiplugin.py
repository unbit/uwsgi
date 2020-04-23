NAME = "cffi"

import os.path
import sys

CFLAGS = [
    "-pthread",
    "-DNDEBUG",
    f"-I{sys.base_exec_prefix}/include",
    f"-I{sys.prefix}/include",
    "-fvisibility=hidden",
]


LDFLAGS = [f"-L{sys.prefix}/bin/", f"-Wl,-rpath={sys.prefix}/bin/", "-lpypy3-c"]
LIBS = []
GCC_LIST = ["cffi_plugin"]

import subprocess

subprocess.check_call(["make"], cwd="plugins/cffi")

print("uwsgiplugin.py", dir())
