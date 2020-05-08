NAME = "pyexample"

import os.path
import sys

CFLAGS = [
    "-pthread",
    "-DNDEBUG",
    f"-I{sys.base_exec_prefix}/include",
    f"-I{sys.prefix}/include",
    "-fvisibility=hidden",
]

if sys.platform == 'linux':
    LDFLAGS = [f"-L{sys.prefix}/bin/", f"-Wl,-rpath={sys.prefix}/bin/", "-lpypy3-c"]
else:
    LDFLAGS = [f"-L{sys.prefix}/bin/", "-lpypy3-c"]


LDFLAGS = [f"-L{sys.prefix}/bin/", "-lpypy3-c"]
if sys.platform == 'linux':
    LDFLAGS += [f"-Wl,-rpath={venv}/bin/"]
LIBS = []
GCC_LIST = ["pyexample_plugin"]

import subprocess
subprocess.check_call(['make'], cwd="plugins/pyexample")
