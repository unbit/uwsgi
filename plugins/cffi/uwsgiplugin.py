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

if sys.platform == "linux":
    LDFLAGS = [f"-L{sys.prefix}/bin/", f"-Wl,-rpath={sys.prefix}/bin/", "-lpypy3-c"]
else:
    LDFLAGS = [f"-L{sys.prefix}/bin/", "-lpypy3-c"]
LIBS = []
GCC_LIST = ["cffi_plugin"]

import subprocess

subprocess.check_call(["make"], cwd="plugins/cffi")


def post_build(config):
    # find pypy3-c on osx
    if sys.platform == "darwin":
        rpath = os.path.dirname(sys.executable)
        subprocess.check_call(
            ["install_name_tool", "-add_rpath", rpath, "cffi_plugin.so"]
        )
