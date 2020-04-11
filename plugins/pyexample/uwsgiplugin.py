NAME = "pyexample"

import os.path
orig = os.path.expanduser("~/opt/pypy3.6-7.1.1-beta-linux_x86_64-portable")
venv = os.path.expanduser("~/prog/uwsgi/.venv")

CFLAGS = [
    "-pthread",
    "-DNDEBUG",
    f"-I{venv}/include",
    f"-I{orig}/include",
    "-fvisibility=hidden"
]


LDFLAGS = [f"-L{venv}/bin/", f"-Wl,-rpath={venv}/bin/", "-lpypy3-c"]
LIBS = []
GCC_LIST = ["pyexample_plugin"]

import subprocess
subprocess.check_call(['make'], cwd="plugins/pyexample")