"""
Process uwsgi cflags, dot-h into something cffi can use.
"""

import re
import subprocess

# or could run the preprocessor to omit this on unsupported platforms
skip = set(("MSG_FASTOPEN", "UWSGI_DEBUG"))

define_re = re.compile(".*#define\s+(\w+)\s+\d+")

try:
    uwsgi_cflags = subprocess.check_output(["../../uwsgi", "--cflags"]).decode("utf-8")
except subprocess.CalledProcessError:
    uwsgi_cflags = ""

uwsgi_cdef = []
uwsgi_defines = []
uwsgi_cflags = uwsgi_cflags.split()

for cflag in uwsgi_cflags:
    if cflag.startswith("-D"):
        line = cflag[2:]
        if "=" in line or line in skip:
            continue
        else:
            uwsgi_cdef.append("#define %s ..." % line)

uwsgi_dot_h = open("../../uwsgi.h").read()

with open("_constants.h", "w+") as defines:
    defines.write("\n".join(uwsgi_cdef))
    defines.write("\n\n")
    for line in uwsgi_dot_h.splitlines():
        match = define_re.match(line)
        if match and not match.group(1).startswith("__") and not match.group(1) in skip:
            defines.write("#define %s ...\n" % match.group(1))
