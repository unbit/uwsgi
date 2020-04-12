"""
Process uwsgi cflags, dot-h into something cffi can use.
"""

import re
import subprocess

define_re = re.compile(".*#define\s+(\w+)\s+\d+")

uwsgi_cflags = subprocess.check_output(["../../uwsgi", "--cflags"]).decode("utf-8")

uwsgi_cdef = []
uwsgi_defines = []
uwsgi_cflags = uwsgi_cflags.split()

for cflag in uwsgi_cflags:
    if cflag.startswith("-D"):
        line = cflag[2:]
        if "=" in line:
            continue
        else:
            uwsgi_cdef.append("#define %s ..." % line)

uwsgi_dot_h = dot_h = subprocess.check_output(["../../uwsgi", "--dot-h"]).decode(
    "utf-8"
)

with open("defines.h", "w+") as defines:
    defines.write("\n".join(uwsgi_cdef))
    defines.write("\n\n")
    for line in uwsgi_dot_h.splitlines():
        match = define_re.match(line)
        if match and not match.group(1).startswith("__"):
            defines.write("#define %s ...\n" % match.group(1))
