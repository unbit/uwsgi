
# please read README in this directory
import os

PYPY_HOME = os.environ.get('PYPY_HOME', None)
if PYPY_HOME is None:
    print "Please set PYPY_HOME to wherever your libpypy-c.so leaves"
    raise Exception

NAME='pypy'
LDFLAGS = ['-L' + PYPY_HOME]
LIBS = ['-lpypy-c']
GCC_LIST = ['pypy_plugin']
CFLAGS = ['-Iplugins/pypy']
