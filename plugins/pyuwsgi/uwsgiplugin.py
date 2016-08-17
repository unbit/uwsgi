from distutils import sysconfig
import os, sys

os.environ['UWSGI_PYTHON_NOLIB'] = '1'

NAME='pyuwsgi'
CFLAGS = ['-I' + sysconfig.get_python_inc(), '-I' + sysconfig.get_python_inc(plat_specific=True)]
LDFLAGS = []
LIBS = []

PY3 = sys.version_info[0] >= 3
if not PY3:
    GCC_LIST = ['pyuwsgi']
else:
    GCC_LIST = []
