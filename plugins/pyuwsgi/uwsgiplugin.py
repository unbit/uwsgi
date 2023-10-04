import sysconfig
import os, sys

os.environ['UWSGI_PYTHON_NOLIB'] = '1'

NAME = 'pyuwsgi'

CFLAGS = [
    '-I' + sysconfig.get_path('include'),
    '-I' + sysconfig.get_path('platinclude'),
]
LDFLAGS = []
LIBS = []

PY3 = sys.version_info[0] >= 3
if not PY3:
    GCC_LIST = ['pyuwsgi']
else:
    GCC_LIST = []
