import sysconfig
import os, sys

def get_includes():
    try:
        from distutils import sysconfig as legacy
    except ImportError:
        legacy = None

    yield sysconfig.get_path('include')
    yield sysconfig.get_path('platinclude')
    if legacy:
        yield legacy.get_python_inc()
        yield legacy.get_python_inc(plat_specific=True)

os.environ['UWSGI_PYTHON_NOLIB'] = '1'

NAME = 'pyuwsgi'

CFLAGS = ['-I' + i for i in filter(os.path.exists, get_includes())]
LDFLAGS = []
LIBS = []

PY3 = sys.version_info[0] >= 3
if not PY3:
    GCC_LIST = ['pyuwsgi']
else:
    GCC_LIST = []
