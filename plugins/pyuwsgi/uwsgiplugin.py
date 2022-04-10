import os, sys
try:
    import sysconfig
    def get_python_include(plat_specific=False):
        key = "include" if not plat_specific else "platinclude"
        return sysconfig.get_paths()[key]
except ImportError:
    from distutils import sysconfig
    get_python_include = sysconfig.get_python_inc

os.environ['UWSGI_PYTHON_NOLIB'] = '1'

NAME = 'pyuwsgi'

CFLAGS = [
    '-I' + get_python_include(),
    '-I' + get_python_include(plat_specific=True),
]
LDFLAGS = []
LIBS = []

PY3 = sys.version_info[0] >= 3
if not PY3:
    GCC_LIST = ['pyuwsgi']
else:
    GCC_LIST = []
