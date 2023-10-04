import os
import sysconfig

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

NAME = 'gevent'

CFLAGS = ['-I' + i for i in filter(os.path.exists, get_includes())]
LDFLAGS = []
LIBS = []

GCC_LIST = ['gevent', 'hooks']
