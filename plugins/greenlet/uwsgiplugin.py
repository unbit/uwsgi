try:
    from distutils import sysconfig
    paths = [
        sysconfig.get_python_inc(),
        sysconfig.get_python_inc(plat_specific=True),
    ]
except ImportError:
    import sysconfig
    paths = [
        sysconfig.get_path('include'),
        sysconfig.get_path('platinclude'),
    ]

NAME = 'greenlet'

CFLAGS = ['-I' + path for path in paths]
LDFLAGS = []
LIBS = []

GCC_LIST = ['greenlet']
