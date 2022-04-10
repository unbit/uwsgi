try:
    import sysconfig
    def get_python_include(plat_specific=False):
        key = "include" if not plat_specific else "platinclude"
        return sysconfig.get_paths()[key]
except ImportError:
    from distutils import sysconfig
    get_python_include = sysconfig.get_python_inc

NAME = 'tornado'

CFLAGS = [
    '-I' + get_python_include(),
    '-I' + get_python_include(plat_specific=True),
]
LDFLAGS = []
LIBS = []

GCC_LIST = ['tornado']
