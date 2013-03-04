from distutils import sysconfig

NAME='gevent'
CFLAGS = ['-I' + sysconfig.get_python_inc(), '-I' + sysconfig.get_python_inc(plat_specific=True)]
LDFLAGS = []
LIBS = []

GCC_LIST = ['gevent', 'hooks']
