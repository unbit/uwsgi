from distutils import sysconfig
import os

os.environ['UWSGI_PYTHON_NOLIB'] = '1'

NAME='pyuwsgi'
CFLAGS = ['-I' + sysconfig.get_python_inc(), '-I' + sysconfig.get_python_inc(plat_specific=True)]
LDFLAGS = []
LIBS = []

GCC_LIST = ['pyuwsgi']
