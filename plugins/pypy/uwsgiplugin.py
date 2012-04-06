import os,sys

from distutils import sysconfig

NAME='pypy'
GCC_LIST = ['../python/python_plugin', '../python/pyutils', '../python/pyloader', '../python/wsgi_handlers', '../python/wsgi_headers', '../python/wsgi_subhandler',
    '../python/web3_subhandler', '../python/pump_subhandler','../python/gil', '../python/uwsgi_pymodule', '../python/profiler', '../python/symimporter']

CFLAGS = ['-I' + sysconfig.get_python_inc(), '-I' + sysconfig.get_python_inc(plat_specific=True) ] 
CFLAGS.append('-DUWSGI_PYPY')

LIBS = ['-lpypy-c']
LDFLAGS = []
