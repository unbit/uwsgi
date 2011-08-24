import os,sys

NAME='python31'

GCC_LIST = map(lambda x: '../python/' + x, ['python_plugin', 'pyutils', 'pyloader', 'wsgi_handlers', 'wsgi_headers', 'wsgi_subhandler', 'web3_subhandler', 'pump_subhandler', 'gil', 'uwsgi_pymodule', 'profiler', 'symimporter'])

CFLAGS = os.popen('python3.1-config --cflags').read().rstrip().split()
CFLAGS.append('-Wno-unused-parameter')
CFLAGS.append('-Wno-strict-prototypes')
CFLAGS.append('-Dpython_plugin=python31_plugin')
LDFLAGS = os.popen('python3.1-config --ldflags').read().rstrip().split()
LIBS = os.popen('python3.1-config --libs').read().rstrip().split()
