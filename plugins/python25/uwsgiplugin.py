import os,sys

NAME='python25'

GCC_LIST = map(lambda x: '../python/' + x, ['python_plugin', 'pyutils', 'pyloader', 'wsgi_handlers', 'wsgi_headers', 'wsgi_subhandler', 'gil', 'uwsgi_pymodule'])

CFLAGS = os.popen('python2.5-config --cflags').read().rstrip().split()
CFLAGS.append('-Wno-unused-parameter')
CFLAGS.append('-Wno-strict-prototypes')
CFLAGS.append('-Dpython_plugin=python25_plugin')
LDFLAGS = os.popen('python2.5-config --ldflags').read().rstrip().split()
LIBS = os.popen('python2.5-config --libs').read().rstrip().split()
