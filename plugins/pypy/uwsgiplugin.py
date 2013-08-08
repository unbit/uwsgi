NAME='pypy'
LDFLAGS = []
LIBS = []
GCC_LIST = ['pypy_plugin']
BINARY_LIST = [ ('_uwsgi_pypy_setup','pypy_setup.py')]
CFLAGS = []
try:
    import __pypy__
    import sys
    CFLAGS.append('-DUWSGI_PYPY_HOME="\\"%s\\""' % sys.prefix)
except:
    pass
