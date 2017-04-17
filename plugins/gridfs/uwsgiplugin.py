import os

NAME = 'gridfs'

CFLAGS = ['-I/usr/include/mongo', '-I/usr/local/include/mongo']
LDFLAGS = []

LIBS = []
if 'UWSGI_MONGODB_NOLIB' not in os.environ:
    LIBS.append('-lmongoclient')
    LIBS.append('-lstdc++')
    LIBS.append('-lboost_thread')
    LIBS.append('-lboost_system')
    LIBS.append('-lboost_filesystem')
    LIBS.append('-lboost_regex')

GCC_LIST = ['plugin', 'gridfs.cc']
