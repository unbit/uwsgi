import os

NAME='gridfs'

CFLAGS = ['-I/usr/include/mongo','-I/usr/local/include/mongo']
LDFLAGS = []

LIBS = []
if not 'UWSGI_MONGODB_NOLIB' in os.environ:
    LIBS.append('-lmongoclient')
    LIBS.append('-lstdc++')
    LIBS.append('-lboost_thread')
    LIBS.append('-lboost_system')
    LIBS.append('-lboost_filesystem')

GCC_LIST = ['plugin', 'gridfs.cc']
