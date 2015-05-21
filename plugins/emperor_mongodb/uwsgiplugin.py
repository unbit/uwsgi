import os

NAME = 'emperor_mongodb'

CFLAGS = [
    '-I/usr/include/mongo',
    '-I/usr/local/include/mongo',
    '-std=c++11',
    '-Wno-error'
]
LDFLAGS = []

LIBS = ['-lstdc++']
if 'UWSGI_MONGODB_NOLIB' not in os.environ:
    LIBS.append('-lmongoclient')
    LIBS.append('-lboost_thread')
    LIBS.append('-lboost_filesystem')
    LIBS.append('-lboost_system')
    LIBS.append('-lboost_regex')


GCC_LIST = ['plugin', 'emperor_mongodb.cc']
