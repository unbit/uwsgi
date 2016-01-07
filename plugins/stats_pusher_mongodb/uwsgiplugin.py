import os

NAME = 'stats_pusher_mongodb'

CFLAGS = [
    '-I/usr/include/mongo',
    '-I/usr/local/include/mongo',
    '-std=c++11',
    '-Wno-error'
]
LDFLAGS = []

LIBS = []
if not 'UWSGI_MONGODB_NOLIB' in os.environ:
    LIBS.append('-lmongoclient')
    LIBS.append('-lboost_thread')
    LIBS.append('-lboost_filesystem')

GCC_LIST = ['plugin', 'stats_pusher_mongodb.cc']
