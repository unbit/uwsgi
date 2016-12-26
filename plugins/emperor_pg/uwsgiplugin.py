import os

NAME = 'emperor_pg'

CFLAGS = ['-I' + os.popen('pg_config --includedir').read().rstrip()]
LDFLAGS = []
LIBS = [
    '-L' + os.popen('pg_config --libdir').read().rstrip(),
    '-lpq'
]

GCC_LIST = ['emperor_pg']
