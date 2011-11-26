import os

NAME='probepg'
CFLAGS = os.popen('pg_config --cflags').read().rstrip().split()
CFLAGS.append('-I' + os.popen('pg_config --includedir').read().rstrip())
LDFLAGS = os.popen('pg_config --ldflags').read().rstrip().split()
LIBS = ['-L' + os.popen('pg_config --libdir').read().rstrip(), '-lpq']

GCC_LIST = ['pgprobe']
