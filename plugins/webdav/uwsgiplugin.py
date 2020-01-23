import os

NAME = 'webdav'

CFLAGS = ['-Wno-deprecated-declarations']
CFLAGS += os.popen('pkg-config --cflags libxml-2.0').read().rstrip().split()
LDFLAGS = []
LIBS = os.popen('pkg-config --libs libxml-2.0').read().rstrip().split()

GCC_LIST = ['webdav']
