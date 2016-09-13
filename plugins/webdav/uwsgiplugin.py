import os

NAME = 'webdav'

CFLAGS = ['-Wno-deprecated-declarations']
CFLAGS += os.popen('xml2-config --cflags').read().rstrip().split()
LDFLAGS = []
LIBS = os.popen('xml2-config --libs').read().rstrip().split()

GCC_LIST = ['webdav']
