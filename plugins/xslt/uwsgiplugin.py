import os

NAME='xslt'
CFLAGS = os.popen('xslt-config --cflags').read().rstrip().split()
LDFLAGS = []
LIBS = os.popen('xslt-config --libs').read().rstrip().split()

GCC_LIST = ['xslt']
