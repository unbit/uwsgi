import os

NAME='xslt'
CFLAGS = os.popen('xslt-config --cflags').read().rstrip().split()
LDFLAGS = os.popen('xslt-config --libs').read().rstrip().split()
LIBS = []

GCC_LIST = ['xslt']
