import os
NAME='mono'

CFLAGS = os.popen('pkg-config --cflags mono-2').read().rstrip().split()
LDFLAGS = []
LIBS = os.popen('pkg-config --libs mono-2').read().rstrip().split() 
GCC_LIST = ['mono_plugin']
