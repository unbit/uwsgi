import os
NAME='rados'

CFLAGS = []	# os.popen('pkg-config --cflags glusterfs-api').read().rstrip().split()
LDFLAGS = []
LIBS = []	#os.popen('pkg-config --libs glusterfs-api').read().rstrip().split() 
GCC_LIST = ['rados']
