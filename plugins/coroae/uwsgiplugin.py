import os

NAME='coroae'
CFLAGS = os.popen('perl -MExtUtils::Embed -e ccopts').read().rstrip().split()
LDFLAGS = []
LIBS = []

GCC_LIST = ['coroae']
