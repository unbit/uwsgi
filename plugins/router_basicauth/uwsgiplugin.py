import os
NAME='router_basicauth'

CFLAGS = []
LDFLAGS = []
LIBS = []

if os.uname()[0] == 'Linux':
    LIBS.append('-lcrypt')

GCC_LIST = ['router_basicauth']
