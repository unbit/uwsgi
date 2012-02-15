import os
NAME='router_basicauth'

CFLAGS = []
LDFLAGS = []
LIBS = []

# osx does not need libcrypt
if os.uname()[0] != 'Darwin':
    LIBS.append('-lcrypt')

GCC_LIST = ['router_basicauth']
