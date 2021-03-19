import os
import platform

NAME = 'router_basicauth'

CFLAGS = []
LDFLAGS = []
LIBS = []

# osx and openbsd do not need libcrypt
if platform.uname()[0] not in ('Darwin', 'OpenBSD'):
    LIBS.append('-lcrypt')

GCC_LIST = ['router_basicauth']
