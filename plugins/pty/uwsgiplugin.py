import os
import platform

NAME = 'pty'

uwsgi_os = platform.uname()[0]

CFLAGS = []
LDFLAGS = []
if uwsgi_os in ('Linux', 'FreeBSD', 'GNU', 'NetBSD', 'DragonFly'):
    LIBS = ['-lutil']
else:
    LIBS = []
GCC_LIST = ['pty']
