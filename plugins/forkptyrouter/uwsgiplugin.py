import os
import platform

uwsgi_os = platform.uname()[0]

NAME = 'forkptyrouter'

CFLAGS = []
LDFLAGS = []
if uwsgi_os in ('Linux', 'FreeBSD', 'GNU', 'NetBSD', 'DragonFly'):
    LIBS = ['-lutil']
else:
    LIBS = []

REQUIRES = ['corerouter']

GCC_LIST = ['forkptyrouter']
