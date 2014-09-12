import os
uwsgi_os = os.uname()[0]

NAME='forkptyrouter'
CFLAGS = []
LDFLAGS = []
if uwsgi_os in ('Linux', 'FreeBSD', 'GNU', 'NetBSD', 'DragonFly'):
    LIBS = ['-lutil']
else:
    LIBS = []

REQUIRES = ['corerouter']

GCC_LIST = ['forkptyrouter']
