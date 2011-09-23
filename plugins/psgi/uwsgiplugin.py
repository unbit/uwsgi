import os,sys

NAME='psgi'
CFLAGS = os.popen('perl -MExtUtils::Embed -e ccopts').read().rstrip().split()
LDFLAGS = os.popen('perl -MExtUtils::Embed -e ldopts').read().rstrip().split()
LIBS = []
GCC_LIST = ['uwsgi_plmodule', 'psgi_loader', 'psgi_response', 'psgi_plugin']

for item in LDFLAGS:
    if item.endswith('DynaLoader.a'):
        GCC_LIST.append(item)
