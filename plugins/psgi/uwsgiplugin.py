import os,sys

NAME='psgi'
CFLAGS = os.popen('perl -MExtUtils::Embed -e ccopts').read().rstrip().split()
LDFLAGS = os.popen('perl -MExtUtils::Embed -e ldopts').read().rstrip().split()
LIBS = []
for lib in LDFLAGS:
    if lib.startswith('-l'):
        LIBS.append(lib)

GCC_LIST = ['uwsgi_plmodule', 'psgi_loader', 'psgi_response', 'psgi_plugin']

for item in LDFLAGS:
    if item.endswith('DynaLoader.a'):
        GCC_LIST.append(item)
