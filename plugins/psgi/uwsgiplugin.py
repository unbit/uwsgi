import os,sys

NAME='psgi'
CFLAGS = [os.popen('perl -MExtUtils::Embed -e ccopts').read().rstrip()]
LDFLAGS = [os.popen('perl -MExtUtils::Embed -e ldopts').read().rstrip()]
LIBS = []
GCC_LIST = ['uwsgi_plmodule', 'psgi_response', 'psgi_plugin']
