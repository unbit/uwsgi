import os
NAME='router_spnego'

CFLAGS = []
LDFLAGS = []
LIBS = ['-L' + os.popen('krb5-config --libs gssapi').read().rstrip()]

GCC_LIST = ['router_spnego']
