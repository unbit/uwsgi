import os
NAME='router_spnego'

CFLAGS = []
LDFLAGS = []
LIBS = os.popen('krb5-config --libs gssapi').read().rstrip().split()

GCC_LIST = ['router_spnego']
