import os
NAME='router_spnego'

CFLAGS = os.popen('krb5-config --cflags gssapi').read().rstrip().split()
LDFLAGS = []
LIBS = os.popen('krb5-config --libs gssapi').read().rstrip().split()

GCC_LIST = ['router_spnego']
