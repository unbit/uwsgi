import os

NAME='php'

CFLAGS = [os.popen('php-config --includes').read().rstrip()]

LDFLAGS = os.popen('php-config --ldflags').read().rstrip().split()
LIBS = [os.popen('php-config --libs').read().rstrip(), '-lphp5']

GCC_LIST = ['php_plugin']
