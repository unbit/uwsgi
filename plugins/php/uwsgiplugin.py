import os

NAME='php'

try:
    PHPPATH = os.environ['UWSGICONFIG_PHPPATH']
except:
    PHPPATH = 'php-config'

CFLAGS = [os.popen(PHPPATH + ' --includes').read().rstrip()]

LDFLAGS = os.popen(PHPPATH + ' --ldflags').read().rstrip().split()
LIBS = [os.popen(PHPPATH + ' --libs').read().rstrip(), '-lphp5']

GCC_LIST = ['php_plugin']
