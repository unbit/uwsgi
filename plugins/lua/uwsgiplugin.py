import os,sys

try:
        LUALIB = os.environ['UWSGICONFIG_LUALIB']
except:
        LUALIB = 'lua5.1'

NAME='lua'
CFLAGS = ['-I/usr/include/lua5.1/']
LDFLAGS = []
GCC_LIST = ['lua_plugin']
LIBS = ['-l%s' % LUALIB]
