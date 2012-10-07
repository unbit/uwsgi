import os,sys

try:
        LUALIB = os.environ['UWSGICONFIG_LUALIB']
except:
        LUALIB = 'lua5.1'

try:
        LUAINC = os.environ['UWSGICONFIG_LUAINC']
except:
        LUAINC = '/usr/include/lua5.1'

try:
        LUALIBPATH = os.environ['UWSGICONFIG_LUALIBPATH']
except:
        LUALIBPATH = '/usr/lib/lua5.1'

NAME='lua'
CFLAGS = ['-I%s' % LUAINC]
LDFLAGS = ['-L%s' % LUALIBPATH]
GCC_LIST = ['lua_plugin']
LIBS = ['-l%s' % LUALIB]
