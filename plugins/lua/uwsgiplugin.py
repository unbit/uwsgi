import os,sys

LUALIB = os.environ.get('UWSGICONFIG_LUALIB', 'lua5.1')
LUAINC = os.environ.get('UWSGICONFIG_LUAINC', '/usr/include/lua5.1')
LUALIBPATH = os.environ.get('UWSGICONFIG_LUALIBPATH', '/usr/lib/lua5.1')

NAME='lua'
CFLAGS = ['-I%s' % LUAINC]
LDFLAGS = ['-L%s' % LUALIBPATH]
GCC_LIST = ['lua_plugin']
LIBS = ['-l%s' % LUALIB]
