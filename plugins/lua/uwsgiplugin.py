import os,sys

LUAINC = os.environ.get('UWSGICONFIG_LUAINC')
LUALIB = os.environ.get('UWSGICONFIG_LUALIB')
LUALIBPATH = os.environ.get('UWSGICONFIG_LUALIBPATH')
LUAPC = os.environ.get('UWSGICONFIG_LUAPC', 'lua5.1')

# we LUAINC/LUALIB/LUALIBPATH override the LUAPC for backwards compat
if LUAINC:
	CFLAGS = ['-I%s' % LUAINC]
else:
	try:
		CFLAGS = os.popen('pkg-config --cflags %s' % LUAPC).read().rstrip().split()
	except:
		CFLAGS = ['-I/usr/include/lua5.1']

if LUALIB:
	LIBS = ['-l%s' % LUALIB]
else:
	try:
		LIBS = os.popen('pkg-config --libs %s' % LUAPC).read().rstrip().split() 
	except:
		LIBS = ['-llua5.1']

if LUALIBPATH:
	LDFLAGS = ['-L%s' % LUALIBPATH]
else:
	LDFLAGS = []

NAME='lua'
GCC_LIST = ['lua_plugin']


