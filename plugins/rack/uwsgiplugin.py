import os,sys

NAME='rack'

try:
	RUBYPATH = os.environ['UWSGICONFIG_RUBYPATH']
except:
	RUBYPATH = 'ruby'

CFLAGS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['CFLAGS']\"").read().rstrip().split()

version = os.popen(RUBYPATH + " -e \"print RUBY_VERSION\"").read().rstrip()
v = version.split('.')

GCC_LIST = ['rack_plugin']

if v[0] == '1' and v[1] == '9':
	CFLAGS.append('-DRUBY19')
	CFLAGS.append('-Wno-unused-parameter')
	GCC_LIST.append('fiber')

includedir = os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['rubyhdrdir']\"").read().rstrip()
if includedir == 'nil':
	includedir = os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['archdir']\"").read().rstrip()
	CFLAGS.append('-I' + includedir)
else:
	CFLAGS.append('-I' + includedir)
	archdir = os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['archdir']\"").read().rstrip()
	arch = os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['arch']\"").read().rstrip()
	CFLAGS.append('-I' + archdir)
	CFLAGS.append('-I' + archdir + '/' + arch)
	CFLAGS.append('-I' + includedir + '/' + arch)

LDFLAGS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['LDFLAGS']\"").read().rstrip().split()

libpath = os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['libdir']\"").read().rstrip()
LDFLAGS.append('-L' + libpath )
os.environ['LD_RUN_PATH'] = libpath
LIBS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print '-l' + Config::CONFIG['RUBY_SO_NAME']\"").read().rstrip().split()

