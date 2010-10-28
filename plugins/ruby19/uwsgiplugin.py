import os,sys

NAME='ruby19'

#RUBYPATH = '/opt/ruby19/bin/ruby'
RUBYPATH = '/Users/roberto/RUBY/bin/ruby'

GCC_LIST = ['../rack/rack_plugin']
CFLAGS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['CFLAGS']\"").read().rstrip().split()

version = os.popen(RUBYPATH + " -e \"print RUBY_VERSION\"").read().rstrip()
v = version.split('.')

if v[0] == '1' and v[1] == '9':
	CFLAGS.append('-DRUBY19')
	GCC_LIST.append('../rack/fiber')

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

CFLAGS.append('-Drack_plugin=ruby19_plugin')

LDFLAGS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['LDFLAGS']\"").read().rstrip().split()
LDFLAGS.append('-L' + os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['libdir']\"").read().rstrip() )
LIBS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print '-l' + Config::CONFIG['RUBY_SO_NAME']\"").read().rstrip().split()

