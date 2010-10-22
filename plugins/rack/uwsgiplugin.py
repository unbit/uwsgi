import os,sys

NAME='rack'

includedir = os.popen("ruby -e \"require 'rbconfig';print Config::CONFIG['rubyhdrdir']\"").read().rstrip()

if includedir == 'nil':
	includedir = os.popen("ruby -e \"require 'rbconfig';print Config::CONFIG['archdir']\"").read().rstrip()

CFLAGS = os.popen("ruby -e \"require 'rbconfig';print Config::CONFIG['CFLAGS']\"").read().rstrip().split()
CFLAGS.append('-I' + includedir)

LDFLAGS = os.popen("ruby -e \"require 'rbconfig';print Config::CONFIG['LDFLAGS']\"").read().rstrip().split()
LIBS = os.popen("ruby -e \"require 'rbconfig';print '-l' + Config::CONFIG['RUBY_SO_NAME']\"").read().rstrip().split()
GCC_LIST = ['rack_plugin']

