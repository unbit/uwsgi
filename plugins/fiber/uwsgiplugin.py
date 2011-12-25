import os

try:
    RUBYPATH = os.environ['UWSGICONFIG_RUBYPATH']
except:
    RUBYPATH = 'ruby'

NAME='fiber'
CFLAGS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print Config::CONFIG['CFLAGS']\"").read().rstrip().split()

CFLAGS.append('-Wno-unused-parameter')
CFLAGS.append('-DRUBY19')

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
LDFLAGS = []
LIBS = []

GCC_LIST = ['fiber']
