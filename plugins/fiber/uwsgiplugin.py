import os

NAME='fiber'

try:
    RUBYPATH = os.environ['UWSGICONFIG_RUBYPATH']
except:
    RUBYPATH = 'ruby'


CFLAGS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print RbConfig::CONFIG['CFLAGS']\"").read().rstrip().split()
CFLAGS.append('-DRUBY19')
CFLAGS.append('-Wno-unused-parameter')
rbconfig = 'RbConfig'

includedir = os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['rubyhdrdir']\"" % rbconfig).read().rstrip()
if includedir == 'nil':
    includedir = os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['archdir']\"" % rbconfig).read().rstrip()
    CFLAGS.append('-I' + includedir)
else:
    CFLAGS.append('-I' + includedir)
    archdir = os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['archdir']\"" % rbconfig).read().rstrip()
    arch = os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['arch']\"" % rbconfig).read().rstrip()
    CFLAGS.append('-I' + archdir)
    CFLAGS.append('-I' + archdir + '/' + arch)
    CFLAGS.append('-I' + includedir + '/' + arch)
    archdir2 = os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['rubyarchhdrdir']\"" % rbconfig).read().rstrip()
    if archdir2:
        CFLAGS.append('-I' + archdir2)

LDFLAGS = []
LIBS = []

GCC_LIST = ['fiber']
