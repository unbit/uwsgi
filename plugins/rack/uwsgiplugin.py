import os,sys

NAME='rack'

try:
	RUBYPATH = os.environ['UWSGICONFIG_RUBYPATH']
except:
	RUBYPATH = 'ruby'

rbconfig = 'Config'

version = os.popen(RUBYPATH + " -e \"print RUBY_VERSION\"").read().rstrip()
v = version.split('.')

GCC_LIST = ['rack_plugin', 'rack_api']

if (v[0] == '1' and v[1] == '9') or v[0] >= '2':
    CFLAGS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print RbConfig::CONFIG['CFLAGS']\"").read().rstrip().split()
    CFLAGS.append('-DRUBY19')
    CFLAGS.append('-Wno-unused-parameter')
    rbconfig = 'RbConfig'	 
else:
    CFLAGS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['CFLAGS']\"" % rbconfig).read().rstrip().split()

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


LDFLAGS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['LDFLAGS']\"" % rbconfig).read().rstrip().split()
libpath = os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['libdir']\"" % rbconfig).read().rstrip()

has_shared = os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['ENABLE_SHARED']\"" % rbconfig).read().rstrip()

LIBS = os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['LIBS']\"" % rbconfig).read().rstrip().split()

if has_shared == 'yes':
    LDFLAGS.append('-L' + libpath )
    os.environ['LD_RUN_PATH'] = libpath
    LIBS.append(os.popen(RUBYPATH + " -e \"require 'rbconfig';print '-l' + %s::CONFIG['RUBY_SO_NAME']\"" % rbconfig).read().rstrip())
else:
    GCC_LIST.append("%s/%s" % (libpath, os.popen(RUBYPATH + " -e \"require 'rbconfig';print %s::CONFIG['LIBRUBY_A']\"" % rbconfig).read().rstrip()))

