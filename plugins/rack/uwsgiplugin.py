import os,sys

NAME='rack'
#CFLAGS = ['-I/Users/roberto/RUBY//include/ruby-1.9.1 -DHAVE_STRUCT_TIMESPEC -DHAVE_STRUCT_TIMEZONE']
CFLAGS = ['-I/System/Library/Frameworks/Ruby.framework/Versions/Current/Headers']
#LDFLAGS = ['-l' + os.popen("/Users/roberto/RUBY/bin/ruby -e \"require 'mkmf';print CONFIG['RUBY_SO_NAME']\"").read().rstrip()]
LDFLAGS = []
LIBS = ['-lruby']
GCC_LIST = ['rack_plugin']

