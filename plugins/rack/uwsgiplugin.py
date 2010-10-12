import os,sys

NAME='rack'
#CFLAGS = '-I' + os.popen("/Users/roberto/RUBY/bin/ruby -e \"require 'mkmf';print Config::CONFIG['archdir']\"").read().rstrip()
CFLAGS = '-I/Users/roberto/RUBY//include/ruby-1.9.1 -DHAVE_STRUCT_TIMESPEC -DHAVE_STRUCT_TIMEZONE'
LDFLAGS = '-l' + os.popen("/Users/roberto/RUBY/bin/ruby -e \"require 'mkmf';print CONFIG['RUBY_SO_NAME']\"").read().rstrip()
