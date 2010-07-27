import os,sys

NAME='rack'
CFLAGS = '-I' + os.popen("ruby -e \"require 'mkmf';print Config::CONFIG['archdir']\"").read().rstrip()
LDFLAGS = '-l' + os.popen("ruby -e \"require 'mkmf';print CONFIG['RUBY_SO_NAME']\"").read().rstrip()
