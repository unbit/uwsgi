import os
from distutils import sysconfig

NAME='pyerl'

ERLANGPATH = os.environ.get('UWSGICONFIG_ERLANGPATH', 'erl')

includedir = os.popen(ERLANGPATH + " -noshell -noinput -eval \"io:format('~s~n', [code:lib_dir(erl_interface, include)])\" -s erlang halt").read().rstrip()
libpath = os.popen(ERLANGPATH + " -noshell -noinput -eval \"io:format('~s~n', [code:lib_dir(erl_interface, lib)])\" -s erlang halt").read().rstrip()

CFLAGS = [ '-I' + includedir, '-I' + sysconfig.get_python_inc(), '-I' + sysconfig.get_python_inc(plat_specific=True)]
LDFLAGS = [ '-L' + libpath ]

LIBS = ['-lei']

GCC_LIST = ['pyerl']
