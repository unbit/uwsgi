import os,sys

NAME='jvm'

JVM_INCPATH = "/Developer/SDKs/MacOSX10.6.sdk//System/Library/Frameworks/JavaVM.framework/Versions/1.6.0/Headers/"
JVM_LIBPATH = "/Developer/SDKs/MacOSX10.6.sdk//System/Library/Frameworks/JavaVM.framework/Versions/1.6.0/Libraries/ -framework JavaVM"


CFLAGS = ['-I' + JVM_INCPATH]
LDFLAGS = ['-L' + JVM_LIBPATH]
LIBS = ['-ljvm']
GCC_LIST = ['jvm_plugin']

if os.environ.has_key('LD_RUN_PATH'):
	os.environ['LD_RUN_PATH'] += ':' + JVM_LIBPATH
else:
	os.environ['LD_RUN_PATH'] = JVM_LIBPATH
