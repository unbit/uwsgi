import os,sys

NAME='jwsgi'

# Snow Leopard
#JVM_INCPATH = "/Developer/SDKs/MacOSX10.6.sdk/System/Library/Frameworks/JavaVM.framework/Versions/1.6.0/Headers/"
#JVM_LIBPATH = "/Developer/SDKs/MacOSX10.6.sdk/System/Library/Frameworks/JavaVM.framework/Versions/1.6.0/Libraries/ -framework JavaVM"

# Ubuntu
JVM_INCPATH = "/usr/lib/jvm/java-6-sun-1.6.0.15/include/ -I/usr/lib/jvm/java-6-sun-1.6.0.15/include/linux"
JVM_LIBPATH = "/usr/lib/jvm/java-6-sun-1.6.0.15/jre/lib/i386/server/"


CFLAGS = ['-I' + JVM_INCPATH]
LDFLAGS = ['-L' + JVM_LIBPATH]
LIBS = ['-ljvm']
GCC_LIST = ['jwsgi_plugin']

if os.environ.has_key('LD_RUN_PATH'):
	os.environ['LD_RUN_PATH'] += ':' + JVM_LIBPATH
else:
	os.environ['LD_RUN_PATH'] = JVM_LIBPATH
