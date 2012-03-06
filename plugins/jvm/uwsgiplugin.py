import os,sys

NAME='jvm'

# Snow Leopard
#JVM_INCPATH = "/Developer/SDKs/MacOSX10.6.sdk/System/Library/Frameworks/JavaVM.framework/Versions/1.6.0/Headers/"
#JVM_LIBPATH = "/Developer/SDKs/MacOSX10.6.sdk/System/Library/Frameworks/JavaVM.framework/Versions/1.6.0/Libraries/ -framework JavaVM"

# FreeBSD openjdk7 example
# env UWSGICONFIG_JVM_INCPATH="/usr/local/openjdk7/include -I/usr/local/openjdk7/include/freebsd/" UWSGICONFIG_JVM_LIBPATH="/usr/local/openjdk7/jre/lib/amd64/server" python uwsgiconfig.py --plugin plugins/jvm

# NexentaOS example
# UWSGICONFIG_JVM_INCPATH="/usr/java/include -I /usr/java/include/solaris" UWSGICONFIG_JVM_LIBPATH="/usr/java/jre/lib/i386/" python uwsgiconfig.py --plugin plugins/jvm

# Ubuntu
JVM_INCPATH = "/usr/lib/jvm/java-6-openjdk/include/ -I/usr/lib/jvm/java-6-openjdk/include/linux"
JVM_LIBPATH = "/usr/lib/jvm/java-6-openjdk/jre/lib/amd64/server/"

try: 
    JVM_INCPATH = os.environ['UWSGICONFIG_JVM_INCPATH'] 
except: 
    pass 

try: 
    JVM_LIBPATH = os.environ['UWSGICONFIG_JVM_LIBPATH'] 
except: 
    pass 

try:
    JVM_INCPATH = os.environ['UWSGICONFIG_JVM_INCPATH']
except:
    pass

try:
    JVM_LIBPATH = os.environ['UWSGICONFIG_JVM_LIBPATH']
except:
    pass

CFLAGS = ['-I' + JVM_INCPATH]
LDFLAGS = ['-L' + JVM_LIBPATH]
LIBS = ['-ljvm']
GCC_LIST = ['jvm_plugin']

if os.environ.has_key('LD_RUN_PATH'):
	os.environ['LD_RUN_PATH'] += ':' + JVM_LIBPATH
else:
	os.environ['LD_RUN_PATH'] = JVM_LIBPATH
