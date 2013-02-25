import os
NAME='mono'

CFLAGS = os.popen('pkg-config --cflags mono-2').read().rstrip().split()
LDFLAGS = []
LIBS = os.popen('pkg-config --libs mono-2').read().rstrip().split() 
GCC_LIST = ['mono_plugin']

def post_build(config):
    if os.system("mcs /target:library /r:System.Web.dll plugins/mono/uwsgi.cs") != 0:
        os._exit(1)
    print("*** uwsgi.dll available in %s/plugins/mono ***" % os.getcwd())
