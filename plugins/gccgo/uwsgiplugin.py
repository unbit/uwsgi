import os
NAME='gccgo'

CFLAGS = []
LDFLAGS = []
LIBS = []
GCC_LIST = ['gccgo_plugin']

def post_build(config):
    if os.system("gccgo -c -o plugins/gccgo/uwsgi.o plugins/gccgo/uwsgi.go") != 0:
        os._exit(1)
    if os.system("objcopy -j .go_export plugins/gccgo/uwsgi.o plugins/gccgo/uwsgi.gox") != 0:
        os._exit(1)
    print("*** uwsgi.gox available in %s/plugins/gccgo ***" % os.getcwd())
