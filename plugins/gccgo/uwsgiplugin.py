import os
NAME='gccgo'

CFLAGS = ['-g']
LDFLAGS = []
LIBS = ['-lgo']
GCC_LIST = ['gccgo_plugin', 'uwsgi.go']

def post_build(config):
    if os.path.exists('plugins/gccgo/uwsgi.go.o'):
        if os.system("objcopy -j .go_export plugins/gccgo/uwsgi.go.o plugins/gccgo/uwsgi.gox") != 0:
            os._exit(1)
        print("*** uwsgi.gox available in %s/plugins/gccgo ***" % os.getcwd())
