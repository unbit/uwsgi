import os
import shutil

jvm_path = 'plugins/jvm'

up = {}
try:
    execfile('%s/uwsgiplugin.py' % jvm_path, up)
except:
    f = open('%s/uwsgiplugin.py' % jvm_path)
    exec(f.read(), up)
    f.close()

NAME='ring'
CFLAGS = up['CFLAGS']
CFLAGS.append('-I%s' % jvm_path)
LDFLAGS = []
LIBS = []
GCC_LIST = ['ring_plugin']

def post_build(config):
    env = os.environ.get('VIRTUAL_ENV')
    if env:
        plugin = "%s/ring_plugin.so" % os.getcwd()
        if os.path.exists(plugin):
            tgt = "%s/bin/ring_plugin.so" % env
            shutil.copyfile(plugin, tgt)
            print("*** ring_plugin.so had been copied to %s" % tgt)

