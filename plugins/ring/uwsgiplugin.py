jvm_path = 'plugins/jvm'

up = {}
try:
    execfile('%s/uwsgiplugin.py' % jvm_path, up)
except:
    with open('%s/uwsgiplugin.py' % jvm_path) as f:
        exec(f.read(), up)
NAME='ring'
CFLAGS = up['CFLAGS']
CFLAGS.append('-I%s' % jvm_path)
LDFLAGS = []
LIBS = []
GCC_LIST = ['ring_plugin']
