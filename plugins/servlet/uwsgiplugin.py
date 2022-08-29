NAME = 'servlet'

jvm_path = 'plugins/jvm'

up = {}
try:
    execfile('%s/uwsgiplugin.py' % jvm_path, up)
except Exception:
    f = open('%s/uwsgiplugin.py' % jvm_path)
    exec(f.read(), up)
    f.close()

CFLAGS = up['CFLAGS']
CFLAGS.append('-I%s' % jvm_path)
LDFLAGS = []
LIBS = []
GCC_LIST = ['servlet_plugin']
