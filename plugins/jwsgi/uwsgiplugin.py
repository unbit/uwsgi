jvm_path = 'plugins/jvm'

up = {}
try:
    execfile('%s/uwsgiplugin.py' % jvm_path, up)
except:
    f = open('%s/uwsgiplugin.py' % jvm_path)
    exec(f.read(), up)
    f.close()

NAME='jwsgi'
CFLAGS = up['CFLAGS']
CFLAGS.append('-I%s' % jvm_path)
LDFLAGS = []
LIBS = []
GCC_LIST = ['jwsgi_plugin']
