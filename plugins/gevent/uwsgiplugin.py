import sysconfig

NAME = 'gevent'

CFLAGS = [
    '-I' + sysconfig.get_path('include'),
    '-I' + sysconfig.get_path('platinclude')
]
LDFLAGS = []
LIBS = []

GCC_LIST = ['gevent', 'hooks']
