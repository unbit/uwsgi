import sysconfig

NAME = 'greenlet'

CFLAGS = [
    '-I' + sysconfig.get_path('include'),
    '-I' + sysconfig.get_path('platinclude')
]
LDFLAGS = []
LIBS = []

GCC_LIST = ['greenlet']
