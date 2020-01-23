from uwsgiconfig import spcall

NAME = 'airbrake'

CFLAGS = [spcall('pkg-config --cflags libxml-2.0')]
LDFLAGS = []
LIBS = [
    '-lcurl',
    spcall('pkg-config --libs libxml-2.0')
]
GCC_LIST = ['airbrake_plugin']
