from uwsgiconfig import spcall

NAME='airbrake'

CFLAGS = [spcall('xml2-config --cflags')]
LDFLAGS = []
LIBS = ['-lcurl', spcall('xml2-config --libs')]
GCC_LIST = ['airbrake_plugin']

