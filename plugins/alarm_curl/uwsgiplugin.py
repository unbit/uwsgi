from uwsgiconfig import spcall


NAME='alarm_curl'

CFLAGS = [spcall('xml2-config --cflags')]
LDFLAGS = []
LIBS = ['-lcurl', spcall('xml2-config --libs')]
GCC_LIST = ['alarm_curl_plugin']
