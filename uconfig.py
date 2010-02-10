# configuration

XML=True
SNMP=False
SCTP=False



# end of configuration

import os
uwsgi_os = os.uname()[0]

import sys


cflags = ''
ldflags = ''

if uwsgi_os == 'SunOS':
	ldflags = ldflags + ' -lsendfile '

if XML:
	ldflags = ldflags + os.popen('xml2-config --libs').read().rstrip()
	cflags = cflags + os.popen('xml2-config --cflags').read().rstrip()
else:
	cflags = cflags + ' -DNOXML '

if SCTP:
	ldflags = ldflags + ' -lsctp '
	cflags = cflags + ' -DSCTP '


if sys.argv[1] == '--cflags':
	print(cflags)
else:
	print(ldflags)
