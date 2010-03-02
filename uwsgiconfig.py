# uWSGI configuration

XML=True
SNMP=True
SCTP=True
ERLANG=True
SPOOLER=True
EMBEDDED=True
UDP=True
THREADING=True
SENDFILE=True
PROFILER=True
NAGIOS=True
PROXY=True




# end of configuration

import os
uwsgi_os = os.uname()[0]

import sys


cflags = ''
ldflags = ''

kvm_list = ['SunOS', 'FreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly']

if uwsgi_os == 'SunOS':
        ldflags = ldflags + ' -lsendfile '

if uwsgi_os in kvm_list:
        ldflags = ldflags + ' -lkvm '

if EMBEDDED:
	cflags = cflags + ' -DUWSGI_EMBEDDED '

if UDP:
	cflags = cflags + ' -DUWSGI_UDP '

if NAGIOS:
	cflags = cflags + ' -DUWSGI_NAGIOS '

if PROXY:
	cflags = cflags + ' -DUWSGI_PROXY '

if SNMP:
	cflags = cflags + ' -DUWSGI_SNMP '

if THREADING:
	cflags = cflags + ' -DUWSGI_THREADING '

if PROFILER:
	cflags = cflags + ' -DUWSGI_PROFILER '

if SENDFILE:
	cflags = cflags + ' -DUWSGI_SENDFILE '

if XML:
        ldflags = ldflags + os.popen('xml2-config --libs').read().rstrip()
        cflags = cflags + ' -DUWSGI_XML ' + os.popen('xml2-config --cflags').read().rstrip()

if ERLANG:
	cflags = cflags + ' -DUWSGI_ERLANG '
	ldflags = ldflags + ' -lerl_interface -lei '

if SCTP:
        ldflags = ldflags + ' -lsctp '
        cflags = cflags + ' -DUWSGI_SCTP '

if SPOOLER:
	cflags = cflags + ' -DUWSGI_SPOOLER '


if sys.argv[1] == '--cflags':
        print(cflags)
else:
        print(ldflags)
