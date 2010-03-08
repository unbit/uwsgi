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
PLUGINS = ['example', 'lua', 'psgi']
UWSGI_BIN_NAME = 'uwsgi'
GCC='gcc'




# end of configuration

import os
uwsgi_os = os.uname()[0]

import sys

gcc_list = ['utils', 'protocol', 'socket', 'logging', 'wsgi_handlers', 'uwsgi_handlers', 'uwsgi']

cflags = []
ldflags = []

def add_o(x):
	if x == 'uwsgi':
		x = 'main'
	x = x + '.o'
	return x


def build_uwsgi(bin_name, version, cflags, ldflags):
	cflags.insert(0, os.popen("python%s-config --cflags" % version).read().rstrip())
	ldflags.insert(0, os.popen("python%s-config --libs" % version).read().rstrip())
	print("*** uWSGI compiling ***")
	for file in gcc_list:
		objfile = file
		if objfile == 'uwsgi':
			objfile = 'main'
		cmdline = "%s -c %s -o %s %s" % (GCC, ' '.join(cflags), objfile + '.o', file + '.c')
		print(cmdline)
		ret = os.system(cmdline)
		if ret != 0:
			sys.exit(1)

	if len(PLUGINS) > 0:
		print("*** uWSGI embedding plugin ***")
		for plugin in PLUGINS:
			print plugin

	print("*** uWSGI linking ***")
	ldline = "%s -o %s -lpthread -export-dynamic %s %s" % (GCC, bin_name, ' '.join(map(add_o, gcc_list)), ' '.join(ldflags))
	print(ldline)
	ret = os.system(ldline)
	if ret != 0:
		print("*** error linking uWSGI ***")
		sys.exit(1)

	print("*** uWSGI is ready, launch it with ./%s ***" % bin_name)



kvm_list = ['SunOS', 'FreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly']

if uwsgi_os == 'SunOS':
        ldflags.append('-lsendfile')

if uwsgi_os in kvm_list:
        ldflags.append('-lkvm')

if EMBEDDED:
	cflags.append('-DUWSGI_EMBEDDED')
	gcc_list.append('uwsgi_pymodule')

if UDP:
	cflags.append("-DUWSGI_UDP")

if NAGIOS:
	cflags.append("-DUWSGI_NAGIOS")

if PROXY:
	cflags.append("-DUWSGI_PROXY")
	gcc_list.append('proxy')

if SNMP:
	cflags.append("-DUWSGI_SNMP")
	gcc_list.append('snmp')

if THREADING:
	cflags.append("-DUWSGI_THREADING")

if PROFILER:
	cflags.append("-DUWSGI_PROFILER")

if SENDFILE:
	cflags.append("-DUWSGI_SENDFILE")

if XML:
        ldflags.append(os.popen('xml2-config --libs').read().rstrip())
        cflags.append("-DUWSGI_XML")
	cflags.append(os.popen('xml2-config --cflags').read().rstrip())
	gcc_list.append('xmlconf')

if ERLANG:
	cflags.append("-DUWSGI_ERLANG")
	ldflags.append("-lerl_interface -lei")
	gcc_list.append('erlang')

if SCTP:
        ldflags.append("-lsctp")
        cflags.append("-DUWSGI_SCTP")

if SPOOLER:
	cflags.append("-DUWSGI_SPOOLER")
	gcc_list.append('spooler')

version = sys.version_info
uver = "%d.%d" % (version[0], version[1])


if __name__ == "__main__":
	if sys.argv[1] == '--cflags':
        	print(' '.join(cflags))
	if sys.argv[1] == '--ldflags':
        	print(' '.join(ldflags))
	elif sys.argv[1] == '--build':
		build_uwsgi(UWSGI_BIN_NAME, uver, cflags, ldflags)
