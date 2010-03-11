# uWSGI configuration

XML=True
SNMP=True
SCTP=False
ERLANG=False
SPOOLER=True
EMBEDDED=True
UDP=True
THREADING=True
SENDFILE=True
PROFILER=True
NAGIOS=True
PROXY=True
PLUGINS = []
UWSGI_BIN_NAME = 'uwsgi'
GCC='gcc'




# end of configuration

import os
uwsgi_os = os.uname()[0]

import sys
import subprocess

gcc_list = ['utils', 'protocol', 'socket', 'logging', 'wsgi_handlers', 'uwsgi_handlers', 'uwsgi']

# large file support
cflags = ['-D_LARGEFILE_SOURCE', '-D_FILE_OFFSET_BITS=64']
ldflags = ['-lpthread', '-rdynamic']

def spcall(cmd):
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

	if p.wait() == 0:
        	return p.stdout.read().rstrip().decode()
	else:
        	return None

def add_o(x):
	if x == 'uwsgi':
		x = 'main'
	x = x + '.o'
	return x


def build_uwsgi(bin_name):
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
			print(plugin)

	print("*** uWSGI linking ***")
	ldline = "%s -o %s %s %s" % (GCC, bin_name, ' '.join(map(add_o, gcc_list)), ' '.join(ldflags))
	print(ldline)
	ret = os.system(ldline)
	if ret != 0:
		print("*** error linking uWSGI ***")
		sys.exit(1)

	if bin_name.find("/") < 0:
		bin_name = './' + bin_name
	print("*** uWSGI is ready, launch it with %s ***" % bin_name)


def parse_vars():

	version = sys.version_info
	uver = "%d.%d" % (version[0], version[1])

	pyconf = spcall("python%s-config --cflags" % uver)
	if pyconf is None:
		print("python development headers unavailable !!!!")
		sys.exit(1)
	cflags.insert(0,pyconf)

	pyconf = spcall("python%s-config --libs" % uver)
	if pyconf is None:
		print("python development headers unavailable !!!!")
		sys.exit(1)
	ldflags.insert(0,pyconf)

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
		xmlconf = spcall('xml2-config --libs')
		if xmlconf is None:
			print("libxml2 headers unavailable. XML support will be disabled")
		else:
			ldflags.append(xmlconf)
			xmlconf = spcall("xml2-config --cflags")
			if xmlconf is None:
                        	print("libxml2 headers unavailable. XML support will be disabled")
			else:
				cflags.append(xmlconf)
				cflags.append("-DUWSGI_XML")
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

def build_plugin(path):
	path = path.rstrip('/')

	sys.path.insert(0, path)
	import uwsgiplugin as up

	cflags.append(up.CFLAGS)
	ldflags.append(up.LDFLAGS)

	cflags.insert(0, '-I.')

	plugin_base = path + '/' + up.NAME + '_plugin'

	gccline = "%s -fPIC -shared -o %s.so %s %s.c %s" % (GCC, plugin_base, ' '.join(cflags), plugin_base, ' '.join(ldflags))
	print(gccline)

	ret = os.system(gccline)
	if ret != 0:
		print("*** unable to build %s plugin ***" % up.NAME)
		sys.exit(1)

	print("*** %s plugin built and available in %s ***" % (up.NAME, plugin_base + '.so'))
	
	

	
	



if __name__ == "__main__":
	try:
		cmd = sys.argv[1]
	except:
		print("please specify an argument")
		sys.exit(1)

	if cmd == '--cflags':
        	print(' '.join(cflags))
	if cmd == '--ldflags':
        	print(' '.join(ldflags))
	elif cmd == '--build':
		parse_vars()
		build_uwsgi(UWSGI_BIN_NAME)
	elif cmd == '--plugin':
		parse_vars()
		build_plugin(sys.argv[2])
	else:
		print("unknown uwsgiconfig command")
		sys.exit(1)
		
