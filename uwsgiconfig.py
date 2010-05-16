# uWSGI configuration

XML=True
SNMP=True
SCTP=False
ERLANG=False
SPOOLER=True
EMBEDDED=True
UDP=True
MULTICAST=True
THREADING=True
SENDFILE=True
PROFILER=True
NAGIOS=True
PROXY=True
PASTE=True
MINTERPRETERS=True
ASYNC=True
UGREEN=True
STACKLESS=False
PLUGINS = []
USWALLOW=False
UNBIT=False
UWSGI_BIN_NAME = 'uwsgi'

# specific compilation flags
# libxml2 or expat
XML_IMPLEMENTATION = 'libxml2'
# if you want to use alternative python lib, specifiy its path here
#PYLIB_PATH = '/home/roberto/uwsgi/STACKLESS/slp/lib'
PYLIB_PATH = ''
ERLANG_CFLAGS = ''
ERLANG_LDFLAGS = '-lerl_interface -lei'
# for source distribution installed in /usr/local
#ERLANG_CFLAGS = '-I /usr/local/lib/erlang/lib/erl_interface-3.6.5/include/'
#ERLANG_LDFLAGS = '-L/usr/local/lib/erlang/lib/erl_interface-3.6.5/lib -lerl_interface -lei'



# end of configuration

import os
uwsgi_os = os.uname()[0]

import sys
import subprocess

from distutils import sysconfig

GCC = os.environ.get('CC', sysconfig.get_config_var('CC'))
if not GCC:
	GCC = 'gcc'

gcc_list = ['utils', 'pyutils', 'protocol', 'socket', 'logging', 'wsgi_handlers', 'wsgi_headers', 'uwsgi_handlers', 'uwsgi']

# large file support
try:
	cflags = ['-D_LARGEFILE_SOURCE', '-D_FILE_OFFSET_BITS=64'] + os.environ.get("CFLAGS", "").split()
except:
	print("You need python headers to build uWSGI.")
	sys.exit(1)

cflags = cflags + ['-I' + sysconfig.get_python_inc(), '-I' + sysconfig.get_python_inc(plat_specific=True) ]
ldflags = os.environ.get("LDFLAGS", "").split()
libs = ['-lpthread', '-rdynamic'] + sysconfig.get_config_var('LIBS').split() + sysconfig.get_config_var('SYSLIBS').split()

if USWALLOW:
	cflags = cflags + sysconfig.get_config_var('LLVM_CXXFLAGS').split()
	ldflags = ldflags + sysconfig.get_config_var('LLVM_LDFLAGS').split() + sysconfig.get_config_var('LINKFORSHARED').split()
	GCC = 'clang'

def depends_on(what, dep):
	for d in dep:
		if not globals()[d]:
			print("%s needs %s support." % (what, d))
			sys.exit(1)

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
	ldline = "%s -o %s %s %s %s" % (GCC, bin_name, ' '.join(ldflags), ' '.join(map(add_o, gcc_list)), ' '.join(libs))
	print(ldline)
	ret = os.system(ldline)
	if ret != 0:
		print("*** error linking uWSGI ***")
		sys.exit(1)

	if bin_name.find("/") < 0:
		bin_name = './' + bin_name
	print("*** uWSGI is ready, launch it with %s ***" % bin_name)

def unbit_setup():
	global XML, SNMP, SCTP, ERLANG, SPOOLER
	global EMBEDDED, UDP, MULTICAST, THREADING
	global SENDFILE, PROFILER, NAGIOS, PROXY

	global UWSGI_BIN_NAME

	XML=False
	SNMP=False
	SCTP=False
	ERLANG=False
	UDP=False
	MULTICAST=False
	NAGIOS=False
	PROXY=False

	EMBEDDED=True
	SPOOLER=True
	THREADING=True
	SENDFILE=True
	PROFILER=True

	UNBIT=True
	UWSGI_BIN_NAME='/usr/share/unbit/uwsgi26'


def parse_vars():

	global UGREEN
	
	version = sys.version_info
	uver = "%d.%d" % (version[0], version[1])

	libs.append('-lpython' + uver)

	if str(PYLIB_PATH) != '':
		libs.insert(0,'-L' + PYLIB_PATH)

	kvm_list = ['FreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly']

	if uwsgi_os == 'SunOS':
		libs.append('-lsendfile')
		libs.remove('-rdynamic')

	if uwsgi_os in kvm_list:
		libs.append('-lkvm')

	if uwsgi_os == 'OpenBSD':
		UGREEN = False

	if EMBEDDED:
		cflags.append('-DUWSGI_EMBEDDED')
		gcc_list.append('uwsgi_pymodule')

	if UDP:
		cflags.append("-DUWSGI_UDP")

	if ASYNC:
		cflags.append("-DUWSGI_ASYNC")
		gcc_list.append('async')

	if MULTICAST:
		depends_on("MULTICAST", ['UDP'])
		cflags.append("-DUWSGI_MULTICAST")

	if STACKLESS:
		if not cflags.__contains__('-DSTACKLESS_FRHACK=1'):
			print("you need Stackless Python to use Tasklet")
			sys.exit(1)
		cflags.append("-DUWSGI_STACKLESS")
		gcc_list.append('stackless')

	if MINTERPRETERS:
		cflags.append("-DUWSGI_MINTERPRETERS")

	if NAGIOS:
		cflags.append("-DUWSGI_NAGIOS")
		gcc_list.append('nagios')

	if PROXY:
		depends_on("PROXY", ['ASYNC'])
		cflags.append("-DUWSGI_PROXY")
		gcc_list.append('proxy')

	if UGREEN:
		if uwsgi_os == 'Darwin':
			cflags.append("-D_XOPEN_SOURCE")
		depends_on("UGREEN", ['ASYNC'])
		cflags.append("-DUWSGI_UGREEN")
		gcc_list.append('ugreen')

	if SNMP:
		depends_on("SNMP", ['UDP'])
		cflags.append("-DUWSGI_SNMP")
		gcc_list.append('snmp')

	if THREADING:
		cflags.append("-DUWSGI_THREADING")

	if PROFILER:
		cflags.append("-DUWSGI_PROFILER")

	if PASTE:
		cflags.append('-DUWSGI_PASTE')

	if SENDFILE:
		cflags.append("-DUWSGI_SENDFILE")
		gcc_list.append('sendfile')

	if XML:
		if XML_IMPLEMENTATION == 'libxml2':
			xmlconf = spcall('xml2-config --libs')
			if xmlconf is None:
				print("*** libxml2 headers unavailable. uWSGI build is interrupted. You have to install libxml2 development package or use libexpat or disable XML")
				sys.exit(1)
			else:
				libs.append(xmlconf)
				xmlconf = spcall("xml2-config --cflags")
				if xmlconf is None:
					print("*** libxml2 headers unavailable. uWSGI build is interrupted. You have to install libxml2 development package or use libexpat or disable XML")
					sys.exit(1)
				else:
					cflags.append(xmlconf)
					cflags.append("-DUWSGI_XML -DUWSGI_XML_LIBXML2")
					gcc_list.append('xmlconf')
		elif XML_IMPLEMENTATION == 'expat':
			cflags.append("-DUWSGI_XML -DUWSGI_XML_EXPAT")
			libs.append('-lexpat')
			gcc_list.append('xmlconf')
			

	if ERLANG:
		depends_on("ERLANG", ['EMBEDDED'])
		cflags.append("-DUWSGI_ERLANG")
		libs.append(ERLANG_LDFLAGS)
		if str(ERLANG_CFLAGS) != '':
			cflags.append(ERLANG_CFLAGS)
		gcc_list.append('erlang')

	if SCTP:
		libs.append("-lsctp")
		cflags.append("-DUWSGI_SCTP")

	if SPOOLER:
		depends_on("SPOOLER", ['EMBEDDED'])
		cflags.append("-DUWSGI_SPOOLER")
		gcc_list.append('spooler')

	if UNBIT:
		cflags.append("-DUWSGI_UNBIT")

def build_plugin(path):
	path = path.rstrip('/')

	sys.path.insert(0, path)
	import uwsgiplugin as up

	cflags.append(up.CFLAGS)
	libs.append(up.LDFLAGS)

	cflags.insert(0, '-I.')

	plugin_base = path + '/' + up.NAME + '_plugin'

	gccline = "%s -fPIC -shared -o %s.so %s %s %s.c %s" % (GCC, plugin_base, ' '.join(cflags), ' '.join(ldflags), plugin_base, ' '.join(libs))
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
	if cmd == '--libs':
		print(' '.join(libs))
	elif cmd == '--build':
		parse_vars()
		build_uwsgi(UWSGI_BIN_NAME)
	elif cmd == '--unbit':
		unbit_setup()
		parse_vars()
		build_uwsgi(UWSGI_BIN_NAME)
	elif cmd == '--plugin':
		parse_vars()
		build_plugin(sys.argv[2])
	else:
		print("unknown uwsgiconfig command")
		sys.exit(1)
		
