# uWSGI configuration

XML=True
INI=True
SNMP=True
SCTP=False
ERLANG=False
SPOOLER=True
EMBEDDED=True
UDP=True
MULTICAST=True
THREADING=True
SENDFILE=True
PROFILER=False
NAGIOS=True
PROXY=True
PASTE=True
MINTERPRETERS=True
ASYNC=True
UGREEN=False
HTTP=True
EVDIS=False
LDAP=False
WSGI2=False
ROUTING=False
STACKLESS=False
#PLUGINS = ['psgi']
PLUGINS = []
USWALLOW=False
UNBIT=False
DEBUG=False
EMBED_PLUGINS=True
UWSGI_BIN_NAME = 'uwsgi'
UWSGI_PLUGIN_DIR = '.'


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
uwsgi_cpu = os.uname()[4]

import sys
import subprocess

from distutils import sysconfig

GCC = os.environ.get('CC', sysconfig.get_config_var('CC'))
if not GCC:
	GCC = 'gcc'


def spcall(cmd):
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

	if p.wait() == 0:
		if sys.version_info[0] > 2:
			return p.stdout.read().rstrip().decode()
		return p.stdout.read().rstrip()
	else:
		return None

def spcall2(cmd):
	p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE)

	if p.wait() == 0:
		if sys.version_info[0] > 2:
			return p.stderr.read().rstrip().decode()
		return p.stderr.read().rstrip()
	else:
		return None

gcc_version = str(spcall2("%s -v" % GCC)).split('\n')[-1].split()[2]

gcc_major = int(gcc_version.split('.')[0])
gcc_minor = int(gcc_version.split('.')[1])


gcc_list = ['utils', 'pyutils', 'protocol', 'socket', 'logging', 'wsgi_handlers', 'wsgi_headers', 'uwsgi_handlers', 'plugins', 'uwsgi']

cflags = ['-O2', '-Wall', '-Werror', '-D_LARGEFILE_SOURCE', '-D_FILE_OFFSET_BITS=64'] + os.environ.get("CFLAGS", "").split()

# add -fno-strict-aliasing only on python2 and gcc < 4.3
if (sys.version_info[0] == 2) or (gcc_major < 4) or (gcc_major == 4 and gcc_minor < 3):
	cflags = cflags + ['-fno-strict-aliasing']

if gcc_major >= 4:
	cflags = cflags + [ '-Wextra', '-Wno-unused-parameter', '-Wno-missing-field-initializers' ]

cflags = cflags + ['-I' + sysconfig.get_python_inc(), '-I' + sysconfig.get_python_inc(plat_specific=True) ]

ldflags = os.environ.get("LDFLAGS", "").split()
libs = ['-lpthread', '-rdynamic'] + sysconfig.get_config_var('LIBS').split() + sysconfig.get_config_var('SYSLIBS').split()
if not sysconfig.get_config_var('Py_ENABLE_SHARED'):
	libs.append('-L' + sysconfig.get_config_var('LIBPL'))


if USWALLOW:
	cflags = cflags + sysconfig.get_config_var('LLVM_CXXFLAGS').split()
	ldflags = ldflags + sysconfig.get_config_var('LLVM_LDFLAGS').split() + sysconfig.get_config_var('LINKFORSHARED').split()
	GCC = 'clang'

def depends_on(what, dep):
	for d in dep:
		if not globals()[d]:
			print("%s needs %s support." % (what, d))
			sys.exit(1)


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
		print("*** uWSGI building plugins ***")
		for plugin in PLUGINS:
			print("*** building plugin: %s ***" % plugin)
			build_plugin("plugins/%s" % plugin)

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

	global XML
	XML=True

	global INI
	INI=False

	global SNMP
	SNMP=False

	global SCTP
	SCTP=False

	global ERLANG
	ERLANG=False

	global SPOOLER
	SPOOLER=True

	global EMBEDDED
	EMBEDDED=True
	
	global UDP
	UDP=False

	global MULTICAST
	MULTICAST=False

	global THREADING
	THREADING=False

	global SENDFILE
	SENDFILE=True

	global PROFILER
	PROFILER=False

	global NAGIOS
	NAGIOS=False

	global PROXY
	PROXY=False

	global PASTE
	PASTE=False

	global MINTERPRETERS
	MINTERPRETERS=False
	
	global ASYNC
	ASYNC=False

	global UGREEN
	UGREEN=False

	global HTTP
	HTTP=False

	global EVDIS
	EVDIS=False

	global WSGI2
	WSGI2=False

	global LDAP
	LDAP=False

	global ROUTING
	ROUTING=False

	global STACKLESS
	STACKLESS=False

	global PLUGINS
	#PLUGINS = ['psgi']
	PLUGINS = []

	global USWALLOW
	USWALLOW=False

	global UNBIT
	UNBIT=True

	global DEBUG
	DEBUG=False

	global EMBED_PLUGINS
	EMBED_PLUGINS=True

	global UWSGI_BIN_NAME
	UWSGI_BIN_NAME = '../bin/uwsgi'

	global UWSGI_PLUGIN_DIR
	UWSGI_PLUGIN_DIR = '../bin'

	global PYLIB_PATH
	PYLIB_PATH = '/proc/unbit/opt/python26/lib'

def parse_vars():

	global UGREEN, ASYNC, PROXY
	
	version = sys.version_info
	uver = "%d.%d" % (version[0], version[1])

	libs.append('-lpython' + uver)

	if str(PYLIB_PATH) != '':
		libs.insert(0,'-L' + PYLIB_PATH)
		os.environ['LD_RUN_PATH'] = PYLIB_PATH

	kvm_list = ['FreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly']

	if uwsgi_os == 'SunOS':
		libs.append('-lsendfile')
		libs.remove('-rdynamic')

	if uwsgi_os in kvm_list:
		libs.append('-lkvm')

	if uwsgi_os == 'OpenBSD' or uwsgi_cpu[0:3] == 'arm' or uwsgi_os == 'Haiku':
		UGREEN = False

	if uwsgi_os == 'Haiku':
		ASYNC = False
		PROXY = False
		libs.remove('-rdynamic')
		libs.remove('-lpthread')
		libs.append('-lroot')

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

	if INI:
		cflags.append("-DUWSGI_INI")
		gcc_list.append('ini')

	if DEBUG:
		cflags.append("-DUWSGI_DEBUG")

	if PROXY:
		depends_on("PROXY", ['ASYNC'])
		cflags.append("-DUWSGI_PROXY")
		gcc_list.append('proxy')

	if LDAP:
		cflags.append("-DUWSGI_LDAP")
		gcc_list.append('ldap')
		libs.append('-lldap')

	if ROUTING:
		depends_on("ROUTING", ['WSGI2', 'XML'])
		cflags.append("-DUWSGI_ROUTING")
		gcc_list.append('routing')
		pcreconf = spcall("pcre-config --cflags")
		if pcreconf is None:
			print ("*** Unable to locate pcre-config.  The uWSGI build has been interrupted.  You have to install pcre.")
			sys.exit(1)
		else:
			cflags.append(pcreconf)

		pcreconf = spcall("pcre-config --libs")
		if pcreconf is None:
			print ("*** Unable to locate pcre-config.  The uWSGI build has been interrupted.  You have to install pcre.")
			sys.exit(1)
		else:
			libs.append(pcreconf)

	if HTTP:
		cflags.append("-DUWSGI_HTTP")
		gcc_list.append('http')

	if EVDIS:
		cflags.append("-DUWSGI_EVDIS")
		gcc_list.append('evdis')
		

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

	if UWSGI_PLUGIN_DIR is not None:
		cflags.append("-DUWSGI_PLUGIN_DIR=\\\"%s\\\"" % UWSGI_PLUGIN_DIR)

	if len(PLUGINS) > 0 and EMBED_PLUGINS:
		cflags.append("-DUWSGI_EMBED_PLUGINS")
		for plugin in PLUGINS:
			cflags.append("-DUWSGI_EMBED_PLUGIN_%s" % plugin.upper())

	if SCTP:
		libs.append("-lsctp")
		cflags.append("-DUWSGI_SCTP")

	if SPOOLER:
		depends_on("SPOOLER", ['EMBEDDED'])
		cflags.append("-DUWSGI_SPOOLER")
		gcc_list.append('spooler')

	if WSGI2:
		cflags.append("-DUWSGI_WSGI2")

	if DEBUG:
		cflags.append("-DUWSGI_DEBUG")
		cflags.append("-g")

	if UNBIT:
		cflags.append("-DUNBIT")

def build_plugin(path):
	path = path.rstrip('/')

	sys.path.insert(0, path)
	import uwsgiplugin as up

	p_cflags = cflags[:]
	p_ldflags = ldflags[:]

	p_cflags.append(up.CFLAGS)
	p_ldflags.append(up.LDFLAGS)

	p_cflags.insert(0, '-I.')

	plugin_base = path + '/' + up.NAME + '_plugin'
	plugin_dest = UWSGI_PLUGIN_DIR + '/' + up.NAME + '_plugin'

	shared_flag = '-shared'

	if uwsgi_os == 'Darwin':
		shared_flag = '-dynamiclib -undefined dynamic_lookup'

	gccline = "%s -fPIC %s -o %s.so %s %s %s.c" % (GCC, shared_flag, plugin_dest, ' '.join(p_cflags), ' '.join(p_ldflags), plugin_base )
	print(gccline)

	ret = os.system(gccline)
	if ret != 0:
		print("*** unable to build %s plugin ***" % up.NAME)
		sys.exit(1)

	print("*** %s plugin built and available in %s ***" % (up.NAME, plugin_dest + '.so'))
	
	

	
	



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
		
