# uWSGI build system

uwsgi_version = '2.0.30'

import os
import re
import time
uwsgi_os = os.uname()[0]
uwsgi_os_k = re.split('[-+_]', os.uname()[2])[0]
uwsgi_os_v = os.uname()[3]
uwsgi_cpu = os.uname()[4]

import sys
import subprocess
import sysconfig
from threading import Thread, Lock
from optparse import OptionParser

try:
    from queue import Queue
except ImportError:
    from Queue import Queue

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

try:
    from shlex import quote
except ImportError:
    from pipes import quote

PY3 = sys.version_info[0] == 3

if uwsgi_os == 'Darwin':
    GCC = os.environ.get('CC', 'clang')
else:
    GCC = os.environ.get('CC', sysconfig.get_config_var('CC'))
    if not GCC:
        GCC = 'gcc'

def get_preprocessor():
    if 'clang' in GCC:
        return 'clang -xc core/clang_fake.c'
    return 'cpp'

CPP = os.environ.get('CPP', get_preprocessor())

try:
    CPUCOUNT = int(os.environ.get('CPUCOUNT', -1))
except:
    CPUCOUNT = -1

if CPUCOUNT < 1:
    try:
        import multiprocessing
        CPUCOUNT = multiprocessing.cpu_count()
    except:
        try:
            CPUCOUNT = int(os.sysconf('SC_NPROCESSORS_ONLN'))
        except:
            CPUCOUNT = 1


# force single cpu in cygwin mode
if uwsgi_os.startswith('CYGWIN'):
    CPUCOUNT=1

binary_list = []

started_at = time.time()

# this is used for reporting (at the end of the build)
# the server configuration
report = {
    'kernel': False,
    'execinfo': False,
    'ifaddrs': False,
    'locking': False,
    'event': False,
    'timer': False,
    'filemonitor': False,
    'pcre': False,
    'routing': False,
    'capabilities': False,
    'yaml': False,
    'json': False,
    'ssl': False,
    'xml': False,
    'debug': False,
    'plugin_dir': False,
    'zlib': False,
    'ucontext': False,
}

verbose_build = False

def print_compilation_output(default_str, verbose_str):
    if verbose_build:
        print(verbose_str)
    elif default_str is not None:
        print(default_str)

compile_queue = None
print_lock = None
thread_compilers = []

def thread_compiler(num):
    while True:
        (objfile, cmdline) = compile_queue.get()
        if objfile:
            print_lock.acquire()
            print_compilation_output("[thread %d][%s] %s" % (num, GCC, objfile), "[thread %d] %s" % (num, cmdline))
            print_lock.release()
            ret = subprocess.call(cmdline, shell=True)
            if ret != 0:
                os._exit(1)
        elif cmdline:
            print_lock.acquire()    
            print(cmdline)
            print_lock.release()    
        else:
            return


  
	
def binarize(name):
    return name.replace('/', '_').replace('.','_').replace('-','_')

def spcall(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,stderr=open('uwsgibuild.log','w'))

    if p.wait() == 0:
        if sys.version_info[0] > 2:
            return p.stdout.read().rstrip().decode()
        return p.stdout.read().rstrip()
    else:
        return None

# commodity function to remove -W* duplicates
def uniq_warnings(elements):
    new_elements = []
    for element in elements:
        if element.startswith('-W'):
            if not element in new_elements:
                new_elements.append(element)
        else:
            new_elements.append(element)

    return new_elements

if uwsgi_version.endswith('-dev') and os.path.exists('%s/.git' % os.path.dirname(os.path.abspath( __file__ ))):
    try:
        uwsgi_version += '+%s' % spcall('git rev-parse --short HEAD')
    except:
        pass


def spcall2(cmd):
    p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE)

    if p.wait() == 0:
        if sys.version_info[0] > 2:
            return p.stderr.read().rstrip().decode()
        return p.stderr.read().rstrip()
    else:
        return None


def test_snippet(snippet):
    """Compile a C snippet to see if features are available at build / link time."""
    if sys.version_info[0] >= 3 or (sys.version_info[0] == 2 and sys.version_info[1] > 5):
        if not isinstance(snippet, bytes):
            if PY3:
                snippet = bytes(snippet, sys.getdefaultencoding())
            else:
                snippet = bytes(snippet)
        cmd = "{0} -xc - -o /dev/null".format(GCC)
    else:
        cmd = GCC + " -xc - -o /dev/null"
    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    p.communicate(snippet)
    return p.returncode == 0


def has_usable_ucontext():
    if uwsgi_os in ('OpenBSD', 'Haiku'):
        return False
    if uwsgi_os.startswith('CYGWIN'):
        return False
    if uwsgi_os == 'Darwin' and uwsgi_os_k.startswith('8'):
        return False
    if uwsgi_cpu[0:3] == 'arm':
        return False
    # check for ucontext.h functions definitions, musl has only declarations
    return test_snippet("""#include <ucontext.h>
int main()
{
	ucontext_t uc;
	getcontext(&uc);
	return 0;
}""")


def spcall3(cmd):
    p = subprocess.Popen(cmd, shell=True, stdin=open('/dev/null'), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    (out, err) = p.communicate()

    if p.returncode == 0:
        if sys.version_info[0] > 2:
            return err.rstrip().decode()
        return err.rstrip()
    else:
        return None


def add_o(x):
    if x == 'uwsgi':
        x = 'main'
    elif x.endswith('.a') or x.endswith('.o'):
        return x
    x = x + '.o'
    return x

def push_print(msg):
    if not compile_queue:
        print(msg)
    else:
        compile_queue.put((None, msg))

def push_command(objfile, cmdline):
    if not compile_queue:
        print_compilation_output("[%s] %s" % (GCC, objfile), cmdline)
        ret = subprocess.call(cmdline, shell=True)
        if ret != 0:
            sys.exit(1)
    else:
        compile_queue.put((objfile, cmdline))
        

def uwsgi_compile(cflags, last_cflags_ts, objfile, srcfile):
    source_stat = os.stat(srcfile)
    header_stat = os.stat('uwsgi.h')
    try:
        if os.environ.get('UWSGI_FORCE_REBUILD', None):
            raise
        if source_stat[8] >= last_cflags_ts:
            raise
        if header_stat[8] >= last_cflags_ts:
            raise
        object_stat = os.stat(objfile)
        if object_stat[8] <= source_stat[8]:
            raise
        if object_stat[8] <= header_stat[8]:
            raise
        for profile in os.listdir('buildconf'):
            profile_stat = os.stat('buildconf/%s' % profile)
            if object_stat[8] <= profile_stat[8]:
                raise
        print("%s is up to date" % objfile)
        return
    except:
        pass
    cmdline = "%s -c %s -o %s %s" % (GCC, cflags, objfile, srcfile)
    push_command(objfile, cmdline)


def build_uwsgi(uc, print_only=False, gcll=None):

    global print_lock, compile_queue, thread_compilers

    if CPUCOUNT > 1:
        print_lock = Lock()
        compile_queue = Queue(maxsize=CPUCOUNT)
        for i in range(0,CPUCOUNT):
            t = Thread(target=thread_compiler,args=(i,))
            t.daemon = True
            t.start()
            thread_compilers.append(t)

    if not gcll:
        gcc_list, cflags, ldflags, libs = uc.get_gcll()
    else:
        gcc_list, cflags, ldflags, libs = gcll

    if 'UWSGI_EMBED_PLUGINS' in os.environ:
        ep = uc.get('embedded_plugins')
        if ep:
            uc.set('embedded_plugins', ep + ',' + os.environ['UWSGI_EMBED_PLUGINS'])
        else:
            uc.set('embedded_plugins', os.environ['UWSGI_EMBED_PLUGINS'])

    if uc.get('embedded_plugins'):
        ep = uc.get('embedded_plugins').split(',')
        epc = "-DUWSGI_DECLARE_EMBEDDED_PLUGINS=\""
        eplc = "-DUWSGI_LOAD_EMBEDDED_PLUGINS=\""
        for item in ep:
            # allow name=path syntax
            kv = item.split('=')
            p = kv[0]
            p = p.strip()
            if not p or p == 'None':
                continue
            if p == 'ugreen':
                if not report['ucontext']:
                    continue
            epc += "UDEP(%s);" % p
            eplc += "ULEP(%s);" % p
        epc += "\""
        eplc += "\""

        cflags.append(epc)
        cflags.append(eplc)

    if print_only:
        print(' '.join(cflags))
        sys.exit(0)

    if 'APPEND_CFLAGS' in os.environ:
        cflags += os.environ['APPEND_CFLAGS'].split()

    print("detected CPU cores: %d" % CPUCOUNT)
    print("configured CFLAGS: %s" % ' '.join(cflags))

    if sys.version_info[0] >= 3:
        import binascii
        uwsgi_cflags = binascii.b2a_hex(' '.join(cflags).encode('ascii')).decode('ascii')
    else:
        uwsgi_cflags = ' '.join(cflags).encode('hex')

    last_cflags_ts = 0
    
    if os.path.exists('uwsgibuild.lastcflags'):
            ulc = open('uwsgibuild.lastcflags','r')
            last_cflags = ulc.read()
            ulc.close()
            if uwsgi_cflags != last_cflags:
                os.environ['UWSGI_FORCE_REBUILD'] = '1'
            else:
                last_cflags_ts = os.stat('uwsgibuild.lastcflags')[8]
            

    ulc = open('uwsgibuild.lastcflags','w')
    ulc.write(uwsgi_cflags)
    ulc.close()

    # embed uwsgi.h in the server binary. It increases the binary size, but will be very useful
    # for various tricks (like cffi integration)
    # if possibile, the blob is compressed
    if sys.version_info[0] >= 3:
        uwsgi_dot_h_content = open('uwsgi.h', 'rb').read()
    else:
        uwsgi_dot_h_content = open('uwsgi.h').read()
    if report['zlib']:
        import zlib
        # maximum level of compression
        uwsgi_dot_h_content = zlib.compress(uwsgi_dot_h_content, 9)
    if sys.version_info[0] >= 3:
        import binascii
        uwsgi_dot_h = binascii.b2a_hex(uwsgi_dot_h_content).decode('ascii')
    else:
        uwsgi_dot_h = uwsgi_dot_h_content.encode('hex')
    open('core/dot_h.c', 'w').write('char *uwsgi_dot_h = "%s";\n' % uwsgi_dot_h);
    gcc_list.append('core/dot_h') 

    # embed uwsgiconfig.py in the server binary. It increases the binary size, but will be very useful
    # if possibile, the blob is compressed
    if sys.version_info[0] >= 3:
        uwsgi_config_py_content = open('uwsgiconfig.py', 'rb').read()
    else:
        uwsgi_config_py_content = open('uwsgiconfig.py').read()
    if report['zlib']:
        import zlib
        # maximum level of compression
        uwsgi_config_py_content = zlib.compress(uwsgi_config_py_content, 9)
    if sys.version_info[0] >= 3:
        import binascii
        uwsgi_config_py = binascii.b2a_hex(uwsgi_config_py_content).decode('ascii')
    else:
        uwsgi_config_py = uwsgi_config_py_content.encode('hex')
    open('core/config_py.c', 'w').write('char *uwsgi_config_py = "%s";\n' % uwsgi_config_py);
    gcc_list.append('core/config_py')

    additional_sources = os.environ.get('UWSGI_ADDITIONAL_SOURCES')
    if not additional_sources:
        additional_sources = uc.get('additional_sources')
    if additional_sources:
        for item in additional_sources.split(','):
            gcc_list.append(item)

    if uc.filename.endswith('coverity.ini'):
        cflags.append('-DUWSGI_CFLAGS=\\"\\"')
    else:
        cflags.append('-DUWSGI_CFLAGS=\\"%s\\"' % uwsgi_cflags)
    build_date = int(os.environ.get('SOURCE_DATE_EPOCH', time.time()))
    cflags.append('-DUWSGI_BUILD_DATE="\\"%s\\""' % time.strftime("%d %B %Y %H:%M:%S", time.gmtime(build_date)))

    post_build = []

    push_print("*** uWSGI compiling server core ***")
    for file in gcc_list:
        objfile = file
        if objfile == 'uwsgi':
            objfile = 'main'
        if not objfile.endswith('.a') and not objfile.endswith('.o'):
            if objfile.endswith('.c') or objfile.endswith('.cc') or objfile.endswith('.m') or objfile.endswith('.go'):
                if objfile.endswith('.go'):
                    cflags.append('-Wno-error')
                uwsgi_compile(' '.join(cflags), last_cflags_ts, objfile + '.o', file)
                if objfile.endswith('.go'):
                    cflags.pop()
            else:
                if objfile == 'core/dot_h':
                    cflags.append('-g')
                uwsgi_compile(' '.join(cflags), last_cflags_ts, objfile + '.o', file + '.c')
                if objfile == 'core/dot_h':
                    cflags.pop()

    if uc.get('embedded_plugins'):
        ep = uc.get('embedded_plugins').split(',')

        if len(ep) > 0:
            push_print("*** uWSGI compiling embedded plugins ***")
            for item in ep:
                # allows name=path syntax
                kv = item.split('=')
                if len(kv) > 1:
                    p = kv[1]
                    p = p.strip()
                    if p.startswith('http://') or p.startswith('https://') or p.startswith('git://') or p.startswith('ssh://'):
                        git_dir = p.split('/').pop()
                        if not os.path.isdir(git_dir):
                            if os.system('git clone %s' % p) != 0:
                                sys.exit(1)
                        else:
                            if os.system('cd %s ; git pull' % git_dir) != 0:
                                sys.exit(1)
                        p = git_dir
                    path = os.path.abspath(p)
                else:
                    p = kv[0]
                    p = p.strip()
                    path = 'plugins/%s' % p

                if not p or p == 'None':
                    continue

                if p == 'ugreen':
                    if not report['ucontext']:
                        continue

                path = path.rstrip('/')

                up = {}

               	if os.path.isfile(path):
                    bname = os.path.basename(path)
                    # override path
                    path = os.path.dirname(path)
                    up['GCC_LIST'] = [bname]
                    up['NAME'] = bname.split('.')[0]
                    if not path: path = '.' 
                elif os.path.isdir(path):
                    try:
                        execfile('%s/uwsgiplugin.py' % path, up)
                    except:
                        f = open('%s/uwsgiplugin.py' % path)
                        exec(f.read(), up)
                        f.close() 
                else:
                    print("Error: plugin '%s' not found" % p)
                    sys.exit(1)

                p_cflags = cflags[:]
                try:
                    p_cflags += up['CFLAGS']
                except:
                    pass

                if uwsgi_os.startswith('CYGWIN'):
                    try:
                        p_cflags.remove('-fstack-protector')
                    except:
                        pass

                if GCC in ('clang',):
                    try:
                        p_cflags.remove('-fno-fast-math')
                        p_cflags.remove('-ggdb3')
                    except:
                        pass

                try:
                    p_cflags.remove('-Wdeclaration-after-statement')
                except:
                    pass

                try:
                    p_cflags.remove('-Werror=declaration-after-statement')
                except:
                    pass

                try:
                    p_cflags.remove('-Wwrite-strings')
                except:
                    pass

                try:
                    p_cflags.remove('-Werror=write-strings')
                except:
                    pass

                try:
                    if up['post_build']:
                        post_build.append(up['post_build'])
                except:
                    pass

                for cfile in up['GCC_LIST']:
                    if cfile.endswith('.a'):
                        gcc_list.append(cfile)
                    elif cfile.endswith('.o'):
                        gcc_list.append('%s/%s' % (path, cfile))
                    elif not cfile.endswith('.c') and not cfile.endswith('.cc') and not cfile.endswith('.go') and not cfile.endswith('.m'):
                        uwsgi_compile(' '.join(uniq_warnings(p_cflags)), last_cflags_ts,
                            path + '/' + cfile + '.o', path + '/' + cfile + '.c')
                        gcc_list.append('%s/%s' % (path, cfile))
                    else:
                        if cfile.endswith('.go'):
                            p_cflags.append('-Wno-error')
                        uwsgi_compile(' '.join(uniq_warnings(p_cflags)), last_cflags_ts,
                            path + '/' + cfile + '.o', path + '/' + cfile)
                        gcc_list.append('%s/%s' % (path, cfile))
                for bfile in up.get('BINARY_LIST', []):
                    try:
                        binary_link_cmd = "ld -z noexecstack -r -b binary -o %s/%s.o %s/%s" % (path, bfile[1], path, bfile[1])
                        print(binary_link_cmd)
                        if subprocess.call(binary_link_cmd, shell=True) != 0:
                            raise Exception('unable to link binary file')
                        for kind in ('start', 'end'):
                            objcopy_cmd = "objcopy --redefine-sym _binary_%s_%s=%s_%s %s/%s.o" % (binarize('%s/%s' % (path, bfile[1])), kind, bfile[0], kind, path, bfile[1])
                            print(objcopy_cmd)
                            if subprocess.call(objcopy_cmd, shell=True) != 0:
                                raise Exception('unable to link binary file')
                        gcc_list.append('%s/%s.o' % (path, bfile[1]))
                    except:
                        pass

                try:
                    libs += up['LIBS']
                except:
                    pass

                if not 'LDFLAGS' in up:
                    up['LDFLAGS'] = []

                if uwsgi_os == 'Darwin':
                    found_arch = False
                    sanitized_ldflags = []
                    for flag in up['LDFLAGS']:
                        if flag == '-arch':
                            found_arch = True
                            continue
                        if found_arch:
                            found_arch = False
                            continue
                        sanitized_ldflags.append(flag)
                    ldflags += sanitized_ldflags
                else:
                    ldflags += up['LDFLAGS']

    if uc.get('plugins'):

        plugins = uc.get('plugins').split(',')
        if len(plugins) > 0:
            push_print("*** uWSGI building plugins ***")

            for p in plugins:
                p = p.strip()
                push_print("*** building plugin: %s ***" % p)
                build_plugin("plugins/%s" % p, uc, cflags, ldflags, libs)

    bin_name = os.environ.get('UWSGI_BIN_NAME', uc.get('bin_name'))

    if uc.embed_config:
        gcc_list.append("%s.o" % binarize(uc.embed_config))
    for ef in binary_list:
        gcc_list.append("%s.o" % ef)

    if compile_queue:
        for t in thread_compilers:
            compile_queue.put((None, None))
        for t in thread_compilers:
            t.join()

    print("*** uWSGI linking ***")
    ldline = "%s -o %s %s %s %s" % (GCC, quote(bin_name), ' '.join(uniq_warnings(ldflags)),
        ' '.join(map(add_o, gcc_list)), ' '.join(uniq_warnings(libs)))
    print(ldline)
    ret = subprocess.call(ldline, shell=True)
    if ret != 0:
        print("*** error linking uWSGI ***")
        sys.exit(1)

    print("################# uWSGI configuration #################")
    print("")
    for report_key in report:
        print("%s = %s" % (report_key, report[report_key]))
    print("")
    print("############## end of uWSGI configuration #############")

    print("total build time: %d seconds" % (time.time() - started_at))

    if bin_name.find("/") < 0:
        bin_name = './' + bin_name
    if uc.get('as_shared_library'):
        print("*** uWSGI shared library (%s) is ready, move it to a library directory ***" % bin_name)
    else:
        print("*** uWSGI is ready, launch it with %s ***" % bin_name)

    for pb in post_build:
        pb(uc)

def open_profile(filename):
    if filename.startswith('http://') or filename.startswith('https://') or filename.startswith('ftp://'):
        wrapped = False
        try:
            import urllib2
        except:
            import urllib.request
            wrapped = True

        if wrapped:
            import io
            return io.TextIOWrapper(urllib.request.urlopen(filename), encoding='utf-8')
        return urllib2.urlopen(filename)
    return open(filename)

class uConf(object):

    def __init__(self, filename, mute=False):
        global GCC

        self.filename = filename
        self.config = ConfigParser.ConfigParser()
        if not mute:
            print("using profile: %s" % filename)

        if os.path.exists('uwsgibuild.lastprofile'):
            ulp = open('uwsgibuild.lastprofile','r')
            last_profile = ulp.read()
            ulp.close()
            if last_profile != filename:
                os.environ['UWSGI_FORCE_REBUILD'] = '1'

        ulp = open('uwsgibuild.lastprofile', 'w')
        ulp.write(filename)
        ulp.close()

        if hasattr(self.config, 'read_file'):
            self.config.read_file(open_profile(filename))
        else:
            self.config.readfp(open_profile(filename))
        self.gcc_list = ['core/utils', 'core/protocol', 'core/socket', 'core/logging', 'core/master', 'core/master_utils', 'core/emperor',
            'core/notify', 'core/mule', 'core/subscription', 'core/stats', 'core/sendfile', 'core/async', 'core/master_checks', 'core/fifo',
            'core/offload', 'core/io', 'core/static', 'core/websockets', 'core/spooler', 'core/snmp', 'core/exceptions', 'core/config',
            'core/setup_utils', 'core/clock', 'core/init', 'core/buffer', 'core/reader', 'core/writer', 'core/alarm', 'core/cron', 'core/hooks',
            'core/plugins', 'core/lock', 'core/cache', 'core/daemons', 'core/errors', 'core/hash', 'core/master_events', 'core/chunked',
            'core/queue', 'core/event', 'core/signal', 'core/strings', 'core/progress', 'core/timebomb', 'core/ini', 'core/fsmon', 'core/mount',
            'core/metrics', 'core/plugins_builder', 'core/sharedarea',
            'core/rpc', 'core/gateway', 'core/loop', 'core/cookie', 'core/querystring', 'core/rb_timers', 'core/transformations', 'core/uwsgi']
        # add protocols
        self.gcc_list.append('proto/base')
        self.gcc_list.append('proto/uwsgi')
        self.gcc_list.append('proto/http')
        self.gcc_list.append('proto/fastcgi')
        self.gcc_list.append('proto/scgi')
        self.gcc_list.append('proto/puwsgi')
        self.include_path = []

        if 'UWSGI_INCLUDES' in os.environ:
            self.include_path += os.environ['UWSGI_INCLUDES'].split(',')

        cflags = [
            '-O2',
            '-I.',
            '-Wall',
            '-D_LARGEFILE_SOURCE',
            '-D_FILE_OFFSET_BITS=64'
        ]
        self.cflags = cflags + os.environ.get("CFLAGS", "").split() + self.get('cflags', '').split()

        report['kernel'] = uwsgi_os

        if uwsgi_os == 'Linux':
            if uwsgi_cpu != 'ia64':
                self.gcc_list.append('lib/linux_ns')
            try:
                lk_ver = uwsgi_os_k.split('.')
                if int(lk_ver[0]) <= 2 and int(lk_ver[1]) <= 6 and int(lk_ver[2]) <= 9:
                    self.cflags.append('-DOBSOLETE_LINUX_KERNEL')                    
                    report['kernel'] = 'Old Linux'
            except:
                pass

        if uwsgi_os == 'GNU':
            self.cflags.append('-D__HURD__')

        gcc_version = spcall("%s -dumpfullversion -dumpversion" % GCC)
        if not gcc_version and GCC.startswith('gcc'):
            if uwsgi_os == 'Darwin':
                GCC = 'llvm-' + GCC
            else:
                GCC = 'gcc'
            gcc_version = spcall("%s -dumpfullversion -dumpversion" % GCC)

        try:
            add_it = False
            cpp_include_list = str(spcall3("%s -v" % CPP)).split("\n")
            for line in cpp_include_list:
                if line.startswith('#include <...> search starts here:'):
                    add_it = True
                elif line.startswith('End of search list.'):
                    add_it = False
                elif add_it:
                    self.include_path.append(line.strip().split()[0])
            
            if not self.include_path:
                raise 
        except:
            self.include_path = ['/usr/include', '/usr/local/include']

        additional_include_paths = self.get('additional_include_paths')
        if additional_include_paths:
            for ipath in additional_include_paths.split():
                self.include_path.append(ipath)

        if 'UWSGI_REMOVE_INCLUDES' in os.environ:
            for inc in os.environ['UWSGI_REMOVE_INCLUDES'].split(','):
                try:
                    self.include_path.remove(inc)
                except:
                    pass

            
        if not mute:
            print("detected include path: %s" % self.include_path)

        try:
            gcc_version_components = gcc_version.split('.')
            gcc_major = int(gcc_version_components[0])
            if len(gcc_version_components) > 1:
                gcc_minor = int(gcc_version_components[1])
            else:
                # gcc 5.0 is represented as simply "5"
                gcc_minor = 0
        except:
            raise Exception("you need a C compiler to build uWSGI")
        if (sys.version_info[0] == 2) or (gcc_major < 4) or (gcc_major == 4 and gcc_minor < 3):
            self.cflags = self.cflags + ['-fno-strict-aliasing']
        # add -fno-strict-aliasing only on python2 and gcc < 4.3
        if gcc_major >= 4:
            self.cflags = self.cflags + [ '-Wextra', '-Wno-unused-parameter', '-Wno-missing-field-initializers' ]
        if gcc_major == 4 and gcc_minor < 9:
            self.cflags.append('-Wno-format -Wno-format-security')
        if "gcc" in GCC and gcc_major >= 5:
            self.cflags.append('-Wformat-signedness')

        self.ldflags = os.environ.get("LDFLAGS", "").split()
        self.libs = ['-lpthread', '-lm', '-rdynamic']
        if uwsgi_os in ('Linux', 'GNU', 'GNU/kFreeBSD'):
            self.libs.append('-ldl')
        if uwsgi_os == 'GNU/kFreeBSD':
            self.cflags.append('-D__GNU_kFreeBSD__')
            self.libs.append('-lbsd')

        # check for inherit option
        inherit = self.get('inherit')
        if inherit:
            if not '/' in inherit:
                inherit = 'buildconf/%s' % inherit

            if not inherit.endswith('.ini'):
                inherit = '%s.ini' % inherit

            interpolations = {}
            for option in self.config.options('uwsgi'):
                interpolations[option] = self.get(option, default='')
            iconfig = ConfigParser.ConfigParser(interpolations)
            if hasattr(self.config, 'read_file'):
                iconfig.read_file(open_profile(inherit))
            else:
                iconfig.readfp(open_profile(inherit))

            for opt in iconfig.options('uwsgi'):
                if not self.config.has_option('uwsgi', opt):
                    self.set(opt, iconfig.get('uwsgi', opt))
                elif self.get(opt):
                    if self.get(opt).startswith('+'):
                        self.set(opt, iconfig.get('uwsgi', opt) + self.get(opt)[1:])
                    elif self.get(opt) == 'null':
                        self.config.remove_option('uwsgi', opt)


    def set(self, key, value):
        self.config.set('uwsgi',key, value)

    def get(self,key,default=None):
        try:
            value = self.config.get('uwsgi', key)
            if value == "" or value == "false":
                return default
            return value
        except:
            if default is not None:
                return default
            return None

    def depends_on(self, what, dep):
        for d in dep:
            if not self.get(d):
                print("%s needs %s support." % (what, d))
                sys.exit(1)

    def has_include(self, what):
        for include in self.include_path:
            if os.path.exists("%s/%s" %(include, what)):
                return True
        return False

    def get_gcll(self):

        global uwsgi_version

        kvm_list = ['FreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly']

        if 'UWSGI_PROFILE_OVERRIDE' in os.environ:
            for item in os.environ['UWSGI_PROFILE_OVERRIDE'].split(';'):
                k,v = item.split('=', 1)
                self.set(k, v)

        if 'UWSGI_AS_LIB' in os.environ:
            self.set('as_shared_library', 'true')
            self.set('bin_name', os.environ['UWSGI_AS_LIB'])

        if self.has_include('ifaddrs.h'):
            self.cflags.append('-DUWSGI_HAS_IFADDRS')
            report['ifaddrs'] = True

        if uwsgi_os in ('FreeBSD', 'DragonFly', 'OpenBSD'):
            if self.has_include('execinfo.h') or os.path.exists('/usr/local/include/execinfo.h'):
                if os.path.exists('/usr/local/include/execinfo.h'):
                    self.cflags.append('-I/usr/local/include')
                    self.ldflags.append('-L/usr/local/lib')
                self.cflags.append('-DUWSGI_HAS_EXECINFO')
                self.libs.append('-lexecinfo')
                report['execinfo'] = True

        if uwsgi_os == 'GNU/kFreeBSD':
            if self.has_include('execinfo.h'):
                self.cflags.append('-DUWSGI_HAS_EXECINFO')
                report['execinfo'] = True

        if self.has_include('zlib.h'):
            self.cflags.append('-DUWSGI_ZLIB')
            self.libs.append('-lz')
            self.gcc_list.append('core/zlib')
            report['zlib'] = True

        if uwsgi_os == 'OpenBSD':
            try:
                obsd_major = uwsgi_os_k.split('.')[0]
                obsd_minor = uwsgi_os_k.split('.')[1]
                obsd_ver = int(obsd_major + obsd_minor)
                if obsd_ver > 50:
                    self.cflags.append('-DUWSGI_NEW_OPENBSD')
                    report['kernel'] = 'New OpenBSD'
            except:
                pass

        if uwsgi_os == 'SunOS':
            self.libs.append('-lsendfile')
            self.libs.append('-lrt')
            self.gcc_list.append('lib/sun_fixes')
            self.ldflags.append('-L/lib')
            if not uwsgi_os_v.startswith('Nexenta'):
                self.libs.remove('-rdynamic')

        if uwsgi_os == 'GNU/kFreeBSD':
            if self.has_include('kvm.h'):
                kvm_list.append('GNU/kFreeBSD')

        if uwsgi_os in kvm_list:
            self.libs.append('-lkvm')

        if uwsgi_os == 'Haiku':
            self.libs.remove('-rdynamic')
            self.libs.remove('-lpthread')
            self.libs.append('-lroot')

        if uwsgi_os == 'Darwin':
            if uwsgi_os_k.startswith('8'):
                self.cflags.append('-DUNSETENV_VOID')
                self.cflags.append('-DNO_SENDFILE')
                self.cflags.append('-DNO_EXECINFO')
                self.cflags.append('-DOLD_REALPATH')
            self.cflags.append('-mmacosx-version-min=10.5')
            if GCC in ('clang',):
                self.libs.remove('-rdynamic')

        # compile extras
        extras = self.get('extras', None)
        if extras:
            for extra in extras.split(','):
                self.gcc_list.append(extra)

        # check for usable ucontext
        report['ucontext'] = has_usable_ucontext()

        # set locking subsystem
        locking_mode = self.get('locking','auto')

        if locking_mode == 'auto':
            if uwsgi_os == 'Linux' or uwsgi_os == 'SunOS':
                locking_mode = 'pthread_mutex'
            # FreeBSD umtx is still not ready for process shared locking
            # starting from FreeBSD 9 posix semaphores can be shared between processes
            elif uwsgi_os in ('FreeBSD', 'GNU/kFreeBSD'):
                 try:
                     fbsd_major = int(uwsgi_os_k.split('.')[0])
                     if fbsd_major >= 9:
                         locking_mode = 'posix_sem'
                 except:
                     pass
            elif uwsgi_os == 'GNU':
                locking_mode = 'posix_sem'
            elif uwsgi_os == 'Darwin':
                locking_mode = 'osx_spinlock'
            elif uwsgi_os.startswith('CYGWIN'):
                locking_mode = 'windows_mutex'

        if locking_mode == 'pthread_mutex':
            self.cflags.append('-DUWSGI_LOCK_USE_MUTEX')
        # FreeBSD umtx is still not ready for process shared locking
        elif locking_mode == 'posix_sem':
            self.cflags.append('-DUWSGI_LOCK_USE_POSIX_SEM')
        elif locking_mode == 'osx_spinlock':
            self.cflags.append('-DUWSGI_LOCK_USE_OSX_SPINLOCK')
        elif locking_mode == 'windows_mutex':
            self.cflags.append('-DUWSGI_LOCK_USE_WINDOWS_MUTEX')
        else:
            self.cflags.append('-DUWSGI_IPCSEM_ATEXIT')

        if locking_mode == 'auto':
            report['locking'] = 'sysv semaphores'
        else:
            report['locking'] = locking_mode

        # set event subsystem
        event_mode = self.get('event','auto')

        if event_mode == 'auto':
            if uwsgi_os == 'Linux':
                event_mode = 'epoll'
            if uwsgi_os == 'SunOS':
                event_mode = 'devpoll'
                sun_major, sun_minor = uwsgi_os_k.split('.')
                if int(sun_major) >= 5:
                    if int(sun_minor) >= 10:
                        event_mode = 'port'
            elif uwsgi_os in ('Darwin', 'FreeBSD', 'GNU/kFreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly'):
                event_mode = 'kqueue'
            elif uwsgi_os.startswith('CYGWIN') or uwsgi_os == 'GNU':
                event_mode = 'poll'

        if event_mode == 'epoll':
            self.cflags.append('-DUWSGI_EVENT_USE_EPOLL')
        elif event_mode == 'kqueue':
            self.cflags.append('-DUWSGI_EVENT_USE_KQUEUE')
        elif event_mode == 'devpoll':
            self.cflags.append('-DUWSGI_EVENT_USE_DEVPOLL')
        elif event_mode == 'port':
            self.cflags.append('-DUWSGI_EVENT_USE_PORT')
        elif event_mode == 'poll':
            self.cflags.append('-DUWSGI_EVENT_USE_POLL')

        report['event'] = event_mode

        # set timer subsystem
        timer_mode = self.get('timer','auto')

        if timer_mode == 'auto':
            if uwsgi_os == 'Linux':
                k_all = uwsgi_os_k.split('.')
                k_base = k_all[0]
                k_major = k_all[1]
                if len(k_all) > 2:
                    k_minor = k_all[2]
                else:
                    k_minor = 0
                if int(k_base) > 2:
                    timer_mode = 'timerfd'
                elif int(k_minor) >= 25:
                    timer_mode = 'timerfd'
                else:
                    timer_mode = 'none'

            elif uwsgi_os == 'SunOS':
                sun_major, sun_minor = uwsgi_os_k.split('.')
                if int(sun_major) >= 5:
                    if int(sun_minor) >= 10:
                        timer_mode = 'port'

            elif uwsgi_os in ('Darwin', 'FreeBSD', 'GNU/kFreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly'):
                timer_mode = 'kqueue'

        if timer_mode == 'timerfd':
            self.cflags.append('-DUWSGI_EVENT_TIMER_USE_TIMERFD')
            if not self.has_include('sys/timerfd.h'):
                self.cflags.append('-DUWSGI_EVENT_TIMER_USE_TIMERFD_NOINC')
        elif timer_mode == 'kqueue':
            self.cflags.append('-DUWSGI_EVENT_TIMER_USE_KQUEUE')
        elif timer_mode == 'port':
            self.cflags.append('-DUWSGI_EVENT_TIMER_USE_PORT')
        else:
            self.cflags.append('-DUWSGI_EVENT_TIMER_USE_NONE')

        report['timer'] = timer_mode

        # set filemonitor subsystem
        filemonitor_mode = self.get('filemonitor','auto')

        if filemonitor_mode == 'auto':
            if uwsgi_os == 'Linux':
                filemonitor_mode = 'inotify'
            elif uwsgi_os == 'SunOS':
                sun_major, sun_minor = uwsgi_os_k.split('.')
                if int(sun_major) >= 5:
                    if int(sun_minor) >= 10:
                        filemonitor_mode = 'port'
            elif uwsgi_os in ('Darwin', 'FreeBSD', 'GNU/kFreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly'):
                filemonitor_mode = 'kqueue'

        if filemonitor_mode == 'inotify':
            self.cflags.append('-DUWSGI_EVENT_FILEMONITOR_USE_INOTIFY')
        elif filemonitor_mode == 'kqueue':
            self.cflags.append('-DUWSGI_EVENT_FILEMONITOR_USE_KQUEUE')
        elif filemonitor_mode == 'port':
            self.cflags.append('-DUWSGI_EVENT_FILEMONITOR_USE_PORT')
        else:
            self.cflags.append('-DUWSGI_EVENT_FILEMONITOR_USE_NONE')


        report['filemonitor'] = filemonitor_mode

        if self.get('malloc_implementation') != 'libc':
            if self.get('malloc_implementation') == 'tcmalloc':
                self.libs.append('-ltcmalloc')
            if self.get('malloc_implementation') == 'jemalloc':
                self.libs.append('-ljemalloc')

        report['malloc'] = self.get('malloc_implementation')


        if self.get('as_shared_library'):
            self.ldflags.append('-shared')
            # on cygwin we do not need PIC (it is implicit)
            if not uwsgi_os.startswith('CYGWIN'):
                self.ldflags.append('-fPIC')
                self.cflags.append('-fPIC')
            self.cflags.append('-DUWSGI_AS_SHARED_LIBRARY')
            if uwsgi_os == 'Darwin':
                self.ldflags.append('-dynamiclib')
                self.ldflags.append('-undefined dynamic_lookup')

        if self.get('blacklist'):
            self.cflags.append('-DUWSGI_BLACKLIST="\\"%s\\""' % self.get('blacklist'))

        if self.get('whitelist'):
            self.cflags.append('-DUWSGI_WHITELIST="\\"%s\\""' % self.get('whitelist'))

        has_pcre = False

        required_pcre = self.get('pcre')
        if required_pcre:
            pcre_libs = spcall('pcre2-config --libs8')
            if pcre_libs:
                pcre_cflags = spcall("pcre2-config --cflags")
                pcre_define = "-DUWSGI_PCRE2"
            else:
                pcre_libs = spcall('pcre-config --libs')
                pcre_cflags = spcall("pcre-config --cflags")
                pcre_define = "-DUWSGI_PCRE"
        else:
            pcre_libs = None

        if required_pcre:
            if required_pcre != 'auto' and pcre_libs is None:
                print("*** libpcre headers unavailable. uWSGI build is interrupted. You have to install pcre development package or disable pcre")
                sys.exit(1)

            if pcre_libs:
                self.libs.append(pcre_libs)
                self.cflags.append(pcre_cflags)
                self.gcc_list.append('core/regexp')
                self.cflags.append(pcre_define)
                has_pcre = True

        if has_pcre:
            report['pcre'] = True

        if self.get('routing'):
            if self.get('routing') == 'auto':
                if has_pcre:
                    self.gcc_list.append('core/routing')
                    self.cflags.append("-DUWSGI_ROUTING") 
                    report['routing'] = True
            else:
                self.gcc_list.append('core/routing')
                self.cflags.append("-DUWSGI_ROUTING")
                report['routing'] = True


        if self.has_include('sys/capability.h') and uwsgi_os == 'Linux':
            self.cflags.append("-DUWSGI_CAP")
            self.libs.append('-lcap')
            report['capabilities'] = True

        if self.has_include('uuid/uuid.h'):
            self.cflags.append("-DUWSGI_UUID")
            if uwsgi_os in ('Linux', 'GNU', 'GNU/kFreeBSD') or uwsgi_os.startswith('CYGWIN') or os.path.exists('/usr/lib/libuuid.so') or os.path.exists('/usr/local/lib/libuuid.so') or os.path.exists('/usr/lib64/libuuid.so') or os.path.exists('/usr/local/lib64/libuuid.so'):
                self.libs.append('-luuid')

        if self.get('append_version'):
            if not self.get('append_version').startswith('-'):
                uwsgi_version += '-'
            uwsgi_version += self.get('append_version')


        if uwsgi_os in ('FreeBSD','GNU/kFreeBSD') and self.has_include('jail.h'):
            self.cflags.append('-DUWSGI_HAS_FREEBSD_LIBJAIL')
            self.libs.append('-ljail')

        self.embed_config = None

        if uwsgi_os not in ('Darwin',):
            self.embed_config = os.environ.get('UWSGI_EMBED_CONFIG')
            if not self.embed_config:
                self.embed_config = self.get('embed_config')
            if self.embed_config:
                binary_link_cmd = "ld -z noexecstack -r -b binary -o %s.o %s" % (binarize(self.embed_config), self.embed_config)
                print(binary_link_cmd)
                subprocess.call(binary_link_cmd, shell=True)
                self.cflags.append("-DUWSGI_EMBED_CONFIG=_binary_%s_start" % binarize(self.embed_config))
                self.cflags.append("-DUWSGI_EMBED_CONFIG_END=_binary_%s_end" % binarize(self.embed_config))
            embed_files = os.environ.get('UWSGI_EMBED_FILES')
            if not embed_files:
                embed_files = self.get('embed_files')
            if embed_files:
                for ef in embed_files.split(','):
                    ef_parts = ef.split('=')
                    symbase = None
                    if len(ef_parts) > 1:
                        ef = ef_parts[1]
                        symbase = ef_parts[0]
                    if os.path.isdir(ef):
                        for directory, directories, files in os.walk(ef):
                            for f in files:
                                fname = "%s/%s" % (directory, f)
                                binary_link_cmd = "ld -z noexecstack -r -b binary -o %s.o %s" % (binarize(fname), fname)
                                print(binary_link_cmd)
                                subprocess.call(binary_link_cmd, shell=True)
                                if symbase:
                                    for kind in ('start','end'):
                                        objcopy_cmd = "objcopy --redefine-sym _binary_%s_%s=_binary_%s%s_%s build/%s.o" % (binarize(fname), kind, binarize(symbase), binarize(fname[len(ef):]), kind, binarize(fname))
                                        print(objcopy_cmd)
                                        subprocess.call(objcopy_cmd, shell=True)
                                binary_list.append(binarize(fname))
                    else:
                        binary_link_cmd = "ld -z noexecstack -r -b binary -o %s.o %s" % (binarize(ef), ef)
                        print(binary_link_cmd)
                        subprocess.call(binary_link_cmd, shell=True)
                        binary_list.append(binarize(ef))
                        if symbase:
                            for kind in ('start','end'):
                                objcopy_cmd = "objcopy --redefine-sym _binary_%s_%s=_binary_%s_%s build/%s.o" % (binarize(ef), kind, binarize(symbase), kind, binarize(ef))
                                print(objcopy_cmd)
                                subprocess.call(objcopy_cmd, shell=True)

        self.cflags.append('-DUWSGI_VERSION="\\"' + uwsgi_version + '\\""')

        uver_whole = uwsgi_version.split('-', 1)
        if len(uver_whole) == 1:
            uver_custom = ''
        else:
            uver_custom = uver_whole[1]

        uver_dots = uver_whole[0].split('.')

        uver_base = uver_dots[0]
        uver_maj = uver_dots[1]
        uver_min = '0'
        uver_rev = '0'

        if len(uver_dots) > 2:
            uver_min = uver_dots[2]

        if len(uver_dots) > 3:
            uver_rev = uver_dots[3]
        

        self.cflags.append('-DUWSGI_VERSION_BASE="' + uver_base + '"')
        self.cflags.append('-DUWSGI_VERSION_MAJOR="' + uver_maj + '"')
        self.cflags.append('-DUWSGI_VERSION_MINOR="' + uver_min + '"')
        self.cflags.append('-DUWSGI_VERSION_REVISION="' + uver_rev + '"')
        self.cflags.append('-DUWSGI_VERSION_CUSTOM="\\"' + uver_custom + '\\""')

        if self.get('yaml'):
            self.cflags.append("-DUWSGI_YAML")
            self.gcc_list.append('core/yaml')
            report['yaml'] = 'embedded'
            if self.get('yaml') == 'libyaml':
                self.cflags.append("-DUWSGI_LIBYAML")
                self.libs.append('-lyaml')
                report['yaml'] = 'libyaml'

        if self.get('json'):
            if self.get('json') in ('auto', 'true'):
                jsonconf = spcall("pkg-config --cflags jansson")
                if jsonconf:
                    self.cflags.append(jsonconf)
                    self.cflags.append("-DUWSGI_JSON")
                    self.gcc_list.append('core/json')
                    self.libs.append(spcall("pkg-config --libs jansson"))
                    report['json'] = 'jansson'
                elif self.has_include('jansson.h'):
                    self.cflags.append("-DUWSGI_JSON")
                    self.gcc_list.append('core/json')
                    self.libs.append('-ljansson')
                    report['json'] = 'jansson'
                else:
                    jsonconf = spcall("pkg-config --cflags yajl")
                    if jsonconf:
                        if jsonconf.endswith('include/yajl'):
                            jsonconf = jsonconf.rstrip('yajl')
                        self.cflags.append(jsonconf)
                        self.cflags.append("-DUWSGI_JSON")
                        self.gcc_list.append('core/json')
                        self.libs.append(spcall("pkg-config --libs yajl"))
                        self.cflags.append("-DUWSGI_JSON_YAJL")
                        report['json'] = 'yajl'
                    elif self.get('json') == 'true':
                        print("*** jansson and yajl headers unavailable. uWSGI build is interrupted. You have to install jansson or yajl development headers or disable JSON")
                        sys.exit(1)
            elif self.get('json') == 'jansson':
                jsonconf = spcall("pkg-config --cflags jansson")
                if jsonconf:
                    self.cflags.append(jsonconf)
                    self.cflags.append("-DUWSGI_JSON")
                    self.gcc_list.append('core/json')
                    self.libs.append(spcall("pkg-config --libs jansson"))
                    report['json'] = 'jansson'
                elif self.has_include('jansson.h'):
                    self.cflags.append("-DUWSGI_JSON")
                    self.gcc_list.append('core/json')
                    self.libs.append('-ljansson')
                    report['json'] = 'jansson'
                else:
                    print("*** jansson headers unavailable. uWSGI build is interrupted. You have to install jansson development package or use yajl or disable JSON")
                    sys.exit(1)
            elif self.get('json') == 'yajl':
                jsonconf = spcall("pkg-config --cflags yajl")
                if jsonconf:
                    self.cflags.append(jsonconf)
                    self.cflags.append("-DUWSGI_JSON")
                    self.gcc_list.append('core/json')
                    self.libs.append(spcall("pkg-config --libs yajl"))
                    self.cflags.append("-DUWSGI_JSON_YAJL")
                    report['json'] = 'yajl'
                elif self.has_include('yajl/yajl_tree.h'):
                    self.cflags.append("-DUWSGI_JSON")
                    self.gcc_list.append('core/json')
                    self.libs.append('-lyajl')
                    self.cflags.append("-DUWSGI_JSON_YAJL")
                    report['json'] = 'yajl'
                elif self.has_include('yajl/yajl_parse.h'):
                    self.cflags.append("-DUWSGI_JSON")
                    self.gcc_list.append('core/json')
                    self.libs.append('-lyajl')
                    self.cflags.append("-DUWSGI_JSON_YAJL_OLD")
                    report['json'] = 'yajl_old'
                else:
                    print("*** yajl headers unavailable. uWSGI build is interrupted. You have to install yajl development package or use jansson or disable JSON")
                    sys.exit(1)
        
                
        if self.get('ssl'):
            if self.get('ssl') == 'auto':
                if self.has_include('openssl/ssl.h'):
                    self.cflags.append("-DUWSGI_SSL")
                    self.libs.append('-lssl')
                    self.libs.append('-lcrypto')
                    self.gcc_list.append('core/ssl')
                    self.gcc_list.append('core/legion')
                    report['ssl'] = True
            else:
                self.cflags.append("-DUWSGI_SSL")
                self.libs.append('-lssl')
                self.libs.append('-lcrypto')
                self.gcc_list.append('core/ssl')
                self.gcc_list.append('core/legion')
                report['ssl'] = True

        if self.get('xml'):
            if self.get('xml') == 'auto':
                xmlconf = spcall('xml2-config --libs')
                if xmlconf and uwsgi_os != 'Darwin':
                    self.libs.append(xmlconf)
                    xmlconf = spcall("xml2-config --cflags")
                    self.cflags.append(xmlconf)
                    self.cflags.append("-DUWSGI_XML -DUWSGI_XML_LIBXML2")
                    self.gcc_list.append('core/xmlconf')
                    report['xml'] = 'libxml2'
                elif self.has_include('expat.h'):
                    self.cflags.append("-DUWSGI_XML -DUWSGI_XML_EXPAT")
                    self.libs.append('-lexpat')
                    self.gcc_list.append('core/xmlconf')
                    report['xml'] = 'expat'
            elif self.get('xml') == 'libxml2':
                xmlconf = spcall('xml2-config --libs')
                if xmlconf is None:
                    print("*** libxml2 headers unavailable. uWSGI build is interrupted. You have to install libxml2 development package or use libexpat or disable XML")
                    sys.exit(1)
                else:
                    self.libs.append(xmlconf)
                    xmlconf = spcall("xml2-config --cflags")
                    if xmlconf is None:
                        print("*** libxml2 headers unavailable. uWSGI build is interrupted. You have to install libxml2 development package or use libexpat or disable XML")
                        sys.exit(1)
                    else:
                        self.cflags.append(xmlconf)
                        self.cflags.append("-DUWSGI_XML -DUWSGI_XML_LIBXML2")
                        self.gcc_list.append('core/xmlconf')
                        report['xml'] = 'libxml2'
            elif self.get('xml') == 'expat':
                self.cflags.append("-DUWSGI_XML -DUWSGI_XML_EXPAT")
                self.libs.append('-lexpat')
                self.gcc_list.append('core/xmlconf')
                report['xml'] = 'expat'

        if self.get('plugin_dir'):
            self.cflags.append('-DUWSGI_PLUGIN_DIR="\\"%s\\""' % self.get('plugin_dir'))
            report['plugin_dir'] = self.get('plugin_dir')

        if self.get('debug'):
            self.cflags.append("-DUWSGI_DEBUG")
            self.cflags.append("-g")
            report['debug'] = True

        if self.get('unbit'):
            self.cflags.append("-DUNBIT")

        return self.gcc_list, self.cflags, self.ldflags, self.libs

def build_plugin(path, uc, cflags, ldflags, libs, name = None):
    path = path.rstrip('/')

    plugin_started_at = time.time()

    up = {}

    if path.startswith('http://') or path.startswith('https://') or path.startswith('git://') or path.startswith('ssh://'):
        git_dir = path.split('/').pop()
        if not os.path.isdir(git_dir):
            if os.system('git clone %s' % path) != 0:
                sys.exit(1)
        else:
            if os.system('cd %s ; git pull' % git_dir) != 0:
                sys.exit(1)
        path = os.path.abspath(git_dir)

    if os.path.isfile(path):
        bname = os.path.basename(path)
        # override path
        path = os.path.dirname(path)
        up['GCC_LIST'] = [bname]
        up['NAME'] = bname.split('.')[0]
        if not path: path = '.'
    elif os.path.isdir(path):
        try:
            execfile('%s/uwsgiplugin.py' % path, up)
        except:
            f = open('%s/uwsgiplugin.py' % path)
            exec(f.read(), up)
            f.close()
    else:
        print("Error: unable to find directory '%s'" % path)
        sys.exit(1)

    requires = []

    p_cflags = cflags[:]
    p_ldflags = ldflags[:]

    try:
        p_cflags += up['CFLAGS']
    except:
        pass

    try:
        p_ldflags += up['LDFLAGS']
    except:
        pass

    try:
        p_libs = up['LIBS']
    except:
        p_libs = []

    post_build = None

    try:
        requires = up['REQUIRES']
    except:
        pass

    try:
        post_build = up['post_build']
    except:
        pass

    p_cflags.insert(0, '-I.')

    if name is None:
        name = up['NAME']
    else:
        p_cflags.append("-D%s_plugin=%s_plugin" % (up['NAME'], name))

    try:
        for opt in uc.config.options(name):
            p_cflags.append('-DUWSGI_PLUGIN_%s_%s="%s"' % (name.upper(), opt.upper(), uc.config.get(name, opt, '1')))
    except:
        pass

    if uc:
        plugin_dest = uc.get('plugin_build_dir', uc.get('plugin_dir')) + '/' + name + '_plugin'
    else:
        plugin_dest = name + '_plugin'

    shared_flag = '-shared'

    gcc_list = []

    if uwsgi_os == 'Darwin':
        shared_flag = '-dynamiclib -undefined dynamic_lookup'

    for cfile in up['GCC_LIST']:
        if cfile.endswith('.a'): 
            gcc_list.append(cfile)
        elif not cfile.endswith('.c') and not cfile.endswith('.cc') and not cfile.endswith('.m') and not cfile.endswith('.go') and not cfile.endswith('.o'):
            gcc_list.append(path + '/' + cfile + '.c')
        else:
            if cfile.endswith('.go'):
                p_cflags.append('-Wno-error')
            gcc_list.append(path + '/' + cfile)
    for bfile in up.get('BINARY_LIST', []):
        try:
            binary_link_cmd = "ld -r -b binary -o %s/%s.o %s/%s" % (path, bfile[1], path, bfile[1])
            print(binary_link_cmd)
            if subprocess.call(binary_link_cmd, shell=True) != 0:
                raise Exception('unable to link binary file')
            for kind in ('start','end'):
                objcopy_cmd = "objcopy --redefine-sym _binary_%s_%s=%s_%s %s/%s.o" % (binarize('%s/%s' % (path, bfile[1])), kind, bfile[0], kind, path, bfile[1])
                print(objcopy_cmd)
                if subprocess.call(objcopy_cmd, shell=True) != 0:
                    raise Exception('unable to link binary file')
            gcc_list.append('%s/%s.o' % (path, bfile[1]))
        except:
            pass

    try:
        p_ldflags.remove('-Wl,--no-undefined')
    except:
        pass

    try:
        p_cflags.remove('-Wwrite-strings')
    except:
        pass

    try:
        p_cflags.remove('-Werror=write-strings')
    except:
        pass

    try:
        p_cflags.remove('-Wdeclaration-after-statement')
    except:
        pass

    try:
        p_cflags.remove('-Werror=declaration-after-statement')
    except:
        pass

    try:
        p_cflags.remove('-Winline')
    except:
        pass

    try:
        p_cflags.remove('-pie')
    except:
        pass

    if GCC in ('clang',):
        try:
            p_cflags.remove('-fno-fast-math')
            p_cflags.remove('-ggdb3')
        except:
            pass

    if uwsgi_os.startswith('CYGWIN'):
        try:
            p_cflags.remove('-fstack-protector')
            p_ldflags.remove('-fstack-protector')
        except:
            pass

    need_pic = ' -fPIC'
    # on cygwin we do not need PIC
    if uwsgi_os.startswith('CYGWIN'):
        need_pic = ' -L. -luwsgi'

    gccline = "%s%s %s -o %s.so %s %s %s %s" % (GCC, need_pic, shared_flag, plugin_dest, ' '.join(uniq_warnings(p_cflags)), ' '.join(gcc_list), ' '.join(uniq_warnings(p_ldflags)), ' '.join(uniq_warnings(p_libs)) )
    print_compilation_output("[%s] %s.so" % (GCC, plugin_dest), gccline)

    ret = subprocess.call(gccline, shell=True)
    if ret != 0:
        print("*** unable to build %s plugin ***" % name)
        sys.exit(1)

    try:
        if requires:
            f = open('.uwsgi_plugin_section', 'w')
            for rp in requires:
                f.write("requires=%s\n" % rp)
            f.close()
            objline = "objcopy %s.so --add-section uwsgi=.uwsgi_plugin_section %s.so" % (plugin_dest, plugin_dest)
            print_compilation_output(None, objline)
            subprocess.call(objline, shell=True)
            os.unlink('.uwsgi_plugin_section')
    except:
        pass

    if post_build:
        post_build(uc)

    print("build time: %d seconds" % (time.time() - plugin_started_at))
    print("*** %s plugin built and available in %s ***" % (name, plugin_dest + '.so'))

def vararg_callback(option, opt_str, value, parser):
    assert value is None
    value = []
    for arg in parser.rargs:
        # stop on --foo like options
        if arg[:2] == "--" and len(arg) > 2:
            break
        # stop on -a, but not on -3 or -3.0
        if arg[:1] == "-" and len(arg) > 1:
            break
        value.append(arg)

    del parser.rargs[:len(value)]
    setattr(parser.values, option.dest, value)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-b", "--build", action="callback", callback=vararg_callback, dest="build", help="build a specific profile if provided or default.ini", metavar="PROFILE")
    parser.add_option("-f", "--cflags", action="callback", callback=vararg_callback, dest="cflags", help="same as --build but less verbose", metavar="PROFILE")
    parser.add_option("-u", "--unbit", action="store_true", dest="unbit", help="build unbit profile")
    parser.add_option("-p", "--plugin", action="callback", callback=vararg_callback, dest="plugin", help="build a plugin as shared library, optionally takes a build profile name", metavar="PLUGIN [PROFILE]")
    parser.add_option("-x", "--extra-plugin", action="callback", callback=vararg_callback,  dest="extra_plugin", help="build an external plugin as shared library, takes an optional include dir", metavar="PLUGIN [NAME]")
    parser.add_option("-c", "--clean", action="store_true", dest="clean", help="clean the build")
    parser.add_option("-e", "--check", action="store_true", dest="check", help="run cppcheck")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="more verbose build")
    parser.add_option("-g", "--debug", action="store_true", dest="debug", help="build with debug symbols, affects only full build")
    parser.add_option("-a", "--asan", action="store_true", dest="asan", help="build with address sanitizer, it's a debug option and affects only full build")

    (options, args) = parser.parse_args()

    if options.verbose:
        verbose_build = True

    add_cflags = []
    add_ldflags = []

    if options.debug:
       add_cflags.append('-g')
       add_ldflags.append('-g')

    if options.asan:
       add_cflags.extend(['-g', '-fsanitize=address', '-fno-omit-frame-pointer'])
       add_ldflags.extend(['-g', '-fsanitize=address'])

    if options.build is not None or options.cflags is not None:
        is_cflags = options.cflags is not None
        try:
            if not is_cflags:
                bconf = options.build[0]
            else:
                bconf = options.cflags[0]
        except:
            bconf = os.environ.get('UWSGI_PROFILE','default.ini')
        if not bconf.endswith('.ini'):
            bconf += '.ini'
        if not '/' in bconf:
            bconf = 'buildconf/%s' % bconf

        uc = uConf(bconf, is_cflags)
        if add_cflags or add_ldflags:
            gcc_list, cflags, ldflags, libs = uc.get_gcll()
            if add_cflags:
                cflags.extend(add_cflags)
            if add_ldflags:
                ldflags.extend(add_ldflags)
            gcll = (gcc_list, cflags, ldflags, libs)
        else:
            gcll = None
        build_uwsgi(uc, is_cflags, gcll=gcll)
    elif options.unbit:
        build_uwsgi(uConf('buildconf/unbit.ini'))
    elif options.plugin:
        try:
            bconf = options.plugin[1]
        except:
            bconf = os.environ.get('UWSGI_PROFILE','default.ini')
        if not bconf.endswith('.ini'):
            bconf += '.ini'
        if not '/' in bconf:
            bconf = 'buildconf/%s' % bconf
        uc = uConf(bconf)
        gcc_list, cflags, ldflags, libs = uc.get_gcll()
        try:
            name = options.plugin[2]
        except:
            name = None
        print("*** uWSGI building and linking plugin %s ***" % options.plugin[0] )
        build_plugin(options.plugin[0], uc, cflags, ldflags, libs, name)
    elif options.extra_plugin:
        print("*** uWSGI building and linking plugin from %s ***" % options.extra_plugin[0])
        cflags = os.environ['UWSGI_PLUGINS_BUILDER_CFLAGS'].split() + os.environ.get("CFLAGS", "").split()
        cflags.append('-I.uwsgi_plugins_builder/')
        ldflags = os.environ.get("LDFLAGS", "").split()
        name = None
        try:
            name = options.extra_plugin[1]
        except:
            pass
        build_plugin(options.extra_plugin[0], None, cflags, ldflags, None, name)
    elif options.clean:
        subprocess.call("rm -f core/*.o", shell=True)
        subprocess.call("rm -f proto/*.o", shell=True)
        subprocess.call("rm -f lib/*.o", shell=True)
        subprocess.call("rm -f plugins/*/*.o", shell=True)
        subprocess.call("rm -f build/*.o", shell=True)
        subprocess.call("rm -f core/dot_h.c", shell=True)
        subprocess.call("rm -f core/config_py.c", shell=True)
    elif options.check:
        subprocess.call("cppcheck --max-configs=1000 --enable=all -q core/ plugins/ proto/ lib/ apache2/", shell=True)
    else:
        parser.print_help()
        sys.exit(1)
