# uWSGI build system

import os
import re
import time
uwsgi_os = os.uname()[0]
uwsgi_os_k = re.split('[-+]', os.uname()[2])[0]
uwsgi_os_v = os.uname()[3]
uwsgi_cpu = os.uname()[4]

import sys
import subprocess

from distutils import sysconfig

try:
    import ConfigParser
except:
    import configparser as ConfigParser
    from imp import reload

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


def add_o(x):
    if x == 'uwsgi':
        x = 'main'
    x = x + '.o'
    return x


def compile(file, objfile, cflags):
    cmdline = "%s -c %s -o %s %s" % (GCC, cflags, objfile, file)
    print(cmdline)
    ret = os.system(cmdline)
    if ret != 0:
        sys.exit(1)


def build_uwsgi(uc):

    gcc_list, cflags, ldflags, libs = uc.get_gcll()

    if uc.get('embedded_plugins'):
        ep = uc.get('embedded_plugins').split(',')
        epc = "-DUWSGI_DECLARE_EMBEDDED_PLUGINS=\""
        eplc = "-DUWSGI_LOAD_EMBEDDED_PLUGINS=\""
        for p in ep:
            p = p.rstrip().lstrip()
            if p == 'ugreen':
                if uwsgi_os == 'OpenBSD' or uwsgi_cpu[0:3] == 'arm' or uwsgi_os == 'Haiku':
                    continue
            epc += "UDEP(%s);" % p
            eplc += "ULEP(%s);" % p
        epc += "\""
        eplc += "\""

        cflags.append(epc)
        cflags.append(eplc)

    print("*** uWSGI compiling server core ***")
    for file in gcc_list:
        objfile = file
        if objfile == 'uwsgi':
            objfile = 'main'
        compile(' '.join(cflags), objfile + '.o', file + '.c')

    if uc.get('embedded_plugins'):
        ep = uc.get('embedded_plugins').split(',')

        if len(ep) > 0:
            print("*** uWSGI compiling embedded plugins ***")
            for p in ep:
                p = p.rstrip().lstrip()

                if p == 'ugreen':
                    if uwsgi_os == 'OpenBSD' or uwsgi_cpu[0:3] == 'arm' or uwsgi_os == 'Haiku':
                        continue
                path = 'plugins/%s' % p
                path = path.rstrip('/')

                sys.path.insert(0, path)
                import uwsgiplugin as up
                reload(up)

                p_cflags = cflags[:]
                p_cflags += up.CFLAGS

                for cfile in up.GCC_LIST:
                    compile(' '.join(p_cflags),
                        path + '/' + cfile + '.o', path + '/' + cfile + '.c')
                    gcc_list.append('%s/%s' % (path, cfile))

                libs += up.LIBS
                ldflags += up.LDFLAGS

                up.CFLAGS = None
                up.LDFLAGS = None
                up.LIBS = None
                up.GCC_LIST = None

    if uc.get('plugins'):

        plugins = uc.get('plugins').split(',')
        if len(plugins) > 0:
            print("*** uWSGI building plugins ***")

            for p in plugins:
                p = p.rstrip().lstrip()
                print("*** building plugin: %s ***" % p)
                build_plugin("plugins/%s" % p, uc, cflags, ldflags, libs)

    bin_name = uc.get('bin_name')

    print("*** uWSGI linking ***")
    ldline = "%s -o %s %s %s %s" % (GCC, bin_name, ' '.join(ldflags),
        ' '.join(map(add_o, gcc_list)), ' '.join(libs))
    print(ldline)
    ret = os.system(ldline)
    if ret != 0:
        print("*** error linking uWSGI ***")
        sys.exit(1)

    if bin_name.find("/") < 0:
        bin_name = './' + bin_name
    print("*** uWSGI is ready, launch it with %s ***" % bin_name)


class uConf(object):

    def __init__(self, filename):
        self.config = ConfigParser.ConfigParser()
        print("using profile: %s" % filename)
        self.config.read(filename)
        self.gcc_list = ['utils', 'protocol', 'socket', 'logging', 'master', 'emperor',
            'plugins', 'lock', 'cache', 'queue', 'event', 'signal', 'rpc', 'gateway', 'loop', 'lib/rbtree', 'lib/amqp', 'rb_timers', 'uwsgi']
        #if uwsgi_os == 'Linux':
        #    self.gcc_list.append('lib/netlink')
        self.cflags = ['-O2', '-Wall', '-Werror', '-D_LARGEFILE_SOURCE', '-D_FILE_OFFSET_BITS=64'] + os.environ.get("CFLAGS", "").split()
        try:
            gcc_version = str(spcall("%s -dumpversion" % GCC))
        except:
            print("*** you need a c compiler to build uWSGI ***")
            sys.exit(1)
        gcc_major = int(gcc_version.split('.')[0])
        gcc_minor = int(gcc_version.split('.')[1])
        if (sys.version_info[0] == 2) or (gcc_major < 4) or (gcc_major == 4 and gcc_minor < 3):
            self.cflags = self.cflags + ['-fno-strict-aliasing']
        # add -fno-strict-aliasing only on python2 and gcc < 4.3
        if gcc_major >= 4:
            self.cflags = self.cflags + [ '-Wextra', '-Wno-unused-parameter', '-Wno-missing-field-initializers' ]

        self.ldflags = os.environ.get("LDFLAGS", "").split()
        self.libs = ['-lpthread', '-rdynamic']
        if uwsgi_os == 'Linux':
            self.libs.append('-ldl')

        # check for inherit option
        inherit = self.get('inherit')
        if inherit:
            if not '/' in inherit:
                inherit = 'buildconf/%s' % inherit

            if not inherit.endswith('.ini'):
                inherit = '%s.ini' % inherit

            iconfig = ConfigParser.ConfigParser()
            iconfig.read(inherit)
            for opt in iconfig.options('uwsgi'):
                if not self.get(opt):
                    self.set(opt, iconfig.get('uwsgi', opt))
                elif self.get(opt).startswith('+'):
                    self.set(opt, iconfig.get('uwsgi', opt) + self.get(opt)[1:])
                elif self.get(opt) == 'null':
                    self.config.remove_option('uwsgi', opt)


    def set(self, key, value):
        self.config.set('uwsgi',key, value)

    def get(self,key,default=None):
        try:
            value = self.config.get('uwsgi', key)
            if value == "" or value == "false":
                return None
            return value
        except:
            if default:
                return default
            return None

    def depends_on(self, what, dep):
        for d in dep:
            if not self.get(d):
                print("%s needs %s support." % (what, d))
                sys.exit(1)

    def get_gcll(self):

        self.cflags.append('-DUWSGI_BUILD_DATE="\\"%s\\""' % time.strftime("%d %B %Y %H:%M:%S"))
        kvm_list = ['FreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly']

        if uwsgi_os == 'SunOS':
            self.libs.append('-lsendfile')
            self.gcc_list.append('lib/sun_fixes')
            if not uwsgi_os_v.startswith('Nexenta'):
                self.libs.remove('-rdynamic')

        if uwsgi_os in kvm_list:
            self.libs.append('-lkvm')

        if uwsgi_os == 'Haiku':
            self.set('async', 'false')
            self.libs.remove('-rdynamic')
            self.libs.remove('-lpthread')
            self.libs.append('-lroot')

        if uwsgi_os == 'Darwin':
            self.cflags.append('-mmacosx-version-min=10.5')

        # set locking subsystem
        locking_mode = self.get('locking','auto')

        if locking_mode == 'auto':
            if uwsgi_os == 'Linux' or uwsgi_os == 'SunOS':
                locking_mode = 'pthread_mutex'
            elif uwsgi_os == 'FreeBSD':
                locking_mode = 'umtx'
            elif uwsgi_os == 'Darwin':
                locking_mode = 'osx_spinlock'

        if locking_mode == 'pthread_mutex':
            self.cflags.append('-DUWSGI_LOCK_USE_MUTEX')
        elif locking_mode == 'umtx':
            self.cflags.append('-DUWSGI_LOCK_USE_UMTX')
        elif locking_mode == 'osx_spinlock':
            self.cflags.append('-DUWSGI_LOCK_USE_OSX_SPINLOCK')
        else:
            self.cflags.append('-DUWSGI_LOCK_USE_FLOCK')

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
            elif uwsgi_os in ('Darwin', 'FreeBSD', 'OpenBSD', 'NetBSD'):
                event_mode = 'kqueue'

        if event_mode == 'epoll':
            self.cflags.append('-DUWSGI_EVENT_USE_EPOLL')
        elif event_mode == 'kqueue':
            self.cflags.append('-DUWSGI_EVENT_USE_KQUEUE')
        elif event_mode == 'devpoll':
            self.cflags.append('-DUWSGI_EVENT_USE_DEVPOLL')
        elif event_mode == 'port':
            self.cflags.append('-DUWSGI_EVENT_USE_PORT')

        # set timer subsystem
        timer_mode = self.get('timer','auto')

        if timer_mode == 'auto':
            if uwsgi_os == 'Linux':
                k_all = uwsgi_os_k.split('.')
                k_base = k_all[0]
                k_major = k_all[1]
                k_minor = k_all[2]
                if int(k_minor) >= 25:
                    timer_mode = 'timerfd'
                else:
                    timer_mode = 'none'

            elif uwsgi_os == 'SunOS':
                sun_major, sun_minor = uwsgi_os_k.split('.')
                if int(sun_major) >= 5:
                    if int(sun_minor) >= 10:
                        timer_mode = 'port'

            elif uwsgi_os in ('Darwin', 'FreeBSD'):
                timer_mode = 'kqueue'

        if timer_mode == 'timerfd':
            self.cflags.append('-DUWSGI_EVENT_TIMER_USE_TIMERFD')
            if not os.path.exists('/usr/include/sys/timerfd.h') and not os.path.exists('/usr/local/include/sys/timerfd.h'):
                self.cflags.append('-DUWSGI_EVENT_TIMER_USE_TIMERFD_NOINC')
        elif timer_mode == 'kqueue':
            self.cflags.append('-DUWSGI_EVENT_TIMER_USE_KQUEUE')
        elif timer_mode == 'port':
            self.cflags.append('-DUWSGI_EVENT_TIMER_USE_PORT')
        else:
            self.cflags.append('-DUWSGI_EVENT_TIMER_USE_NONE')

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
            elif uwsgi_os in ('Darwin', 'FreeBSD'):
                filemonitor_mode = 'kqueue'

        if filemonitor_mode == 'inotify':
            self.cflags.append('-DUWSGI_EVENT_FILEMONITOR_USE_INOTIFY')
        elif filemonitor_mode == 'kqueue':
            self.cflags.append('-DUWSGI_EVENT_FILEMONITOR_USE_KQUEUE')
        elif filemonitor_mode == 'port':
            self.cflags.append('-DUWSGI_EVENT_FILEMONITOR_USE_PORT')
        else:
            self.cflags.append('-DUWSGI_EVENT_FILEMONITOR_USE_NONE')


        if self.get('embedded'):
            self.cflags.append('-DUWSGI_EMBEDDED')

        if self.get('udp'):
            self.cflags.append("-DUWSGI_UDP")

        # re-enable after pcre fix
        if self.get('pcreOFF'):
            if self.get('pcre') == 'auto':
                pcreconf = spcall('pcre-config --libs')
                if pcreconf:
                    self.libs.append(pcreconf)
                    pcreconf = spcall("pcre-config --cflags")
                    self.cflags.append(pcreconf)
                    self.gcc_list.append('regexp')
                    self.cflags.append("-DUWSGI_PCRE")

            else:
                pcreconf = spcall('pcre-config --libs')
                if pcreconf is None:
                    print("*** libpcre headers unavailable. uWSGI build is interrupted. You have to install pcre development package or disable pcre")
                    sys.exit(1)
                else:
                    self.libs.append(pcreconf)
                    pcreconf = spcall("pcre-config --cflags")
                    self.cflags.append(pcreconf)
                    self.gcc_list.append('regexp')
                    self.cflags.append("-DUWSGI_PCRE")

        if self.get('async'):
            self.cflags.append("-DUWSGI_ASYNC")
            self.gcc_list.append('async')

        if self.get('multicast'):
            self.depends_on('multicast', ['udp'])
            self.cflags.append("-DUWSGI_MULTICAST")

        if self.get('minterpreters'):
            self.cflags.append("-DUWSGI_MINTERPRETERS")

        if self.get('ini'):
            self.cflags.append("-DUWSGI_INI")
            self.gcc_list.append('ini')

        if self.get('yaml'):
            self.cflags.append("-DUWSGI_YAML")
            self.gcc_list.append('yaml')

        if self.get('ldap'):
            if self.get('ldap') == 'auto':
                if os.path.exists('/usr/include/ldap.h'):
                    self.cflags.append("-DUWSGI_LDAP")
                    self.gcc_list.append('ldap')
                    self.libs.append('-lldap')
            else:
                self.cflags.append("-DUWSGI_LDAP")
                self.gcc_list.append('ldap')
                self.libs.append('-lldap')

        if self.get('evdis'):
            self.cflags.append("-DUWSGI_EVDIS")
            self.gcc_list.append('evdis')

        if self.get('snmp'):
            self.depends_on("snmp", ['udp'])
            self.cflags.append("-DUWSGI_SNMP")
            self.gcc_list.append('snmp')

        if self.get('threading'):
            self.cflags.append("-DUWSGI_THREADING")

        if self.get('sendfile'):
            self.cflags.append("-DUWSGI_SENDFILE")
            self.gcc_list.append('sendfile')

        if self.get('xml'):
            if self.get('xml_implementation') == 'libxml2':
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
                        self.gcc_list.append('xmlconf')
            elif self.get('xml_implementation') == 'expat':
                self.cflags.append("-DUWSGI_XML -DUWSGI_XML_EXPAT")
                self.libs.append('-lexpat')
                self.gcc_list.append('xmlconf')


        if self.get('plugin_dir'):
            self.cflags.append('-DUWSGI_PLUGIN_DIR=\\"%s\\"' % self.get('plugin_dir'))

        if self.get('spooler'):
            self.depends_on("spooler", ['embedded'])
            self.cflags.append("-DUWSGI_SPOOLER")
            self.gcc_list.append('spooler')

        if self.get('debug'):
            self.cflags.append("-DUWSGI_DEBUG")
            self.cflags.append("-g")

        if self.get('unbit'):
            self.cflags.append("-DUNBIT")

        return self.gcc_list, self.cflags, self.ldflags, self.libs

def build_plugin(path, uc, cflags, ldflags, libs, name = None):
    path = path.rstrip('/')

    sys.path.insert(0, path)
    import uwsgiplugin as up
    reload(up)

    p_cflags = cflags[:]
    p_ldflags = ldflags[:]
    p_libs = libs[:]

    p_cflags += up.CFLAGS
    p_ldflags += up.LDFLAGS
    p_libs += up.LIBS

    p_cflags.insert(0, '-I.')

    if name is None:
        name = up.NAME
    else:
        p_cflags.append("-D%s_plugin=%s_plugin" % (up.NAME, name))

    plugin_dest = uc.get('plugin_dir') + '/' + name + '_plugin'

    shared_flag = '-shared'

    gcc_list = []

    if uwsgi_os == 'Darwin':
        shared_flag = '-dynamiclib -undefined dynamic_lookup'

    for cfile in up.GCC_LIST:
        gcc_list.append(path + '/' + cfile + '.c')


    gccline = "%s -fPIC %s -o %s.so %s %s %s %s" % (GCC, shared_flag, plugin_dest, ' '.join(p_cflags), ' '.join(p_ldflags), ' '.join(gcc_list), ' '.join(p_libs) )
    print(gccline)

    ret = os.system(gccline)
    if ret != 0:
        print("*** unable to build %s plugin ***" % name)
        sys.exit(1)

    print("*** %s plugin built and available in %s ***" % (name, plugin_dest + '.so'))

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
        bconf = 'default.ini'
        try:
            bconf = sys.argv[2]
            if not bconf.endswith('.ini'):
                bconf += '.ini'
        except:
            pass
        if not '/' in bconf:
            bconf = 'buildconf/%s' % bconf
        build_uwsgi(uConf(bconf))
    elif cmd == '--unbit':
        build_uwsgi(uConf('buildconf/unbit.ini'))
    elif cmd == '--plugin':
        bconf = 'default.ini'
        try:
            bconf = sys.argv[3]
            if not bconf.endswith('.ini'):
                bconf += '.ini'
        except:
            pass
        if not '/' in bconf:
            bconf = 'buildconf/%s' % bconf

        uc = uConf(bconf)
        gcc_list, cflags, ldflags, libs = uc.get_gcll()
        try:
            name = sys.argv[4]
        except:
            name = None
        build_plugin(sys.argv[2], uc, cflags, ldflags, libs, name)
    else:
        print("unknown uwsgiconfig command")
        sys.exit(1)
