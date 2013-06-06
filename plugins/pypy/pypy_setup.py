import sys
import os
sys.path.insert(0, '.')
sys.path.extend(os.environ.get('PYTHONPATH','').split(os.pathsep))
import imp
import traceback


__name__ = '__main__'
mainmodule = type(sys)('__main__')
sys.modules['__main__'] = mainmodule

import cffi

# this is a list holding object we do not want to be freed (like callback and handlers)
uwsgi_gc = []
# the main ffi
ffi = cffi.FFI()

# the hooks we need to patch
hooks = '''
void free(void *);

void (*uwsgi_pypy_hook_loader)(char *);
void (*uwsgi_pypy_hook_file_loader)(char *);
void (*uwsgi_pypy_hook_pythonpath)(char *);
void (*uwsgi_pypy_hook_request)(struct wsgi_request *);
void (*uwsgi_pypy_post_fork_hook)(void);
'''

# here we load CFLAGS and uwsgi.h from the binary
defines0 = '''
char *uwsgi_get_cflags();
char *uwsgi_get_dot_h();
'''
ffi.cdef(defines0)
lib0 = ffi.verify(defines0)


# this is ugly, we should find a better approach
# basically it build a list of #define from binary CFLAGS
uwsgi_cdef = []
uwsgi_defines = []
uwsgi_cflags = ffi.string(lib0.uwsgi_get_cflags()).split()
for cflag in uwsgi_cflags:
    if cflag.startswith('-D'):
        line = cflag[2:]
        if '=' in line:
            (key, value) = line.split('=', 1)
            uwsgi_cdef.append('#define %s ...' % key)
            uwsgi_defines.append('#define %s %s' % (key, value.replace('\\"','"').replace('""','"')))            
        else:
            uwsgi_cdef.append('#define %s ...' % line)
            uwsgi_defines.append('#define %s 1' % line)            
uwsgi_dot_h = ffi.string(lib0.uwsgi_get_dot_h())

# uwsgi definitions
cdefines = '''
%s

struct iovec {
	void *iov_base;
	size_t iov_len;
	...;
};

struct wsgi_request {
	int async_id;
	uint16_t var_cnt;
	struct iovec *hvec;

	...;
};

struct uwsgi_opt {
	char *key;
	char *value;
	...;
};

struct uwsgi_worker {
	int id;
	int pid;
	uint64_t requests;
	uint64_t delta_requests;
	uint64_t signals;

	int cheaped;
	int suspended;
	int sig;
	uint8_t signum;

	uint64_t running_time;
	uint64_t avg_response_time;
	uint64_t tx;
	...;
};

struct uwsgi_plugin {
	uint8_t modifier1;
	...;
};

struct uwsgi_server {
	char hostname[];
	int mywid;
	int muleid;
	int master_process;

	struct uwsgi_opt **exported_opts;
	int exported_opts_cnt;	

	struct uwsgi_worker *workers;

	int signal_socket;
	int numproc;
	...;
};
struct uwsgi_server uwsgi;

struct uwsgi_plugin *pypy_plugin;

const char *uwsgi_pypy_version;

char *uwsgi_binary_path();

int uwsgi_response_prepare_headers(struct wsgi_request *, char *, size_t);
int uwsgi_response_add_header(struct wsgi_request *, char *, uint16_t, char *, uint16_t);
int uwsgi_response_write_body_do(struct wsgi_request *, char *, size_t);
int uwsgi_response_sendfile_do_can_close(struct wsgi_request *, int, size_t, size_t, int);

char *uwsgi_request_body_read(struct wsgi_request *, ssize_t , ssize_t *);
char *uwsgi_request_body_readline(struct wsgi_request *, ssize_t, ssize_t *);

int uwsgi_register_rpc(char *, struct uwsgi_plugin *, uint8_t, void *);
int uwsgi_register_signal(uint8_t, char *, void *, uint8_t);

char *uwsgi_do_rpc(char *, char *, uint8_t, char **, uint16_t *, uint16_t *);

void uwsgi_set_processname(char *);
int uwsgi_signal_send(int, uint8_t);
uint64_t uwsgi_worker_exceptions(int);
int uwsgi_worker_is_busy(int);

char *uwsgi_cache_magic_get(char *, uint16_t, uint64_t *, uint64_t *, char *);
int uwsgi_cache_magic_set(char *, uint16_t, char *, uint64_t, uint64_t, uint64_t, char *);
int uwsgi_cache_magic_del(char *, uint16_t, char *);
int uwsgi_cache_magic_exists(char *, uint16_t, char *);
int uwsgi_cache_magic_clear(char *);

int uwsgi_add_file_monitor(uint8_t, char *);
int uwsgi_add_timer(uint8_t, int);
int uwsgi_signal_add_rb_timer(uint8_t, int, int);

int uwsgi_user_lock(int);
int uwsgi_user_unlock(int);

int uwsgi_signal_registered(uint8_t);

int uwsgi_signal_add_cron(uint8_t, int, int, int, int, int);
void uwsgi_alarm_trigger(char *, char *, size_t);

%s

''' % ('\n'.join(uwsgi_cdef), hooks)

cverify = '''
%s

const char *uwsgi_pypy_version = UWSGI_VERSION;

%s

extern struct uwsgi_server uwsgi;
extern struct uwsgi_plugin *pypy_plugin;
%s
''' % ('\n'.join(uwsgi_defines), uwsgi_dot_h, hooks)

ffi.cdef(cdefines)
lib = ffi.verify(cverify)
libc = ffi.dlopen(None)



"""
this is a global object point the the WSGI callable
it sucks, i will fix it in the near future...
"""
wsgi_application = None


sys.argv.insert(0, ffi.string(lib.uwsgi_binary_path()))


"""
load a wsgi module
"""
@ffi.callback("void(char *)")
def uwsgi_pypy_loader(module):
    global wsgi_application
    m = ffi.string(module)
    c = 'application'
    if ':' in m:
        m, c = m.split(':')
    if '.' in m:
        mod = __import__(m, None, None, '*')
    else:
        mod = __import__(m)
    wsgi_application = getattr(mod, c)

"""
load a mod_wsgi compliant .wsgi file
"""
@ffi.callback("void(char *)")
def uwsgi_pypy_file_loader(filename):
    global wsgi_application
    w = ffi.string(filename)
    c = 'application'
    mod = imp.load_source('uwsgi_file_wsgi', w)
    wsgi_application = getattr(mod, c)

"""
.post_fork_hokk
"""
@ffi.callback("void()")
def uwsgi_pypy_post_fork_hook():
    import uwsgi
    if hasattr(uwsgi, 'post_fork_hook'):
        uwsgi.post_fork_hook()

"""
add an item to the pythonpath
"""
@ffi.callback("void(char *)")
def uwsgi_pypy_pythonpath(item):
    path = ffi.string(item)
    sys.path.append(path)
    print "added %s to pythonpath" % path


"""
class implementing wsgi.file_wrapper
"""
class WSGIfilewrapper(object):
    def __init__(self, wsgi_req, f, chunksize=0):
        self.wsgi_req = wsgi_req
        self.f = f
        self.chunksize = chunksize
        if hasattr(f, 'close'):
            self.close = f.close

    def __iter__(self):
        return self

    def sendfile(self):
        if hasattr(self.f, 'fileno'):
            lib.uwsgi_response_sendfile_do_can_close(self.wsgi_req, self.f.fileno(), 0, 0, 0)
        elif hasattr(self.f, 'read'):
            if self.chunksize == 0:
                chunk = self.f.read()
                if len(chunk) > 0:
                    lib.uwsgi_response_write_body_do(self.wsgi_req, ffi.new("char[]", chunk), len(chunk))
                return
            while True:
                chunk = self.f.read(self.chunksize)
                if chunk is None or len(chunk) == 0:
                    break
                lib.uwsgi_response_write_body_do(self.wsgi_req, ffi.new("char[]", chunk), len(chunk))


"""
class implementing wsgi.input
"""
class WSGIinput(object):
    def __init__(self, wsgi_req):
        self.wsgi_req = wsgi_req

    def read(self, size=0):
        rlen = ffi.new('int64_t*')
        chunk = lib.uwsgi_request_body_read(self.wsgi_req, size, rlen)
        if chunk != ffi.NULL:
            return ffi.string(chunk, rlen[0])
        if rlen[0] < 0:
            raise IOError("error reading wsgi.input")
        raise IOError("error waiting for wsgi.input")

    def getline(self, hint=0):
        rlen = ffi.new('ssize_t*')
        chunk = lib.uwsgi_request_body_readline(self.wsgi_req, hint, rlen)
        if chunk != ffi.NULL:
            return ffi.string(chunk, rlen[0])
        if rlen[0] < 0:
            raise IOError("error reading line from wsgi.input")
        raise IOError("error waiting for line on wsgi.input")

    def readline(self, hint=0):
        return self.getline(hint)

    def readlines(self, hint=0):
        lines = []
        while True:
            chunk = self.getline(hint)
            if len(chunk) == 0:
                break
            lines.append(chunk)
        return lines

    def __iter__(self):
        return self

    def __next__(self):
        chunk = self.getline()
        if len(chunk) == 0:
            raise StopIteration
        return chunk


"""
the WSGI request handler
"""
@ffi.callback("void(struct wsgi_request *)")
def uwsgi_pypy_wsgi_handler(wsgi_req):
    import uwsgi
    global wsgi_application

    def writer(data):
        lib.uwsgi_response_write_body_do(wsgi_req, ffi.new("char[]", data), len(data))

    def start_response(status, headers, exc_info=None):
        if exc_info:
            traceback.print_exception(*exc_info)
        lib.uwsgi_response_prepare_headers(wsgi_req, ffi.new("char[]", status), len(status))
        for hh in headers:
            lib.uwsgi_response_add_header(wsgi_req, ffi.new("char[]", hh[0]), len(hh[0]), ffi.new("char[]", hh[1]), len(hh[1]))
        return writer

    environ = {}
    iov = wsgi_req.hvec
    for i in range(0, wsgi_req.var_cnt, 2):
        environ[ffi.buffer(iov[i].iov_base, iov[i].iov_len)[:]] = ffi.buffer(iov[i+1].iov_base, iov[i+1].iov_len)[:]

    print environ

    environ['wsgi.version'] = (1, 0)
    scheme = 'http'
    if 'HTTPS' in environ:
        if environ['HTTPS'] in ('on', 'ON', 'On', '1', 'true', 'TRUE', 'True'):
            scheme = 'https'
    environ['wsgi.url_scheme'] = environ.get('UWSGI_SCHEME', scheme)
    environ['wsgi.input'] = WSGIinput(wsgi_req)
    environ['wsgi.errors'] = sys.stderr
    environ['wsgi.run_once'] = False
    environ['wsgi.file_wrapper'] = lambda f, chunksize=0: WSGIfilewrapper(wsgi_req, f, chunksize)
    environ['wsgi.multithread'] = True
    environ['wsgi.multiprocess'] = True

    environ['uwsgi.core'] = wsgi_req.async_id
    environ['uwsgi.node'] = uwsgi.hostname

    response = wsgi_application(environ, start_response)
    if type(response) is str:
        writer(response)
    else:
        try:
            if isinstance(response, WSGIfilewrapper):
                response.sendfile()
            else:
                for chunk in response:
                    if isinstance(chunk, WSGIfilewrapper):
                        try:
                            chunk.sendfile()
                        finally:
                            chunk.close()
                    else:
                        writer(chunk)
        finally:
            if hasattr(response, 'close'):
                response.close()

lib.uwsgi_pypy_hook_loader = uwsgi_pypy_loader
lib.uwsgi_pypy_hook_file_loader = uwsgi_pypy_file_loader
lib.uwsgi_pypy_hook_pythonpath = uwsgi_pypy_pythonpath
lib.uwsgi_pypy_hook_request = uwsgi_pypy_wsgi_handler
lib.uwsgi_pypy_post_fork_hook = uwsgi_pypy_post_fork_hook

"""
Here we define the "uwsgi" virtual module
"""

uwsgi = imp.new_module('uwsgi')
sys.modules['uwsgi'] = uwsgi
uwsgi.version = ffi.string(lib.uwsgi_pypy_version)
uwsgi.hostname = ffi.string(lib.uwsgi.hostname)

def uwsgi_pypy_uwsgi_register_signal(signum, kind, handler):
    cb = ffi.callback('void(int)', handler)
    uwsgi_gc.append(cb)
    if lib.uwsgi_register_signal(signum, ffi.new("char[]", kind), cb, lib.pypy_plugin.modifier1) < 0:
        raise Exception("unable to register signal %d" % signum)
uwsgi.register_signal = uwsgi_pypy_uwsgi_register_signal


class uwsgi_pypy_RPC(object):
    def __init__(self, func):
        self.func = func

    def __call__(self, argc, argv, argvs, buf):
        pargs = []
        for i in range(0, argc):
            pargs.append(ffi.string(argv[i], argvs[i]))
        response = self.func(*pargs)
        if len(response) > 0 and len(response) <= 65535:
            dst = ffi.buffer(buf, 65536)
            dst[:len(response)] = response
        return len(response)


def uwsgi_pypy_uwsgi_register_rpc(name, func, argc=0):
    rpc_func = uwsgi_pypy_RPC(func)
    cb = ffi.callback("int(int, char*[], int[], char*)", rpc_func)
    uwsgi_gc.append(cb)
    if lib.uwsgi_register_rpc(ffi.new("char[]", name), lib.pypy_plugin, argc, cb) < 0:
        raise Exception("unable to register rpc func %s" % name)
uwsgi.register_rpc = uwsgi_pypy_uwsgi_register_rpc

def uwsgi_pypy_rpc(node, func, *args):
    argc = 0
    argv = ffi.new('char*[256]')
    argvs = ffi.new('uint16_t[256]')
    rsize = ffi.new('uint16_t*')

    for arg in args:
        if argc >= 255:
            raise Exception('invalid number of rpc arguments')
        if len(arg) >= 65535:
            raise Exception('invalid rpc argument size (must be < 65535)')
        argv[argc] = ffi.new('char[]', arg)
        argvs[argc] = len(arg)
        argc += 1

    if node:
        c_node = ffi.new("char[]", node)
    else:
        c_node = ffi.NULL

    response = lib.uwsgi_do_rpc(c_node, ffi.new("char[]",func), argc, argv, argvs, rsize)
    if response:
        ret = ffi.string(response, rsize[0])
        lib.free(response)
        return ret
    return None
uwsgi.rpc = uwsgi_pypy_rpc

def uwsgi_pypy_call(func, *args):
    node = None
    if '@' in func:
        (func, node) = func.split('@')
    return uwsgi_pypy_rpc(node, func, *args)
uwsgi.call = uwsgi_pypy_call
    
uwsgi.signal = lambda x: lib.uwsgi_signal_send(lib.uwsgi.signal_socket, x)


def uwsgi_pypy_uwsgi_cache_get(key, cache=ffi.NULL):
    vallen = ffi.new('uint64_t*')
    value = lib.uwsgi_cache_magic_get(key, len(key), vallen, ffi.NULL, cache)
    if value == ffi.NULL:
        return None
    ret = ffi.string(value, vallen[0])
    libc.free(value)
    return ret
uwsgi.cache_get = uwsgi_pypy_uwsgi_cache_get

def uwsgi_pypy_uwsgi_cache_set(key, value, expires=0, cache=ffi.NULL):
    if lib.uwsgi_cache_magic_set(key, len(key), value, len(value), expires, 0, cache) < 0:
        raise Exception('unable to store item in the cache')
uwsgi.cache_set = uwsgi_pypy_uwsgi_cache_set

def uwsgi_pypy_uwsgi_cache_update(key, value, expires=0, cache=ffi.NULL):
    if lib.uwsgi_cache_magic_set(key, len(key), value, len(value), expires, 1 << 1, cache) < 0:
        raise Exception('unable to store item in the cache')
uwsgi.cache_update = uwsgi_pypy_uwsgi_cache_update

def uwsgi_pypy_uwsgi_cache_del(key, cache=ffi.NULL):
    if lib.uwsgi_cache_magic_del(key, len(key), cache) < 0:
        raise Exception('unable to delete item from the cache')
uwsgi.cache_del = uwsgi_pypy_uwsgi_cache_del


def uwsgi_pypy_uwsgi_add_timer(signum, secs):
    if lib.uwsgi_add_timer(signum, secs) < 0:
        raise Exception("unable to register timer")
uwsgi.add_timer = uwsgi_pypy_uwsgi_add_timer

def uwsgi_pypy_uwsgi_add_rb_timer(signum, secs):
    if lib.uwsgi_signal_add_rb_timer(signum, secs, 0) < 0:
        raise Exception("unable to register redblack timer")
uwsgi.add_rb_timer = uwsgi_pypy_uwsgi_add_rb_timer


def uwsgi_pypy_uwsgi_add_file_monitor(signum, filename):
    if lib.uwsgi_add_file_monitor(signum, ffi.new("char[]", filename)) < 0:
        raise Exception("unable to register file monitor")
uwsgi.add_file_monitor = uwsgi_pypy_uwsgi_add_file_monitor

def uwsgi_pypy_lock(num):
    if lib.uwsgi_user_lock(num) < 0:
        raise Exception("invalid lock")
uwsgi.lock = uwsgi_pypy_lock

def uwsgi_pypy_unlock(num):
    if lib.uwsgi_user_unlock(num) < 0:
        raise Exception("invalid lock")
uwsgi.unlock = uwsgi_pypy_unlock

def uwsgi_pypy_masterpid():
    if lib.uwsgi.master_process:
        return lib.uwsgi.workers[0].pid
    return 0
uwsgi.masterpid = uwsgi_pypy_masterpid

uwsgi.worker_id = lambda: lib.uwsgi.mywid

uwsgi.mule_id = lambda: lib.uwsgi.muleid

def uwsgi_pypy_signal_registered(signum):
    if lib.uwsgi_signal_registered(signum) > 0:
        return True
    return False
uwsgi.signal_registered = uwsgi_pypy_signal_registered

def uwsgi_pypy_alarm(alarm, msg):
    lib.uwsgi_alarm_trigger(ffi.new('char[]', alarm), ffi.new('char[]', msg), len(msg))
uwsgi.alarm = uwsgi_pypy_alarm

uwsgi.setprocname = lambda name: lib.uwsgi_set_processname(ffi.new('char[]', name))

def uwsgi_pypy_add_cron(signum, minute, hour, day, month, week):
    if lib.uwsgi_signal_add_cron(signum, minute, hour, day, month, week) < 0:
        raise Exception("unable to register cron")
    return True
uwsgi.add_cron = uwsgi_pypy_add_cron

"""
populate uwsgi.opt
"""
uwsgi.opt = {}
for i in range(0, lib.uwsgi.exported_opts_cnt):
    uo = lib.uwsgi.exported_opts[i]
    k = ffi.string(uo.key)
    if uo.value == ffi.NULL:
        v = True
    else:
        v = ffi.string(uo.value)
    if k in uwsgi.opt:
        if type(uwsgi.opt[k]) is list:
            uwsgi.opt[k].append(v)
        else:
            uwsgi.opt[k] = [uwsgi.opt[k], v]
    else:
        uwsgi.opt[k] = v

"""
uwsgi.workers()
"""
def uwsgi_pypy_workers():
    workers = []
    for i in range(1, lib.uwsgi.numproc+1):
        worker = {}
        worker['id'] = lib.uwsgi.workers[i].id
        worker['pid'] = lib.uwsgi.workers[i].pid
        worker['requests'] = lib.uwsgi.workers[i].requests
        worker['delta_requests'] = lib.uwsgi.workers[i].delta_requests
        worker['signals'] = lib.uwsgi.workers[i].signals
        worker['exceptions'] = lib.uwsgi_worker_exceptions(i);
        worker['apps'] = []
        if lib.uwsgi.workers[i].cheaped:
            worker['status'] == 'cheap'
        elif lib.uwsgi.workers[i].suspended and not lib.uwsgi_worker_is_busy(i):
            worker['status'] == 'pause'
        else:
            if lib.uwsgi.workers[i].sig:
                worker['status'] = 'sig%d' % lib.uwsgi.workers[i].signum
            elif lib.uwsgi_worker_is_busy(i):
                worker['status'] = 'busy' 
            else:
                worker['status'] = 'idle'
        worker['running_time'] = lib.uwsgi.workers[i].running_time
        worker['avg_rt'] = lib.uwsgi.workers[i].avg_response_time
        worker['tx'] = lib.uwsgi.workers[i].tx
            
        workers.append(worker)
    print workers
    return workers
    
uwsgi.workers = uwsgi_pypy_workers

print "Initialized PyPy with Python", sys.version
print "PyPy Home:", sys.prefix
