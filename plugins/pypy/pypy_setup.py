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

defines = '''
void free(void *);

void (*uwsgi_pypy_hook_loader)(char *);
void (*uwsgi_pypy_hook_file_loader)(char *);
void (*uwsgi_pypy_hook_pythonpath)(char *);
void (*uwsgi_pypy_hook_request)(void *, int);
void (*uwsgi_pypy_post_fork_hook)(void);

struct iovec {
    char *iov_base;
    uint64_t iov_len;
};

struct uwsgi_opt {
        char *key;
        char *value;
        int configured;
};

char *uwsgi_binary_path();
void uwsgi_set_processname(char *);
void uwsgi_alarm_trigger(char *, char *, uint64_t);
int uwsgi_signal_registered(uint8_t);

int uwsgi_response_write_body_do(void *, char *, uint64_t);
int uwsgi_response_sendfile_do_can_close(void *, int, uint64_t, uint64_t, int);
int uwsgi_response_prepare_headers(void *, char *, uint16_t);
int uwsgi_response_add_header(void *, char *, uint16_t, char *, uint16_t);
char *uwsgi_request_body_read(void *, uint64_t, int64_t *);
char *uwsgi_request_body_readline(void *, uint64_t, int64_t *);

struct iovec *uwsgi_pypy_helper_environ(void *, uint16_t *);

char *uwsgi_pypy_helper_version();
int uwsgi_pypy_helper_register_signal(int, char *, void *);
int uwsgi_pypy_helper_register_rpc(char *, int, void *);
void uwsgi_pypy_helper_signal(int);
struct uwsgi_opt** uwsgi_pypy_helper_opts(int *);
int uwsgi_pypy_helper_masterpid();
int uwsgi_pypy_helper_worker_id();
int uwsgi_pypy_helper_mule_id();

char *uwsgi_cache_magic_get(char *, uint64_t, uint64_t *, uint64_t *, char *);
int uwsgi_cache_magic_set(char *, uint64_t, char *, uint64_t, uint64_t, uint64_t, char *);
int uwsgi_cache_magic_del(char *, uint64_t, char *);
int uwsgi_add_timer(uint8_t, int);
int uwsgi_add_rb_timer(uint8_t, int, int);
int uwsgi_add_file_monitor(uint8_t, char *);
char *uwsgi_do_rpc(char *, char *, uint8_t, char **, uint16_t *, uint16_t *);
int uwsgi_signal_add_cron(uint8_t, int, int, int, int, int);

int uwsgi_user_lock(int);
int uwsgi_user_unlock(int);

'''

ffi = cffi.FFI()
ffi.cdef(defines)
lib = ffi.verify(defines)
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
        rlen = ffi.new('int64_t*')
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
@ffi.callback("void(void *, int)")
def uwsgi_pypy_wsgi_handler(wsgi_req, core):
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
    nv = ffi.new("uint16_t*")
    iov = lib.uwsgi_pypy_helper_environ(wsgi_req, nv)
    for i in range(0, nv[0], 2):
        environ[ffi.string(iov[i].iov_base, iov[i].iov_len)] = ffi.string(iov[i+1].iov_base, iov[i+1].iov_len)

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

    environ['uwsgi.core'] = core

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
uwsgi.version = ffi.string(lib.uwsgi_pypy_helper_version())


def uwsgi_pypy_uwsgi_register_signal(signum, kind, handler):
    cb = ffi.callback('void(int)', handler)
    uwsgi_gc.append(cb)
    if lib.uwsgi_pypy_helper_register_signal(signum, ffi.new("char[]", kind), cb) < 0:
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
    if lib.uwsgi_pypy_helper_register_rpc(ffi.new("char[]", name), argc, cb) < 0:
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
    
def uwsgi_pypy_uwsgi_signal(signum):
    lib.uwsgi_pypy_helper_signal(signum)
uwsgi.signal = uwsgi_pypy_uwsgi_signal


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
    if lib.uwsgi_add_rb_timer(signum, secs, 0) < 0:
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
    return lib.uwsgi_pypy_helper_masterpid()
uwsgi.masterpid = uwsgi_pypy_masterpid

def uwsgi_pypy_worker_id():
    return lib.uwsgi_pypy_helper_worker_id()
uwsgi.worker_id = uwsgi_pypy_worker_id

def uwsgi_pypy_mule_id():
    return lib.uwsgi_pypy_helper_mule_id()
uwsgi.mule_id = uwsgi_pypy_mule_id

def uwsgi_pypy_signal_registered(signum):
    if lib.uwsgi_signal_registered(signum) > 0:
        return True
    return False
uwsgi.signal_registered = uwsgi_pypy_signal_registered

def uwsgi_pypy_alarm(alarm, msg):
    lib.uwsgi_alarm_trigger(ffi.new('char[]', alarm), ffi.new('char[]', msg), len(msg))
uwsgi.alarm = uwsgi_pypy_alarm

def uwsgi_pypy_setprocname(name):
    lib.uwsgi_set_processname(ffi.new('char[]',name))
uwsgi.setprocname = uwsgi_pypy_setprocname

def uwsgi_pypy_add_cron(signum, minute, hour, day, month, week):
    if lib.uwsgi_signal_add_cron(signum, minute, hour, day, month, week) < 0:
        raise Exception("unable to register cron")
    return True
uwsgi.add_cron = uwsgi_pypy_add_cron

"""
populate uwsgi.opt
"""
uwsgi.opt = {}
n_opts = ffi.new('int*')
u_opts = lib.uwsgi_pypy_helper_opts(n_opts)
for i in range(0, n_opts[0]):
    k = ffi.string(u_opts[i].key)
    if u_opts[i].value == ffi.NULL:
        v = True
    else:
        v = ffi.string(u_opts[i].value)
    if k in uwsgi.opt:
        if type(uwsgi.opt[k]) is list:
            uwsgi.opt[k].append(v)
        else:
            uwsgi.opt[k] = [uwsgi.opt[k], v]
    else:
        uwsgi.opt[k] = v

print "Initialized PyPy with Python", sys.version
print "PyPy Home:", sys.prefix
