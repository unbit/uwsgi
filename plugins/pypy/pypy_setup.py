import sys
sys.path.insert(0, '.')

import cffi

# this is a list holding object we do not want to be freed (like callback and handlers)
uwsgi_gc = []

defines = '''
void free(void *);

void (*uwsgi_pypy_hook_loader)(char *);
void (*uwsgi_pypy_hook_request)(int);

struct iovec {
	char *iov_base;
	uint64_t iov_len;
};

struct iovec *uwsgi_pypy_helper_environ(int, uint16_t *);

void uwsgi_pypy_helper_status(int, char *, int);
void uwsgi_pypy_helper_header(int, char *, int, char *, int);

void uwsgi_pypy_helper_write(int, char *, int);

char *uwsgi_pypy_helper_version();
int uwsgi_pypy_helper_register_signal(int, char *, void *);
int uwsgi_pypy_helper_register_rpc(char *, int, void *);
void uwsgi_pypy_helper_signal(int);

char *uwsgi_cache_magic_get(char *, uint64_t, uint64_t *, uint64_t *, char *);
'''

ffi = cffi.FFI()
ffi.cdef(defines)
lib = ffi.verify(defines)
libc = ffi.dlopen(None)

wsgi_application = None

@ffi.callback("void(char *)")
def uwsgi_pypy_loader(module):
    global wsgi_application
    m = ffi.string(module)
    c = 'application'
    if ':' in m:
        m, c = m.split(':')
    mod = __import__(m)
    wsgi_application = getattr(mod, c)

@ffi.callback("void(int)")
def uwsgi_pypy_wsgi_handler(core):
    global wsgi_application

    def writer(data):
        lib.uwsgi_pypy_helper_write(core, ffi.new("char[]", data), len(data))

    def start_response(status, headers, exc_info=None):
        lib.uwsgi_pypy_helper_status(core, ffi.new("char[]", status), len(status))
        for hh in headers:
            lib.uwsgi_pypy_helper_header(core, ffi.new("char[]", hh[0]), len(hh[0]), ffi.new("char[]", hh[1]), len(hh[1]))
        return writer

    class WSGIinput():
        pass

    environ = {}
    nv = ffi.new("uint16_t *")
    iov = lib.uwsgi_pypy_helper_environ(core, nv)
    for i in range(0, nv[0], 2):
        environ[ffi.string(iov[i].iov_base, iov[i].iov_len)] = ffi.string(iov[i+1].iov_base, iov[i+1].iov_len)

    environ['wsgi.version'] = (1, 0)
    scheme = 'http'
    if 'HTTPS' in environ:
        if environ['HTTPS'] in ('on', 'ON', 'On', '1', 'true', 'TRUE', 'True'):
            scheme = 'https'
    environ['wsgi.url_scheme'] = environ.get('UWSGI_SCHEME', scheme)
    environ['wsgi.input'] = WSGIinput
    environ['wsgi.errors'] = sys.stderr
    environ['wsgi.run_once'] = False

    environ['uwsgi.core'] = core

    response = wsgi_application(environ, start_response) 
    if type(response) is str:
        writer(response)
    else:
        for chunk in response:
            writer(chunk)

lib.uwsgi_pypy_hook_loader = uwsgi_pypy_loader
lib.uwsgi_pypy_hook_request = uwsgi_pypy_wsgi_handler

"""
Here we define the "uwsgi" virtual module
"""
import imp

uwsgi = imp.new_module('uwsgi')
sys.modules['uwsgi'] = uwsgi
uwsgi.version = ffi.string( lib.uwsgi_pypy_helper_version() )

def uwsgi_pypy_uwsgi_register_signal(signum, kind, handler):
    global uwsgi_gc
    uwsgi_gc.append(handler)
    if lib.uwsgi_pypy_helper_register_signal(signum, ffi.new("char[]", kind), ffi.callback('void(int)', handler)) < 0:
        raise Exception("unable to register signal %d" % signum)
uwsgi.register_signal = uwsgi_pypy_uwsgi_register_signal

class uwsgi_pypy_RPC():
    def __init__(self, func):
        self.func = func
    def __call__(self, argc, argv, argvs, buf):
        pargs = []
        for i in range(0, argc):
            pargs.append(ffi.string(argv[i],argvs[i]))
        response = self.func(*pargs)
        if len(response) > 0 and len(response) <= 65535:
            dst = ffi.buffer(buf, 65536)
            dst[:len(response)] = response
        return len(response)

def uwsgi_pypy_uwsgi_register_rpc(name, func, argc=0):
    global uwsgi_gc
    uwsgi_gc.append(func)
    if lib.uwsgi_pypy_helper_register_rpc(ffi.new("char[]", name), argc, ffi.callback("int(int, char*[], int[], char*)", uwsgi_pypy_RPC(func))) < 0:
        raise Exception("unable to register rpc func %s" % name)
uwsgi.register_rpc = uwsgi_pypy_uwsgi_register_rpc

def uwsgi_pypy_uwsgi_signal(signum):
    lib.uwsgi_pypy_helper_signal(signum)
uwsgi.signal = uwsgi_pypy_uwsgi_signal

def uwsgi_pypy_uwsgi_cache_get(key, cache=ffi.NULL):
    vallen = ffi.new('uint64_t *')
    value = lib.uwsgi_cache_magic_get(key, len(key), vallen, ffi.NULL, cache)
    if value == ffi.NULL:
        return None
    ret = ffi.string(value, vallen[0])
    libc.free(value)
    return ret
uwsgi.cache_get = uwsgi_pypy_uwsgi_cache_get


print "Initialized PyPy with Python",sys.version
