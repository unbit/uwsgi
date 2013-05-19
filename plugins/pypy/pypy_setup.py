import sys
sys.path.insert(0, '.')

# avoid problems (need to find a better solution)
sys.modules['__main__'] = None

import cffi

# this is a list holding object we do not want to be freed (like callback and handlers)
uwsgi_gc = []

defines = '''
void free(void *);

void (*uwsgi_pypy_hook_loader)(char *);
void (*uwsgi_pypy_hook_request)(void *, int);

struct iovec {
	char *iov_base;
	uint64_t iov_len;
};

struct uwsgi_opt {
        char *key;
        char *value;
        int configured;
};

int uwsgi_response_write_body_do(void *, char *, uint64_t);
int uwsgi_response_sendfile_do(void *, int, uint64_t, uint64_t);
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

char *uwsgi_cache_magic_get(char *, uint64_t, uint64_t *, uint64_t *, char *);
int uwsgi_add_timer(uint8_t, int);
int uwsgi_add_file_monitor(uint8_t, char *);
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
    if '.' in m: 
        mod = __import__(m, None, None, '*')
    else:
        mod = __import__(m)
    wsgi_application = getattr(mod, c)

@ffi.callback("void(void *, int)")
def uwsgi_pypy_wsgi_handler(wsgi_req, core):
    global wsgi_application

    def writer(data):
        lib.uwsgi_response_write_body_do(wsgi_req, ffi.new("char[]", data), len(data))

    def start_response(status, headers, exc_info=None):
        lib.uwsgi_response_prepare_headers(wsgi_req, ffi.new("char[]", status), len(status))
        for hh in headers:
            lib.uwsgi_response_add_header(wsgi_req, ffi.new("char[]", hh[0]), len(hh[0]), ffi.new("char[]", hh[1]), len(hh[1]))
        return writer

    class WSGIfilewrapper():
        def __init__(self, f, chunksize=0):
            self.fd = f.fileno()
            self.chunksize = chunksize
            if hasattr(f, 'close'):
                self.close = f.close

        def __getitem__(self, key):
            data = self.filelike.read(self.blksize)
            if data:
                return data
            raise IndexError

        def sendfile(self):
            lib.uwsgi_response_sendfile_do(wsgi_req, self.fd, 0, 0)

    class WSGIinput():
        def read(self, size=0):
            rlen = ffi.new('int64_t *')
            chunk = lib.uwsgi_request_body_read(wsgi_req, size, rlen)
            if chunk != ffi.NULL:
                return ffi.string(chunk, rlen[0])
            if rlen[0] < 0:
                raise IOError("error reading wsgi.input")
            raise IOError("error waiting for wsgi.input")

        def getline(self,hint=0):
            rlen = ffi.new('int64_t *')
            chunk = lib.uwsgi_request_body_readline(wsgi_req, hint, rlen)
            if chunk != ffi.NULL:
                return ffi.string(chunk, rlen[0])
            if rlen[0] < 0:
                raise IOError("error reading line from wsgi.input")
            raise IOError("error waiting for line on wsgi.input")
        
        def readline(self, hint=0):
            return self.getline(hint)

        def readlines(self,hint=0):
            lines = []
            for chunk in self.getline(hint):
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
            

    environ = {}
    nv = ffi.new("uint16_t *")
    iov = lib.uwsgi_pypy_helper_environ(wsgi_req, nv)
    for i in range(0, nv[0], 2):
        environ[ffi.string(iov[i].iov_base, iov[i].iov_len)] = ffi.string(iov[i+1].iov_base, iov[i+1].iov_len)

    environ['wsgi.version'] = (1, 0)
    scheme = 'http'
    if 'HTTPS' in environ:
        if environ['HTTPS'] in ('on', 'ON', 'On', '1', 'true', 'TRUE', 'True'):
            scheme = 'https'
    environ['wsgi.url_scheme'] = environ.get('UWSGI_SCHEME', scheme)
    environ['wsgi.input'] = WSGIinput()
    environ['wsgi.errors'] = sys.stderr
    environ['wsgi.run_once'] = False
    environ['wsgi.file_wrapper'] = WSGIfilewrapper

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
                        chunk.sendfile()
                    else:
                        writer(chunk)
        finally:
            if hasattr(response, 'close'):
                response.close()

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

def uwsgi_pypy_uwsgi_add_timer(signum, secs):
    if lib.uwsgi_add_timer(signum, secs) < 0:
        raise Exception("unable to register timer")
uwsgi.add_timer = uwsgi_pypy_uwsgi_add_timer

def uwsgi_pypy_uwsgi_add_file_monitor(signum, filename):
    if lib.uwsgi_add_file_monitor(signum, ffi.new("char[]", filename)) < 0:
        raise Exception("unable to register file monitor")
uwsgi.add_file_monitor = uwsgi_pypy_uwsgi_add_file_monitor

"""
populate uwsgi.opt
"""
uwsgi.opt = {}
n_opts = ffi.new('int *')
u_opts = lib.uwsgi_pypy_helper_opts(n_opts)
for i in range(0,n_opts[0]):
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

print "Initialized PyPy with Python",sys.version
