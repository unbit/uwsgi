import sys

sys.path.insert(0, '.')

import cffi

defines = '''
void (*uwsgi_pypy_hook_loader)(char *);
void (*uwsgi_pypy_hook_request)(void *);
void (*uwsgi_pypy_hook_signal_handler)(void *, int);

char *uwsgi_pypy_helper_key(void *, int);
int uwsgi_pypy_helper_keylen(void *, int);

char *uwsgi_pypy_helper_val(void *, int);
int uwsgi_pypy_helper_vallen(void *, int);

int uwsgi_pypy_helper_vars(void *);

void uwsgi_pypy_helper_status(void *, char *, int);
void uwsgi_pypy_helper_header(void *, char *, int, char *, int);

void uwsgi_pypy_helper_write(void *, char *, int);

char *uwsgi_pypy_helper_version();
int uwsgi_pypy_helper_register_signal(int, char *, void *);
void uwsgi_pypy_helper_signal(int);
'''

ffi = cffi.FFI()
ffi.cdef(defines)
lib = ffi.verify(defines)

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

@ffi.callback("void(void *)")
def uwsgi_pypy_wsgi_handler(wsgi_req):
    global wsgi_application

    def writer(data):
        lib.uwsgi_pypy_helper_write(wsgi_req, ffi.new("char[]", data), len(data))

    def start_response(status, headers, exc_info=None):
        lib.uwsgi_pypy_helper_status(wsgi_req, ffi.new("char[]", status), len(status))
        for hh in headers:
            lib.uwsgi_pypy_helper_header(wsgi_req, ffi.new("char[]", hh[0]), len(hh[0]), ffi.new("char[]", hh[1]), len(hh[1]))
        return writer

    class WSGIinput():
        pass

    environ = {}
    n = lib.uwsgi_pypy_helper_vars(wsgi_req)
    for i in range(0, n, 2):
        key = ffi.string( lib.uwsgi_pypy_helper_key(wsgi_req, i), lib.uwsgi_pypy_helper_keylen(wsgi_req, i) )
        value = ffi.string( lib.uwsgi_pypy_helper_val(wsgi_req, i), lib.uwsgi_pypy_helper_vallen(wsgi_req, i) )
        environ[key] = value

    environ['wsgi.version'] = (1, 0)
    scheme = 'http'
    if 'HTTPS' in environ:
        if environ['HTTPS'] in ('on', 'ON', 'On', '1', 'true', 'TRUE'):
            scheme = 'https'
    environ['wsgi.url_scheme'] = environ.get('UWSGI_SCHEME', scheme)
    environ['wsgi.input'] = WSGIinput
    environ['wsgi.errors'] = sys.stderr
    environ['wsgi.run_once'] = False

    response = wsgi_application(environ, start_response) 
    if type(response) == 'str':
        writer(response)
    else:
        for chunk in response:
            writer(chunk)

@ffi.callback("void(void *, int)")
def uwsgi_pypy_signal_handler(func, signum):
    py_func = ffi.callback('void(int)', func)
    py_func(signum)

lib.uwsgi_pypy_hook_loader = uwsgi_pypy_loader
lib.uwsgi_pypy_hook_request = uwsgi_pypy_wsgi_handler
lib.uwsgi_pypy_hook_signal_handler = uwsgi_pypy_signal_handler

"""
Here we define the "uwsgi" virtual module
"""
import imp

uwsgi = imp.new_module('uwsgi')
sys.modules['uwsgi'] = uwsgi
uwsgi.version = ffi.string( lib.uwsgi_pypy_helper_version() )

def uwsgi_pypy_uwsgi_register_signal(signum, kind, handler):
    if lib.uwsgi_pypy_helper_register_signal(signum, ffi.new("char[]", kind), ffi.callback('void(int)', handler)) < 0:
        raise Exception("unable to register signal %d" % signum)
uwsgi.register_signal = uwsgi_pypy_uwsgi_register_signal

def uwsgi_pypy_uwsgi_signal(signum):
    lig.uwsgi_pypy_helper_signal(signum)
uwsgi.signal = uwsgi_pypy_uwsgi_signal

print "Initialized PyPy with Python",sys.version
