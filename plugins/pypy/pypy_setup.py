import sys

import cffi

defines = '''
void (*uwsgi_pypy_hook_loader)(char *);
void (*uwsgi_pypy_hook_request)(void *);

char *uwsgi_pypy_helper_key(void *, int);
int uwsgi_pypy_helper_keylen(void *, int);

char *uwsgi_pypy_helper_val(void *, int);
int uwsgi_pypy_helper_vallen(void *, int);

int uwsgi_pypy_helper_vars(void *);

void uwsgi_pypy_helper_status(void *, char *, int);
void uwsgi_pypy_helper_header(void *, char *, int, char *, int);

void uwsgi_pypy_helper_write(void *, char *, int);
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
         

lib.uwsgi_pypy_hook_loader = uwsgi_pypy_loader
lib.uwsgi_pypy_hook_request = uwsgi_pypy_wsgi_handler

print "Initialized Python",sys.version
