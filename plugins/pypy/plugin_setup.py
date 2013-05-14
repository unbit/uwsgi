
import sys
# XXX temp
sys.path.insert(0, '/home/fijal/src/pypy/lib-python/2.7')
sys.path.insert(0, '/home/fijal/src/pypy/lib_pypy')

import os
import cffi
ffi = cffi.FFI()
ffi.cdef('''
typedef struct wsgi_request {
   ...;
};

typedef struct uwsgi_plugin {
   const char *name;
   int (*request)(struct wsgi_request *);
   ...;
};

int uwsgi_response_prepare_headers(struct wsgi_request*, char*, int);
int uwsgi_response_add_header(struct wsgi_request*, char*, int, char*, int);
int uwsgi_response_write_body_do(struct wsgi_request*, char*, int);

#define UWSGI_OK ...
''')
static = ffi.verify('#include "uwsgi.h"', include_dirs=[os.getcwd()])
ffi.cdef("struct uwsgi_plugin pypy_plugin;")

# XXX don't hard-code the directory here
lib = ffi.dlopen("./pypy_plugin.so")

@ffi.callback("int(struct wsgi_request*)")
def request(wsgi_req):
    s = '200 OK'
    static.uwsgi_response_prepare_headers(wsgi_req, s, len(s))
    s = "Content-type"
    s2 = "text/html"
    static.uwsgi_response_add_header(wsgi_req, s, len(s), s2, len(s2))
    s = "<h1>Hello world</h1>\n"
    static.uwsgi_response_write_body_do(wsgi_req, s, len(s))
    return static.UWSGI_OK

lib.pypy_plugin.request = request
