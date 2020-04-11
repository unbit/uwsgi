# based on the example and pypy plugins

import cffi

ffibuilder = cffi.FFI()

ffibuilder.cdef(
    """
extern struct uwsgi_server uwsgi;

void uwsgi_pyexample_more_apps();

int uwsgi_response_prepare_headers(struct wsgi_request *, char *, size_t);
int uwsgi_response_add_header(struct wsgi_request *, char *, uint16_t, char *, uint16_t);
int uwsgi_response_write_body_do(struct wsgi_request *, char *, size_t);
"""
)

ffibuilder.embedding_api(
    """
extern struct uwsgi_server uwsgi;

static int uwsgi_pyexample_init();
static void uwsgi_pyexample_init_apps();
static int uwsgi_pyexample_request(struct wsgi_request *wsgi_req);
static void uwsgi_pyexample_after_request(struct wsgi_request *wsgi_req);
"""
)

ffibuilder.embedding_init_code(
    """
from pyexample_plugin import ffi
from pyexample_plugin.lib import *

import sys

print("Initialized PyPy with Python %s" % sys.version)
print("PyPy Home: %s" % sys.prefix)

@ffi.def_extern()
def uwsgi_pyexample_init():
    print("init called")
    return 0


@ffi.def_extern()
def uwsgi_pyexample_init_apps():
    uwsgi_pyexample_more_apps()


@ffi.def_extern()
def uwsgi_pyexample_request(wsgi_req):
    uwsgi_response_prepare_headers(wsgi_req, b"200 OK", 6)
    uwsgi_response_add_header(wsgi_req, b"Content-type", 12, b"text/html", 9)
    uwsgi_response_write_body_do(wsgi_req, b"<h1>Hello World</h1>", 20)
    return 0


@ffi.def_extern()
def uwsgi_pyexample_after_request(wsgi_req):
    print("i am the example plugin after request function")

"""
)

ffibuilder.set_source(
    "pyexample_plugin",
    """
#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

static int uwsgi_pyexample_init();
static void uwsgi_pyexample_init_apps();
static int uwsgi_pyexample_request(struct wsgi_request *wsgi_req);
static void uwsgi_pyexample_after_request(struct wsgi_request *wsgi_req);

extern void uwsgi_pyexample_more_apps() {
    uwsgi_apps_cnt++;
}

CFFI_DLLEXPORT struct uwsgi_plugin pyexample_plugin = {
    .name = "pyexample",
    .modifier1 = 250,
    .init = uwsgi_pyexample_init,
    .init_apps = uwsgi_pyexample_init_apps,
    .request = uwsgi_pyexample_request,
    .after_request = uwsgi_pyexample_after_request,
};
""",
)


ffibuilder.emit_c_code("pyexample_plugin.c")

