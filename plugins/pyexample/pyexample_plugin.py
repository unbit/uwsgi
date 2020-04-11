# based on the example and pypy plugins

import cffi

ffibuilder = cffi.FFI()

ffibuilder.cdef(
    """
extern struct uwsgi_server uwsgi;
"""
)

ffibuilder.embedding_api(
    """
extern struct uwsgi_server uwsgi;

static int uwsgi_example_init();
static int uwsgi_example_request(struct wsgi_request *wsgi_req);
static void uwsgi_example_after_request(struct wsgi_request *wsgi_req);
"""
)

ffibuilder.embedding_init_code(
    """
from _example_plugin import ffi

print("example Python")


@ffi.def_extern()
def uwsgi_example_init():
    print("init called")
    return 0


@ffi.def_extern()
def uwsgi_example_request(wsgi_req):
    uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)
    uwsgi_response_add_header(wsgi_req, "Content-type", 12, "text/html", 9)
    uwsgi_response_write_body_do(wsgi_req, "<h1>Hello World</h1>", 20)
    return 0


@ffi.def_extern()
def uwsgi_example_after_request(wsgi_req):
    print("i am the example plugin after request function\n")

"""
)

ffibuilder.set_source(
    "pyexample_plugin",
    """
#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

static int uwsgi_example_init();
static int uwsgi_example_request(struct wsgi_request *wsgi_req);
static void uwsgi_example_after_request(struct wsgi_request *wsgi_req);

struct uwsgi_plugin example_plugin = {
    .name = "example",
    .modifier1 = 250,
    .init = uwsgi_example_init,
    .request = uwsgi_example_request,
    .after_request = uwsgi_example_after_request,
};
""",
)

ffibuilder.emit_c_code("pyexample_plugin.c")
