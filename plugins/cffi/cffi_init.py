"""
cffi embedding API based Python plugin, based on pypy plugin.

Should work with both CPython and PyPy in theory.
"""

from cffi_plugin import ffi, lib
from cffi_plugin.lib import *

import pprint
import sys

# fix argv if needed (too late?)
if len(sys.argv) == 0:
    sys.argv.insert(0, ffi.string(lib.uwsgi_binary_path()).decode("utf-8"))

print("Initialized with Python %s" % sys.version)
print("Home: %s" % sys.prefix)
pprint.pprint(sys.argv)
pprint.pprint(dir(ffi))
pprint.pprint(dir(lib))


@ffi.def_extern()
def uwsgi_cffi_init():
    print("init called")
    # doesn't seem to use PYTHONPATH
    sys.path[0:0] = ["."]
    return lib.UWSGI_OK


@ffi.def_extern()
def uwsgi_cffi_init_apps():
    # one app is required or uWSGI quits
    uwsgi_cffi_more_apps()
    if lib.ucffi.wsgi:
        uwsgi_pypy_loader(ffi.string(lib.ucffi.wsgi).decode("utf-8"))
    return lib.UWSGI_OK


class WSGIfilewrapper(object):
    """
    class implementing wsgi.file_wrapper
    """

    def __init__(self, wsgi_req, f, chunksize=0):
        self.wsgi_req = wsgi_req
        self.f = f
        self.chunksize = chunksize
        if hasattr(f, "close"):
            self.close = f.close

    def __iter__(self):
        return self

    def __next__(self):
        if self.chunksize:
            data = self.f.read(self.chunksize)
        else:
            data = self.f.read()
        if data:
            return data
        raise StopIteration()

    next = __next__

    def sendfile(self):
        if hasattr(self.f, "fileno"):
            lib.uwsgi_response_sendfile_do_can_close(
                self.wsgi_req, self.f.fileno(), 0, 0, 0
            )
        elif hasattr(self.f, "read"):
            if self.chunksize == 0:
                chunk = self.f.read()
                if len(chunk) > 0:
                    lib.uwsgi_response_write_body_do(
                        self.wsgi_req, ffi.new("char[]", chunk), len(chunk)
                    )
                return
            while True:
                chunk = self.f.read(self.chunksize)
                if chunk is None or len(chunk) == 0:
                    break
                lib.uwsgi_response_write_body_do(
                    self.wsgi_req, ffi.new("char[]", chunk), len(chunk)
                )


class WSGIinput(object):
    """
    class implementing wsgi.input
    """

    def __init__(self, wsgi_req):
        self.wsgi_req = wsgi_req

    def read(self, size=0):
        rlen = ffi.new("ssize_t*")
        chunk = lib.uwsgi_request_body_read(self.wsgi_req, size, rlen)
        if chunk != ffi.NULL:
            return ffi.buffer(chunk, rlen[0])[:]
        if rlen[0] < 0:
            raise IOError("error reading wsgi.input")
        raise IOError("error waiting for wsgi.input")

    def getline(self, hint=0):
        rlen = ffi.new("ssize_t*")
        chunk = lib.uwsgi_request_body_readline(self.wsgi_req, hint, rlen)
        if chunk != ffi.NULL:
            return ffi.buffer(chunk, rlen[0])[:]
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


@ffi.def_extern()
def uwsgi_cffi_request(wsgi_req):
    """
    the WSGI request handler
    """
    global wsgi_application

    def writer(data):
        lib.uwsgi_response_write_body_do(wsgi_req, ffi.new("char[]", data), len(data))

    def start_response(status, headers, exc_info=None):
        if exc_info:
            traceback.print_exception(*exc_info)
        lib.uwsgi_response_prepare_headers(
            wsgi_req, ffi.new("char[]", status), len(status)
        )
        for hh in headers:
            lib.uwsgi_response_add_header(
                wsgi_req,
                ffi.new("char[]", hh[0]),
                len(hh[0]),
                ffi.new("char[]", hh[1]),
                len(hh[1]),
            )
        return writer

    environ = {}
    iov = wsgi_req.hvec
    for i in range(0, wsgi_req.var_cnt, 2):
        environ[
            ffi.string(ffi.cast("char*", iov[i].iov_base), iov[i].iov_len)
        ] = ffi.string(ffi.cast("char*", iov[i + 1].iov_base), iov[i + 1].iov_len)

    environ["wsgi.version"] = (1, 0)
    scheme = "http"
    if "HTTPS" in environ:
        if environ["HTTPS"] in ("on", "ON", "On", "1", "true", "TRUE", "True"):
            scheme = "https"
    environ["wsgi.url_scheme"] = environ.get("UWSGI_SCHEME", scheme)
    environ["wsgi.input"] = WSGIinput(wsgi_req)
    environ["wsgi.errors"] = sys.stderr
    environ["wsgi.run_once"] = False
    environ["wsgi.file_wrapper"] = lambda f, chunksize=0: WSGIfilewrapper(
        wsgi_req, f, chunksize
    )
    environ["wsgi.multithread"] = True
    environ["wsgi.multiprocess"] = True

    environ["uwsgi.core"] = wsgi_req.async_id
    environ["uwsgi.node"] = ffi.string(lib.uwsgi.hostname).decode("latin1")

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
            if hasattr(response, "close"):
                response.close()

    return lib.UWSGI_OK


@ffi.def_extern()
def uwsgi_cffi_after_request(wsgi_req):
    lib.log_request(wsgi_req)


#
# Non-callback section
#

wsgi_application = None


def uwsgi_pypy_loader(m):
    """
    load a wsgi module
    """
    global wsgi_application
    c = "application"
    if ":" in m:
        m, c = m.split(":")
    if "." in m:
        mod = __import__(m, None, None, "*")
    else:
        mod = __import__(m)
    wsgi_application = getattr(mod, c)
