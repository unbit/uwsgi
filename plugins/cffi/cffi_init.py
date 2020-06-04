"""
cffi embedding API based Python plugin, based on pypy plugin.

Should work with both CPython and PyPy in theory.
"""

import imp
import importlib
import sys
import os
import inspect

import cffi_plugin

from cffi_plugin import ffi, lib
from cffi_plugin.lib import *

# predictable name
sys.modules["_uwsgi"] = cffi_plugin

print("cffi_init", __name__)


def print_exc():
    import traceback

    traceback.print_exc()


def to_network(native):
    return native.encode("latin1")


@ffi.def_extern()
def uwsgi_cffi_init():
    # pypy will find environment from current working directory
    # (uwsgi --chdir $VIRTUAL_ENV/bin)
    if "PYTHONPATH" in os.environ:
        sys.path[0:0] = os.environ["PYTHONPATH"].split(os.pathsep)

    # define or override callbacks
    if lib.ucffi.init:
        init_name = ffi.string(lib.ucffi.init).decode("utf-8")
        importlib.import_module(init_name)

    return lib.UWSGI_OK


@ffi.def_extern()
def uwsgi_cffi_init_apps():
    try:
        if lib.ucffi.wsgi:
            init_app(ffi.string(lib.ucffi.wsgi), b"")
    except:
        print_exc()


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

    if wsgi_req.async_force_again:
        print("force again")
        wsgi_req.async_force_again = 0
        # just close it
        return lib.UWSGI_OK

    def writer(data):
        lib.uwsgi_response_write_body_do(wsgi_req, ffi.new("char[]", data), len(data))

    def start_response(status, headers, exc_info=None):
        if exc_info:
            traceback.print_exception(*exc_info)
        status = to_network(status)
        lib.uwsgi_response_prepare_headers(
            wsgi_req, ffi.new("char[]", status), len(status)
        )
        for hh in headers:
            header, value = to_network(hh[0]), to_network(hh[1])
            lib.uwsgi_response_add_header(
                wsgi_req,
                ffi.new("char[]", header),
                len(hh[0]),
                ffi.new("char[]", value),
                len(hh[1]),
            )
        return writer

    if lib.uwsgi_parse_vars(wsgi_req):
        return -1

    # check dynamic
    # check app_id
    app_id = lib.uwsgi_get_app_id(
        wsgi_req, wsgi_req.appid, wsgi_req.appid_len, lib.cffi_plugin.modifier1
    )
    if app_id == -1 and not lib.uwsgi.no_default_app and lib.uwsgi.default_app > -1:
        # and default app modifier1 == our modifier1
        app_id = lib.uwsgi.default_app
    wsgi_req.app_id = app_id
    app_mount = ""
    # app_mount can be something while app_id is -1
    if wsgi_req.appid != ffi.NULL:
        app_mount = ffi.string(wsgi_req.appid).decode("utf-8")
    app = wsgi_apps.get(app_id)

    # (see python wsgi_handlers.c)

    environ = {}
    iov = wsgi_req.hvec
    for i in range(0, wsgi_req.var_cnt, 2):
        environ[
            ffi.string(ffi.cast("char*", iov[i].iov_base), iov[i].iov_len).decode(
                "latin1"
            )
        ] = ffi.string(
            ffi.cast("char*", iov[i + 1].iov_base), iov[i + 1].iov_len
        ).decode(
            "latin1"
        )

    # check bytes on environ...
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

    try:
        response = app(environ, start_response)
    except:
        print("app exception")
        wsgi_req.async_force_again = 1
        return lib.UWSGI_AGAIN

    if type(response) is bytes:
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


@ffi.def_extern()
def uwsgi_cffi_preinit_apps():
    pass


@ffi.def_extern()
def uwsgi_cffi_post_fork():
    """
    .post_fork_hook
    """
    import uwsgi

    if hasattr(uwsgi, "post_fork_hook"):
        uwsgi.post_fork_hook()


def uwsgi_apps_cnt():
    # we init in worker 0 and then serve in worker n
    return lib.uwsgi.workers[lib.uwsgi.mywid].apps_cnt


def uwsgi_apps():
    return lib.uwsgi.workers[lib.uwsgi.mywid].apps


wsgi_apps = {}


def iscoroutine(app):
    """
    Could app be ASGI?
    """
    return inspect.iscoroutinefunction(app) or inspect.iscoroutinefunction(
        getattr(app, "__call__")
    )


def init_app(app, mountpoint):
    # based on pyloader.c's init_uwsgi_app(int loader, void *arg1, struct wsgi_request *wsgi_req, PyThreadState *interpreter, int app_type)

    now = lib.uwsgi_now()

    id = uwsgi_apps_cnt()
    if lib.uwsgi.default_app == -1 and not lib.uwsgi.no_default_app:
        lib.uwsgi.default_app = id

    # uwsgi_get_app_id(ffi.NULL, mountpoint, len(mountpoint), -1)
    # "already configured"

    wi = uwsgi_apps()[id]  # zero out wi?

    wi.modifier1 = lib.cffi_plugin.modifier1
    wi.mountpoint_len = len(mountpoint)  # TODO clamp to 0xff-1
    ffi.memmove(wi.mountpoint, mountpoint, len(mountpoint))

    # original does dynamic chdir
    # cffi always in "single interpreter" mode
    application = app.decode("utf-8")

    if application.endswith((".wsgi", ".py")):
        # application.py / application.wsgi
        wsgi_apps[id] = uwsgi_file_loader(application)
    else:
        # importable:callable syntax
        wsgi_apps[id] = uwsgi_pypy_loader(application)

    # callable has to be not NULL for uwsgi_get_app_id:
    wi.callable = ffi.cast("void *", 1)
    if iscoroutine(wsgi_apps[id]):
        print(f"{application} is ASGI")
        wi.callable = ffi.cast("void *", 2)
    wi.started_at = now
    wi.startup_time = lib.uwsgi_now() - now

    lib.uwsgi_log(
        (
            "WSGI app %d (mountpoint='%s') ready in %d seconds\n"
            % (id, mountpoint.decode("utf-8"), wi.startup_time)
        ).encode("utf-8")
    )

    # log if error
    lib.uwsgi_cffi_more_apps()

    # TODO if uwsgi_apps[id] is a dict, deal with multiple applications...

    # copies wi to other workers if wid = 0
    lib.uwsgi_emulate_cow_for_apps(id)

    return id


@ffi.def_extern()
def uwsgi_cffi_mount_app(mountpoint, app):
    try:
        app_id = init_app(ffi.string(app), ffi.string(mountpoint))
        return app_id
    except:
        print_exc()
    return -1


@ffi.def_extern()
def uwsgi_cffi_enable_threads():
    pass


@ffi.def_extern()
def uwsgi_cffi_init_thread():
    pass


@ffi.def_extern()
def uwsgi_cffi_signal_handler(sig, handler):
    ffi.from_handle(handler)(sig)
    return 0


@ffi.def_extern()
def uwsgi_cffi_mule(opt):
    opt = ffi.string(opt).decode("latin1")


@ffi.def_extern()
def uwsgi_cffi_rpc(func, argc, argv, argvs, buffer):
    return ffi.from_handle(func)(argc, argv, argvs, buffer)


#
# Non-callback section
#


def uwsgi_pypy_loader(m):
    """
    load a wsgi module
    """
    c = "application"
    if ":" in m:
        m, c = m.split(":")
    mod = importlib.import_module(m)
    return getattr(mod, c)


def uwsgi_file_loader(path):
    """
    load a .wsgi or .py file from path
    """
    c = "application"
    mod = imp.load_source("uwsgi_file_wsgi", path)
    return getattr(mod, c)


sys.modules["wsgi_apps"] = wsgi_apps
