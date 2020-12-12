"""
cffi embedding API based Python plugin.
Should work with both CPython and PyPy 3.


Based on PyPy plugin by Maciej Fijalkowski.
"""

import os
import sys
import site

# add expected __main__ module
sys.modules["__main__"] = type(sys)("__main__")

from cffi_plugin import ffi, lib

# set desired virtualenv (may only work on Python 3?)
if lib.ucffi.home != ffi.NULL:
    sys.path = [entry for entry in sys.path if not "site-packages" in entry]
    sys.executable = os.path.join(
        ffi.string(lib.ucffi.home).decode("utf-8"), "bin", "python"
    )
    site.main()

import imp
import importlib
import inspect
import types


class UwsgiModule(types.ModuleType):
    pass


_uwsgi = UwsgiModule("_uwsgi")
_uwsgi.lib = lib
_uwsgi.ffi = ffi
_uwsgi._applications = {}
# predictable name
sys.modules["_uwsgi"] = _uwsgi

wsgi_apps = _uwsgi._applications


def print_exc():
    import traceback

    traceback.print_exc()


def to_network(native):
    return native.encode("latin1")


@ffi.def_extern()
def uwsgi_cffi_init():
    global wsgi_apps

    # pypy will find environment from current working directory
    # (uwsgi --chdir $VIRTUAL_ENV/bin)
    if "PYTHONPATH" in os.environ:
        sys.path[0:0] = os.environ["PYTHONPATH"].split(os.pathsep)

    # define or override callbacks?
    if lib.ucffi.init:
        init_name = ffi.string(lib.ucffi.init).decode("utf-8")
        importlib.import_module(init_name)

    return lib.UWSGI_OK


@ffi.def_extern()
def uwsgi_cffi_init_apps():
    """
    (The --mount= syntax is more general.)
    """
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
        wsgi_req.async_force_again = 0
        # just close it
        # it would be possible to continue with the response iterator here
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
    # uwsgi app struct
    wi = lib.uwsgi.workers[lib.uwsgi.mywid].apps[app_id]
    wi.requests += 1  # we might wind up here more often than expected
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
        print_exc()
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


def uwsgi_foreach(usl):
    # define uwsgi_foreach(x, y) for(x=y;x;x = x->next)
    while usl != ffi.NULL:
        yield usl
        usl = usl.next


def execfile(path):
    with open(path) as py:
        code = compile(py.read(), path, "exec")
    exec(code, globals(), {})


def eval_exec(to_eval, to_exec):
    for usl in uwsgi_foreach(to_eval):
        code = compile(ffi.string(usl.value), "<eval>", "exec")
        exec(code, globals(), {})

    for usl in uwsgi_foreach(to_exec):
        execfile(ffi.string(usl.value))


@ffi.def_extern()
def uwsgi_cffi_preinit_apps():
    eval_exec(lib.ucffi.eval, lib.ucffi.exec)


@ffi.def_extern()
def uwsgi_cffi_post_fork():
    """
    .post_fork_hook
    """
    eval_exec(lib.ucffi.eval_post_fork, lib.ucffi.exec_post_fork)

    import uwsgi

    if hasattr(uwsgi, "post_fork_hook"):
        uwsgi.post_fork_hook()


def uwsgi_apps_cnt():
    # we init in worker 0 and then serve in worker n
    return lib.uwsgi.workers[lib.uwsgi.mywid].apps_cnt


def uwsgi_apps():
    return lib.uwsgi.workers[lib.uwsgi.mywid].apps


def iscoroutine(app):
    """
    Could app be ASGI?
    """
    return inspect.iscoroutinefunction(app) or inspect.iscoroutinefunction(
        getattr(app, "__call__")
    )


def init_app(app, mountpoint):

    id = uwsgi_apps_cnt()

    if id >= lib.uwsgi.max_apps:
        lib.uwsgi_log(
            b"ERROR: you cannot load more than %d apps in a worker\n" % uwsgi.max_apps
        )
        return -1

    if len(mountpoint) > 0xFF - 1:
        # original uses prefix for very long mountpoints
        lib.uwsgi_log(b"ERROR: mountpoint must be shorter than %d bytes\n" % 0xFF - 1)

    if lib.uwsgi_get_app_id(ffi.NULL, mountpoint, len(mountpoint), -1) != -1:
        lib.uwsgi_log(b"mountpoint %s already configured. skip.\n" % mountpoint)
        return -1

    now = lib.uwsgi_now()

    if lib.uwsgi.default_app == -1 and not lib.uwsgi.no_default_app:
        lib.uwsgi.default_app = id

    wi = uwsgi_apps()[id]  # zero out wi?

    wi.modifier1 = lib.cffi_plugin.modifier1
    wi.mountpoint_len = len(mountpoint)
    ffi.memmove(wi.mountpoint, mountpoint, len(mountpoint))

    # original does dynamic chdir
    # cffi is always in "single interpreter" mode
    application = app.decode("utf-8")

    if application.endswith((".wsgi", ".py")):
        # application.py / application.wsgi
        wsgi_apps[id] = uwsgi_file_loader(application)
    else:
        # importable:callable syntax
        wsgi_apps[id] = uwsgi_pypy_loader(application)

    # callable has to be not NULL for uwsgi_get_app_id:
    app_type = "WSGI"
    wi.callable = ffi.cast("void *", 1)
    if iscoroutine(wsgi_apps[id]):
        app_type = "ASGI"
        wi.callable = ffi.cast("void *", 2)
    wi.started_at = now
    wi.startup_time = lib.uwsgi_now() - now

    lib.uwsgi_log(
        (
            "%s app %d (mountpoint='%s') ready in %d seconds\n"
            % (app_type, id, mountpoint.decode("utf-8"), wi.startup_time)
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
    """
    Handle the versatile --mount <mountpoint>=<app> flag
    """
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
    """
    From the docs:
    As mentioned before, mules can be programmed.
    To give custom logic to a mule, give the mule
    option a path to a script (it must end in ".py")
    or a "package.module:callable" value.
    """
    opt = ffi.string(opt).decode("latin1")
    if opt.endswith(".py"):
        execfile(opt)
    else:
        uwsgi_pypy_loader(opt)()


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
