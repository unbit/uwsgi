"""
Implement the uwsgi module.

Based on plugins/pypy/pypy_setup.py
"""

import os
from _uwsgi import ffi, lib

# this is a list holding object we do not want to be freed (like callback and handlers)
uwsgi_gc = []

applications = {}  # TODO

# latin1 might be better
hostname = ffi.string(lib.uwsgi.hostname, lib.uwsgi.hostname_len).decode("utf-8")
numproc = lib.uwsgi.numproc
buffer_size = lib.uwsgi.buffer_size
if lib.uwsgi.mode:
    mode = ffi.string(lib.uwsgi.mode).decode("utf-8")
if lib.uwsgi.pidfile:
    pidfile = ffi.string(lib.uwsgi.pidfile).decode("utf-8")

# parse version from cflags
_version = {}
for _flag in ffi.string(lib.uwsgi_get_cflags()).decode("utf-8").split():
    if _flag.startswith("-DUWSGI_VERSION"):
        _k, _v = _flag.split("=", 1)
        _version[_k] = _v.replace('"', "").replace("\\", "")

version = _version["-DUWSGI_VERSION"]
version_info = tuple(
    int(_version["-DUWSGI_VERSION_" + _k])
    for _k in ("BASE", "MAJOR", "MINOR", "REVISION")
) + (_version["-DUWSGI_VERSION_CUSTOM"],)


def _current_wsgi_req():
    wsgi_req = lib.uwsgi.current_wsgi_req()
    if wsgi_req == ffi.NULL:
        raise SystemError("you can call uwsgi api function only from the main callable")
    return wsgi_req


def _print_exc():
    import traceback

    traceback.print_exc()


def request_id():
    wsgi_req = _current_wsgi_req()
    return lib.uwsgi.workers[lib.uwsgi.mywid].cores[wsgi_req.async_id].requests


def async_id():
    wsgi_req = _current_wsgi_req()
    return wsgi_req.async_id


def register_signal(signum, kind, handler):
    cb = ffi.callback("void(int)", handler)
    uwsgi_gc.append(cb)
    if (
        lib.uwsgi_register_signal(
            signum, ffi.new("char[]", kind), cb, lib.cffi_plugin.modifier1
        )
        < 0
    ):
        raise Exception("unable to register signal %d" % signum)


class uwsgi_pypy_RPC(object):
    def __init__(self, func):
        self.func = func

    def __call__(self, argc, argv, argvs, buf):
        pargs = []
        for i in range(0, argc):
            pargs.append(ffi.buffer(argv[i], argvs[i])[:])
        response = self.func(*pargs)
        if len(response) > 0:
            buf[0] = lib.uwsgi_malloc(len(response))
            dst = ffi.buffer(buf[0], len(response))
            dst[: len(response)] = response
        return len(response)


def register_rpc(name, func, argc=0):
    rpc_func = uwsgi_pypy_RPC(func)
    cb = ffi.callback("int(int, char*[], int[], char**)", rpc_func)
    uwsgi_gc.append(cb)
    if (
        lib.uwsgi_register_rpc(
            ffi.new("char[]", name), ffi.addressof(lib.cffi_plugin), argc, cb
        )
        < 0
    ):
        raise Exception("unable to register rpc func %s" % name)


def rpc(node, func, *args):
    argc = 0
    argv = ffi.new("char*[256]")
    argvs = ffi.new("uint16_t[256]")
    rsize = ffi.new("uint64_t*")

    for arg in args:
        if argc >= 255:
            raise Exception("invalid number of rpc arguments")
        if len(arg) >= 65535:
            raise Exception("invalid rpc argument size (must be < 65535)")
        argv[argc] = ffi.new("char[]", arg)
        argvs[argc] = len(arg)
        argc += 1

    if node:
        c_node = ffi.new("char[]", node)
    else:
        c_node = ffi.NULL

    response = lib.uwsgi_do_rpc(
        c_node, ffi.new("char[]", func), argc, argv, argvs, rsize
    )
    if response:
        ret = ffi.buffer(response, rsize[0])[:]
        lib.free(response)
        return ret
    return None


def call(func, *args):
    node = None
    if "@" in func:
        (func, node) = func.split("@")
    return uwsgi_pypy_rpc(node, func, *args)


signal = lambda x: lib.uwsgi_signal_send(lib.uwsgi.signal_socket, x)

metric_get = lambda x: lib.uwsgi_metric_get(x, ffi.NULL)
metric_set = lambda x, y: lib.uwsgi_metric_set(x, ffi.NULL, y)
metric_inc = lambda x, y=1: lib.uwsgi_metric_inc(x, ffi.NULL, y)
metric_dec = lambda x, y=1: lib.uwsgi_metric_dec(x, ffi.NULL, y)
metric_mul = lambda x, y=1: lib.uwsgi_metric_mul(x, ffi.NULL, y)
metric_div = lambda x, y=1: lib.uwsgi_metric_div(x, ffi.NULL, y)


def cache_get(key, cache=ffi.NULL):
    vallen = ffi.new("uint64_t*")
    value = lib.uwsgi_cache_magic_get(key, len(key), vallen, ffi.NULL, cache)
    if value == ffi.NULL:
        return None
    ret = ffi.buffer(value, vallen[0])[:]
    lib.free(value)
    return ret


def cache_set(key, value, expires=0, cache=ffi.NULL):
    if (
        lib.uwsgi_cache_magic_set(key, len(key), value, len(value), expires, 0, cache)
        < 0
    ):
        raise Exception("unable to store item in the cache")


def cache_update(key, value, expires=0, cache=ffi.NULL):
    if (
        lib.uwsgi_cache_magic_set(
            key, len(key), value, len(value), expires, 1 << 1, cache
        )
        < 0
    ):
        raise Exception("unable to store item in the cache")


def cache_del(key, cache=ffi.NULL):
    if lib.uwsgi_cache_magic_del(key, len(key), cache) < 0:
        raise Exception("unable to delete item from the cache")


def cache_keys(cache=ffi.NULL):
    uc = lib.uwsgi_cache_by_name(cache)
    if uc == ffi.NULL:
        raise Exception("no local uWSGI cache available")
    l = []
    lib.uwsgi_cache_rlock(uc)
    pos = ffi.new("uint64_t *")
    uci = ffi.new("struct uwsgi_cache_item **")
    while True:
        uci[0] = lib.uwsgi_cache_keys(uc, pos, uci)
        if uci[0] == ffi.NULL:
            break
        l.append(ffi.buffer(lib.uwsgi_cache_item_key(uci[0]), uci[0].keysize)[:])
    lib.uwsgi_cache_rwunlock(uc)
    return l


def add_timer(signum, secs):
    if lib.uwsgi_add_timer(signum, secs) < 0:
        raise Exception("unable to register timer")


def add_rb_timer(signum, secs):
    if lib.uwsgi_signal_add_rb_timer(signum, secs, 0) < 0:
        raise Exception("unable to register redblack timer")


def add_file_monitor(signum, filename):
    if lib.uwsgi_add_file_monitor(signum, ffi.new("char[]", filename)) < 0:
        raise Exception("unable to register file monitor")


def lock(num=0):
    if lib.uwsgi_user_lock(num) < 0:
        raise Exception("invalid lock")


def unlock(num=0):
    if lib.uwsgi_user_unlock(num) < 0:
        raise Exception("invalid lock")


def masterpid():
    if lib.uwsgi.master_process:
        return lib.uwsgi.workers[0].pid
    return 0


def worker_id():
    return lib.uwsgi.mywid


def mule_id():
    return lib.uwsgi.muleid


def mule_msg_recv_size():
    return lib.uwsgi.mule_msg_recv_size


mule_msg_extra_hooks = []


def install_mule_msg_hook(mule_msg_dispatcher):
    mule_msg_extra_hooks.append(mule_msg_dispatcher)


# plugin callback defined outside cffi_init.py
@ffi.def_extern()
def uwsgi_cffi_mule_msg(message, len):
    msg = ffi.string(message, len)
    if not mule_msg_extra_hooks:
        return 0
    for hook in mule_msg_extra_hooks:
        try:
            hook(msg)
        except:
            _print_exc()

    return 1


def logsize():
    return lib.uwsgi.shared.logsize


def signal_registered(signum):
    if lib.uwsgi_signal_registered(signum) > 0:
        return True
    return False


def alarm(alarm, msg):
    lib.uwsgi_alarm_trigger(ffi.new("char[]", alarm), ffi.new("char[]", msg), len(msg))


setprocname = lambda name: lib.uwsgi_set_processname(ffi.new("char[]", name))


def add_cron(signum, minute, hour, day, month, week):
    if lib.uwsgi_signal_add_cron(signum, minute, hour, day, month, week) < 0:
        raise Exception("unable to register cron")


def suspend():
    """
    uwsgi.suspend()
    """
    wsgi_req = _current_wsgi_req()
    if lib.uwsgi.schedule_to_main:
        lib.uwsgi.schedule_to_main(wsgi_req)


def workers():
    """
    uwsgi.workers()
    """
    workers = []
    for i in range(1, lib.uwsgi.numproc + 1):
        worker = {}
        worker["id"] = lib.uwsgi.workers[i].id
        worker["pid"] = lib.uwsgi.workers[i].pid
        worker["requests"] = lib.uwsgi.workers[i].requests
        worker["delta_requests"] = lib.uwsgi.workers[i].delta_requests
        worker["signals"] = lib.uwsgi.workers[i].signals
        worker["exceptions"] = lib.uwsgi_worker_exceptions(i)
        worker["apps"] = []
        apps_cnt = lib.uwsgi.workers[i].apps_cnt
        apps = lib.uwsgi.workers[i].apps
        for j in range(0, apps_cnt):
            app = apps[j]
            worker["apps"].append(
                {
                    "id": j,
                    "mountpoint": ffi.string(app.mountpoint, app.mountpoint_len).decode(
                        "utf-8"
                    ),
                    "startup_time": app.startup_time,
                    "requests": app.requests,
                }
            )
        if lib.uwsgi.workers[i].cheaped:
            worker["status"] == "cheap"
        elif lib.uwsgi.workers[i].suspended and not lib.uwsgi_worker_is_busy(i):
            worker["status"] == "pause"
        else:
            if lib.uwsgi.workers[i].sig:
                worker["status"] = "sig%d" % lib.uwsgi.workers[i].signum
            elif lib.uwsgi_worker_is_busy(i):
                worker["status"] = "busy"
            else:
                worker["status"] = "idle"
        worker["running_time"] = lib.uwsgi.workers[i].running_time
        worker["avg_rt"] = lib.uwsgi.workers[i].avg_response_time
        worker["tx"] = lib.uwsgi.workers[i].tx

        workers.append(worker)
    return workers


def async_sleep(timeout):
    """
    uwsgi.async_sleep(timeout)
    """
    if timeout > 0:
        wsgi_req = _current_wsgi_req()
        lib.async_add_timeout(wsgi_req, timeout)


def async_connect(addr):
    """
    uwsgi.async_connect(addr)
    """
    fd = lib.uwsgi_connect(ffi.new("char[]", addr), 0, 1)
    if fd < 0:
        raise Exception("unable to connect to %s" % addr)
    return fd


connection_fd = lambda: _current_wsgi_req().fd


def wait_fd_read(fd, timeout=0):
    """
    uwsgi.wait_fd_read(fd, timeout=0)
    """
    wsgi_req = _current_wsgi_req()
    if lib.async_add_fd_read(wsgi_req, fd, timeout) < 0:
        raise Exception("unable to add fd %d to the event queue" % fd)


def wait_fd_write(fd, timeout=0):
    """
    uwsgi.wait_fd_write(fd, timeout=0)
    """
    wsgi_req = _current_wsgi_req()
    if lib.async_add_fd_write(wsgi_req, fd, timeout) < 0:
        raise Exception("unable to add fd %d to the event queue" % fd)


def ready_fd():
    """
    uwsgi.ready_fd()
    """
    wsgi_req = _current_wsgi_req()
    return lib.uwsgi_ready_fd(wsgi_req)


def send(*args):
    """
    uwsgi.send(fd=None,data)
    """
    if len(args) == 0:
        raise ValueError("uwsgi.send() takes at least 1 argument")
    elif len(args) == 1:
        wsgi_req = _current_wsgi_req()
        fd = wsgi_req.fd
        data = args[0]
    else:
        fd = args[0]
        data = args[1]
    rlen = lib.write(fd, data, len(data))
    if rlen <= 0:
        raise IOError("unable to send data")
    return rlen


def recv(*args):
    """
    uwsgi.recv(fd=None,len)
    """
    if len(args) == 0:
        raise ValueError("uwsgi.recv() takes at least 1 argument")
    elif len(args) == 1:
        wsgi_req = _current_wsgi_req()
        fd = wsgi_req.fd
        l = args[0]
    else:
        fd = args[0]
        l = args[1]
    data = ffi.new("char[%d]" % l)
    # why not os.read()?
    rlen = lib.read(fd, data, l)
    if rlen <= 0:
        raise IOError("unable to receive data")
    return ffi.string(data[0:rlen])


"""
uwsgi.close(fd)
"""
close = lambda fd: lib.close(fd)

"""
uwsgi.disconnect()
"""
disconnect = lambda: lib.uwsgi_disconnect(_current_wsgi_req())


def sendfile(filename):
    # TODO support all argument types from uwsgi_pymodule.c

    fd = os.open(filename, os.O_RDONLY)
    pos = 0
    filesize = 0
    lib.uwsgi_response_sendfile_do(_current_wsgi_req(), fd, pos, filesize)
    # uwsgi check write errors?
    return []


def websocket_recv():
    """
    uwsgi.websocket_recv()
    """
    wsgi_req = lib.uwsgi.current_wsgi_req()
    ub = lib.uwsgi_websocket_recv(wsgi_req)
    if ub == ffi.NULL:
        raise IOError("unable to receive websocket message")
    ret = ffi.buffer(ub.buf, ub.pos)[:]
    lib.uwsgi_buffer_destroy(ub)
    return ret


def websocket_recv_nb():
    """
    uwsgi.websocket_recv_nb()
    """
    wsgi_req = lib.uwsgi.current_wsgi_req()
    ub = lib.uwsgi_websocket_recv_nb(wsgi_req)
    if ub == ffi.NULL:
        raise IOError("unable to receive websocket message")
    ret = ffi.buffer(ub.buf, ub.pos)[:]
    lib.uwsgi_buffer_destroy(ub)
    return ret


def websocket_handshake(key=None, origin=None, proto=None):
    """
    uwsgi.websocket_handshake(key, origin)
    """
    wsgi_req = _current_wsgi_req()
    len_key = 0
    len_origin = 0
    len_proto = 0
    c_key = ffi.NULL
    c_origin = ffi.NULL
    c_proto = ffi.NULL
    if key:
        len_key = len(key)
        c_key = ffi.new("char[]", key.encode("latin1"))  # correct encoding?
    if origin:
        len_origin = len(origin)
        c_origin = ffi.new("char[]", origin.encode("latin1"))
    if proto:
        len_proto = len(proto)
        c_proto = ffi.new("char[]", proto.encode("latin1"))
    if (
        lib.uwsgi_websocket_handshake(
            wsgi_req, c_key, len_key, c_origin, len_origin, c_proto, len_proto
        )
        < 0
    ):
        raise IOError("unable to complete websocket handshake")


def websocket_send(msg):
    """
    uwsgi.websocket_send(msg)
    """
    wsgi_req = lib.uwsgi.current_wsgi_req()
    if lib.uwsgi_websocket_send(wsgi_req, ffi.new("char[]", msg), len(msg)) < 0:
        raise IOError("unable to send websocket message")


def websocket_send_binary(msg):
    """
    uwsgi.websocket_send_binary(msg)
    """
    wsgi_req = lib.uwsgi.current_wsgi_req()
    if lib.uwsgi_websocket_send_binary(wsgi_req, ffi.new("char[]", msg), len(msg)) < 0:
        raise IOError("unable to send binary websocket message")


def chunked_read(timeout=0):
    """
    uwsgi.chunked_read(timeout=0)
    """
    wsgi_req = _current_wsgi_req()
    rlen = ffi.new("size_t*")
    chunk = lib.uwsgi_chunked_read(wsgi_req, rlen, timeout, 0)
    if chunk == ffi.NULL:
        raise IOError("unable to receive chunked part")
    return ffi.buffer(chunk, rlen[0])[:]


def chunked_read_nb():
    """
    uwsgi.chunked_read_nb()
    """
    wsgi_req = _current_wsgi_req()
    rlen = ffi.new("size_t*")
    chunk = lib.uwsgi_chunked_read(wsgi_req, rlen, 0, 1)
    if chunk == ffi.NULL:
        if lib.uwsgi_is_again() > 0:
            return None
        raise IOError("unable to receive chunked part")

    return ffi.buffer(chunk, rlen[0])[:]


def set_user_harakiri(x):
    """
    uwsgi.set_user_harakiri(sec)
    """
    wsgi_req = _current_wsgi_req()
    lib.set_user_harakiri(wsgi_req, x)


def get_logvar(key):
    """
    uwsgi.get_logvar(key)
    """
    wsgi_req = _current_wsgi_req()
    c_key = ffi.new("char[]", key)
    lv = lib.uwsgi_logvar_get(wsgi_req, c_key, len(key))
    if lv:
        return ffi.string(lv.val[0 : lv.vallen])
    return None


def set_logvar(key, val):
    """
    uwsgi.set_logvar(key, value)
    """
    wsgi_req = _current_wsgi_req()
    c_key = ffi.new("char[]", key)
    c_val = ffi.new("char[]", val)
    lib.uwsgi_logvar_add(wsgi_req, c_key, len(key), c_val, len(val))


def _init():
    """
    Create uwsgi module, with properties.
    """
    import sys
    import types

    class UwsgiModule(types.ModuleType):
        pass

    module = UwsgiModule("uwsgi")
    module.__dict__.update(
        (k, v) for (k, v) in globals().items() if not k.startswith("_")
    )

    """
    populate uwsgi.opt
    """
    opt = {}
    for i in range(0, lib.uwsgi.exported_opts_cnt):
        uo = lib.uwsgi.exported_opts[i]
        k = ffi.string(uo.key)
        if uo.value == ffi.NULL:
            v = True
        else:
            v = ffi.string(uo.value)
        if k in opt:
            if type(opt[k]) is list:
                opt[k].append(v)
            else:
                opt[k] = [opt[k], v]
        else:
            opt[k] = v
    module.opt = opt

    sys.modules["uwsgi"] = module


_init()
