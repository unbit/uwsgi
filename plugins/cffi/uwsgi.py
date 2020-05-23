"""
Implement the uwsgi module.
"""

from cffi_plugin import ffi, lib

# version = ... # parse from uwsgi_get_cflags()?
hostname = ffi.string(lib.uwsgi.hostname)


def masterpid():
    if lib.uwsgi.master_process:
        return lib.uwsgi.workers[0].pid
    return 0


def signal_registered(signum):
    return lib.uwsgi_signal_registered(signum)


def worker_id():
    return lib.uwsgi.mywid


def mule_id():
    return lib.uwsgi.muleid


def logsize():
    return lib.uwsgi.shared.logsize


def mule_msg_recv_size():
    return lib.uwsgi.mule_msg_recv_size


def _current_wsgi_req():
    wsgi_req = lib.uwsgi.current_wsgi_req()
    if wsgi_req == ffi.NULL:
        raise SystemError("you can call uwsgi api function only from the main callable")
    return wsgi_req


def request_id():
    wsgi_req = _current_wsgi_req()
    return lib.uwsgi.workers[lib.uwsgi.mywid].cores[wsgi_req.async_id].requests


def async_id():
    wsgi_req = _current_wsgi_req()
    return wsgi_req.async_id


def connection_fd():
    fd = _current_wsgi_req().fd
    print("request_id", request_id(), "connection_fd", fd)
    return fd


def uwsgi_pypy_current_wsgi_req():
    return lib.uwsgi.current_wsgi_req()


def suspend():
    """
    uwsgi.suspend()
    """
    wsgi_req = uwsgi_pypy_current_wsgi_req()
    if lib.uwsgi.schedule_to_main:
        lib.uwsgi.schedule_to_main(wsgi_req)


def wait_fd_read(fd, timeout=0):
    """
    uwsgi.wait_fd_read(fd, timeout=0)
    """
    wsgi_req = uwsgi_pypy_current_wsgi_req()
    if lib.async_add_fd_read(wsgi_req, fd, timeout) < 0:
        raise Exception("unable to add fd %d to the event queue" % fd)


def wait_fd_write(fd, timeout=0):
    """
    uwsgi.wait_fd_write(fd, timeout=0)
    """
    wsgi_req = uwsgi_pypy_current_wsgi_req()
    if lib.async_add_fd_write(wsgi_req, fd, timeout) < 0:
        raise Exception("unable to add fd %d to the event queue" % fd)


def ready_fd():
    """
    uwsgi.ready_fd()
    """
    wsgi_req = uwsgi_pypy_current_wsgi_req()
    return lib.uwsgi_ready_fd(wsgi_req)


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


def websocket_handshake(key="", origin="", proto=""):
    """
    uwsgi.websocket_handshake(key, origin)
    """
    wsgi_req = _current_wsgi_req()
    c_key = ffi.new("char[]", key.encode("latin1"))  # correct encoding?
    c_origin = ffi.new("char[]", origin.encode("latin1"))
    c_proto = ffi.new("char[]", proto.encode("latin1"))
    if (
        lib.uwsgi_websocket_handshake(
            wsgi_req, c_key, len(key), c_origin, len(origin), c_proto, len(proto)
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
