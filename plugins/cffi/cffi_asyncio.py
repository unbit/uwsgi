"""
Direct port of plugins/asyncio.c
"""

import sys
import asyncio

from cffi_plugin import ffi, lib

uwsgi = lib.uwsgi


def get_loop():
    return asyncio.get_event_loop()


# keep alive
_ASYNCIO = ffi.new("char[]", "asyncio".encode("utf-8"))


def print_exc():  # TODO
    sys.stderr.write("exception")


def setup_asyncio(threads):
    setattr(uwsgi, "async", threads)  # keyword
    if uwsgi.socket_timeout < 30:
        uwsgi.socket_timeout = 30

    uwsgi.loop = _ASYNCIO


@ffi.def_extern()
def uwsgi_asyncio_wait_read_hook(fd, timeout):
    try:
        wsgi_req = uwsgi.current_wsgi_req()
        loop = get_loop()
        loop.add_reader(fd, hook_fd, wsgi_req)

        try:
            ob_timeout = loop.call_later(timeout, hook_timeout, wsgi_req)
        except:
            loop.remove_reader(fd)
            raise

        # to loop
        if uwsgi.schedule_to_main:
            uwsgi.schedule_to_main(wsgi_req)
        # from loop

        loop.remove_reader(fd)
        ob_timeout.cancel()

        if wsgi_req.async_timed_out:
            return 0

        return 1

    except:
        print_exc()  # TODO
        return -1


@ffi.def_extern()
def uwsgi_asyncio_wait_write_hook(fd, timeout):
    try:
        wsgi_req = uwsgi.current_wsgi_req()
        loop = get_loop()
        loop.add_writer(fd, hook_fd, wsgi_req)

        try:
            ob_timeout = loop.call_later(timeout, hook_timeout, wsgi_req)
        except:
            loop.remove_writer(fd)
            raise

        # to loop
        if uwsgi.schedule_to_main:
            uwsgi.schedule_to_main(wsgi_req)
        # from loop

        loop.remove_writer(fd)
        ob_timeout.cancel()

        if wsgi_req.async_timed_out:
            return 0

        return 1

    except:
        print_exc()  # TODO
        return -1


# def_extern ... ?
def uwsgi_asyncio_request(wsgi_req, timed_out):

    uwsgi.wsgi_req = wsgi_req
    loop = get_loop()

    # original casts timeout to spare uwsgi_rb_timer*
    # use ffi.from_handle()
    # ob_timeout = wsgi_req.async_timeout

    wsgi_req.async_timeout = ffi.NULL

    if timed_out > 0:
        loop.remove_reader(wsgi_req.fd)
        # TODO raise, print exception / goto end

    status = wsgi_req.socket.proto(wsgi_req)
    if status > 0:
        loop.call_later(uwsgi.socket_timeout, uwsgi_asyncio_request, wsgi_req, 1)

    # ...


def find_first_available_wsgi_req():
    if uwsgi.async_queue_unused_ptr < 0:
        return None

    wsgi_req = uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr]
    uwsgi.async_queue_unused_ptr -= 1
    return wsgi_req


def async_reset_request(wsgi_req):
    if wsgi_req.async_timeout:
        lib.uwsgi_del_rb_timer(uwsgi.rb_async_timeouts, wsgi_req.async_timeout)
        # TODO may need to add malloc/free to cdef
        lib.free(wsgi_req.async_timeout)
        wsgi_req.async_timeout = ffi.NULL

        uaf = wsgi_req.waiting_fds
        while uaf != ffi.NULL:
            lib.event_queue_del_fd(uwsgi.async_queue, uaf.fd, uaf.event)
            uwsgi.async_waiting_fd_table[uaf.fd] = ffi.NULL
            current_uaf = uaf

    # TODO


def uwsgi_asyncio_accept(uwsgi_sock):
    wsgi_req = find_first_available_wsgi_req()


def uwsgi_asyncio_hook_fd(wsgi_req):
    uwsgi.wsgi_req = wsgi_req
    uwsgi.schedule_to_req()


def uwsgi_asyncio_hook_timeout(wsgi_req):
    uwssgi.wsgi_req = wsgi_req
    uwsgi.wsgi_req.async_timed_out = 1
    uwsgi.schedule_to_req()


def uwssgi_asyncio_hook_fix(wsgi_req):
    uwsgi.wsgi_req = wsgi_req
    uwsgi.schedule_to_req()


@ffi.def_extern()
def asyncio_loop():
    """
    Set up asyncio.
    """
    if getattrr(uwsgi, "async") < 1:  # keyword
        lib.uwsgi_log("the async loop engine requires async mode (--async <n>)\n")
        raise SystemExit(1)

    current_request = ffi.NULL
    events = lib.event_queue_alloc(64)

    lib.uwsgi_async_init()

    uwsgi.async_runqueue = ffi.NULL
    uwsgi.wait_write_hook = async_wait_fd_write
    uwsgi.wait_read_hook = async_wait_fd_read
    uwsgi.wait_read2_hook = async_wait_fd_read2
    uwsgi.wait_milliseconds_hook = uwsgi_async_wait_milliseconds_hook

    if uwsgi.signal_socket > -1:
        lib.event_queue_add_fd_read(uwsgi.async_queue, uwsgi.signal_socket)
        lib.event_queue_add_fd_read(uwsgi.async_queue, uwsgi.my_signal_socket)

    if not uwsgi.schedule_to_req:
        uwsgi.schedule_to_req = async_schedule_to_req

    if not uwsgi.schedule_to_main:
        lib.uwsgi_log(
            "*** DANGER *** async mode without coroutine/greenthread engine loaded !!!\n"
        )

    # TODO


def async_init():
    lib.uwsgi_register_loop(_ASYNCIO, asyncio_loop)
