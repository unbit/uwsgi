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


@ffi.def_extern()
def asyncio_loop():
    """
    Set up asyncio.
    """
    pass


def async_init():
    lib.uwsgi_register_loop(_ASYNCIO, asyncio_loop)
