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


def print_exc():
    import traceback

    traceback.print_exc()


def setup_asyncio(threads):
    setattr(uwsgi, "async", threads)  # keyword
    if uwsgi.socket_timeout < 30:
        uwsgi.socket_timeout = 30

    uwsgi.loop = _ASYNCIO


def free_req_queue(wsgi_req):
    """
    A #define that uses wsgi_req from context.
    """
    lib.uwsgi.async_queue_unused_ptr += 1
    lib.uwsgi.async_queue_unused[lib.uwsgi.async_queue_unused_ptr] = wsgi_req


@ffi.def_extern()
def uwsgi_asyncio_wait_read_hook(fd, timeout):
    try:
        uwsgi = lib.uwsgi
        wsgi_req = uwsgi.current_wsgi_req()
        loop = get_loop()
        loop.add_reader(fd, uwsgi_asyncio_hook_fd, wsgi_req)

        ob_timeout = loop.call_later(timeout, hook_timeout, wsgi_req)

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
        print_exc()
        return -1

    finally:
        # returns False if not added
        loop.remove_writer(fd)


@ffi.def_extern()
def uwsgi_asyncio_wait_write_hook(fd, timeout):
    try:
        wsgi_req = uwsgi.current_wsgi_req()
        loop = get_loop()
        loop.add_writer(fd, uwsgi_asyncio_hook_fd, wsgi_req)

        ob_timeout = loop.call_later(timeout, hook_timeout, wsgi_req)

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
        print_exc()
        return -1

    finally:
        loop.remove_writer(fd)


def find_first_available_wsgi_req():
    uwsgi = lib.uwsgi

    if uwsgi.async_queue_unused_ptr < 0:
        print("unused_ptr", uwsgi.async_queue_unused_ptr)
        return None

    wsgi_req = uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr]
    print("wsgi_req", wsgi_req)
    uwsgi.async_queue_unused_ptr -= 1
    return wsgi_req


def uwsgi_asyncio_request(wsgi_req, timed_out):
    try:
        uwsgi.wsgi_req = wsgi_req
        loop = get_loop()

        # original casts timeout to spare uwsgi_rb_timer*
        # maybe we could do a dict with the request or core id.
        handle = ffi.cast("void *", wsgi_req.async_timeout)
        ob_timeout = ffi.from_handle(handle)

        ob_timeout.cancel()

        wsgi_req.async_timeout = ffi.NULL

        if timed_out > 0:
            loop.remove_reader(wsgi_req.fd)
            raise IOError("timed out")  # goto end

        status = wsgi_req.socket.proto(wsgi_req)
        if status > 0:
            ob_timeout = loop.call_later(
                uwsgi.socket_timeout, uwsgi_asyncio_request, wsgi_req, 1
            )
            ob_timeout_handle = ffi.new_handle(ob_timeout)
            wsgi_req.async_timeout = ffi.cast(
                "struct uwsgi_rb_timer *", ob_timeout_handle
            )
            # goto again

        else:
            loop.remove_reader(wsgi_req.fd)

            if status == 0:
                # we call this two time... overengineering :(
                uwsgi.async_proto_fd_table[wsgi_req.fd] = ffi.NULL
                uwsgi.schedule_to_req()
                # goto again

        # again
        return None

    except:
        uwsgi.async_proto_fd_table[wsgi_req.fd] = ffi.NULL
        uwsgi_close_request(uwsgi.wsgi_req)
        free_req_queue(wsgi_req)
        print_exc()
        raise


def uwsgi_asyncio_accept(uwsgi_sock):
    uwsgi = lib.uwsgi
    wsgi_req = find_first_available_wsgi_req()
    if wsgi_req == ffi.NULL:
        lib.uwsgi_async_queue_is_full(lib.uwsgi_now())
        raise IOError("no available wsgi req")

    uwsgi.wsgi_req = wsgi_req
    lib.wsgi_req_setup(wsgi_req, wsgi_req.async_id, uwsgi_sock)
    uwsgi.workers[uwsgi.mywid].cores[wsgi_req.async_id].in_request = 1

    if lib.wsgi_req_simple_accept(wsgi_req, uwsgi_sock.fd):
        uwsgi.workers[uwsgi.mywid].cores[wsgi_req.async_id].in_request = 0
        free_req_queue(wsgi_req)
        raise IOError("simple_accept failed")

    wsgi_req.start_of_request = lib.uwsgi_micros()
    wsgi_req.start_of_request_in_sec = wsgi_req.start_of_request // 1000000

    # enter harakiri mode
    if uwsgi.harakiri_options.workers > 0:
        lib.set_harakiri(wsgi_req, uwsgi.harakiri_options.workers)

    uwsgi.async_proto_fd_table[wsgi_req.fd] = wsgi_req

    loop = get_loop()

    # add callback for protocol
    try:
        loop.add_reader(wsgi_req.id, uwsgi_asyncio_request, wsgi_req)
        ob_timeout = loop.call_later(
            uwsgi.socket_timeout, uwsgi_asyncio_request, wsgi_req, 1
        )
    except:
        loop.remove_reader(wsgi_req.fd)
        free_req_queue(wsgi_req)
        print_exce()

    # TODO keepalive
    ob_timeout_handle = ffi.new_handle(ob_timeout)
    wsgi_req.async_timeout = ffi.cast("struct uwsgi_rb_timer *", ob_timeout_handle)


def uwsgi_asyncio_hook_fd(wsgi_req):
    uwsgi = lib.uwsgi
    uwsgi.wsgi_req = wsgi_req
    uwsgi.schedule_to_req()


def uwsgi_asyncio_hook_timeout(wsgi_req):
    uwsgi = lib.uwsgi
    uwssgi.wsgi_req = wsgi_req
    uwsgi.wsgi_req.async_timed_out = 1
    uwsgi.schedule_to_req()


def uwssgi_asyncio_hook_fix(wsgi_req):
    uwsgi.wsgi_req = wsgi_req
    uwsgi.schedule_to_req()


@ffi.def_extern()
def uwsgi_asyncio_schedule_fix(wsgi_req):
    loop = get_loop()
    loop.call_soon(uwsgi_asyncio_hook_fix, wsgi_req)


@ffi.def_extern()
def asyncio_loop():
    """
    Set up asyncio.
    """

    if not uwsgi.has_threads and uwsgi.mywid == 1:
        lib.uwsgi_log(
            "!!! Running asyncio without threads IS NOT recommended, enable "
            "them with --enable-threads !!!\n"
        )

    if uwsgi.socket_timeout < 30:
        lib.uwsgi_log(
            "!!! Running asyncio with a socket-timeout lower than 30 seconds "
            "is not recommended, tune it with --socket-timeout !!!\n"
        )

    if not uwsgi.async_waiting_fd_table:
        uwsgi.async_waiting_fd_table = lib.uwsgi_calloc(
            ffi.sizeof("struct wsgi_request *") * uwsgi.max_fd
        )
    if not uwsgi.async_proto_fd_table:
        uwsgi.async_proto_fd_table = lib.uwsgi_calloc(
            ffi.sizeof("struct wsgi_request *") * uwsgi.max_fd
        )

    uwsgi.wait_write_hook = lib.uwsgi_asyncio_wait_write_hook
    uwsgi.wait_read_hook = lib.uwsgi_asyncio_wait_read_hook

    if getattr(uwsgi, "async") < 1:  # keyword
        lib.uwsgi_log("the async loop engine requires async mode (--async <n>)\n")
        raise SystemExit(1)

    if not uwsgi.schedule_to_main:
        lib.uwsgi_log(
            "*** DANGER *** async mode without coroutine/greenthread engine loaded !!!\n"
        )

    # call uwsgi_cffi_setup_greenlets() first:
    if not uwsgi.schedule_to_req:
        uwsgi.schedule_to_req = lib.async_schedule_to_req
    else:
        uwsgi.schedule_fix = lib.uwsgi_asyncio_schedule_fix

    loop = get_loop()
    uwsgi_sock = uwsgi.sockets[0]
    while uwsgi_sock != ffi.NULL:
        loop.add_reader(uwsgi_sock.fd, uwsgi_asyncio_accept, uwsgi_sock)
        uwsgi_sock = uwsgi_sock.next

    loop.run_forever()


def async_init():
    lib.uwsgi_register_loop(_ASYNCIO, lib.asyncio_loop)
