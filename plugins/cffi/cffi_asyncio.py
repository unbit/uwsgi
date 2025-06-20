"""
Direct port of plugins/asyncio.c
"""

import sys
import asyncio

from _uwsgi import ffi, lib

uwsgi = lib.uwsgi


def print(*values):
    lib.uwsgi_log(" ".join(str(v) for v in values).encode("utf-8") + b"\n")


def get_loop():
    return asyncio.get_event_loop()


# testing
def request_id():
    return (
        lib.uwsgi.workers[lib.uwsgi.mywid].cores[lib.uwsgi.wsgi_req.async_id].requests
    )


# keep alive
_ASYNCIO = ffi.new("char[]", "asyncio".encode("utf-8"))

timeout_handles = {}  # or array with # of cores?

ob_timeout_counter = 0


def store_ob_timeout(wsgi_req, ob_timeout):
    global ob_timeout_counter
    # TODO check if wsgi_req.async_id is consistent enough for us
    ob_timeout_counter += 1
    wsgi_req.async_timeout = ffi.cast("struct uwsgi_rb_timer *", ob_timeout_counter)
    timeout_handles[ob_timeout_counter] = ob_timeout


def get_ob_timeout(wsgi_req):
    ob_timeout_ = ffi.cast("ssize_t", wsgi_req.async_timeout)
    wsgi_req.async_timeout = ffi.NULL
    return timeout_handles.pop(ob_timeout_)


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
    #define free_req_queue uwsgi.async_queue_unused_ptr++; uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = wsgi_req
    """
    lib.uwsgi.async_queue_unused_ptr = lib.uwsgi.async_queue_unused_ptr + 1
    lib.uwsgi.async_queue_unused[lib.uwsgi.async_queue_unused_ptr] = wsgi_req
    print("free_req_queue", lib.uwsgi.async_queue_unused_ptr, wsgi_req)


@ffi.def_extern()
def uwsgi_asyncio_wait_read_hook(fd, timeout):
    print("enter read hook")
    wsgi_req = uwsgi.current_wsgi_req()
    loop = get_loop()
    loop.add_reader(fd, uwsgi_asyncio_hook_fd, wsgi_req)
    try:
        ob_timeout = loop.call_later(timeout, hook_timeout, wsgi_req)
        try:

            # to loop
            if uwsgi.schedule_to_main:
                print("wait_read_hook", fd)
                uwsgi.schedule_to_main(wsgi_req)
            else:
                print("no read hook", uwsgi.schedule_to_mani)
            # from loop
        finally:
            ob_timeout.cancel()

        if wsgi_req.async_timed_out:
            return 0

        return 1

    except:
        print_exc()
        return -1

    finally:
        # returns False if not added
        loop.remove_reader(fd)


@ffi.def_extern()
def uwsgi_asyncio_wait_write_hook(fd, timeout):
    print("enter write hook")
    wsgi_req = uwsgi.current_wsgi_req()
    loop = get_loop()
    loop.add_writer(fd, uwsgi_asyncio_hook_fd, wsgi_req)
    try:
        ob_timeout = loop.call_later(timeout, hook_timeout, wsgi_req)
        try:
            # to loop
            if uwsgi.schedule_to_main:
                print("wait_write_hook", fd)
                uwsgi.schedule_to_main(wsgi_req)
            # from loop

        finally:
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
    wsgi_req = lib.find_first_available_wsgi_req()
    print("accept wsgi_req", uwsgi.async_queue_unused_ptr, wsgi_req)
    return wsgi_req


def uwsgi_asyncio_request(wsgi_req, timed_out):
    try:
        loop = get_loop()
        uwsgi.wsgi_req = wsgi_req

        ob_timeout = get_ob_timeout(wsgi_req)
        ob_timeout.cancel()

        if timed_out > 0:
            loop.remove_reader(wsgi_req.fd)
            raise IOError("timed out")  # goto end

        status = wsgi_req.socket.proto(wsgi_req)
        print("status", status)

        if status > 0:
            ob_timeout = loop.call_later(
                uwsgi.socket_timeout, uwsgi_asyncio_request, wsgi_req, True
            )
            store_ob_timeout(wsgi_req, ob_timeout)
            # goto again
            print("again a", request_id())
            return None

        else:
            loop.remove_reader(wsgi_req.fd)

            if status == 0:
                # we call this two time... overengineering :(
                uwsgi.async_proto_fd_table[wsgi_req.fd] = ffi.NULL
                uwsgi.schedule_to_req()
                # goto again
                print("again b", request_id())
                return None

    except IOError:
        loop.remove_reader(wsgi_req.fd)
        print_exc()

    except:
        print("other exception")
        print_exc()

    # end
    r_id = request_id()
    print("normal request end {", r_id)
    uwsgi.async_proto_fd_table[wsgi_req.fd] = ffi.NULL
    lib.uwsgi_close_request(uwsgi.wsgi_req)
    free_req_queue(wsgi_req)
    print("} normal request end", r_id)


def uwsgi_asyncio_accept(uwsgi_sock):
    uwsgi = lib.uwsgi
    wsgi_req = find_first_available_wsgi_req()
    if wsgi_req == ffi.NULL:
        lib.uwsgi_async_queue_is_full(lib.uwsgi_now())
        print("queue is full")
        return None

    uwsgi.wsgi_req = wsgi_req
    lib.wsgi_req_setup(wsgi_req, wsgi_req.async_id, uwsgi_sock)
    uwsgi.workers[uwsgi.mywid].cores[wsgi_req.async_id].in_request = 1

    if lib.wsgi_req_simple_accept(wsgi_req, uwsgi_sock.fd):
        uwsgi.workers[uwsgi.mywid].cores[wsgi_req.async_id].in_request = 0
        free_req_queue(wsgi_req)
        print("no accept")
        return None

    wsgi_req.start_of_request = lib.uwsgi_micros()
    wsgi_req.start_of_request_in_sec = wsgi_req.start_of_request // 1000000

    # enter harakiri mode
    if uwsgi.harakiri_options.workers > 0:
        lib.set_harakiri(wsgi_req, uwsgi.harakiri_options.workers)

    uwsgi.async_proto_fd_table[wsgi_req.fd] = wsgi_req

    loop = get_loop()

    # add callback for protocol
    try:
        loop.add_reader(wsgi_req.fd, uwsgi_asyncio_request, wsgi_req, False)
        ob_timeout = loop.call_later(
            uwsgi.socket_timeout, uwsgi_asyncio_request, wsgi_req, True
        )
        store_ob_timeout(wsgi_req, ob_timeout)

    except:
        loop.remove_reader(wsgi_req.fd)
        free_req_queue(wsgi_req)
        print_exc()
        raise


def uwsgi_asyncio_hook_fd(wsgi_req):
    uwsgi = lib.uwsgi
    print("hook fd", wsgi_req.fd)
    uwsgi.wsgi_req = wsgi_req
    uwsgi.schedule_to_req()


def uwsgi_asyncio_hook_timeout(wsgi_req):
    uwsgi = lib.uwsgi
    print("timeout hook", wsgi_req.fd)
    uwssgi.wsgi_req = wsgi_req
    uwsgi.wsgi_req.async_timed_out = 1
    uwsgi.schedule_to_req()


def uwsgi_asyncio_hook_fix(wsgi_req):
    print("fix hook", wsgi_req.fd)
    uwsgi.wsgi_req = wsgi_req
    uwsgi.schedule_to_req()


@ffi.def_extern()
def uwsgi_asyncio_schedule_fix(wsgi_req):
    if wsgi_req:
        print("fix schedule", wsgi_req.fd)
    print("schedule_fix")
    loop = get_loop()
    loop.call_soon(uwsgi_asyncio_hook_fix, wsgi_req)


@ffi.def_extern()
def asyncio_loop():
    """
    Set up asyncio.
    """

    if not uwsgi.has_threads and uwsgi.mywid == 1:
        print(
            "!!! Running asyncio without threads IS NOT recommended, enable "
            "them with --enable-threads !!!\n"
        )

    if uwsgi.socket_timeout < 30:
        print(
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

    assert lib.uwsgi.wait_write_hook == lib.uwsgi_asyncio_wait_write_hook

    if getattr(uwsgi, "async") < 1:  # keyword
        print("the async loop engine requires async mode (--async <n>)\n")
        raise SystemExit(1)

    if not uwsgi.schedule_to_main:
        print(
            "*** DANGER *** async mode without coroutine/greenthread engine loaded !!!\n"
        )

    # call uwsgi_cffi_setup_greenlets() first:
    if not uwsgi.schedule_to_req:
        print("set schedule_to_req")
        uwsgi.schedule_to_req = lib.async_schedule_to_req
    else:
        print("set schedule_fix")
        uwsgi.schedule_fix = lib.uwsgi_asyncio_schedule_fix

    loop = get_loop()
    uwsgi_sock = uwsgi.sockets
    while uwsgi_sock != ffi.NULL:
        sockname = ffi.string(uwsgi_sock.name, uwsgi_sock.name_len).decode("utf-8")
        print(f"sock {sockname} fd {uwsgi_sock.fd}")
        loop.add_reader(uwsgi_sock.fd, uwsgi_asyncio_accept, uwsgi_sock)
        uwsgi_sock = uwsgi_sock.next

    loop.run_forever()


def async_init():
    lib.uwsgi_register_loop(_ASYNCIO, lib.asyncio_loop)
