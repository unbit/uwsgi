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
        print_exc()
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
            print_exc()
            return -1

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


def find_first_available_wsgi_req():
    if uwsgi.async_queue_unused_ptr < 0:
        return None

    wsgi_req = uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr]
    uwsgi.async_queue_unused_ptr -= 1
    return wsgi_req


def uwsgi_asyncio_request(wsgi_req, timed_out):

    uwsgi.wsgi_req = wsgi_req
    loop = get_loop()

    # original casts timeout to spare uwsgi_rb_timer*
    handle = ffi.cast("void *", wsgi_req.async_timeout)
    ob_timeout = ffi.from_handle(handle)

    wsgi_req.async_timeout = ffi.NULL

    if timed_out > 0:
        loop.remove_reader(wsgi_req.fd)
        raise IOError("timed out")

    status = wsgi_req.socket.proto(wsgi_req)
    if status > 0:
        loop.call_later(uwsgi.socket_timeout, uwsgi_asyncio_request, wsgi_req, 1)

    # ...


# static PyObject *py_uwsgi_asyncio_request(PyObject *self, PyObject *args) {
#   long wsgi_req_ptr = 0;
#   int timed_out = 0;
#   if (!PyArg_ParseTuple(args, "l|i:uwsgi_asyncio_request", &wsgi_req_ptr,
#                         &timed_out)) {
#     uwsgi_log_verbose("[BUG] invalid arguments for asyncio callback !!!\n");
#     exit(1);
#   }

#   struct wsgi_request *wsgi_req = (struct wsgi_request *)wsgi_req_ptr;
#   uwsgi.wsgi_req = wsgi_req;

#   PyObject *ob_timeout = (PyObject *)wsgi_req->async_timeout;
#   if (PyObject_CallMethod(ob_timeout, "cancel", NULL) == NULL)
#     PyErr_Print();
#   Py_DECREF(ob_timeout);
#   // avoid mess when closing the request
#   wsgi_req->async_timeout = NULL;

#   if (timed_out > 0) {
#     if (PyObject_CallMethod(uasyncio.loop, "remove_reader", "i",
#                             wsgi_req->fd) == NULL)
#       PyErr_Print();
#     goto end;
#   }

#   int status = wsgi_req->socket->proto(wsgi_req);
#   if (status > 0) {
#     ob_timeout = PyObject_CallMethod(uasyncio.loop, "call_later", "iOli",
#                                      uwsgi.socket_timeout, uasyncio.request,
#                                      wsgi_req_ptr, 1);
#     if (!ob_timeout) {
#       if (PyObject_CallMethod(uasyncio.loop, "remove_reader", "i",
#                               wsgi_req->fd) == NULL)
#         PyErr_Print();
#       goto end;
#     }
#     // trick for reference counting
#     wsgi_req->async_timeout = (struct uwsgi_rb_timer *)ob_timeout;
#     goto again;
#   }

#   if (PyObject_CallMethod(uasyncio.loop, "remove_reader", "i", wsgi_req->fd) ==
#       NULL) {
#     PyErr_Print();
#     goto end;
#   }

#   if (status == 0) {
#     // we call this two time... overengineering :(
#     uwsgi.async_proto_fd_table[wsgi_req->fd] = NULL;
#     uwsgi.schedule_to_req();
#     goto again;
#   }

# end:
#   uwsgi.async_proto_fd_table[wsgi_req->fd] = NULL;
#   uwsgi_close_request(uwsgi.wsgi_req);
#   free_req_queue;
# again:
#   Py_INCREF(Py_None);
#   return Py_None;
# }


def uwsgi_asyncio_accept(uwsgi_sock):
    uwsgi = lib.uwsgi
    wsgi_req = find_first_available_wsgi_req()
    if wsgi_req == ffi.NULL:
        lib.uwsgi_async_queue_is_full(lib.uwsgi_now())
        # goto end

    uwsgi.wsgi_req = wsgi_req
    lib.wsgi_req_setup(wsgi_req, wsgi_req.async_id, uwsgi_sock)
    uwsgi.workers[uwsgi.mywid].cores[wsgi_req.async_id].in_request = 1

    if lib.wsgi_req_simple_accept(wsgi_req, uwsgi_sock.fd):
        uwsgi.workers[uwsgi.mywid].cores[wsgi_req.async_id].in_request = 0
        free_req_queue(wsgi_req)
        # goto end

    wsgi_req.start_of_request = lib.uwsgi_micros()
    wsgi_req.start_of_request_in_sec = wsgi_req.start_of_request / 1000000

    # enter harakiri mode
    if uwsgi.harakiri_options.workers > 0:
        set_harakiri(wsgi_req, uwsgi.harakiri_options.workers)

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

    uwsgi.wait_write_hook = lib.uwsgi_asyncio_wait_write_hook
    uwsgi.wait_read_hook = lib.uwsgi_asyncio_wait_read_hook

    if getattrr(uwsgi, "async") < 1:  # keyword
        lib.uwsgi_log("the async loop engine requires async mode (--async <n>)\n")
        raise SystemExit(1)

    if not uwsgi.schedule_to_main:
        lib.uwsgi_log(
            "*** DANGER *** asyncio mode without coroutine/greenthread "
            "engine loaded !!!\n"
        )

    if uwsgi.signal_socket > -1:
        lib.event_queue_add_fd_read(uwsgi.async_queue, uwsgi.signal_socket)
        lib.event_queue_add_fd_read(uwsgi.async_queue, uwsgi.my_signal_socket)

    if not uwsgi.schedule_to_main:
        lib.uwsgi_log(
            "*** DANGER *** async mode without coroutine/greenthread engine loaded !!!\n"
        )

    if not uwsgi.schedule_to_req:
        uwsgi.schedule_to_req = lib.async_schedule_to_req
    else:
        uwsgi.schedule_fix = lib.uwsgi_asyncio_schedule_fix

    # TODO


def async_init():
    lib.uwsgi_register_loop(_ASYNCIO, asyncio_loop)
