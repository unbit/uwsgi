#include "../python/uwsgi_python.h"

/*

	python >= 3.4 asyncio (PEP 3156) loop engine

	EXPERIMENTAL !!!

	Author: Roberto De Ioris

*/

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

static struct uwsgi_asyncio {
	PyObject *mod;
	PyObject *loop;
	PyObject *request;
	PyObject *hook_fd;
	PyObject *hook_timeout;
	PyObject *hook_fix;
} uasyncio;

#define free_req_queue uwsgi.async_queue_unused_ptr++; uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = wsgi_req

static void uwsgi_opt_setup_asyncio(char *opt, char *value, void *null) {

	// set async mode
	uwsgi_opt_set_int(opt, value, &uwsgi.async);
	if (uwsgi.socket_timeout < 30) {
		uwsgi.socket_timeout = 30;
	}
	// set loop engine
	uwsgi.loop = "asyncio";

}

static struct uwsgi_option asyncio_options[] = {
        {"asyncio", required_argument, 0, "a shortcut enabling asyncio loop engine with the specified number of async cores and optimal parameters", uwsgi_opt_setup_asyncio, NULL, UWSGI_OPT_THREADS},
        {0, 0, 0, 0, 0, 0, 0},

};

static void gil_asyncio_get() {
	pthread_setspecific(up.upt_gil_key, (void *) PyGILState_Ensure());
}

static void gil_asyncio_release() {
	PyGILState_Release((PyGILState_STATE) pthread_getspecific(up.upt_gil_key));
}

static int uwsgi_asyncio_wait_read_hook(int fd, int timeout) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	if (PyObject_CallMethod(uasyncio.loop, "add_reader", "iOl", fd, uasyncio.hook_fd,(long) wsgi_req) == NULL) {
		goto error;
	}

	PyObject *ob_timeout = PyObject_CallMethod(uasyncio.loop, "call_later", "iOl", timeout, uasyncio.hook_timeout, (long)wsgi_req);
	if (!ob_timeout) {
		if (PyObject_CallMethod(uasyncio.loop, "remove_reader", "i", fd) == NULL) PyErr_Print();
		goto error;
	}
	// back to loop
	if (uwsgi.schedule_to_main) uwsgi.schedule_to_main(wsgi_req);
	// back from loop

	if (PyObject_CallMethod(uasyncio.loop, "remove_reader", "i", fd) == NULL) PyErr_Print();
	if (PyObject_CallMethod(ob_timeout, "cancel", NULL) == NULL) PyErr_Print();

	Py_DECREF(ob_timeout);

	if (wsgi_req->async_timed_out) return 0;

        return 1;

error:
	PyErr_Print();
	return -1;
}

static int uwsgi_asyncio_wait_write_hook(int fd, int timeout) {

        struct wsgi_request *wsgi_req = current_wsgi_req();

        if (PyObject_CallMethod(uasyncio.loop, "add_writer", "iOl", fd, uasyncio.hook_fd,(long) wsgi_req) == NULL) {
                goto error;
        }

        PyObject *ob_timeout = PyObject_CallMethod(uasyncio.loop, "call_later", "iOl", timeout, uasyncio.hook_timeout, (long)wsgi_req);
        if (!ob_timeout) {
		if (PyObject_CallMethod(uasyncio.loop, "remove_writer", "i", fd) == NULL) PyErr_Print();
                goto error;
        }
        // back to loop
        if (uwsgi.schedule_to_main) {
		uwsgi.schedule_to_main(wsgi_req);
	}
        // back from loop

        if (PyObject_CallMethod(uasyncio.loop, "remove_writer", "i", fd) == NULL) PyErr_Print();
	if (PyObject_CallMethod(ob_timeout, "cancel", NULL) == NULL) PyErr_Print();

        Py_DECREF(ob_timeout);

        if (wsgi_req->async_timed_out) return 0;

        return 1;

error:
        PyErr_Print();
        return -1;
}

static PyObject *py_uwsgi_asyncio_request(PyObject *self, PyObject *args) {
        long wsgi_req_ptr = 0;
	int timed_out = 0;
        if (!PyArg_ParseTuple(args, "l|i:uwsgi_asyncio_request", &wsgi_req_ptr, &timed_out)) {
		uwsgi_log_verbose("[BUG] invalid arguments for asyncio callback !!!\n");
		exit(1);
        }

        struct wsgi_request *wsgi_req = (struct wsgi_request *) wsgi_req_ptr;
	uwsgi.wsgi_req = wsgi_req;

	PyObject *ob_timeout = (PyObject *) wsgi_req->async_timeout;
	if (PyObject_CallMethod(ob_timeout, "cancel", NULL) == NULL) PyErr_Print();
	Py_DECREF(ob_timeout);
	// avoid mess when closing the request
	wsgi_req->async_timeout = NULL;

	if (timed_out > 0) {
		if (PyObject_CallMethod(uasyncio.loop, "remove_reader", "i", wsgi_req->fd) == NULL) PyErr_Print();
		goto end;
	}

	int status = wsgi_req->socket->proto(wsgi_req);
	if (status > 0) {
		ob_timeout = PyObject_CallMethod(uasyncio.loop, "call_later", "iOli", uwsgi.socket_timeout, uasyncio.request, wsgi_req_ptr, 1);
        	if (!ob_timeout) {
                	if (PyObject_CallMethod(uasyncio.loop, "remove_reader", "i", wsgi_req->fd) == NULL) PyErr_Print();
			goto end;
        	}
                // trick for reference counting
                wsgi_req->async_timeout = (struct uwsgi_rb_timer *) ob_timeout;
		goto again;
	}

	if (PyObject_CallMethod(uasyncio.loop, "remove_reader", "i", wsgi_req->fd) == NULL) {
		PyErr_Print();
		goto end;
	}

	if (status == 0) {
		// we call this two time... overengineering :(
		uwsgi.async_proto_fd_table[wsgi_req->fd] = NULL;
		uwsgi.schedule_to_req();
		goto again;
	}

end:
	uwsgi.async_proto_fd_table[wsgi_req->fd] = NULL;
	uwsgi_close_request(uwsgi.wsgi_req);	
	free_req_queue;
again:
	Py_INCREF(Py_None);
	return Py_None;
}


static PyObject *py_uwsgi_asyncio_accept(PyObject *self, PyObject *args) {
	long uwsgi_sock_ptr = 0;
	if (!PyArg_ParseTuple(args, "l:uwsgi_asyncio_accept", &uwsgi_sock_ptr)) {
                return NULL;
        }

	struct wsgi_request *wsgi_req = find_first_available_wsgi_req();

        if (wsgi_req == NULL) {
                uwsgi_async_queue_is_full(uwsgi_now());
                goto end;
        }

	uwsgi.wsgi_req = wsgi_req;
	struct uwsgi_socket *uwsgi_sock = (struct uwsgi_socket *) uwsgi_sock_ptr;

        // fill wsgi_request structure
        wsgi_req_setup(wsgi_req, wsgi_req->async_id, uwsgi_sock );

        // mark core as used
        uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 1;

        // accept the connection (since uWSGI 1.5 all of the sockets are non-blocking)
        if (wsgi_req_simple_accept(wsgi_req, uwsgi_sock->fd)) {
                // in case of errors (or thundering herd, just reset it)
                uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 0;
                free_req_queue;
                goto end;
        }

        wsgi_req->start_of_request = uwsgi_micros();
        wsgi_req->start_of_request_in_sec = wsgi_req->start_of_request/1000000;

        // enter harakiri mode
        if (uwsgi.harakiri_options.workers > 0) {
                set_harakiri(uwsgi.harakiri_options.workers);
        }

	uwsgi.async_proto_fd_table[wsgi_req->fd] = wsgi_req;

	// add callback for protocol
	if (PyObject_CallMethod(uasyncio.loop, "add_reader", "iOl", wsgi_req->fd, uasyncio.request, (long) wsgi_req) == NULL) {
		free_req_queue;
		PyErr_Print();
	}

	// add timeout
	PyObject *ob_timeout = PyObject_CallMethod(uasyncio.loop, "call_later", "iOli", uwsgi.socket_timeout, uasyncio.request, (long)wsgi_req, 1);
        if (!ob_timeout) {
		if (PyObject_CallMethod(uasyncio.loop, "remove_reader", "i", wsgi_req->fd) == NULL) PyErr_Print();
		free_req_queue;
        }
	else {
		// trick for reference counting
		wsgi_req->async_timeout = (struct uwsgi_rb_timer *) ob_timeout;
	}
end:
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_asyncio_hook_fd(PyObject *self, PyObject *args) {
	long wsgi_req_ptr = 0;
        if (!PyArg_ParseTuple(args, "l:uwsgi_asyncio_hook_fd", &wsgi_req_ptr)) {
                return NULL;
        }

	uwsgi.wsgi_req = (struct wsgi_request *) wsgi_req_ptr;
	uwsgi.schedule_to_req();

	Py_INCREF(Py_None);
        return Py_None;
}

PyObject *py_uwsgi_asyncio_hook_timeout(PyObject *self, PyObject *args) {
        long wsgi_req_ptr = 0;
        if (!PyArg_ParseTuple(args, "l", &wsgi_req_ptr)) {
                return NULL;
        }

        uwsgi.wsgi_req = (struct wsgi_request *) wsgi_req_ptr;
	uwsgi.wsgi_req->async_timed_out = 1;
        uwsgi.schedule_to_req();

        Py_INCREF(Py_None);
        return Py_None;
}

PyObject *py_uwsgi_asyncio_hook_fix(PyObject *self, PyObject *args) {
        long wsgi_req_ptr = 0;
        if (!PyArg_ParseTuple(args, "l", &wsgi_req_ptr)) {
                return NULL;
        }

        uwsgi.wsgi_req = (struct wsgi_request *) wsgi_req_ptr;
        uwsgi.schedule_to_req();

        Py_INCREF(Py_None);
        return Py_None;
}


PyMethodDef uwsgi_asyncio_accept_def[] = { {"uwsgi_asyncio_accept", py_uwsgi_asyncio_accept, METH_VARARGS, ""} };
PyMethodDef uwsgi_asyncio_request_def[] = { {"uwsgi_asyncio_request", py_uwsgi_asyncio_request, METH_VARARGS, ""} };
PyMethodDef uwsgi_asyncio_hook_fd_def[] = { {"uwsgi_asyncio_hook_fd", py_uwsgi_asyncio_hook_fd, METH_VARARGS, ""} };
PyMethodDef uwsgi_asyncio_hook_timeout_def[] = { {"uwsgi_asyncio_hook_timeout", py_uwsgi_asyncio_hook_timeout, METH_VARARGS, ""} };
PyMethodDef uwsgi_asyncio_hook_fix_def[] = { {"uwsgi_asyncio_hook_fix", py_uwsgi_asyncio_hook_fix, METH_VARARGS, ""} };

static void uwsgi_asyncio_schedule_fix(struct wsgi_request *wsgi_req) {
        PyObject *cb = PyObject_CallMethod(uasyncio.loop, "call_soon", "Ol", uasyncio.hook_fix, (long) wsgi_req);
	if (!cb) goto error;
	Py_DECREF(cb);
        return; 

error:
        PyErr_Print();
} 

static void asyncio_loop() {

	if (!uwsgi.has_threads && uwsgi.mywid == 1) {
		uwsgi_log("!!! Running asyncio without threads IS NOT recommended, enable them with --enable-threads !!!\n");
	}

	if (uwsgi.socket_timeout < 30) {
		uwsgi_log("!!! Running asyncio with a socket-timeout lower than 30 seconds is not recommended, tune it with --socket-timeout !!!\n");
	}

	if (!uwsgi.async_waiting_fd_table)
		uwsgi.async_waiting_fd_table = uwsgi_calloc(sizeof(struct wsgi_request *) * uwsgi.max_fd);
	if (!uwsgi.async_proto_fd_table)
        	uwsgi.async_proto_fd_table = uwsgi_calloc(sizeof(struct wsgi_request *) * uwsgi.max_fd);

	// get the GIL
	UWSGI_GET_GIL

	up.gil_get = gil_asyncio_get;
	up.gil_release = gil_asyncio_release;

	uwsgi.wait_write_hook = uwsgi_asyncio_wait_write_hook;
	uwsgi.wait_read_hook = uwsgi_asyncio_wait_read_hook;

	if (uwsgi.async < 2) {
		uwsgi_log("the asyncio loop engine requires async mode (--async <n>)\n");
		exit(1);
	}

	if (!uwsgi.schedule_to_main) {
                uwsgi_log("*** DANGER *** asyncio mode without coroutine/greenthread engine loaded !!!\n");
        }

	if (!uwsgi.schedule_to_req) {
		uwsgi.schedule_to_req = async_schedule_to_req_green;
	}
	else {
		uwsgi.schedule_fix = uwsgi_asyncio_schedule_fix;
	}

#ifndef PYTHREE
	PyObject *asyncio = PyImport_ImportModule("trollius");
#else
	PyObject *asyncio = PyImport_ImportModule("asyncio");
#endif
	if (!asyncio) uwsgi_pyexit;

	uasyncio.mod = asyncio;

	uasyncio.loop = PyObject_CallMethod(asyncio, "get_event_loop", NULL);
	if (!uasyncio.loop) uwsgi_pyexit;

	 // main greenlet waiting for connection (one greenlet per-socket)
        PyObject *asyncio_accept = PyCFunction_New(uwsgi_asyncio_accept_def, NULL);
	Py_INCREF(asyncio_accept);

	uasyncio.request = PyCFunction_New(uwsgi_asyncio_request_def, NULL);
	if (!uasyncio.request) uwsgi_pyexit;

	uasyncio.hook_fd = PyCFunction_New(uwsgi_asyncio_hook_fd_def, NULL);
	if (!uasyncio.hook_fd) uwsgi_pyexit;
	uasyncio.hook_timeout = PyCFunction_New(uwsgi_asyncio_hook_timeout_def, NULL);
	if (!uasyncio.hook_timeout) uwsgi_pyexit;
	uasyncio.hook_fix = PyCFunction_New(uwsgi_asyncio_hook_fix_def, NULL);
	if (!uasyncio.hook_fix) uwsgi_pyexit;

	Py_INCREF(uasyncio.request);
	Py_INCREF(uasyncio.hook_fd);
	Py_INCREF(uasyncio.hook_timeout);
	Py_INCREF(uasyncio.hook_fix);

	// call add_handler on each socket
	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
	while(uwsgi_sock) {
		if (PyObject_CallMethod(uasyncio.loop, "add_reader", "iOl", uwsgi_sock->fd, asyncio_accept, (long) uwsgi_sock) == NULL) {
			uwsgi_pyexit;
		}
		uwsgi_sock = uwsgi_sock->next;
	}	

	if (PyObject_CallMethod(uasyncio.loop, "run_forever", NULL) == NULL) {
		uwsgi_pyexit;
	}

	// never here ?
}

static void asyncio_init() {
	uwsgi_register_loop( (char *) "asyncio", asyncio_loop);
}


struct uwsgi_plugin asyncio_plugin = {
	.name = "asyncio",
	.options = asyncio_options,
	.on_load = asyncio_init,
};
