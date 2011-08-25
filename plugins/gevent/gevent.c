#include "../python/uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

struct option gevent_options[] = {
	{ 0, 0, 0, 0 }
};

#define GEVENT_SWITCH (void) python_call(uwsgi_gevent_switch, uwsgi_gevent_switch_args, 0, NULL)
#define GET_CURRENT_GREENLET python_call(gevent_current, gevent_current_args, 0, NULL)
#define free_req_queue uwsgi.async_queue_unused_ptr++; uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = uwsgi.wsgi_req

PyObject *uwsgi_gevent_switch = NULL;
PyObject *uwsgi_gevent_switch_args = NULL;
PyObject *uwsgi_gevent_pool = NULL;
PyObject *uwsgi_gevent_greenlet = NULL;
PyObject *uwsgi_gevent_spawn = NULL;
PyObject *uwsgi_greenlet_args = NULL;
PyObject *uwsgi_greenlet_locals = NULL;
PyObject *gevent_hub_loop = NULL;
PyObject *gevent_current = NULL;
PyObject *gevent_current_args = NULL;

PyObject* gevent_wait_io_and_switch(int fd, PyObject *greenlet_switch) {

	PyObject *watcher = PyObject_CallMethod(gevent_hub_loop, "io", "ii", fd, 1);
        if (!watcher) {
                PyErr_Print();
		return NULL; 
        }

	PyObject_CallMethod(watcher, "start", "O", greenlet_switch);

	return watcher;

}

PyObject *py_uwsgi_gevent_callback(PyObject * self, PyObject * args) {


	struct wsgi_request *wsgi_req = find_first_available_wsgi_req();

	if (wsgi_req == NULL) {
		uwsgi_log("async queue is full !!!\n");
		goto clear;
	}
	uwsgi.wsgi_req = wsgi_req;

	wsgi_req_setup(wsgi_req, wsgi_req->async_id, uwsgi.sockets );

	uwsgi.core[wsgi_req->async_id]->in_request = 1;

	gettimeofday(&wsgi_req->start_of_request, NULL);

	if (wsgi_req_simple_accept(wsgi_req, uwsgi.sockets->fd)) {
		uwsgi_close_request(wsgi_req);
		free_req_queue;
		goto clear;
	}

	
	PyTuple_SetItem(uwsgi_greenlet_args, 1, PyLong_FromLong((long)wsgi_req));

	(void) python_call(uwsgi_gevent_spawn, uwsgi_greenlet_args, 0, NULL);

clear:
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_gevent_greenlet(PyObject * self, PyObject * args) {

	PyObject *py_wsgi_req = PyTuple_GetItem(args, 0);
	struct wsgi_request *wsgi_req = (struct wsgi_request *) PyLong_AsLong(py_wsgi_req);
	int status ;

	PyObject *current_greenlet = GET_CURRENT_GREENLET;
	PyObject *greenlet_switch = PyObject_GetAttrString(current_greenlet, "switch");

	for(;;) {
		uwsgi.wsgi_req = wsgi_req;
		PyObject *watcher = gevent_wait_io_and_switch(wsgi_req->poll.fd, greenlet_switch);
		if (!watcher) {
			goto clear;
		}
		uwsgi.wsgi_req = wsgi_req;
		status = wsgi_req->socket->proto(wsgi_req);
		PyObject_CallMethod(watcher, "stop", NULL);
		if (status < 0) {
			goto clear;
		}
		else if (status == 0) {
			break;
		}
		
	}

	for(;;) {
		uwsgi.wsgi_req = wsgi_req;
		wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);
		if (wsgi_req->async_status <= UWSGI_OK) {
			goto clear;
		}
		GEVENT_SWITCH;
	}

clear:
	uwsgi_close_request(wsgi_req);

	uwsgi.wsgi_req = wsgi_req;

	free_req_queue;

	Py_INCREF(Py_None);
	return Py_None;


}

PyMethodDef uwsgi_gevent_callback_method[] = { {"uwsgi_gevent_callback", py_uwsgi_gevent_callback, METH_VARARGS, ""} };
PyMethodDef uwsgi_gevent_greenlet_method[] = { {"uwsgi_gevent_greenlet", py_uwsgi_gevent_greenlet, METH_VARARGS, ""} };


void gevent_loop() {

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;

	if (uwsgi.async < 2) {
		uwsgi_log("the gevent loop engine requires async mode (--async <n>)\n");
		exit(1);
	}


	PyObject *gevent_dict = get_uwsgi_pydict("gevent");
	if (!gevent_dict) {
		PyErr_Print();
		exit(1);
	}

	PyObject *gevent_version = PyDict_GetItemString(gevent_dict, "version_info");
	if (!gevent_version) {
		PyErr_Print();
		exit(1);
	}

	if (PyInt_AsLong(PyTuple_GetItem(gevent_version, 0)) < 1) {
		uwsgi_log("uWSGI requires at least gevent 1.x version\n");
		exit(1);
	}

	uwsgi_gevent_spawn = PyDict_GetItemString(gevent_dict, "spawn");
	if (!uwsgi_gevent_spawn) {
		PyErr_Print();
		exit(1);
	}

	uwsgi_gevent_switch = PyDict_GetItemString(gevent_dict, "sleep");
	if (!uwsgi_gevent_switch) {
		PyErr_Print();
		exit(1);
	}

	uwsgi_gevent_switch_args = PyTuple_New(0);
	Py_INCREF(uwsgi_gevent_switch_args);
	

	PyObject *gevent_get_hub = PyDict_GetItemString(gevent_dict, "get_hub");

	PyObject *gevent_hub = python_call(gevent_get_hub, PyTuple_New(0), 0, NULL);
	if (!gevent_hub) {
		PyErr_Print();
		exit(1);
	}

	gevent_current = PyDict_GetItemString(gevent_dict, "getcurrent");
	if (!gevent_current) {
		PyErr_Print();
		exit(1);
	}
	gevent_current_args = PyTuple_New(0);
	Py_INCREF(gevent_current_args);
	

	gevent_hub_loop = PyObject_GetAttrString(gevent_hub, "loop");
	if (!gevent_hub_loop) {

		PyErr_Print();
		exit(1);
	}


	PyObject *watcher = PyObject_CallMethod(gevent_hub_loop, "io", "ii", uwsgi_sock->fd, 1);
	if (!watcher) {
		PyErr_Print();
		exit(1);
	}


	PyObject *uwsgi_gevent_callback = PyCFunction_New(uwsgi_gevent_callback_method, NULL);
	Py_INCREF(uwsgi_gevent_callback);

	uwsgi_gevent_greenlet = PyCFunction_New(uwsgi_gevent_greenlet_method, NULL);
	Py_INCREF(uwsgi_gevent_greenlet);

	uwsgi_greenlet_args = PyTuple_New(2);
	PyTuple_SetItem(uwsgi_greenlet_args, 0, uwsgi_gevent_greenlet);



	PyObject_CallMethod(watcher, "start", "O", uwsgi_gevent_callback);

	if (PyObject_CallMethod(gevent_hub, "switch", NULL)) {
		PyErr_Print();
		exit(1);
	}

	uwsgi_log("the gevent Hub is no more :(\n");

}

int gevent_init() {

	uwsgi_register_loop( (char *) "gevent", gevent_loop);
	return 0;
}


struct uwsgi_plugin gevent_plugin = {

	.name = "gevent",
	.init = gevent_init,
	.options = gevent_options,
};
