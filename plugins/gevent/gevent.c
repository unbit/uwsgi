#include "../python/uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

struct option gevent_options[] = {
	{ 0, 0, 0, 0 }
};

#define GEVENT_SWITCH PyObject *gswitch = python_call(ugevent.greenlet_switch, ugevent.greenlet_switch_args, 0, NULL); Py_DECREF(gswitch)
#define GET_CURRENT_GREENLET python_call(ugevent.get_current, ugevent.get_current_args, 0, NULL)
#define free_req_queue uwsgi.async_queue_unused_ptr++; uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = uwsgi.wsgi_req

struct uwsgi_gevent {
	PyObject *greenlet_switch;
	PyObject *greenlet_switch_args;
	PyObject *get_current;
	PyObject *get_current_args;
	PyObject *hub;
	PyObject *hub_loop;
	PyObject *spawn;
	PyObject *greenlet_args;
} ugevent;



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

	// enter harakiri mode
        if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
                set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
        }

	if (wsgi_req_simple_accept(wsgi_req, uwsgi.sockets->fd)) {
		uwsgi_close_request(wsgi_req);
		free_req_queue;
		goto clear;
	}

	
	PyTuple_SetItem(ugevent.greenlet_args, 1, PyLong_FromLong((long)wsgi_req));

	PyObject *new_gl = python_call(ugevent.spawn, ugevent.greenlet_args, 0, NULL);
	Py_DECREF(new_gl);

clear:
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *uwsgi_gevent_wait(PyObject *watcher, PyObject *timer, PyObject *current) {

	PyObject *ret;

	// start the io watcher
	ret = PyObject_CallMethod(watcher, "start", "OO", current, watcher);
	if (!ret) return NULL;
	Py_DECREF(ret);

	// start the timeout handler
	ret = PyObject_CallMethod(timer, "start", "OO", current, timer);
	if (!ret) return NULL;
	Py_DECREF(ret);

	// pass control to the hub
	return PyObject_CallMethod(ugevent.hub, "switch", NULL);
}

PyObject *py_uwsgi_gevent_greenlet(PyObject * self, PyObject * args) {

	PyObject *ret;
	PyObject *py_wsgi_req = PyTuple_GetItem(args, 0);
	struct wsgi_request *wsgi_req = (struct wsgi_request *) PyLong_AsLong(py_wsgi_req);
	int status ;

	PyObject *current_greenlet = GET_CURRENT_GREENLET;
	PyObject *greenlet_switch = PyObject_GetAttrString(current_greenlet, "switch");

	uwsgi.wsgi_req = wsgi_req;

	PyObject *watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", wsgi_req->poll.fd, 1);
	if (!watcher) {
		goto clear1;
	}

	PyObject *timer = PyObject_CallMethod(ugevent.hub_loop, "timer", "i", uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
	if (!timer) {
		goto clear0;
	}

	for(;;) {
		PyObject *ret = uwsgi_gevent_wait(watcher, timer, greenlet_switch);
		if (!ret) goto clear_and_stop;

		uwsgi.wsgi_req = wsgi_req;

		// we can safely decref here as watcher and timer has got a +1 for start() method
		Py_DECREF(ret);
		if (ret == timer) {
			uwsgi_log( "timeout. skip request.\n");
			goto clear_and_stop;
		}
		else if (ret == watcher) {

			status = wsgi_req->socket->proto(wsgi_req);
			if (status < 0) {
				goto clear_and_stop;
			}
			else if (status == 0) {
				ret = PyObject_CallMethod(timer, "stop", NULL);
				if (ret) Py_DECREF(ret);

				ret = PyObject_CallMethod(watcher, "stop", NULL);
				if (ret) Py_DECREF(ret);
				break;
			}
		}
		else {
			uwsgi_log("unrecognized gevent event !!!\n");
			goto clear_and_stop;
		}

		ret = PyObject_CallMethod(timer, "stop", NULL);
		if (ret) Py_DECREF(ret);

		ret = PyObject_CallMethod(watcher, "stop", NULL);
		if (ret) Py_DECREF(ret);
		
	}

	for(;;) {
		uwsgi.wsgi_req = wsgi_req;
		wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);
		if (wsgi_req->async_status <= UWSGI_OK) {
			goto clear;
		}
		GEVENT_SWITCH;
	}

	goto clear;

clear_and_stop:

	ret = PyObject_CallMethod(timer, "stop", NULL);
	if (ret) Py_DECREF(ret);

	ret = PyObject_CallMethod(watcher, "stop", NULL);
	if (ret) Py_DECREF(ret);

clear:
	Py_DECREF(timer);
clear0:
	Py_DECREF(watcher);
clear1:
	Py_DECREF(greenlet_switch);
	Py_DECREF(current_greenlet);
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

	ugevent.spawn = PyDict_GetItemString(gevent_dict, "spawn");
	if (!ugevent.spawn) {
		PyErr_Print();
		exit(1);
	}

	ugevent.greenlet_switch = PyDict_GetItemString(gevent_dict, "sleep");
	if (!ugevent.greenlet_switch) {
		PyErr_Print();
		exit(1);
	}

	ugevent.greenlet_switch_args = PyTuple_New(0);
	Py_INCREF(ugevent.greenlet_switch_args);
	

	PyObject *gevent_get_hub = PyDict_GetItemString(gevent_dict, "get_hub");

	ugevent.hub = python_call(gevent_get_hub, PyTuple_New(0), 0, NULL);
	if (!ugevent.hub) {
		PyErr_Print();
		exit(1);
	}

	ugevent.get_current = PyDict_GetItemString(gevent_dict, "getcurrent");
	if (!ugevent.get_current) {
		PyErr_Print();
		exit(1);
	}
	ugevent.get_current_args = PyTuple_New(0);
	Py_INCREF(ugevent.get_current_args);
	

	ugevent.hub_loop = PyObject_GetAttrString(ugevent.hub, "loop");
	if (!ugevent.hub_loop) {

		PyErr_Print();
		exit(1);
	}


	PyObject *watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", uwsgi_sock->fd, 1);
	if (!watcher) {
		PyErr_Print();
		exit(1);
	}


	PyObject *uwsgi_gevent_callback = PyCFunction_New(uwsgi_gevent_callback_method, NULL);
	Py_INCREF(uwsgi_gevent_callback);

	PyObject *uwsgi_gevent_greenlet = PyCFunction_New(uwsgi_gevent_greenlet_method, NULL);
	Py_INCREF(uwsgi_gevent_greenlet);

	ugevent.greenlet_args = PyTuple_New(2);
	PyTuple_SetItem(ugevent.greenlet_args, 0, uwsgi_gevent_greenlet);



	PyObject_CallMethod(watcher, "start", "O", uwsgi_gevent_callback);

	if (!PyObject_CallMethod(ugevent.hub, "join", NULL)) {
		PyErr_Print();
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
