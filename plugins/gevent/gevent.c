#include "../python/uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

#define GEVENT_SWITCH PyObject *gswitch = python_call(ugevent.greenlet_switch, ugevent.greenlet_switch_args, 0, NULL); Py_DECREF(gswitch)
#define GET_CURRENT_GREENLET python_call(ugevent.get_current, ugevent.get_current_args, 0, NULL)
#define free_req_queue uwsgi.async_queue_unused_ptr++; uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = wsgi_req
#define stop_the_watchers ret = PyObject_CallMethod(timer, "stop", NULL);\
                          if (ret) { Py_DECREF(ret); }\
                          ret = PyObject_CallMethod(watcher, "stop", NULL);\
                          if (ret) { Py_DECREF(ret); }

struct uwsgi_gevent {
	PyObject *greenlet_switch;
	PyObject *greenlet_switch_args;
	PyObject *get_current;
	PyObject *get_current_args;
	PyObject *hub;
	PyObject *hub_loop;
	PyObject *spawn;
	PyObject *greenlet_args;
	PyObject *signal_args;
} ugevent;


struct wsgi_request *uwsgi_gevent_current_wsgi_req(void) {
	PyObject *current_greenlet = GET_CURRENT_GREENLET;
	PyObject *py_wsgi_req = PyObject_GetAttrString(current_greenlet, "uwsgi_wsgi_req");
	return (struct wsgi_request*) PyLong_AsLong(py_wsgi_req);
}



PyObject *py_uwsgi_gevent_signal_handler(PyObject * self, PyObject * args) {

	uint8_t uwsgi_signal;
	int signal_socket;

	if (!PyArg_ParseTuple(args, "i:uwsgi_gevent_signal_handler", &signal_socket)) {
        	return NULL;
	}

	if (read(signal_socket, &uwsgi_signal, 1) <= 0) {
        	if (uwsgi.no_orphans) {
                	uwsgi_log_verbose("uWSGI worker %d screams: UAAAAAAH my master died, i will follow him...\n", uwsgi.mywid);
                        end_me(0);
                }
		// close the socket to end the mess...from now on the worker is alone (no master)
                else close(signal_socket);
        }
        else {
#ifdef UWSGI_DEBUG
        	uwsgi_log_verbose("master sent signal %d to worker %d\n", uwsgi_signal, uwsgi.mywid);
#endif
		if (uwsgi_signal_handler(uwsgi_signal)) {
                	uwsgi_log_verbose("error managing signal %d on worker %d\n", uwsgi_signal, uwsgi.mywid);
                }
        }

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_gevent_signal(PyObject * self, PyObject * args) {

	PyTuple_SetItem(ugevent.signal_args, 1, PyInt_FromLong(uwsgi.signal_socket));

	// spawn the signal_handler greenlet
        PyObject *new_gl = python_call(ugevent.spawn, ugevent.signal_args, 0, NULL);
        Py_DECREF(new_gl);

	Py_INCREF(Py_None);
	return Py_None;
	
}

// yes copy&paste no-DRY for me :P
PyObject *py_uwsgi_gevent_my_signal(PyObject * self, PyObject * args) {

	PyTuple_SetItem(ugevent.signal_args, 1, PyInt_FromLong(uwsgi.my_signal_socket));

	// spawn the signal_handler greenlet
        PyObject *new_gl = python_call(ugevent.spawn, ugevent.signal_args, 0, NULL);
        Py_DECREF(new_gl);

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *py_uwsgi_gevent_main(PyObject * self, PyObject * args) {


	struct wsgi_request *wsgi_req = find_first_available_wsgi_req();

	if (wsgi_req == NULL) {
		uwsgi_log("async queue is full !!!\n");
		goto clear;
	}

	// fill wsgi_request structure
	wsgi_req_setup(wsgi_req, wsgi_req->async_id, uwsgi.sockets );

	// mark core as used
	uwsgi.core[wsgi_req->async_id]->in_request = 1;

	gettimeofday(&wsgi_req->start_of_request, NULL);

	// enter harakiri mode
        if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
                set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
        }

	// accept the connection
	if (wsgi_req_simple_accept(wsgi_req, uwsgi.sockets->fd)) {
		free_req_queue;
		goto clear;
	}

	// hack to easily pass wsgi_req pointer to the greenlet
	PyTuple_SetItem(ugevent.greenlet_args, 1, PyLong_FromLong((long)wsgi_req));

	// spawn the request greenlet
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

PyObject *py_uwsgi_gevent_request(PyObject * self, PyObject * args) {

	PyObject *ret;
	PyObject *py_wsgi_req = PyTuple_GetItem(args, 0);
	struct wsgi_request *wsgi_req = (struct wsgi_request *) PyLong_AsLong(py_wsgi_req);
	int status ;

	PyObject *current_greenlet = GET_CURRENT_GREENLET;
	// another hack to retrieve the current wsgi_req;
	PyObject_SetAttrString(current_greenlet, "uwsgi_wsgi_req", py_wsgi_req);
	PyObject *greenlet_switch = PyObject_GetAttrString(current_greenlet, "switch");

	// create a watcher for request socket
	PyObject *watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", wsgi_req->poll.fd, 1);
	if (!watcher) goto clear1;

	// a timer to implement timeoit (thanks Denis)
	PyObject *timer = PyObject_CallMethod(ugevent.hub_loop, "timer", "i", uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
	if (!timer) goto clear0;

	for(;;) {
		// wait for data in the socket
		PyObject *ret = uwsgi_gevent_wait(watcher, timer, greenlet_switch);
		if (!ret) goto clear_and_stop;

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
				stop_the_watchers;
				break;
			}
		}
		else {
			uwsgi_log("unrecognized gevent event !!!\n");
			goto clear_and_stop;
		}

		stop_the_watchers;
	}

	for(;;) {
		wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);
		if (wsgi_req->async_status <= UWSGI_OK) {
			goto clear;
		}
		// switch after each yield
		GEVENT_SWITCH;
	}

	goto clear;

clear_and_stop:

	stop_the_watchers;

clear:
	Py_DECREF(timer);
clear0:
	Py_DECREF(watcher);
clear1:
	Py_DECREF(greenlet_switch);
	Py_DECREF(current_greenlet);
	uwsgi_close_request(wsgi_req);

	free_req_queue;

	Py_INCREF(Py_None);
	return Py_None;


}

PyMethodDef uwsgi_gevent_main_def[] = { {"uwsgi_gevent_main", py_uwsgi_gevent_main, METH_VARARGS, ""} };
PyMethodDef uwsgi_gevent_request_def[] = { {"uwsgi_gevent_request", py_uwsgi_gevent_request, METH_VARARGS, ""} };
PyMethodDef uwsgi_gevent_signal_def[] = { {"uwsgi_gevent_signal", py_uwsgi_gevent_signal, METH_VARARGS, ""} };
PyMethodDef uwsgi_gevent_my_signal_def[] = { {"uwsgi_gevent_my_signal", py_uwsgi_gevent_my_signal, METH_VARARGS, ""} };
PyMethodDef uwsgi_gevent_signal_handler_def[] = { {"uwsgi_gevent_signal_handler", py_uwsgi_gevent_signal_handler, METH_VARARGS, ""} };


void gevent_loop() {

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;

	if (uwsgi.async < 2) {
		uwsgi_log("the gevent loop engine requires async mode (--async <n>)\n");
		exit(1);
	}

	uwsgi.current_wsgi_req = uwsgi_gevent_current_wsgi_req;

	PyObject *gevent_dict = get_uwsgi_pydict("gevent");
	if (!gevent_dict) uwsgi_pyexit;

	PyObject *gevent_version = PyDict_GetItemString(gevent_dict, "version_info");
	if (!gevent_version) uwsgi_pyexit;

	if (PyInt_AsLong(PyTuple_GetItem(gevent_version, 0)) < 1) {
		uwsgi_log("uWSGI requires at least gevent 1.x version\n");
		exit(1);
	}

	ugevent.spawn = PyDict_GetItemString(gevent_dict, "spawn");
	if (!ugevent.spawn) uwsgi_pyexit;

	ugevent.greenlet_switch = PyDict_GetItemString(gevent_dict, "sleep");
	if (!ugevent.greenlet_switch) uwsgi_pyexit;

	ugevent.greenlet_switch_args = PyTuple_New(0);
	Py_INCREF(ugevent.greenlet_switch_args);
	

	PyObject *gevent_get_hub = PyDict_GetItemString(gevent_dict, "get_hub");

	ugevent.hub = python_call(gevent_get_hub, PyTuple_New(0), 0, NULL);
	if (!ugevent.hub) uwsgi_pyexit;

	ugevent.get_current = PyDict_GetItemString(gevent_dict, "getcurrent");
	if (!ugevent.get_current) uwsgi_pyexit;

	ugevent.get_current_args = PyTuple_New(0);
	Py_INCREF(ugevent.get_current_args);
	

	ugevent.hub_loop = PyObject_GetAttrString(ugevent.hub, "loop");
	if (!ugevent.hub_loop) uwsgi_pyexit;

	// this is the watcher for server socket
	PyObject *watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", uwsgi_sock->fd, 1);
	if (!watcher) uwsgi_pyexit;

	// main greenlet waiting for connection
	PyObject *uwsgi_gevent_main = PyCFunction_New(uwsgi_gevent_main_def, NULL);
	Py_INCREF(uwsgi_gevent_main);

	// greenlet to run at each request
	PyObject *uwsgi_request_greenlet = PyCFunction_New(uwsgi_gevent_request_def, NULL);
	Py_INCREF(uwsgi_request_greenlet);

	// pre-fill the greenlet args
	ugevent.greenlet_args = PyTuple_New(2);
	PyTuple_SetItem(ugevent.greenlet_args, 0, uwsgi_request_greenlet);

	if (uwsgi.signal_socket > -1) {
		// and these are the watcher for signal sockets

		PyObject *signal_watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", uwsgi.signal_socket, 1);
        	if (!signal_watcher) uwsgi_pyexit;

		PyObject *my_signal_watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", uwsgi.my_signal_socket, 1);
        	if (!my_signal_watcher) uwsgi_pyexit;

		PyObject *uwsgi_greenlet_signal = PyCFunction_New(uwsgi_gevent_signal_def, NULL);
        	Py_INCREF(uwsgi_greenlet_signal);

		PyObject *uwsgi_greenlet_my_signal = PyCFunction_New(uwsgi_gevent_my_signal_def, NULL);
        	Py_INCREF(uwsgi_greenlet_my_signal);

		PyObject *uwsgi_greenlet_signal_handler = PyCFunction_New(uwsgi_gevent_signal_handler_def, NULL);
        	Py_INCREF(uwsgi_greenlet_signal_handler);

		ugevent.signal_args = PyTuple_New(2);
		PyTuple_SetItem(ugevent.signal_args, 0, uwsgi_greenlet_signal_handler);

		// start the two signal watchers
		if (!PyObject_CallMethod(signal_watcher, "start", "O", uwsgi_greenlet_signal)) uwsgi_pyexit;
		if (!PyObject_CallMethod(my_signal_watcher, "start", "O", uwsgi_greenlet_my_signal)) uwsgi_pyexit;

	}
	
	// start the main greenlet
	PyObject_CallMethod(watcher, "start", "O", uwsgi_gevent_main);

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
};
