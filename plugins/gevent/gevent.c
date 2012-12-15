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
#define stop_the_watchers_and_clear stop_the_watchers\
                        Py_DECREF(current); Py_DECREF(current_greenlet);\
                        Py_DECREF(watcher);\
                        Py_DECREF(timer);


struct uwsgi_gevent {
	PyObject *greenlet_switch;
	PyObject *greenlet_switch_args;
	PyObject *get_current;
	PyObject *get_current_args;
	PyObject *hub;
	PyObject *hub_loop;
	PyObject *spawn;
	PyObject *signal;
	PyObject *greenlet_args;
	PyObject *signal_args;
	PyObject *my_signal_watcher;
	PyObject *signal_watcher;
	PyObject **watchers;
} ugevent;

void uwsgi_opt_setup_gevent(char *opt, char *value, void *null) {

	// set async mode
	uwsgi_opt_set_int(opt, value, &uwsgi.async);
	if (uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT] < 30) {
		uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT] = 30;
	}
	// set loop engine
	uwsgi.loop = "gevent";

}

struct uwsgi_option gevent_options[] = {
        {"gevent", required_argument, 0, "a shortcut enabling gevent loop engine with the specified number of async cores and optimal parameters", uwsgi_opt_setup_gevent, NULL, UWSGI_OPT_THREADS},
        {0, 0, 0, 0, 0, 0, 0},

};



PyObject *py_uwsgi_gevent_graceful(PyObject *self, PyObject *args) {

	uwsgi_log("Gracefully killing worker %d (pid: %d)...\n", uwsgi.mywid, uwsgi.mypid);
        uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
	
	uwsgi_log("stopping gevent signals watchers for worker %d (pid: %d)...\n", uwsgi.mywid, uwsgi.mypid);
	PyObject_CallMethod(ugevent.my_signal_watcher, "stop", NULL);
	PyObject_CallMethod(ugevent.signal_watcher, "stop", NULL);

	uwsgi_log("stopping gevent sockets watchers for worker %d (pid: %d)...\n", uwsgi.mywid, uwsgi.mypid);
	int i,count = uwsgi_count_sockets(uwsgi.sockets);
	for(i=0;i<count;i++) {
		PyObject_CallMethod(ugevent.watchers[i], "stop", NULL);
	}
	uwsgi_log("main gevent watchers stopped for worker %d (pid: %d)...\n", uwsgi.mywid, uwsgi.mypid);

	if (args) {
		exit(UWSGI_RELOAD_CODE);
	}

	Py_INCREF(Py_None);
	return Py_None;
}

void uwsgi_gevent_gbcw() {

	uwsgi_log("...The work of process %d is done. Seeya!\n", getpid());
	
	py_uwsgi_gevent_graceful(NULL, NULL);

	exit(0);

}

struct wsgi_request *uwsgi_gevent_current_wsgi_req(void) {
	PyObject *current_greenlet = GET_CURRENT_GREENLET;
	PyObject *py_wsgi_req = PyObject_GetAttrString(current_greenlet, "uwsgi_wsgi_req");
	// not in greenlet
	if (!py_wsgi_req) {
		PyErr_Clear();
		return NULL;
	}
	struct wsgi_request *wsgi_req = (struct wsgi_request*) PyLong_AsLong(py_wsgi_req);
	Py_DECREF(py_wsgi_req);
	Py_DECREF(current_greenlet);
	return wsgi_req;
}



PyObject *py_uwsgi_gevent_signal_handler(PyObject * self, PyObject * args) {

	int signal_socket;

	if (!PyArg_ParseTuple(args, "i:uwsgi_gevent_signal_handler", &signal_socket)) {
        	return NULL;
	}

	uwsgi_receive_signal(signal_socket, "worker", uwsgi.mywid);

	Py_INCREF(Py_None);
	return Py_None;
}

// the following two functions are called whenever an event is available in the signal queue
// they both trigger the same function
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

	// hack to retrieve the socket address
	PyObject *py_uwsgi_sock = PyTuple_GetItem(args, 0);
        struct uwsgi_socket *uwsgi_sock = (struct uwsgi_socket *) PyLong_AsLong(py_uwsgi_sock);
	struct wsgi_request *wsgi_req = NULL;
edge:
	wsgi_req = find_first_available_wsgi_req();

	if (wsgi_req == NULL) {
		uwsgi_log("async queue is full !!!\n");
		goto clear;
	}

	// fill wsgi_request structure
	wsgi_req_setup(wsgi_req, wsgi_req->async_id, uwsgi_sock );

	// mark core as used
	uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 1;

	wsgi_req->start_of_request = uwsgi_micros();
	wsgi_req->start_of_request_in_sec = wsgi_req->start_of_request/1000000;

	// enter harakiri mode
        if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
                set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
        }

	// accept the connection
	if (wsgi_req_simple_accept(wsgi_req, uwsgi_sock->fd)) {
		free_req_queue;
		if (uwsgi_sock->retry && uwsgi_sock->retry[wsgi_req->async_id]) {
			goto edge;
		}	
		goto clear;
	}

// on linux we need to set the socket in non-blocking as it is not inherited
#ifdef __linux__
	uwsgi_socket_nb(wsgi_req->poll.fd);
#endif

	// hack to easily pass wsgi_req pointer to the greenlet
	PyTuple_SetItem(ugevent.greenlet_args, 1, PyLong_FromLong((long)wsgi_req));

	// spawn the request greenlet
	PyObject *new_gl = python_call(ugevent.spawn, ugevent.greenlet_args, 0, NULL);
	Py_DECREF(new_gl);

	if (uwsgi_sock->edge_trigger) {
#ifdef UWSGI_DEBUG
		uwsgi_log("i am an edge triggered socket !!!\n");
#endif
		goto edge;
	}

clear:
	Py_INCREF(Py_None);
	return Py_None;
}

ssize_t uwsgi_gevent_hook_input_read(struct wsgi_request *wsgi_req, char *tmp_buf, size_t remains, size_t *tmp_pos) {

	/// create a watcher for reads
        PyObject *watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", wsgi_req->poll.fd, 1);
        if (!watcher) return -1;

        PyObject *timer = PyObject_CallMethod(ugevent.hub_loop, "timer", "i", uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
        if (!timer) {
                Py_DECREF(watcher);
                return -1;
        }

        PyObject *current_greenlet = GET_CURRENT_GREENLET;
        PyObject *current = PyObject_GetAttrString(current_greenlet, "switch");

        while(remains) {

		PyObject *ret = PyObject_CallMethod(watcher, "start", "OO", current, watcher);
        	if (!ret) {
                	stop_the_watchers_and_clear
                	return -1;
        	}
        	Py_DECREF(ret);

        	ret = PyObject_CallMethod(timer, "start", "OO", current, timer);
        	if (!ret) {
                	stop_the_watchers_and_clear
                	return -1;
        	}
        	Py_DECREF(ret);

        	ret = PyObject_CallMethod(ugevent.hub, "switch", NULL);
		wsgi_req->switches++;
        	if (!ret) {
                	stop_the_watchers_and_clear
                	return -1;
        	}
        	Py_DECREF(ret);

        	if (ret == timer) {
                	stop_the_watchers_and_clear
                	return 0;
        	}

		UWSGI_RELEASE_GIL;	
                ssize_t rlen = read(wsgi_req->poll.fd, tmp_buf+*tmp_pos, remains);
                if (rlen <= 0) {
			uwsgi_error("[uwsgi-gevent] read()");
                        UWSGI_GET_GIL
			stop_the_watchers_and_clear
                        return -1;
                }
                *tmp_pos += rlen;
                remains -= rlen;
		UWSGI_GET_GIL
		stop_the_watchers
        }

        return *tmp_pos;

}


ssize_t uwsgi_gevent_hook_input_readline(struct wsgi_request *wsgi_req, char *readline, size_t max_size) {
        ssize_t rlen = 0;

	/// create a watcher for reads
        PyObject *watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", wsgi_req->poll.fd, 1);
        if (!watcher) return -1;

        PyObject *timer = PyObject_CallMethod(ugevent.hub_loop, "timer", "i", uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
        if (!timer) {
                Py_DECREF(watcher);
		return -1;
        }

        PyObject *current_greenlet = GET_CURRENT_GREENLET;
        PyObject *current = PyObject_GetAttrString(current_greenlet, "switch");

	PyObject *ret = PyObject_CallMethod(watcher, "start", "OO", current, watcher);
        if (!ret) {
        	stop_the_watchers_and_clear
		return -1;
        }
        Py_DECREF(ret);

        ret = PyObject_CallMethod(timer, "start", "OO", current, timer);
        if (!ret) {
        	stop_the_watchers_and_clear
		return -1;
        }
        Py_DECREF(ret);

        ret = PyObject_CallMethod(ugevent.hub, "switch", NULL);
	wsgi_req->switches++;
        if (!ret) {
        	stop_the_watchers_and_clear
		return -1;
        }
        Py_DECREF(ret);

        if (ret == timer) {
        	stop_the_watchers_and_clear
		return 0;
        }

        UWSGI_RELEASE_GIL;
        if (max_size > 0 && max_size < UWSGI_PY_READLINE_BUFSIZE) {
                rlen = read(wsgi_req->poll.fd, readline, max_size);
        }
        else {
                rlen = read(wsgi_req->poll.fd, readline, UWSGI_PY_READLINE_BUFSIZE);
        }
        UWSGI_GET_GIL;
        stop_the_watchers_and_clear
        return rlen;
}


void uwsgi_gevent_nb_write(struct wsgi_request *wsgi_req, PyObject *str) {
	PyObject *ret;
	char *content = PyString_AsString(str);
	size_t content_len = PyString_Size(str);
	/// create a watcher for writes
	PyObject *watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", wsgi_req->poll.fd, 2);
	if (!watcher) goto error;

	PyObject *timer = PyObject_CallMethod(ugevent.hub_loop, "timer", "i", uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
        if (!timer) {
		Py_DECREF(watcher);
		goto error;
	}

	PyObject *current_greenlet = GET_CURRENT_GREENLET;
	PyObject *current = PyObject_GetAttrString(current_greenlet, "switch");

	char *ptr = content;
	size_t remains = content_len;

	// this is the main writing cycle, wait for writability and send...
	for(;;) {
		ret = PyObject_CallMethod(watcher, "start", "OO", current, watcher);
		if (!ret) {
			stop_the_watchers_and_clear
			goto error;
		}
		Py_DECREF(ret);

		ret = PyObject_CallMethod(timer, "start", "OO", current, timer);
		if (!ret) {
			stop_the_watchers_and_clear
			goto error;
		}
		Py_DECREF(ret);

		ret = PyObject_CallMethod(ugevent.hub, "switch", NULL);
		wsgi_req->switches++;
		if (!ret) {
			stop_the_watchers_and_clear
			goto error;
		}
		Py_DECREF(ret);

		if (ret == timer) {
			goto fail;
		}

		// ok we can write a chunk to the socket
		UWSGI_RELEASE_GIL
		ssize_t len = write(wsgi_req->poll.fd, ptr, remains);
		UWSGI_GET_GIL
		if (len > 0) {
			ptr += len;
			remains -= len;
			wsgi_req->response_size += len;
			if (remains == 0) {
				break;
			}
			stop_the_watchers
			continue;
		}
		else if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
				stop_the_watchers
				continue;
			}
		}

fail:
		stop_the_watchers_and_clear
		goto error;
	}
		
	stop_the_watchers
	Py_DECREF(current); Py_DECREF(current_greenlet);
	Py_DECREF(watcher);
        Py_DECREF(timer);
	return ;
	
error:
	if (PyErr_Occurred())
		PyErr_Print();
	wsgi_req->write_errors++;
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

	PyObject *py_wsgi_req = PyTuple_GetItem(args, 0);
	struct wsgi_request *wsgi_req = (struct wsgi_request *) PyLong_AsLong(py_wsgi_req);
	int status ;
	PyObject *ret = NULL, *watcher = NULL, *timer = NULL, *greenlet_switch = NULL;

	PyObject *current_greenlet = GET_CURRENT_GREENLET;
	// another hack to retrieve the current wsgi_req;
	PyObject_SetAttrString(current_greenlet, "uwsgi_wsgi_req", py_wsgi_req);

	// if in edge-triggered mode read from socket now !!!
	if (wsgi_req->socket->edge_trigger) {
		status = wsgi_req->socket->proto(wsgi_req);
		if (status < 0) {
			goto clear2;
		}
		goto request;
	}

	// create a watcher for request socket
	watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", wsgi_req->poll.fd, 1);
	if (!watcher) goto clear1;

	// a timer to implement timeout (thanks Denis)
	timer = PyObject_CallMethod(ugevent.hub_loop, "timer", "i", uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
	if (!timer) goto clear0;

	greenlet_switch = PyObject_GetAttrString(current_greenlet, "switch");

	for(;;) {
		// wait for data in the socket
		ret = uwsgi_gevent_wait(watcher, timer, greenlet_switch);
		wsgi_req->switches++;
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

request:
	for(;;) {
		wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);
		if (wsgi_req->async_status <= UWSGI_OK) {
			goto clear;
		}
		wsgi_req->switches++;
		// switch after each yield
		GEVENT_SWITCH;
	}

	goto clear;

clear_and_stop:

	stop_the_watchers;

clear:
	if (wsgi_req->socket->edge_trigger) goto clear2;
	Py_DECREF(timer);
clear0:
	Py_DECREF(watcher);
clear1:
	Py_DECREF(greenlet_switch);
clear2:
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
PyMethodDef uwsgi_gevent_unix_signal_handler_def[] = { {"uwsgi_gevent_unix_signal_handler", py_uwsgi_gevent_graceful, METH_VARARGS, ""} };

void gil_gevent_get() {
	pthread_setspecific(up.upt_gil_key, (void *) PyGILState_Ensure());
}

void gil_gevent_release() {
	PyGILState_Release((PyGILState_STATE) pthread_getspecific(up.upt_gil_key));
}

void gevent_loop() {

	if (!uwsgi.has_threads && uwsgi.mywid == 1) {
		uwsgi_log("!!! Running gevent without threads IS NOT recommended, enable them with --enable-threads !!!\n");
	}

	if (uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT] < 30) {
		uwsgi_log("!!! Running gevent with a socket-timeout lower than 30 seconds is not recommended, tune it with --socket-timeout !!!\n");
	}

	// get the GIL
	UWSGI_GET_GIL

	up.gil_get = gil_gevent_get;
	up.gil_release = gil_gevent_release;

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;

	if (uwsgi.async < 2) {
		uwsgi_log("the gevent loop engine requires async mode (--async <n>)\n");
		exit(1);
	}

	uwsgi.current_wsgi_req = uwsgi_gevent_current_wsgi_req;
	up.hook_write_string =  uwsgi_gevent_nb_write;
	up.hook_wsgi_input_read =  uwsgi_gevent_hook_input_read;
	up.hook_wsgi_input_readline =  uwsgi_gevent_hook_input_readline;

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

	ugevent.signal = PyDict_GetItemString(gevent_dict, "signal");
	if (!ugevent.signal) uwsgi_pyexit;

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

	// main greenlet waiting for connection (one greenlet per-socket)
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

		ugevent.signal_watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", uwsgi.signal_socket, 1);
        	if (!ugevent.signal_watcher) uwsgi_pyexit;

		ugevent.my_signal_watcher = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", uwsgi.my_signal_socket, 1);
        	if (!ugevent.my_signal_watcher) uwsgi_pyexit;

		PyObject *uwsgi_greenlet_signal = PyCFunction_New(uwsgi_gevent_signal_def, NULL);
        	Py_INCREF(uwsgi_greenlet_signal);

		PyObject *uwsgi_greenlet_my_signal = PyCFunction_New(uwsgi_gevent_my_signal_def, NULL);
        	Py_INCREF(uwsgi_greenlet_my_signal);

		PyObject *uwsgi_greenlet_signal_handler = PyCFunction_New(uwsgi_gevent_signal_handler_def, NULL);
        	Py_INCREF(uwsgi_greenlet_signal_handler);

		ugevent.signal_args = PyTuple_New(2);
		PyTuple_SetItem(ugevent.signal_args, 0, uwsgi_greenlet_signal_handler);

		// start the two signal watchers
		if (!PyObject_CallMethod(ugevent.signal_watcher, "start", "O", uwsgi_greenlet_signal)) uwsgi_pyexit;
		if (!PyObject_CallMethod(ugevent.my_signal_watcher, "start", "O", uwsgi_greenlet_my_signal)) uwsgi_pyexit;

	}

	// start a greenlet for each socket
	ugevent.watchers = uwsgi_malloc(sizeof(PyObject *) * uwsgi_count_sockets(uwsgi.sockets));
	int i = 0;
	while(uwsgi_sock) {
		// this is the watcher for server socket
		ugevent.watchers[i] = PyObject_CallMethod(ugevent.hub_loop, "io", "ii", uwsgi_sock->fd, 1);
		if (!ugevent.watchers[i]) uwsgi_pyexit;
	
		// start the main greenlet
		PyObject_CallMethod(ugevent.watchers[i], "start", "Ol", uwsgi_gevent_main,(long)uwsgi_sock);
		uwsgi_sock = uwsgi_sock->next;
		i++;
	}

	// patch goodbye_cruel_world
	uwsgi.gbcw_hook = uwsgi_gevent_gbcw;

	// map SIGHUP with gevent.signal
	PyObject *ge_signal_tuple = PyTuple_New(2);
	PyTuple_SetItem(ge_signal_tuple, 0, PyInt_FromLong(SIGHUP));
	PyObject *uwsgi_gevent_unix_signal_handler = PyCFunction_New(uwsgi_gevent_unix_signal_handler_def, NULL);
        Py_INCREF(uwsgi_gevent_unix_signal_handler);
	PyTuple_SetItem(ge_signal_tuple, 1, uwsgi_gevent_unix_signal_handler);

	python_call(ugevent.signal, ge_signal_tuple, 0, NULL);

	if (!PyObject_CallMethod(ugevent.hub, "join", NULL)) {
		PyErr_Print();
	}

	if (uwsgi.workers[uwsgi.mywid].manage_next_request == 0) {
		uwsgi_log("goodbye to the gevent Hub on worker %d (pid: %d)\n", uwsgi.mywid, uwsgi.mypid);
		exit(UWSGI_RELOAD_CODE);
	}

	uwsgi_log("the gevent Hub is no more :(\n");

}

void gevent_init() {

	uwsgi_register_loop( (char *) "gevent", gevent_loop);
}


struct uwsgi_plugin gevent_plugin = {

	.name = "gevent",
	.options = gevent_options,
	.on_load = gevent_init,
};
