#include "uwsgi.h"

void *uwsgi_request_subhandler_web3(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {

	PyObject *zero, *wsgi_socket;


	wsgi_socket = PyFile_FromFile(wsgi_req->async_post, "web3_input", "r", NULL);
	PyDict_SetItemString(wsgi_req->async_environ, "web3.input", wsgi_socket);
	Py_DECREF(wsgi_socket);

	zero = PyTuple_New(2);
	PyTuple_SetItem(zero, 0, PyInt_FromLong(1));
	PyTuple_SetItem(zero, 1, PyInt_FromLong(0));
	PyDict_SetItemString(wsgi_req->async_environ, "web3.version", zero);
	Py_DECREF(zero);

	zero = PyFile_FromFile(stderr, "web3_input", "w", NULL);
	PyDict_SetItemString(wsgi_req->async_environ, "web3.errors", zero);
	Py_DECREF(zero);

	PyDict_SetItemString(wsgi_req->async_environ, "web3.run_once", Py_False);

	PyDict_SetItemString(wsgi_req->async_environ, "web3.multithread", Py_False);
	if (uwsgi->numproc == 1) {
		PyDict_SetItemString(wsgi_req->async_environ, "web3.multiprocess", Py_False);
	}
	else {
		PyDict_SetItemString(wsgi_req->async_environ, "web3.multiprocess", Py_True);
	}

	if (wsgi_req->scheme_len > 0) {
		zero = PyString_FromStringAndSize(wsgi_req->scheme, wsgi_req->scheme_len);
	}
	else if (wsgi_req->https_len > 0) {
		if (!strncasecmp(wsgi_req->https, "on", 2) || wsgi_req->https[0] == '1') {
			zero = PyString_FromString("https");
		}
		else {
			zero = PyString_FromString("http");
		}
	}
	else {
		zero = PyString_FromString("http");
	}
	PyDict_SetItemString(wsgi_req->async_environ, "web3.url_scheme", zero);
	Py_DECREF(zero);


	wsgi_req->async_app = wi->wsgi_callable ;

	PyDict_SetItemString(uwsgi->embedded_dict, "env", wsgi_req->async_environ);

	// TODO: fix this
	//PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.version", uwsgi_version);


	// call

	PyTuple_SetItem(wsgi_req->async_args, 0, wsgi_req->async_environ);
	return python_call(wsgi_req->async_app, wsgi_req->async_args, uwsgi->catch_exceptions);
}


int uwsgi_response_subhandler_web3(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	return UWSGI_OK;
}
