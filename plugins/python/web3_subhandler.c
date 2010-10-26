#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void *uwsgi_request_subhandler_web3(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {

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
	if (uwsgi.numproc == 1) {
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


	wsgi_req->async_app = wi->wsgi_callable;

	PyDict_SetItemString(uwsgi.embedded_dict, "env", wsgi_req->async_environ);

	// TODO: fix this
	//PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.version", uwsgi_version);


	// call

	PyTuple_SetItem(wsgi_req->async_args, 0, wsgi_req->async_environ);
	return python_call(wsgi_req->async_app, wsgi_req->async_args, uwsgi.catch_exceptions);
}


int uwsgi_response_subhandler_web3(struct wsgi_request *wsgi_req) {

	PyObject *pychunk;
	ssize_t wsize;

	// return or yield ? (PyString on python2 PyBytes on python3)
	if (PyString_Check((PyObject *)wsgi_req->async_result)) {
		if ((wsize = write(wsgi_req->poll.fd, PyString_AsString(wsgi_req->async_result), PyString_Size(wsgi_req->async_result))) < 0) {
			uwsgi_error("write()");
			goto clear;
		}
		wsgi_req->response_size += wsize;
		goto clear;
	}


	// ok its a yield
	if (!wsgi_req->async_placeholder) {
		if (PyTuple_Check((PyObject *)wsgi_req->async_result)) {
			if (PyTuple_Size((PyObject *)wsgi_req->async_result) != 3) { 
				uwsgi_log("invalid Web3 response.\n"); 
				goto clear; 
			} 
			if (py_uwsgi_spit(NULL, (PyObject *)wsgi_req->async_result) == Py_None) { 
				goto clear; 
			} 

			wsgi_req->async_result = PyTuple_GetItem((PyObject *)wsgi_req->async_result, 0); 

			wsgi_req->async_placeholder = PyObject_GetIter( (PyObject *)wsgi_req->async_result );

			if (!wsgi_req->async_placeholder) {
				goto clear2;
			}
#ifdef UWSGI_ASYNC
			if (uwsgi.async > 1) {
				return UWSGI_AGAIN;
			}
		}
		else {
			uwsgi_log("invalid Web3 response.\n"); 
			goto clear; 
		}
#endif
	}



	pychunk = PyIter_Next(wsgi_req->async_placeholder);

	if (!pychunk) {
		if (PyErr_Occurred()) PyErr_Print();
		goto clear;
	}



	if (PyString_Check(pychunk)) {
		if ((wsize = write(wsgi_req->poll.fd, PyString_AsString(pychunk), PyString_Size(pychunk))) < 0) {
			uwsgi_error("write()");
			Py_DECREF(pychunk);
			goto clear;
		}
		wsgi_req->response_size += wsize;
	}


	Py_DECREF(pychunk);
	return UWSGI_AGAIN;

clear:
	if (wsgi_req->async_environ) {
		PyDict_Clear(wsgi_req->async_environ);
	}
	if (wsgi_req->async_post && !wsgi_req->fd_closed) {
		fclose(wsgi_req->async_post);
		if (!uwsgi.post_buffering || wsgi_req->post_cl <= (size_t) uwsgi.post_buffering) {
			wsgi_req->fd_closed = 1;
		}
	}
	Py_XDECREF((PyObject *)wsgi_req->async_placeholder);
clear2:
	Py_DECREF((PyObject *)wsgi_req->async_result);
	PyErr_Clear();

#ifdef UWSGI_DEBUG
	if (wsgi_req->async_placeholder) {
		uwsgi_debug("wsgi_req->async_placeholder: %d\n", ((PyObject *)wsgi_req->async_placeholder)->ob_refcnt);
	}
	if (wsgi_req->async_result) {
		uwsgi_debug("wsgi_req->async_result: %d\n", ((PyObject *)wsgi_req->async_result)->ob_refcnt);
	}
	if (wsgi_req->async_app) {
		uwsgi_debug("wsgi_req->async_app: %d\n", ((PyObject *)wsgi_req->async_app)->ob_refcnt);
	}
#endif
	return UWSGI_OK;
}

