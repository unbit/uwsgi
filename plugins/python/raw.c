#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

static int manage_raw_response(struct wsgi_request *wsgi_req) {
	return 0;
}

int uwsgi_request_python_raw(struct wsgi_request *wsgi_req) {
	if (!up.raw_callable) return UWSGI_OK;

	UWSGI_GET_GIL
	PyObject *args = PyTuple_New(1);
	PyTuple_SetItem(args, 0, PyInt_FromLong(wsgi_req->fd));
	wsgi_req->async_result = PyEval_CallObject(up.raw_callable, args);
	if (wsgi_req->async_result) {
		manage_raw_response(wsgi_req);
		Py_DECREF((PyObject *) wsgi_req->async_result);
	}
	Py_DECREF(args);
	UWSGI_RELEASE_GIL;
	return UWSGI_OK;
}
