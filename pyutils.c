#include "uwsgi.h"

int manage_python_response(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	PyObject *pychunk ;
	ssize_t wsize ;
#ifdef UWSGI_SENDFILE
	ssize_t sf_len = 0 ;
#endif

	// return or yield ?
	if (PyString_Check((PyObject *)wsgi_req->async_result)) {
		if ((wsize = write(wsgi_req->poll.fd, PyString_AsString(wsgi_req->async_result), PyString_Size(wsgi_req->async_result))) < 0) {
                        uwsgi_error("write()");
                        goto clear;
                }
                wsgi_req->response_size += wsize;
		goto clear;
	}

#ifdef PYTHREE
	if (PyBytes_Check((PyObject *)wsgi_req->async_result)) {
		if ((wsize = write(wsgi_req->poll.fd, PyBytes_AsString(wsgi_req->async_result), PyBytes_Size(wsgi_req->async_result))) < 0) {
			uwsgi_error("write()");
			goto clear;
		}
		wsgi_req->response_size += wsize;
		goto clear;
	}
#endif

#ifdef UWSGI_SENDFILE
	if (wsgi_req->sendfile_fd != -1) {
		sf_len = uwsgi_sendfile(uwsgi, wsgi_req);
		if (sf_len < 1) goto clear;
		wsgi_req->response_size += sf_len ;		
#ifdef UWSGI_ASYNC
		if (uwsgi->async > 1) {
			if (wsgi_req->response_size < wsgi_req->sendfile_fd_size) {
				return UWSGI_AGAIN;
			}
		}
#endif
		goto clear;
	}
#endif


	// ok its a yield
	if (!wsgi_req->async_placeholder) {
		wsgi_req->async_placeholder = PyObject_GetIter(wsgi_req->async_result);
                if (!wsgi_req->async_placeholder) {
			goto clear2;
		}
#ifdef UWSGI_ASYNC
		if (uwsgi->async > 1) {
			return UWSGI_AGAIN;
		}
#endif
	}




	pychunk = PyIter_Next(wsgi_req->async_placeholder) ;

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

#ifdef PYTHREE
	if (PyBytes_Check(pychunk)) {
		if ((wsize = write(wsgi_req->poll.fd, PyBytes_AsString(pychunk), PyBytes_Size(pychunk))) < 0) {
			uwsgi_error("write()");
			Py_DECREF(pychunk);
			goto clear;
		}
		wsgi_req->response_size += wsize;
	}
#endif
	
	Py_DECREF(pychunk);
	return UWSGI_AGAIN ;

clear:
	if (wsgi_req->sendfile_fd != -1) {
		Py_DECREF((PyObject *)wsgi_req->async_sendfile);
	}
	if (wsgi_req->async_environ) {
		PyDict_Clear(wsgi_req->async_environ);
	}
	if (wsgi_req->async_post && !wsgi_req->fd_closed) {
		fclose(wsgi_req->async_post);
		if (!uwsgi->post_buffering || wsgi_req->post_cl <= uwsgi->post_buffering) {
			wsgi_req->fd_closed = 1 ;
		}
	}
	Py_XDECREF((PyObject *)wsgi_req->async_placeholder);
clear2:
	Py_DECREF((PyObject *)wsgi_req->async_result);
	PyErr_Clear();
	return UWSGI_OK;
}


PyObject *python_call(PyObject *callable, PyObject *args) {
	
	PyObject *pyret;

	pyret =  PyEval_CallObject(callable, args);
	if (PyErr_Occurred()) {
		PyErr_Print();
	}

	return pyret;
}



int uwsgi_python_call(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, PyObject *callable, PyObject *args) {
	
	wsgi_req->async_result = python_call(callable, args);

	if (wsgi_req->async_result) {
		while ( manage_python_response(uwsgi, wsgi_req) != UWSGI_OK) {
#ifdef UWSGI_ASYNC
			if (uwsgi->async > 1) {
				return UWSGI_AGAIN;
			}
#endif
		}
	}

	return UWSGI_OK;
}
