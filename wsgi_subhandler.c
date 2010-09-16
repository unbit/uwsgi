#include "uwsgi.h"

void *uwsgi_request_subhandler_wsgi(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {

	PyObject *wsgi_socket, *zero;

	wsgi_socket = PyFile_FromFile(wsgi_req->async_post, "wsgi_input", "r", NULL);
        PyDict_SetItemString(wsgi_req->async_environ, "wsgi.input", wsgi_socket);
        Py_DECREF(wsgi_socket);

#ifdef UWSGI_SENDFILE
        PyDict_SetItemString(wsgi_req->async_environ, "wsgi.file_wrapper", wi->wsgi_sendfile);
#endif

#ifdef UWSGI_ASYNC
        if (uwsgi->async > 1) {
                PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.fdevent.readable", wi->wsgi_eventfd_read);
                PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.fdevent.writable", wi->wsgi_eventfd_write);
                PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.fdevent.timeout", Py_None);
        }
#endif

        zero = PyTuple_New(2);
        PyTuple_SetItem(zero, 0, PyInt_FromLong(1));
        PyTuple_SetItem(zero, 1, PyInt_FromLong(0));
        PyDict_SetItemString(wsgi_req->async_environ, "wsgi.version", zero);
        Py_DECREF(zero);

        zero = PyFile_FromFile(stderr, "wsgi_input", "w", NULL);
        PyDict_SetItemString(wsgi_req->async_environ, "wsgi.errors", zero);
        Py_DECREF(zero);

        PyDict_SetItemString(wsgi_req->async_environ, "wsgi.run_once", Py_False);

        PyDict_SetItemString(wsgi_req->async_environ, "wsgi.multithread", Py_False);
        if (uwsgi->numproc == 1) {
                PyDict_SetItemString(wsgi_req->async_environ, "wsgi.multiprocess", Py_False);
        }
        else {
                PyDict_SetItemString(wsgi_req->async_environ, "wsgi.multiprocess", Py_True);
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
        PyDict_SetItemString(wsgi_req->async_environ, "wsgi.url_scheme", zero);
        Py_DECREF(zero);


        wsgi_req->async_app = wi->wsgi_callable ;

        PyDict_SetItemString(uwsgi->embedded_dict, "env", wsgi_req->async_environ);

	// TODO: fix here
        //PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.uwsgi.version", uwsgi_version);


#ifdef UWSGI_ROUTING
        uwsgi_log("routing %d routes %d\n", uwsgi->routing, uwsgi->nroutes);
        if (uwsgi->routing && uwsgi->nroutes > 0) {
                check_route(uwsgi, wsgi_req);
        }
#endif


        // call

#ifdef UWSGI_PROFILER
        if (uwsgi->enable_profiler == 1) {
                PyDict_SetItem(wi->pymain_dict, PyString_FromFormat("uwsgi_environ__%d", wsgi_req->app_id), wsgi_req->async_environ);
                wsgi_req->async_result = python_call(wi->wsgi_cprofile_run, wsgi_req->async_args, 0);
                if (wsgi_req->async_result) {
                        wsgi_req->async_result = PyDict_GetItemString(wi->pymain_dict, "uwsgi_out");
                        Py_INCREF((PyObject*)wsgi_req->async_result);
                        Py_INCREF((PyObject*)wsgi_req->async_result);
                }
        }
        else {
#endif


                PyTuple_SetItem(wsgi_req->async_args, 0, wsgi_req->async_environ);
                return python_call(wsgi_req->async_app, wsgi_req->async_args, uwsgi->catch_exceptions);

#ifdef UWSGI_PROFILER
	}
#endif
}

int uwsgi_response_subhandler_wsgi(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

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

#ifdef UWSGI_SENDFILE
	if (wsgi_req->sendfile_obj == wsgi_req->async_result && wsgi_req->sendfile_fd != -1) {
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

#ifdef UWSGI_SENDFILE
        else if (wsgi_req->sendfile_obj == pychunk && wsgi_req->sendfile_fd != -1) {
                sf_len = uwsgi_sendfile(uwsgi, wsgi_req);
                if (sf_len < 1) goto clear;
                wsgi_req->response_size += sf_len ;
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
		if (!uwsgi->post_buffering || wsgi_req->post_cl <= (size_t) uwsgi->post_buffering) {
			wsgi_req->fd_closed = 1 ;

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


