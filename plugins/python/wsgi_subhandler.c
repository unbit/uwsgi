#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;
extern PyTypeObject uwsgi_InputType;

void *uwsgi_request_subhandler_wsgi(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {


	PyObject *zero;
	int i;
	PyObject *pydictkey, *pydictvalue;
	char *path_info;

        for (i = 0; i < wsgi_req->var_cnt; i += 2) {
#ifdef UWSGI_DEBUG
                uwsgi_debug("%.*s: %.*s\n", wsgi_req->hvec[i].iov_len, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i+1].iov_len, wsgi_req->hvec[i+1].iov_base);
#endif
#ifdef PYTHREE
                pydictkey = PyUnicode_DecodeLatin1(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, NULL);
                pydictvalue = PyUnicode_DecodeLatin1(wsgi_req->hvec[i + 1].iov_base, wsgi_req->hvec[i + 1].iov_len, NULL);
#else
                pydictkey = PyString_FromStringAndSize(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len);
                pydictvalue = PyString_FromStringAndSize(wsgi_req->hvec[i + 1].iov_base, wsgi_req->hvec[i + 1].iov_len);
#endif

#ifdef UWSGI_DEBUG
		uwsgi_log("%p %d %p %d\n", pydictkey, wsgi_req->hvec[i].iov_len, pydictvalue, wsgi_req->hvec[i + 1].iov_len);
#endif
                PyDict_SetItem(wsgi_req->async_environ, pydictkey, pydictvalue);
                Py_DECREF(pydictkey);
		Py_DECREF(pydictvalue);
        }

        if (wsgi_req->uh.modifier1 == UWSGI_MODIFIER_MANAGE_PATH_INFO) {
                wsgi_req->uh.modifier1 = 0;
                pydictkey = PyDict_GetItemString(wsgi_req->async_environ, "SCRIPT_NAME");
                if (pydictkey) {
                        if (PyString_Check(pydictkey)) {
                                pydictvalue = PyDict_GetItemString(wsgi_req->async_environ, "PATH_INFO");
                                if (pydictvalue) {
                                        if (PyString_Check(pydictvalue)) {
                                                path_info = PyString_AsString(pydictvalue);
                                                PyDict_SetItemString(wsgi_req->async_environ, "PATH_INFO", PyString_FromString(path_info + PyString_Size(pydictkey)));
                                        }
                                }
                        }
                }
        }


        // if async_post is mapped as a file, directly use it as wsgi.input
        if (wsgi_req->async_post) {
#ifdef PYTHREE
                wsgi_req->async_input = PyFile_FromFd(fileno((FILE *)wsgi_req->async_post), "wsgi_input", "rb", 0, NULL, NULL, NULL, 0);
#else
                wsgi_req->async_input = PyFile_FromFile(wsgi_req->async_post, "wsgi_input", "r", NULL);
#endif
        }
        else {
                // create wsgi.input custom object
                wsgi_req->async_input = (PyObject *) PyObject_New(uwsgi_Input, &uwsgi_InputType);
                ((uwsgi_Input*)wsgi_req->async_input)->wsgi_req = wsgi_req;
                ((uwsgi_Input*)wsgi_req->async_input)->pos = 0;
                ((uwsgi_Input*)wsgi_req->async_input)->readline_pos = 0;
                ((uwsgi_Input*)wsgi_req->async_input)->readline_max_size = 0;

        }


        PyDict_SetItemString(wsgi_req->async_environ, "wsgi.input", wsgi_req->async_input);

	PyDict_SetItemString(wsgi_req->async_environ, "wsgi.file_wrapper", wi->sendfile);

#ifdef UWSGI_ASYNC
	if (uwsgi.async > 1) {
		PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.fdevent.readable", wi->eventfd_read);
		PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.fdevent.writable", wi->eventfd_write);
		PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.fdevent.timeout", Py_None);
	}
#endif

	PyDict_SetItemString(wsgi_req->async_environ, "wsgi.version", wi->gateway_version);

	zero = PyFile_FromFile(stderr, "wsgi_errors", "w", NULL);
	PyDict_SetItemString(wsgi_req->async_environ, "wsgi.errors", zero);
	Py_DECREF(zero);

	PyDict_SetItemString(wsgi_req->async_environ, "wsgi.run_once", Py_False);



	if (uwsgi.threads > 1) {
		PyDict_SetItemString(wsgi_req->async_environ, "wsgi.multithread", Py_True);
	}
	else {
		PyDict_SetItemString(wsgi_req->async_environ, "wsgi.multithread", Py_False);
	}
	if (uwsgi.numproc == 1) {
		PyDict_SetItemString(wsgi_req->async_environ, "wsgi.multiprocess", Py_False);
	}
	else {
		PyDict_SetItemString(wsgi_req->async_environ, "wsgi.multiprocess", Py_True);
	}


	if (wsgi_req->scheme_len > 0) {
		zero = UWSGI_PYFROMSTRINGSIZE(wsgi_req->scheme, wsgi_req->scheme_len);
	}
	else if (wsgi_req->https_len > 0) {
		if (!strncasecmp(wsgi_req->https, "on", 2) || wsgi_req->https[0] == '1') {
			zero = UWSGI_PYFROMSTRING("https");
		}
		else {
			zero = UWSGI_PYFROMSTRING("http");
		}
	}
	else {
		zero = UWSGI_PYFROMSTRING("http");
	}
	PyDict_SetItemString(wsgi_req->async_environ, "wsgi.url_scheme", zero);
	Py_DECREF(zero);

	wsgi_req->async_app = wi->callable;

	// export .env only in non-threaded mode
	if (uwsgi.threads < 2) {
		PyDict_SetItemString(up.embedded_dict, "env", wsgi_req->async_environ);
	}

	PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.version", wi->uwsgi_version);

	if (uwsgi.cores > 1) {
		zero = PyInt_FromLong(wsgi_req->async_id);
		PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.core", zero);
		Py_DECREF(zero);
	}

	// cache this ?
	if (uwsgi.cluster_fd >= 0) {
		zero = PyString_FromString(uwsgi.cluster);
		PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.cluster", zero);
		Py_DECREF(zero);
		zero = PyString_FromString(uwsgi.hostname);
		PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.cluster_node", zero);
		Py_DECREF(zero);
	}

	PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.node", wi->uwsgi_node);

	// call
	PyTuple_SetItem(wsgi_req->async_args, 0, wsgi_req->async_environ);
	return python_call(wsgi_req->async_app, wsgi_req->async_args, uwsgi.catch_exceptions, wsgi_req);
}

int uwsgi_response_subhandler_wsgi(struct wsgi_request *wsgi_req) {

	PyObject *pychunk;
	ssize_t sf_len = 0;

	// return or yield ?
	if (PyString_Check((PyObject *)wsgi_req->async_result)) {
		size_t content_len = PyString_Size((PyObject *)wsgi_req->async_result);
		if (content_len > 0 && !wsgi_req->headers_sent) {
			if (uwsgi_python_do_send_headers(wsgi_req)) {
				goto clear;
			}
		}
		up.hook_write_string(wsgi_req, (PyObject *) wsgi_req->async_result);
		uwsgi_py_check_write_errors {
			uwsgi_py_write_exception(wsgi_req);
		}
		goto clear;
	}


#ifdef __FreeBSD__
	if ( ((wsgi_req->sendfile_obj == wsgi_req->async_result) || ( wsgi_req->sendfile_fd_size > 0 && wsgi_req->response_size < wsgi_req->sendfile_fd_size)) && wsgi_req->sendfile_fd != -1) {
#else
	if (wsgi_req->sendfile_obj == wsgi_req->async_result && wsgi_req->sendfile_fd != -1) {
#endif
		// send the headers if not already sent
        	if (!wsgi_req->headers_sent && wsgi_req->headers_hvec > 0) {
                	uwsgi_python_do_send_headers(wsgi_req);
        	}
		sf_len = uwsgi_sendfile(wsgi_req);
		if (sf_len < 1) goto clear;
		wsgi_req->response_size += sf_len;
#ifdef UWSGI_ASYNC
		if (uwsgi.async > 1) {
			if (wsgi_req->response_size < wsgi_req->sendfile_fd_size) {
				return UWSGI_AGAIN;
			}
		}
#endif
		goto clear;
	}

	// ok its a yield
	if (!wsgi_req->async_placeholder) {
		wsgi_req->async_placeholder = PyObject_GetIter(wsgi_req->async_result);
		if (!wsgi_req->async_placeholder) {
			goto exception;
		}
#ifdef UWSGI_ASYNC
		if (uwsgi.async > 1) {
			return UWSGI_AGAIN;
		}
#endif
	}

	pychunk = PyIter_Next(wsgi_req->async_placeholder);

	if (!pychunk) {
exception:
		if (PyErr_Occurred()) { 
			int do_exit = uwsgi_python_manage_exceptions();
		        if (PyErr_ExceptionMatches(PyExc_MemoryError)) {
				uwsgi_log("Memory Error detected !!!\n");	
			}		
			uwsgi.workers[uwsgi.mywid].exceptions++;
			uwsgi_apps[wsgi_req->app_id].exceptions++;
			PyErr_Print();
			if (do_exit) {
                        	exit(UWSGI_EXCEPTION_CODE);
                	}
		}	
		goto clear;
	}




	if (PyString_Check(pychunk)) {
		size_t content_len = PyString_Size(pychunk);
		if (content_len > 0 && !wsgi_req->headers_sent) {
                        if (uwsgi_python_do_send_headers(wsgi_req)) {
                                goto clear;
                        }
                }
		up.hook_write_string(wsgi_req, pychunk);
		uwsgi_py_check_write_errors {
			uwsgi_py_write_exception(wsgi_req);
			Py_DECREF(pychunk);
			goto clear;
		}
	}

	else if (wsgi_req->sendfile_obj == pychunk && wsgi_req->sendfile_fd != -1) {
		// send the headers if not already sent
        	if (!wsgi_req->headers_sent && wsgi_req->headers_hvec > 0) {
                	uwsgi_python_do_send_headers(wsgi_req);
        	}
		sf_len = uwsgi_sendfile(wsgi_req);
		if (sf_len < 1) goto clear;
		wsgi_req->response_size += sf_len;
	}


	Py_DECREF(pychunk);
	return UWSGI_AGAIN;

clear:

	if (wsgi_req->sendfile_fd != -1) {
		Py_DECREF((PyObject *)wsgi_req->async_sendfile);
	}

	// send the headers if not already sent
	if (!wsgi_req->headers_sent && wsgi_req->headers_hvec > 0) {
		uwsgi_python_do_send_headers(wsgi_req);
	}

	if (wsgi_req->async_placeholder) {
		// CALL close() ALWAYS if we are working with an iterator !!!
		if (PyObject_HasAttrString((PyObject *)wsgi_req->async_result, "close")) {
                        PyObject *close_method = PyObject_GetAttrString((PyObject *)wsgi_req->async_result, "close");
                        PyObject *close_method_args = PyTuple_New(0);
#ifdef UWSGI_DEBUG
                        uwsgi_log("calling close() for %.*s %p %p\n", wsgi_req->uri_len, wsgi_req->uri, close_method, close_method_args);
#endif
                        PyObject *close_method_output = PyEval_CallObject(close_method, close_method_args);
                        if (PyErr_Occurred()) {
                                PyErr_Print();
                        }
                        Py_DECREF(close_method_args);
                        Py_XDECREF(close_method_output);
                        Py_DECREF(close_method);
                }
		Py_DECREF((PyObject *)wsgi_req->async_placeholder);
	}

	Py_DECREF((PyObject *)wsgi_req->async_result);
	PyErr_Clear();

	return UWSGI_OK;
}


