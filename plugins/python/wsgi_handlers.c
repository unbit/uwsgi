#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;


typedef struct uwsgi_Input {
        PyObject_HEAD
	off_t pos;
	struct wsgi_request *wsgi_req;
} uwsgi_Input;

PyObject *uwsgi_Input_iter(PyObject * self) {
        Py_INCREF(self);
        return self;
}

PyObject *uwsgi_Input_next(PyObject * self) {

	return PyErr_Format(PyExc_NotImplementedError, "wsgi.input __iter__() is not implemented");

}

static void uwsgi_Input_free(uwsgi_Input *self) {
    	PyObject_Del(self);
}

static PyObject *uwsgi_Input_read(uwsgi_Input *self, PyObject *args) {

	long len = 0;
	size_t remains;
	ssize_t rlen;
	char *tmp_buf;
	int fd;
	PyObject *res;

	if (!PyArg_ParseTuple(args, "|l:read", &len)) {
		return NULL;
	}

	// return empty string if no post_cl or pos >= post_cl
	if (!self->wsgi_req->post_cl || (size_t) self->pos >= self->wsgi_req->post_cl) {
		return PyString_FromString("");
	}

	if (uwsgi.post_buffering > 0) {
		fd = -1;
		if (self->wsgi_req->post_cl <= (size_t) uwsgi.post_buffering) {
			fd = fileno((FILE *)self->wsgi_req->async_post);
		}
	}
	else {
		fd = self->wsgi_req->poll.fd;
	}
	// return the whole input
	if (len <= 0) {
		remains = self->wsgi_req->post_cl;
	}
	else {
		remains = len ;
	}

	if (remains + self->pos > self->wsgi_req->post_cl) {
		remains = self->wsgi_req->post_cl - self->pos;
	} 

	if (remains <= 0) {
		return PyString_FromString("");
	}

	if (fd == -1) {
		res = PyString_FromStringAndSize( self->wsgi_req->post_buffering_buf, remains);
		self->pos += remains;	
		return res;
	}

	tmp_buf = uwsgi_malloc(remains);	

	if (uwsgi_waitfd(fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]) <= 0) {
		free(tmp_buf);
		return PyErr_Format(PyExc_IOError, "error waiting for wsgi.input data");
	}

	rlen = read(fd, tmp_buf, remains);
	if (rlen < 0) {
		free(tmp_buf);
		return PyErr_Format(PyExc_IOError, "error reading wsgi.input data");
	}

	self->pos += rlen;
	res = PyString_FromStringAndSize(tmp_buf, rlen);

	free(tmp_buf);
	return res;
		
}

static PyObject *uwsgi_Input_readline(uwsgi_Input *self, PyObject *args) {

	return PyErr_Format(PyExc_NotImplementedError, "wsgi.input readline() is not implemented");

}

static PyObject *uwsgi_Input_readlines(uwsgi_Input *self, PyObject *args) {

	return PyErr_Format(PyExc_NotImplementedError, "wsgi.input readlines() is not implemented");
}

static PyObject *uwsgi_Input_close(uwsgi_Input *self, PyObject *args) {

	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef uwsgi_Input_methods[] = {
	{ "read",      (PyCFunction)uwsgi_Input_read,      METH_VARARGS, 0 },
	{ "readline",  (PyCFunction)uwsgi_Input_readline,  METH_VARARGS, 0 },
	{ "readlines", (PyCFunction)uwsgi_Input_readlines, METH_VARARGS, 0 },
// add close to allow mod_wsgi compatibility
	{ "close",     (PyCFunction)uwsgi_Input_close,     METH_VARARGS, 0 },
	{ NULL, NULL}
};


PyTypeObject uwsgi_InputType = {
        PyVarObject_HEAD_INIT(NULL, 0)
                "uwsgi._Input",  /*tp_name */
        sizeof(uwsgi_Input),     /*tp_basicsize */
        0,                      /*tp_itemsize */
        (destructor) uwsgi_Input_free,	/*tp_dealloc */
        0,                      /*tp_print */
        0,                      /*tp_getattr */
        0,                      /*tp_setattr */
        0,                      /*tp_compare */
        0,                      /*tp_repr */
        0,                      /*tp_as_number */
        0,                      /*tp_as_sequence */
        0,                      /*tp_as_mapping */
        0,                      /*tp_hash */
        0,                      /*tp_call */
        0,                      /*tp_str */
        0,                      /*tp_getattr */
        0,                      /*tp_setattr */
        0,                      /*tp_as_buffer */
#if defined(Py_TPFLAGS_HAVE_ITER)
        Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,
#else
        Py_TPFLAGS_DEFAULT,
#endif
        "uwsgi input object.",      /* tp_doc */
        0,                      /* tp_traverse */
        0,                      /* tp_clear */
        0,                      /* tp_richcompare */
        0,                      /* tp_weaklistoffset */
        uwsgi_Input_iter,        /* tp_iter: __iter__() method */
        uwsgi_Input_next,         /* tp_iternext: next() method */
	uwsgi_Input_methods,
	0,0,0,0,0,0,0,0,0,0,0,0
};


PyObject *py_uwsgi_write(PyObject * self, PyObject * args) {
	PyObject *data;
	char *content;
	int len;

	struct wsgi_request *wsgi_req = current_wsgi_req();

	data = PyTuple_GetItem(args, 0);
	if (PyString_Check(data)) {
		content = PyString_AsString(data);
		len = PyString_Size(data);
		UWSGI_RELEASE_GIL
			wsgi_req->response_size = write(wsgi_req->poll.fd, content, len);
		UWSGI_GET_GIL
	}

	Py_INCREF(Py_None);
	return Py_None;
}

#ifdef UWSGI_ASYNC


PyObject *py_eventfd_read(PyObject * self, PyObject * args) {
	int fd, timeout = 0;

	struct wsgi_request *wsgi_req = current_wsgi_req();

	if (!PyArg_ParseTuple(args, "i|i", &fd, &timeout)) {
		return NULL;
	}

	if (fd >= 0) {
		async_add_fd_read(wsgi_req, fd, timeout);
	}

	return PyString_FromString("");
}


PyObject *py_eventfd_write(PyObject * self, PyObject * args) {
	int fd, timeout = 0;

	struct wsgi_request *wsgi_req = current_wsgi_req();

	if (!PyArg_ParseTuple(args, "i|i", &fd, &timeout)) {
		return NULL;
	}

	if (fd >= 0) {
		async_add_fd_write(wsgi_req, fd, timeout);
	}

	return PyString_FromString("");
}
#endif

int uwsgi_request_wsgi(struct wsgi_request *wsgi_req) {

	int i;

	PyObject *pydictkey, *pydictvalue;

	char *path_info;
	struct uwsgi_app *wi;

	int tmp_stderr;
	char *what;
	int what_len;

	PyObject *wsgi_socket;


#ifdef UWSGI_ASYNC
	if (wsgi_req->async_status == UWSGI_AGAIN) {
		// get rid of timeout
		if (wsgi_req->async_timed_out) {
			PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.fdevent.timeout", Py_True);
			wsgi_req->async_timed_out = 0;
		}
		else {
			PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.fdevent.timeout", Py_None);
		}

		if (wsgi_req->async_ready_fd) {
			PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.ready_fd", PyInt_FromLong(wsgi_req->async_last_ready_fd));
			wsgi_req->async_ready_fd = 0;
		}
		else {
			PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.ready_fd", Py_None);
		}
		return manage_python_response(wsgi_req);
	}
#endif


	/* Standard WSGI request */
	if (!wsgi_req->uh.pktsize) {
		uwsgi_log( "Invalid WSGI request. skip.\n");
		return -1;
	}

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}


	if (!up.ignore_script_name) {

		if (!wsgi_req->script_name)
			wsgi_req->script_name = "";

		if (uwsgi.vhost) {
			what = uwsgi_concat3n(wsgi_req->host, wsgi_req->host_len, "|",1, wsgi_req->script_name, wsgi_req->script_name_len);
			what_len = wsgi_req->host_len + 1 + wsgi_req->script_name_len;
#ifdef UWSGI_DEBUG
			uwsgi_debug("VirtualHost SCRIPT_NAME=%s\n", what);
#endif
		}
		else {
			what = wsgi_req->script_name;
			what_len = wsgi_req->script_name_len;
		}


		if ( (wsgi_req->app_id = uwsgi_get_app_id(what, what_len, 0))  == -1) {
			if (wsgi_req->script_name_len > 1 || uwsgi.default_app < 0 || uwsgi.vhost) {
				/* unavailable app for this SCRIPT_NAME */
				wsgi_req->app_id = -1;
				if (wsgi_req->script_len > 0
						|| wsgi_req->module_len > 0
						|| wsgi_req->file_len > 0
						|| wsgi_req->paste_len > 0
				   ) {
					// a bit of magic: 1-1 = 0 / 0-1 = -1
					// this part must be heavy locked in threaded modes
					if (uwsgi.threads > 1) {
						pthread_mutex_lock(&up.lock_pyloaders);
					}
					UWSGI_GET_GIL
						if (uwsgi.single_interpreter) {
							wsgi_req->app_id = init_uwsgi_app(LOADER_DYN, (void *) wsgi_req, wsgi_req, up.main_thread);
						}
						else {
							wsgi_req->app_id = init_uwsgi_app(LOADER_DYN, (void *) wsgi_req, wsgi_req, NULL);
						}
					UWSGI_RELEASE_GIL
						if (uwsgi.threads > 1) {
							pthread_mutex_unlock(&up.lock_pyloaders);
						}
				}
			}
		}

		if (uwsgi.vhost) {
			free(what);
		}

	}
	else {
		wsgi_req->app_id = 0;
	}


	if (wsgi_req->app_id == -1) {
		// use default app ?
		if (!uwsgi.no_default_app && uwsgi.default_app >= 0) {
			wsgi_req->app_id = uwsgi.default_app;
		}
		else {
			internal_server_error(wsgi_req->poll.fd, "wsgi application not found");
			goto clear2;
		}

	}

	wi = &uwsgi.apps[wsgi_req->app_id];

	up.swap_ts(wsgi_req, wi);
	
	if (wi->chdir) {
#ifdef UWSGI_DEBUG
		uwsgi_debug("chdir to %s\n", wi->chdir);
#endif
		if (chdir(wi->chdir)) {
			uwsgi_error("chdir()");
		}
	}


	if (wsgi_req->protocol_len < 5) {
		uwsgi_log( "INVALID PROTOCOL: %.*s\n", wsgi_req->protocol_len, wsgi_req->protocol);
		internal_server_error(wsgi_req->poll.fd, "invalid HTTP protocol !!!");
		goto clear;

	}
	if (strncmp(wsgi_req->protocol, "HTTP/", 5)) {
		uwsgi_log( "INVALID PROTOCOL: %.*s\n", wsgi_req->protocol_len, wsgi_req->protocol);
		internal_server_error(wsgi_req->poll.fd, "invalid HTTP protocol !!!");
		goto clear;
	}



#ifdef UWSGI_ASYNC
	wsgi_req->async_environ = wi->environ[wsgi_req->async_id];
	wsgi_req->async_args = wi->args[wsgi_req->async_id];
#else
	wsgi_req->async_environ = wi->environ;
	wsgi_req->async_args = wi->args;
#endif

	UWSGI_GET_GIL

	// no fear of race conditions for this counter as it is already protected by the GIL
	wi->requests++;

	Py_INCREF((PyObject *)wsgi_req->async_environ);

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
		PyDict_SetItem(wsgi_req->async_environ, pydictkey, pydictvalue);
		Py_DECREF(pydictkey);
		Py_DECREF(pydictvalue);
	}

	if (wsgi_req->uh.modifier1 == UWSGI_MODIFIER_MANAGE_PATH_INFO) {
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



	if (uwsgi.post_buffering > 0) {
		UWSGI_RELEASE_GIL
		// read to disk if post_cl > post_buffering
		if (!up.pep3333_input) {
			if (wsgi_req->post_cl >= (size_t) uwsgi.post_buffering) {
				if (!uwsgi_read_whole_body(wsgi_req, wsgi_req->post_buffering_buf, uwsgi.post_buffering_bufsize)) {
					goto clear;
				}
			}
			else {
				wsgi_req->async_post = fdopen(wsgi_req->poll.fd, "r");
			}
		}
		else {
			// read to disk if post_cl > post_buffering
			if (wsgi_req->post_cl >= (size_t) uwsgi.post_buffering) {
				if (!uwsgi_read_whole_body(wsgi_req, wsgi_req->post_buffering_buf, uwsgi.post_buffering_bufsize)) {
					goto clear;
				}
			}
			// on tiny post use memory
			else {		
				if (!uwsgi_read_whole_body_in_mem(wsgi_req, wsgi_req->post_buffering_buf)) {
					goto clear;
				}
			}
		}
		UWSGI_GET_GIL
	}
	else {
		wsgi_req->async_post = fdopen(wsgi_req->poll.fd, "r");
	}

	if (!up.pep3333_input) {
		wsgi_socket = PyFile_FromFile(wsgi_req->async_post, "wsgi_input", "r", NULL);
		PyDict_SetItemString(wsgi_req->async_environ, "wsgi.input", wsgi_socket);
		Py_DECREF(wsgi_socket);
	}
	else {
		wsgi_socket = (PyObject *) PyObject_New(uwsgi_Input, &uwsgi_InputType);
		((uwsgi_Input*)wsgi_socket)->wsgi_req = wsgi_req; 
		((uwsgi_Input*)wsgi_socket)->pos = 0;
		PyDict_SetItemString(wsgi_req->async_environ, "wsgi.input", wsgi_socket);
	}

	

	wsgi_req->async_result = wi->request_subhandler(wsgi_req, wi);

	UWSGI_RELEASE_GIL

	if (wsgi_req->async_result) {


		while (wi->response_subhandler(wsgi_req) != UWSGI_OK) {
#ifdef UWSGI_ASYNC
			if (uwsgi.async > 1) {
				return UWSGI_AGAIN;
			}
			else {
#endif
				wsgi_req->switches++;
#ifdef UWSGI_ASYNC
			}
#endif
		}


	}

	else if (up.catch_exceptions) {

		// LOCK THIS PART

		wsgi_req->response_size += write(wsgi_req->poll.fd, wsgi_req->protocol, wsgi_req->protocol_len);
		wsgi_req->response_size += write(wsgi_req->poll.fd, " 500 Internal Server Error\r\n", 28 );
		wsgi_req->response_size += write(wsgi_req->poll.fd, "Content-type: text/plain\r\n\r\n", 28 );
		wsgi_req->header_cnt = 1;

		/*
		   sorry that is a hack to avoid the rewrite of PyErr_Print
		   temporarily map (using dup2) stderr to wsgi_req->poll.fd
		   */
		tmp_stderr = dup(2);
		if (tmp_stderr < 0) {
			uwsgi_error("dup()");
			goto clear;
		}
		// map 2 to wsgi_req
		if (dup2(wsgi_req->poll.fd, 2) < 0) {
			close(tmp_stderr);
			uwsgi_error("dup2()");
			goto clear;
		}
		// print the error
		UWSGI_GET_GIL
		PyErr_Print();
		UWSGI_RELEASE_GIL
		// ...resume the original stderr, in case of error we are damaged forever !!!
		if (dup2(tmp_stderr, 2) < 0) {
			uwsgi_error("dup2()");
		}
		close(tmp_stderr);
	}

	if (up.pep3333_input) {
		Py_DECREF(wsgi_socket);
	}
clear:

	up.reset_ts(wsgi_req, wi);

clear2:

	return UWSGI_OK;

}

void uwsgi_after_request_wsgi(struct wsgi_request *wsgi_req) {


	if (uwsgi.shared->options[UWSGI_OPTION_LOGGING] || wsgi_req->log_this) {
		log_request(wsgi_req);
	}
	else {
		if (uwsgi.shared->options[UWSGI_OPTION_LOG_ZERO]) {
			if (wsgi_req->response_size == 0) { log_request(wsgi_req); return; }
		}
		if (uwsgi.shared->options[UWSGI_OPTION_LOG_SLOW]) {
			if ((uint32_t) wsgi_req_time >= uwsgi.shared->options[UWSGI_OPTION_LOG_SLOW]) { log_request(wsgi_req); return; }
		}
		if (uwsgi.shared->options[UWSGI_OPTION_LOG_4xx]) {
			if (wsgi_req->status >= 400 && wsgi_req->status <= 499) { log_request(wsgi_req); return; }
		}
		if (uwsgi.shared->options[UWSGI_OPTION_LOG_5xx]) {
			if (wsgi_req->status >= 500 && wsgi_req->status <= 599) { log_request(wsgi_req); return; }
		}
		if (uwsgi.shared->options[UWSGI_OPTION_LOG_BIG]) {
			if (wsgi_req->response_size >= uwsgi.shared->options[UWSGI_OPTION_LOG_BIG]) { log_request(wsgi_req); return; }
		}
		if (uwsgi.shared->options[UWSGI_OPTION_LOG_SENDFILE]) {
			if (wsgi_req->sendfile_fd > -1 && wsgi_req->sendfile_obj == wsgi_req->async_result) { log_request(wsgi_req); return; }
		}
	}
}

#ifdef UWSGI_SENDFILE
PyObject *py_uwsgi_sendfile(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	if (!PyArg_ParseTuple(args, "O|i:uwsgi_sendfile", &wsgi_req->async_sendfile, &wsgi_req->sendfile_fd_chunk)) {
		return NULL;
	}

#ifdef PYTHREE
	wsgi_req->sendfile_fd = PyObject_AsFileDescriptor(wsgi_req->async_sendfile);
#else
	if (PyFile_Check((PyObject *)wsgi_req->async_sendfile)) {
		Py_INCREF((PyObject *)wsgi_req->async_sendfile);
		wsgi_req->sendfile_fd = PyObject_AsFileDescriptor(wsgi_req->async_sendfile);
	}
#endif

	// PEP 333 hack
	wsgi_req->sendfile_obj = wsgi_req->async_sendfile;
	//wsgi_req->sendfile_obj = (void *) PyTuple_New(0);

	Py_INCREF((PyObject *) wsgi_req->sendfile_obj);
	return (PyObject *) wsgi_req->sendfile_obj;
}
#endif

void threaded_swap_ts(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {

	if (uwsgi.single_interpreter == 0 && wi->interpreter != up.main_thread) {
		UWSGI_GET_GIL
                PyThreadState_Swap(uwsgi.core[wsgi_req->async_id]->ts[wsgi_req->app_id]);
		UWSGI_RELEASE_GIL
	}

}

void threaded_reset_ts(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {
	if (uwsgi.single_interpreter == 0 && wi->interpreter != up.main_thread) {
		UWSGI_GET_GIL
        	PyThreadState_Swap((PyThreadState *) pthread_getspecific(up.upt_save_key));
        	UWSGI_RELEASE_GIL
	}
}


void simple_reset_ts(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {
	if (uwsgi.single_interpreter == 0 && wi->interpreter != up.main_thread) {
        	// restoring main interpreter
                PyThreadState_Swap(up.main_thread);
	}
}


void simple_swap_ts(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {

	if (uwsgi.single_interpreter == 0 && wi->interpreter != up.main_thread) {
                // set the interpreter
                PyThreadState_Swap(wi->interpreter);
	}
}
