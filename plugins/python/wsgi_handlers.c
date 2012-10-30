#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;


PyObject *uwsgi_Input_iter(PyObject *self) {
        Py_INCREF(self);
        return self;
}

ssize_t uwsgi_python_hook_simple_input_readline(struct wsgi_request *wsgi_req, char *readline, size_t max_size) {
	ssize_t rlen = 0;
	UWSGI_RELEASE_GIL;
        if (uwsgi_waitfd(wsgi_req->poll.fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]) <= 0) {
                UWSGI_GET_GIL
		return 0;
        }

        if (max_size > 0 && max_size < UWSGI_PY_READLINE_BUFSIZE) {
                rlen = read(wsgi_req->poll.fd, readline, max_size);
        }
        else {
                rlen = read(wsgi_req->poll.fd, readline, UWSGI_PY_READLINE_BUFSIZE);
        }
        UWSGI_GET_GIL;
	return rlen;
}

PyObject *uwsgi_Input_getline(uwsgi_Input *self) {
	size_t i;
	ssize_t rlen;
	struct wsgi_request *wsgi_req = self->wsgi_req;
	PyObject *res;

	char *ptr = self->readline;

	if (uwsgi.post_buffering > 0) {
		ptr = wsgi_req->post_buffering_buf;
		self->readline_size = wsgi_req->post_cl;
		if (!self->readline_pos) {
			self->pos += self->readline_size;
		}
	}

	if (self->readline_pos > 0 || uwsgi.post_buffering) {
		for(i=self->readline_pos;i<self->readline_size;i++) {
			if (ptr[i] == '\n') {
				res = PyString_FromStringAndSize(ptr+self->readline_pos, (i-self->readline_pos)+1);
				self->readline_pos = i+1;
				if (self->readline_pos >= self->readline_size) self->readline_pos = 0;
				return res;
			}
		}
		res = PyString_FromStringAndSize(ptr + self->readline_pos, self->readline_size - self->readline_pos);
		self->readline_pos = 0;
		return res;
	}


	rlen = up.hook_wsgi_input_readline(wsgi_req, self->readline, self->readline_max_size);
	if (rlen < 0) {
                return PyErr_Format(PyExc_IOError, "error reading for wsgi.input data (readline/getline)");
        }
	else if (rlen == 0) {
                return PyErr_Format(PyExc_IOError, "error waiting for wsgi.input data (readline/getline)");
	}

	self->readline_size = rlen;
	self->readline_pos = 0;
        self->pos += rlen;

	for(i=0;i<(size_t)rlen;i++) {
		if (self->readline[i] == '\n') {
			res = PyString_FromStringAndSize(self->readline, i+1);
			self->readline_pos+= i+1;
			if (self->readline_pos >= self->readline_size) self->readline_pos = 0;
			return res;
		}
	}
	self->readline_pos = 0;
	return PyString_FromStringAndSize(self->readline, self->readline_size);
	
}

PyObject *uwsgi_Input_next(PyObject* self) {

	if (!((uwsgi_Input *)self)->wsgi_req->post_cl || ((size_t) ((uwsgi_Input *)self)->pos >= ((uwsgi_Input *)self)->wsgi_req->post_cl && !((uwsgi_Input *)self)->readline_pos)) {
		PyErr_SetNone(PyExc_StopIteration);
		return NULL;
	}

	return uwsgi_Input_getline((uwsgi_Input *)self);

}

static void uwsgi_Input_free(uwsgi_Input *self) {
    	PyObject_Del(self);
}

ssize_t uwsgi_python_hook_simple_input_read(struct wsgi_request *wsgi_req, char *tmp_buf, size_t remains, size_t *tmp_pos) {

	UWSGI_RELEASE_GIL

        while(remains) {
                if (uwsgi_waitfd(wsgi_req->poll.fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]) <= 0) {
                        UWSGI_GET_GIL
			return 0;
                }

                ssize_t rlen = read(wsgi_req->poll.fd, tmp_buf+*tmp_pos, remains);
                if (rlen <= 0) {
                        UWSGI_GET_GIL
			return -1;
                }
                *tmp_pos += rlen;
                remains -= rlen;
        }

        UWSGI_GET_GIL
	return *tmp_pos;

}

static PyObject *uwsgi_Input_read(uwsgi_Input *self, PyObject *args) {

	long len = 0;
	size_t remains;
	size_t tmp_pos = 0;
	char *tmp_buf;
	PyObject *res;

	if (!PyArg_ParseTuple(args, "|l:read", &len)) {
		return NULL;
	}

	// return empty string if no post_cl or pos >= post_cl
	if ((!self->wsgi_req->post_cl || (size_t) self->pos >= self->wsgi_req->post_cl ) && !self->readline_pos) {
		return PyString_FromString("");
	}

	// some residual data ?
	if (self->readline_pos && self->readline_size) {
		if (len > 0) {
			if ((size_t) len < (self->readline_size - self->readline_pos)) {
				res = PyString_FromStringAndSize(self->readline + self->readline_pos, len);
				self->readline_pos+=len;
				if (self->readline_pos >= self->readline_size) self->readline_pos = 0;
				return res;	
			}
		}
		self->readline_pos = 0;
		return PyString_FromStringAndSize(self->readline + self->readline_pos, self->readline_size - self->readline_pos);
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

	if (uwsgi.post_buffering > 0) {
		res = PyString_FromStringAndSize( self->wsgi_req->post_buffering_buf+self->pos, remains);
		self->pos += remains;
		return res;
	}

	tmp_buf = uwsgi_malloc(remains);	

	ssize_t rlen = up.hook_wsgi_input_read(self->wsgi_req, tmp_buf, remains, &tmp_pos);
	if (rlen < 0) {
                free(tmp_buf);
        	return PyErr_Format(PyExc_IOError, "error reading for wsgi.input data: Content-Length %llu requested %llu received %llu", (unsigned long long) self->wsgi_req->post_cl, (unsigned long long)  (remains + tmp_pos), (unsigned long long) tmp_pos);
	}
	else if (tmp_pos == 0) {
                free(tmp_buf);
        	return PyErr_Format(PyExc_IOError, "error waiting for wsgi.input data: Content-Length %llu requested %llu received %llu", (unsigned long long) self->wsgi_req->post_cl, (unsigned long long)  (remains + tmp_pos), (unsigned long long) tmp_pos);
	}

	self->pos += tmp_pos;
	res = PyString_FromStringAndSize(tmp_buf, tmp_pos);
	free(tmp_buf);
	return res;
		
}

static PyObject *uwsgi_Input_readline(uwsgi_Input *self, PyObject *args) {

	if (!PyArg_ParseTuple(args, "|l:readline", &((uwsgi_Input *)self)->readline_max_size)) {
                return NULL;
        }

	if (!((uwsgi_Input *)self)->wsgi_req->post_cl || ((size_t) ((uwsgi_Input *)self)->pos >= ((uwsgi_Input *)self)->wsgi_req->post_cl && !((uwsgi_Input *)self)->readline_pos)) {
		return PyString_FromString("");
	}
	return uwsgi_Input_getline(self);

}

static PyObject *uwsgi_Input_readlines(uwsgi_Input *self, PyObject *args) {

	PyObject *res;

	if (!((uwsgi_Input *)self)->wsgi_req->post_cl || ((size_t) ((uwsgi_Input *)self)->pos >= ((uwsgi_Input *)self)->wsgi_req->post_cl && !((uwsgi_Input *)self)->readline_pos)) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	res = PyList_New(0);
	while( ((size_t) ((uwsgi_Input *)self)->pos < ((uwsgi_Input *)self)->wsgi_req->post_cl || ((uwsgi_Input *)self)->readline_pos > 0)) {
		PyObject *a_line = uwsgi_Input_getline(self);
		PyList_Append(res, a_line);	
		Py_DECREF(a_line);
	}

	return res;
}

static PyObject *uwsgi_Input_close(uwsgi_Input *self, PyObject *args) {

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *uwsgi_Input_fileno(uwsgi_Input *self, PyObject *args) {

	return PyInt_FromLong(self->wsgi_req->poll.fd);
}

static PyMethodDef uwsgi_Input_methods[] = {
	{ "read",      (PyCFunction)uwsgi_Input_read,      METH_VARARGS, 0 },
	{ "readline",  (PyCFunction)uwsgi_Input_readline,  METH_VARARGS, 0 },
	{ "readlines", (PyCFunction)uwsgi_Input_readlines, METH_VARARGS, 0 },
// add close to allow mod_wsgi compatibility
	{ "close",     (PyCFunction)uwsgi_Input_close,     METH_VARARGS, 0 },
	{ "fileno",     (PyCFunction)uwsgi_Input_fileno,     METH_VARARGS, 0 },
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
	size_t content_len;

	struct wsgi_request *wsgi_req = current_wsgi_req();

	data = PyTuple_GetItem(args, 0);
	if (PyString_Check(data)) {
		content = PyString_AsString(data);
		content_len = PyString_Size(data);
		if (content_len > 0 && !wsgi_req->headers_sent) {
                        if (uwsgi_python_do_send_headers(wsgi_req)) {
                                return NULL;
                        }
                }
		UWSGI_RELEASE_GIL
			wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, content, content_len);
		UWSGI_GET_GIL
		// this is a special case for the write callable
		// no need to honout write-errors-exception-only
		if (wsgi_req->write_errors > uwsgi.write_errors_tolerance && !uwsgi.disable_write_exception) {
                        uwsgi_py_write_set_exception(wsgi_req);
			return NULL;
		}
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

	struct uwsgi_app *wi;

	int tmp_stderr;
	int free_appid = 0;

#ifdef UWSGI_ASYNC
	if (wsgi_req->async_status == UWSGI_AGAIN) {
		wi = &uwsgi_apps[wsgi_req->app_id];
		UWSGI_GET_GIL
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
		int ret = manage_python_response(wsgi_req);
		if (ret == UWSGI_OK) goto end;
		UWSGI_RELEASE_GIL
		return ret;
	}
#endif


	/* Standard WSGI request */
	if (!wsgi_req->uh.pktsize) {
		uwsgi_log( "Empty python request. skip.\n");
		return -1;
	}

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}


	if (wsgi_req->appid_len == 0) {
		if (!uwsgi.ignore_script_name) {
			wsgi_req->appid = wsgi_req->script_name;
			wsgi_req->appid_len = wsgi_req->script_name_len;
		}

		if (uwsgi.vhost) {
			wsgi_req->appid = uwsgi_concat3n(wsgi_req->host, wsgi_req->host_len, "|",1, wsgi_req->script_name, wsgi_req->script_name_len);
			wsgi_req->appid_len = wsgi_req->host_len + 1 + wsgi_req->script_name_len;
#ifdef UWSGI_DEBUG
			uwsgi_debug("VirtualHost KEY=%.*s\n", wsgi_req->appid_len, wsgi_req->appid);
#endif
			free_appid = 1;
		}
	}


	if ( (wsgi_req->app_id = uwsgi_get_app_id(wsgi_req->appid, wsgi_req->appid_len, 0))  == -1) {
		wsgi_req->app_id = uwsgi.default_app;
		if (uwsgi.no_default_app) {
                	wsgi_req->app_id = -1;
        	}
		if (wsgi_req->dynamic) {
			// this part must be heavy locked in threaded modes
			if (uwsgi.threads > 1) {
				pthread_mutex_lock(&up.lock_pyloaders);
			}

			UWSGI_GET_GIL
			if (uwsgi.single_interpreter) {
				wsgi_req->app_id = init_uwsgi_app(LOADER_DYN, (void *) wsgi_req, wsgi_req, up.main_thread, PYTHON_APP_TYPE_WSGI);
			}
			else {
				wsgi_req->app_id = init_uwsgi_app(LOADER_DYN, (void *) wsgi_req, wsgi_req, NULL, PYTHON_APP_TYPE_WSGI);
			}
			UWSGI_RELEASE_GIL
			if (uwsgi.threads > 1) {
				pthread_mutex_unlock(&up.lock_pyloaders);
			}
		}
	}

	if (free_appid) {
		free(wsgi_req->appid);
	}

	if (wsgi_req->app_id == -1) {
		internal_server_error(wsgi_req, "Python application not found");
		goto clear2;
	}

	wi = &uwsgi_apps[wsgi_req->app_id];

	up.swap_ts(wsgi_req, wi);

	
	if (wi->chdir[0] != 0) {
#ifdef UWSGI_DEBUG
		uwsgi_debug("chdir to %s\n", wi->chdir);
#endif
		if (chdir(wi->chdir)) {
			uwsgi_error("chdir()");
		}
	}


	UWSGI_GET_GIL

	// no fear of race conditions for this counter as it is already protected by the GIL
	wi->requests++;

	// create WSGI environ
	wsgi_req->async_environ = up.wsgi_env_create(wsgi_req, wi);


	wsgi_req->async_result = wi->request_subhandler(wsgi_req, wi);


	if (wsgi_req->async_result) {


		while (wi->response_subhandler(wsgi_req) != UWSGI_OK) {
#ifdef UWSGI_ASYNC
			if (uwsgi.async > 1) {
				UWSGI_RELEASE_GIL
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

	else if (uwsgi.catch_exceptions) {

		// LOCK THIS PART

		wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, wsgi_req->protocol, wsgi_req->protocol_len);
		wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, " 500 Internal Server Error\r\n", 28 );
		wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, "Content-type: text/plain\r\n\r\n", 28 );
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

	// this object must be freed/cleared always
#ifdef UWSGI_ASYNC
end:
#endif
	if (wsgi_req->async_input) {
                Py_DECREF((PyObject *)wsgi_req->async_input);
        }
        if (wsgi_req->async_environ) {
		up.wsgi_env_destroy(wsgi_req);
        }

	UWSGI_RELEASE_GIL

clear:

	up.reset_ts(wsgi_req, wi);

clear2:

	return UWSGI_OK;

}

void uwsgi_after_request_wsgi(struct wsgi_request *wsgi_req) {

	if (up.after_req_hook) {
		if (uwsgi.harakiri_no_arh) {
			// leave harakiri mode
        		if (uwsgi.workers[uwsgi.mywid].harakiri > 0)
                		set_harakiri(0);
		}
		UWSGI_GET_GIL
		PyObject *arh = python_call(up.after_req_hook, up.after_req_hook_args, 0, NULL);
        	if (!arh) {
			PyErr_Print();
                }
		else {
			Py_DECREF(arh);
		}
		PyErr_Clear();
		UWSGI_RELEASE_GIL
	}

	log_request(wsgi_req);
}

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

void threaded_swap_ts(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {

	if (uwsgi.single_interpreter == 0 && wi->interpreter != up.main_thread) {
		UWSGI_GET_GIL
                PyThreadState_Swap(uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].ts[wsgi_req->app_id]);
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

void simple_threaded_reset_ts(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {
	if (uwsgi.single_interpreter == 0 && wi->interpreter != up.main_thread) {
        	// restoring main interpreter
		UWSGI_GET_GIL
                PyThreadState_Swap(up.main_thread);
		UWSGI_RELEASE_GIL
	}
}


void simple_threaded_swap_ts(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {

	if (uwsgi.single_interpreter == 0 && wi->interpreter != up.main_thread) {
                // set the interpreter
		UWSGI_GET_GIL
                PyThreadState_Swap(wi->interpreter);
		UWSGI_RELEASE_GIL
	}
}
