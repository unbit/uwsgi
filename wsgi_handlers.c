#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

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
        int fd, timeout;

	struct wsgi_request *wsgi_req = current_wsgi_req();

        if (!PyArg_ParseTuple(args, "i|i", &fd, &timeout)) {
                return NULL;
        }

        if (fd >= 0) {
                wsgi_req->async_waiting_fd = fd ;
                wsgi_req->async_waiting_fd_type = ASYNC_IN ;
                wsgi_req->async_waiting_fd_monitored = 0 ;
        }

        return PyString_FromString("") ;
}


PyObject *py_eventfd_write(PyObject * self, PyObject * args) {
        int fd, timeout;

	struct wsgi_request *wsgi_req = current_wsgi_req();

        if (!PyArg_ParseTuple(args, "i|i", &fd, &timeout)) {
                return NULL;
        }

        if (fd >= 0) {
                wsgi_req->async_waiting_fd = fd ;
                wsgi_req->async_waiting_fd_type = ASYNC_OUT ;
                wsgi_req->async_waiting_fd_monitored = 0 ;
        }

        return PyString_FromString("") ;
}
#endif

int uwsgi_request_wsgi(struct wsgi_request *wsgi_req) {

	int i;
	
	size_t post_remains = wsgi_req->post_cl;
	ssize_t post_chunk;

	PyObject *pydictkey, *pydictvalue;

	char *path_info;
	struct uwsgi_app *wi ;

	int tmp_stderr;
	char *what;
	int what_len;

#ifdef UWSGI_ASYNC
	if (wsgi_req->async_status == UWSGI_AGAIN) {
		// get rid of timeout
		if (wsgi_req->async_timeout_expired) {
			PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.fdevent.timeout", Py_True);
			wsgi_req->async_timeout_expired = 0 ;
		}
		else {
			PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.fdevent.timeout", Py_None);
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
                uwsgi_log("Invalid WSGI request. skip.\n");
                return -1;
        }

	if (uwsgi.limit_post) {
		if (wsgi_req->post_cl > uwsgi.limit_post) {
                	uwsgi_log("Invalid (too big) CONTENT_LENGTH. skip.\n");
                	return -1;
		}
	}


	if (!uwsgi.ignore_script_name) {

		if (!wsgi_req->script_name)
			wsgi_req->script_name = "";

		if (uwsgi.vhost) {
			what = uwsgi_concat3n(wsgi_req->host, wsgi_req->host_len, "|",1, wsgi_req->script_name, wsgi_req->script_name_len);
			what_len = wsgi_req->host_len + 1 + wsgi_req->script_name_len ;
#ifdef UWSGI_DEBUG
			uwsgi_debug("VirtualHost SCRIPT_NAME=%s\n", what); 
#endif
		}
		else {
			what = wsgi_req->script_name;
			what_len = wsgi_req->script_name_len ;
		}


		if ( (wsgi_req->app_id = uwsgi_get_app_id(what, what_len))  == -1) {
        		if (wsgi_req->script_name_len > 1 || uwsgi.default_app < 0 || uwsgi.vhost) {
        			/* unavailable app for this SCRIPT_NAME */
                		wsgi_req->app_id = -1;
				if (wsgi_req->wsgi_script_len > 0
						|| wsgi_req->wsgi_module_len > 0
						|| wsgi_req->wsgi_file_len > 0
#ifdef UWSGI_PASTE
						|| wsgi_req->wsgi_paste_len > 0
#endif
				) {
					// a bit of magic: 1-1 = 0 / 0-1 = -1
					// this part must be heavy locked in threaded modes
					if (uwsgi.threads > 1) {
						pthread_mutex_lock(&uwsgi.lock_pyloaders);
					}
					UWSGI_GET_GIL
					wsgi_req->app_id = init_uwsgi_app(LOADER_DYN, (void *) wsgi_req, wsgi_req, uwsgi.single_interpreter-1);
					UWSGI_RELEASE_GIL
					if (uwsgi.threads > 1) {
						pthread_mutex_unlock(&uwsgi.lock_pyloaders);
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
			wsgi_req->app_id = uwsgi.default_app ;
		}
		else {
			internal_server_error(wsgi_req->poll.fd, "wsgi application not found");
			goto clear2;
		}

	}

	wi = &uwsgi.apps[wsgi_req->app_id];

	if (uwsgi.single_interpreter == 0 && wsgi_req->app_id > 0) {
		if (!wi->interpreter) {
			internal_server_error(wsgi_req->poll.fd, "wsgi application's %d interpreter not found");
			goto clear2;
		}

		// set the interpreter
		UWSGI_GET_GIL
		if (uwsgi.threads > 1) {
			PyThreadState_Swap(uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id]->ts[wsgi_req->app_id]);
		}
		else {
			PyThreadState_Swap(wi->interpreter);
		}
		UWSGI_RELEASE_GIL
		if (wi->chdir) {
#ifdef UWSGI_DEBUG
			uwsgi_debug("chdir to %s\n", wi->chdir);
#endif
			if (chdir(wi->chdir)) {
				uwsgi_error("chdir()");
			}
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
	wsgi_req->async_environ = wi->wsgi_environ[wsgi_req->async_id];
	wsgi_req->async_args = wi->wsgi_args[wsgi_req->async_id];
#else
	wsgi_req->async_environ = wi->wsgi_environ;
	wsgi_req->async_args = wi->wsgi_args;
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
		pydictkey = PyUnicode_DecodeLatin1(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, "ignore");
		pydictvalue = PyUnicode_DecodeLatin1(wsgi_req->hvec[i + 1].iov_base, wsgi_req->hvec[i + 1].iov_len, "ignore");
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





	if (uwsgi.post_buffering > 0 && wsgi_req->post_cl > (size_t) uwsgi.post_buffering) {
		UWSGI_RELEASE_GIL
		wsgi_req->async_post = tmpfile();
		if (!wsgi_req->async_post) {
			uwsgi_error("tmpfile()");
			goto clear;
		}
		

		while(post_remains > 0) {
			if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
				inc_harakiri(uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
			}
			if (post_remains > (size_t) uwsgi.post_buffering_bufsize) {
				post_chunk = read(wsgi_req->poll.fd, wsgi_req->post_buffering_buf, uwsgi.post_buffering_bufsize);
			}
			else {
				post_chunk = read(wsgi_req->poll.fd, wsgi_req->post_buffering_buf, post_remains);
			}	
			if (post_chunk < 0) {
				uwsgi_error("read()");
				goto clear;
			}
			if (!fwrite(wsgi_req->post_buffering_buf, post_chunk, 1, wsgi_req->async_post)) {
				uwsgi_error("fwrite()");
				goto clear;
			}
			post_remains -= post_chunk;
		}
		rewind(wsgi_req->async_post);
		UWSGI_GET_GIL
	} 
	else {
		wsgi_req->async_post = fdopen(wsgi_req->poll.fd, "r");
	}


	wsgi_req->async_result = (*wi->request_subhandler)(wsgi_req, wi);


	if (wsgi_req->async_result) {


		UWSGI_RELEASE_GIL
		while ( (*wi->response_subhandler)(wsgi_req) != UWSGI_OK) {
			wsgi_req->switches++;
#ifdef UWSGI_ASYNC
			if (uwsgi.async > 1) {
				return UWSGI_AGAIN;
			}
#endif
		}


	}

	else if (uwsgi.catch_exceptions) {

		// LOCK THIS PART

		wsgi_req->response_size += write(wsgi_req->poll.fd, wsgi_req->protocol, wsgi_req->protocol_len);
		wsgi_req->response_size += write(wsgi_req->poll.fd, " 500 Internal Server Error\r\n", 28 );
		wsgi_req->response_size += write(wsgi_req->poll.fd, "Content-type: text/plain\r\n\r\n", 28 );
		wsgi_req->header_cnt = 1 ;
		
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
		PyErr_Print();
		// ...resume the original stderr, in case of error we are damaged forever !!!
		if (dup2(tmp_stderr, 2) < 0) {
			uwsgi_error("dup2()");
		}
		close(tmp_stderr);	
	}


clear:

	UWSGI_GET_GIL

	if (uwsgi.single_interpreter == 0 && wsgi_req->app_id > 0) {
		// restoring main interpreter
		if (uwsgi.threads > 1) {
			PyThreadState_Swap((PyThreadState *) pthread_getspecific(uwsgi.ut_save_key));
		}
		else {
			PyThreadState_Swap(uwsgi.main_thread);
		}
	}

	UWSGI_RELEASE_GIL

clear2:


	return UWSGI_OK;

}

void uwsgi_after_request_wsgi(struct wsgi_request *wsgi_req) {

	if (uwsgi.shared->options[UWSGI_OPTION_LOGGING]) {
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
