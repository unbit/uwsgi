#include "uwsgi.h"

static int uwsgi_sendfile(struct uwsgi_server *, int, int);

static PyObject *wsgi_response(PyObject *chunks, struct wsgi_request *wsgi_req) {

	PyObject *wchunk ;
	ssize_t wsize ;

	wchunk = PyIter_Next(chunks) ;


	if (!wchunk) {
		if (PyErr_Occurred())
			PyErr_Print();
		return NULL;
	}

        if (PyString_Check(wchunk)) {
        	if ((wsize = write(wsgi_req->poll.fd, PyString_AsString(wchunk), PyString_Size(wchunk))) < 0) {
                	perror("write()");
			return NULL;
                }
                wsgi_req->response_size += wsize;

#ifdef UNBIT
                                                if (save_to_disk >= 0) {
                                                        if (write(save_to_disk, PyString_AsString(wchunk), PyString_Size(wchunk)) < 0) {
                                                                perror("write()");
                                                                close(save_to_disk);
                                                                save_to_disk = -1;
                                                                unlinkat(tmp_dir_fd, tmp_filename, 0);
                                                        }
                                                }
#endif


	}

	return wchunk;

}

static void wsgi_end(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	PyErr_Clear();

	Py_XDECREF(wsgi_req->async_placeholder);
	Py_XDECREF(wsgi_req->async_environ);
	fclose(wsgi_req->async_post);

#ifdef UWSGI_THREADING
	if (uwsgi->has_threads && uwsgi->shared->options[UWSGI_OPTION_THREADS] == 1) {
		uwsgi->_save = PyEval_SaveThread();
		uwsgi->workers[uwsgi->mywid].i_have_gil = 0;
	}
#endif

}

int uwsgi_request_wsgi(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int i;
	struct uwsgi_app *wi;

	PyObject *zero, *wsgi_socket;

	PyObject *pydictkey, *pydictvalue;

	char *path_info;

	PyObject *wchunk;


#ifdef UWSGI_ASYNC
	if (wsgi_req->async_status == UWSGI_AGAIN) {
		wchunk = wsgi_response(wsgi_req->async_placeholder, wsgi_req);
		if (!wchunk) {
			wsgi_end(uwsgi, wsgi_req);
			return UWSGI_OK ;
		}
		Py_DECREF(wchunk);
		wsgi_req->async_switches++;
		return UWSGI_AGAIN ;
	}
#endif

	/* Standard WSGI request */
	if (!wsgi_req->size) {
		fprintf(stderr, "Invalid WSGI request. skip.\n");
		return -1;
	}

	if (uwsgi_parse_vars(uwsgi, wsgi_req)) {
                fprintf(stderr,"Invalid WSGI request. skip.\n");
                return -1;
        }


#ifdef UWSGI_THREADING
	if (uwsgi->has_threads && !uwsgi->workers[uwsgi->mywid].i_have_gil) {
		PyEval_RestoreThread(uwsgi->_save);
		uwsgi->workers[uwsgi->mywid].i_have_gil = 1;
	}
#endif


	if (wsgi_req->script_name_len > 0) {
		zero = PyString_FromStringAndSize(wsgi_req->script_name, wsgi_req->script_name_len);
		if (PyDict_Contains(uwsgi->py_apps, zero)) {
                	wsgi_req->app_id = PyInt_AsLong(PyDict_GetItem(uwsgi->py_apps, zero));
                }
                else {
                	/* unavailable app for this SCRIPT_NAME */
                        wsgi_req->app_id = -1;
			if (wsgi_req->wsgi_script_len > 0 || (wsgi_req->wsgi_callable_len > 0 && wsgi_req->wsgi_module_len > 0)) {
				if ((wsgi_req->app_id = init_uwsgi_app(NULL, NULL)) == -1) {
					internal_server_error(wsgi_req->poll.fd, "wsgi application not found");
					wsgi_end(uwsgi, wsgi_req);
				}
			}
                }
                Py_DECREF(zero);
	} 


	if (wsgi_req->app_id == -1) {
		internal_server_error(wsgi_req->poll.fd, "wsgi application not found");
		wsgi_end(uwsgi, wsgi_req);

	}


	wi = &uwsgi->wsgi_apps[wsgi_req->app_id];

	if (uwsgi->single_interpreter == 0) {
		if (!wi->interpreter) {
			internal_server_error(wsgi_req->poll.fd, "wsgi application's %d interpreter not found");
			wsgi_end(uwsgi, wsgi_req);
		}

		// set the interpreter
		PyThreadState_Swap(wi->interpreter);
	}



	if (wsgi_req->protocol_len < 5) {
		fprintf(stderr, "INVALID PROTOCOL: %.*s", wsgi_req->protocol_len, wsgi_req->protocol);
		internal_server_error(wsgi_req->poll.fd, "invalid HTTP protocol !!!");
		wsgi_end(uwsgi, wsgi_req);

	}
	if (strncmp(wsgi_req->protocol, "HTTP/", 5)) {
		fprintf(stderr, "INVALID PROTOCOL: %.*s", wsgi_req->protocol_len, wsgi_req->protocol);
		internal_server_error(wsgi_req->poll.fd, "invalid HTTP protocol !!!");
		wsgi_end(uwsgi, wsgi_req);
	}


	wsgi_req->async_environ = PyDict_New();
	Py_INCREF(wsgi_req->async_environ);

	for (i = 0; i < wsgi_req->var_cnt; i += 2) {
		/*fprintf(stderr,"%.*s: %.*s\n", uwsgi->hvec[i].iov_len, uwsgi->hvec[i].iov_base, uwsgi->hvec[i+1].iov_len, uwsgi->hvec[i+1].iov_base); */
		pydictkey = PyString_FromStringAndSize(uwsgi->hvec[i].iov_base, uwsgi->hvec[i].iov_len);
		pydictvalue = PyString_FromStringAndSize(uwsgi->hvec[i + 1].iov_base, uwsgi->hvec[i + 1].iov_len);
		PyDict_SetItem(wsgi_req->async_environ, pydictkey, pydictvalue);
		Py_DECREF(pydictkey);
		Py_DECREF(pydictvalue);
	}

	if (wsgi_req->modifier == UWSGI_MODIFIER_MANAGE_PATH_INFO) {
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



	// set wsgi vars

	wsgi_req->async_post = fdopen(wsgi_req->poll.fd, "r");

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

#ifdef UNBIT
	if (wsgi_req->unbit_flags & (unsigned long long) 1) {
		if (uri_to_hex() <= 0) {
			tmp_filename[0] = 0;
		}
	}
#endif



	PyTuple_SetItem(wi->wsgi_args, 0, wsgi_req->async_environ);

	// call
#ifdef UWSGI_PROFILER
	if (uwsgi->enable_profiler == 1) {
		wsgi_req->async_result = PyEval_CallObject(wi->wsgi_cprofile_run, wi->wsgi_args);
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		if (wsgi_req->async_result) {
			Py_DECREF(wsgi_req->async_result);
			wsgi_req->async_result = PyDict_GetItemString(wi->pymain_dict, "uwsgi_out");
		}
	}
	else {
#endif

		wsgi_req->async_result = PyEval_CallObject(wi->wsgi_callable, wi->wsgi_args);

		if (PyErr_Occurred()) {
			PyErr_Print();
		}
#ifdef UWSGI_PROFILER
	}
#endif


	if (wsgi_req->async_result) {


#ifdef UWSGI_SENDFILE
		if (wsgi_req->sendfile_fd > -1) {
			wsgi_req->response_size = uwsgi_sendfile(uwsgi, wsgi_req->sendfile_fd, wsgi_req->poll.fd);
		}
		else {

#endif

			wsgi_req->async_placeholder = PyObject_GetIter(wsgi_req->async_result);
			if (wsgi_req->async_placeholder) {
				if (uwsgi->async > 1) {
					return UWSGI_AGAIN;
				}

				while ( (wchunk = wsgi_response(wsgi_req->async_placeholder, wsgi_req)) ) {
					wsgi_req->async_switches++;
					Py_DECREF(wchunk);
				}

				if (PyErr_Occurred()) {
					PyErr_Print();
				}


#ifdef UNBIT
				else if (save_to_disk >= 0) {
					close(save_to_disk);
					save_to_disk = -1;
					fprintf(stderr, "[uWSGI cacher] output of request %llu (%.*s) on pid %d written to cache file %s\n", uwsgi->workers[0].requests + 1, wsgi_req->uri_len, wsgi_req->uri, uwsgi->mypid, tmp_filename);
				}
#endif
			}

#ifdef UWSGI_SENDFILE
		}
#endif

	}


	wsgi_end(uwsgi, wsgi_req);

	wi->requests++;

	if (uwsgi->single_interpreter == 0) {
		// restoring main interpreter
		PyThreadState_Swap(uwsgi->main_thread);
	}


	return UWSGI_OK;

}

void uwsgi_after_request_wsgi(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	if (uwsgi->shared->options[UWSGI_OPTION_LOGGING])
		log_request(wsgi_req);
}

#ifdef UWSGI_SENDFILE
static int uwsgi_sendfile(struct uwsgi_server *uwsgi, int fd, int sockfd) {

	off_t rlen;

#ifdef __sun__
	struct stat stat_buf;
	if (fstat(fd, &stat_buf)) {
		perror("fstat()");
		return 0;
	}
	else {
		rlen = stat_buf.st_size;
	}
#else
	rlen = lseek(fd, 0, SEEK_END);
#endif

	if (rlen > 0) {
		lseek(fd, 0, SEEK_SET);
#if !defined(__linux__) && !defined(__sun__)
#if defined(__FreeBSD__) || defined(__DragonFly__)

		if (sendfile(fd, sockfd, 0, 0, NULL, &rlen, 0)) {
			perror("sendfile()");
		}
#elif __APPLE__
		if (sendfile(fd, sockfd, 0, &rlen, NULL, 0)) {
			perror("sendfile()");
		}
#else
		ssize_t i = 0;
		char *no_sendfile_buf[4096];
		ssize_t jlen = 0;
		rlen = 0;
		i = 0;
		while (i < rlen) {
			jlen = read(fd, no_sendfile_buf, 4096);
			if (jlen <= 0) {
				perror("read()");
				break;
			}
			i += jlen;
			jlen = write(sockfd, no_sendfile_buf, jlen);
			if (jlen <= 0) {
				perror("write()");
				break;
			}
			rlen += jlen;
		}
#endif
#else
		off_t sf_ot = 0;
		rlen = sendfile(sockfd, fd, &sf_ot, rlen);
#endif

	}
	Py_DECREF(uwsgi->py_sendfile);

	return rlen;
}
#endif
