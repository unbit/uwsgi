#include "uwsgi.h"

static int uwsgi_sendfile(struct uwsgi_server *, int , int ) ;

int uwsgi_request_wsgi (struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, char *buffer) {

	char *ptrbuf;
	char *bufferend;
	uint16_t strsize = 0;
	FILE *wsgi_file;
	int i;

	struct uwsgi_app *wi;

	PyObject *zero, *wsgi_socket;

	PyObject *pydictkey, *pydictvalue;

	char *path_info;

	PyObject *wsgi_result, *wsgi_chunks, *wchunk;

	/* Standard WSGI request */
	if (!wsgi_req->size) {
		fprintf (stderr, "Invalid WSGI request. skip.\n");
		return -1;
	}

	ptrbuf = buffer;
	bufferend = ptrbuf + wsgi_req->size;

	/* set an HTTP 500 status as default */
	wsgi_req->status = 500;



	while (ptrbuf < bufferend) {
		if (ptrbuf + 2 < bufferend) {
			memcpy (&strsize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
			strsize = uwsgi_swap16 (strsize);
#endif
			ptrbuf += 2;
			if (ptrbuf + strsize < bufferend) {
				// var key
				uwsgi->hvec[wsgi_req->var_cnt].iov_base = ptrbuf;
				uwsgi->hvec[wsgi_req->var_cnt].iov_len = strsize;
				ptrbuf += strsize;
				if (ptrbuf + 2 < bufferend) {
					memcpy (&strsize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
					strsize = uwsgi_swap16 (strsize);
#endif
					ptrbuf += 2;
					if (ptrbuf + strsize <= bufferend) {
#ifndef ROCK_SOLID
#ifdef UNBIT
						if (single_app_mode == 0 && !strncmp ("SCRIPT_NAME", uwsgi->hvec[wsgi_req->var_cnt].iov_base, uwsgi->hvec[wsgi_req->var_cnt].iov_len)) {
#else
						if (!strncmp ("SCRIPT_NAME", uwsgi->hvec[wsgi_req->var_cnt].iov_base, uwsgi->hvec[wsgi_req->var_cnt].iov_len)) {
#endif
							// set the request app_id
							// LOCKED SECTION
							if (strsize > 0) {
								if (uwsgi->has_threads && !uwsgi->i_have_gil) {
									PyEval_RestoreThread (uwsgi->_save);
									uwsgi->i_have_gil = 1;
								}
								zero = PyString_FromStringAndSize (ptrbuf, strsize);
								if (PyDict_Contains (uwsgi->py_apps, zero)) {
									wsgi_req->app_id = PyInt_AsLong (PyDict_GetItem (uwsgi->py_apps, zero));
								}
								else {
									/* unavailable app for this SCRIPT_NAME */
									wsgi_req->app_id = -1;
								}
								Py_DECREF (zero);
								if (uwsgi->has_threads && uwsgi->options[UWSGI_OPTION_THREADS] == 1) {
									uwsgi->_save = PyEval_SaveThread ();
									uwsgi->i_have_gil = 0;
								}
							}
							// UNLOCK
						}
						else if (!strncmp ("SERVER_PROTOCOL", uwsgi->hvec[wsgi_req->var_cnt].iov_base, uwsgi->hvec[wsgi_req->var_cnt].iov_len)) {
#else
						if (!strncmp ("SERVER_PROTOCOL", uwsgi->hvec[wsgi_req->var_cnt].iov_base, uwsgi->hvec[wsgi_req->var_cnt].iov_len)) {
#endif
							wsgi_req->protocol = ptrbuf;
							wsgi_req->protocol_len = strsize;
						}
						else if (!strncmp ("REQUEST_URI", uwsgi->hvec[wsgi_req->var_cnt].iov_base, uwsgi->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->uri = ptrbuf;
							wsgi_req->uri_len = strsize;
						}
						else if (!strncmp ("QUERY_STRING", uwsgi->hvec[wsgi_req->var_cnt].iov_base, uwsgi->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->query_string = ptrbuf;
							wsgi_req->query_string_len = strsize;
						}
						else if (!strncmp ("REQUEST_METHOD", uwsgi->hvec[wsgi_req->var_cnt].iov_base, uwsgi->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->method = ptrbuf;
							wsgi_req->method_len = strsize;
						}
						else if (!strncmp ("REMOTE_ADDR", uwsgi->hvec[wsgi_req->var_cnt].iov_base, uwsgi->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->remote_addr = ptrbuf;
							wsgi_req->remote_addr_len = strsize;
						}
						else if (!strncmp ("REMOTE_USER", uwsgi->hvec[wsgi_req->var_cnt].iov_base, uwsgi->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->remote_user = ptrbuf;
							wsgi_req->remote_user_len = strsize;
						}
#ifdef UNBIT
						else if (!strncmp ("UNBIT_FLAGS", uwsgi->hvec[wsgi_req->var_cnt].iov_base, uwsgi->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->unbit_flags = *(unsigned long long *) ptrbuf;
						}
#endif
						if (wsgi_req->var_cnt < uwsgi->vec_size - (4 + 1)) {
							wsgi_req->var_cnt++;
						}
						else {
							fprintf (stderr, "max vec size reached. skip this header.\n");
							break;
						}
						// var value
						uwsgi->hvec[wsgi_req->var_cnt].iov_base = ptrbuf;
						uwsgi->hvec[wsgi_req->var_cnt].iov_len = strsize;
						if (wsgi_req->var_cnt < uwsgi->vec_size - (4 + 1)) {
							wsgi_req->var_cnt++;
						}
						else {
							fprintf (stderr, "max vec size reached. skip this header.\n");
							break;
						}
						ptrbuf += strsize;
					}
					else {
						break;
					}
				}
				else {
					break;
				}
			}
		}
		else {
			break;
		}
	}



#ifndef ROCK_SOLID
	if (uwsgi->has_threads && !uwsgi->i_have_gil) {
		PyEval_RestoreThread (uwsgi->_save);
		uwsgi->i_have_gil = 1;
	}
#endif


	wsgi_file = fdopen (uwsgi->poll.fd, "r");

#ifndef ROCK_SOLID

#ifndef UNBIT
	if (wsgi_req->app_id == -1 && uwsgi->xml_config == NULL) {
#else
	if (wsgi_req->app_id == -1 && uwsgi->wsgi_config == NULL) {
#endif
		for (i = 0; i < wsgi_req->var_cnt; i += 2) {
			if (!strncmp ("SCRIPT_NAME", uwsgi->hvec[i].iov_base, uwsgi->hvec[i].iov_len)) {
				wsgi_req->script_name = uwsgi->hvec[i + 1].iov_base;
				wsgi_req->script_name_len = uwsgi->hvec[i + 1].iov_len;
			}
			if (!strncmp ("UWSGI_SCRIPT", uwsgi->hvec[i].iov_base, uwsgi->hvec[i].iov_len)) {
				wsgi_req->wsgi_script = uwsgi->hvec[i + 1].iov_base;
				wsgi_req->wsgi_script_len = uwsgi->hvec[i + 1].iov_len;
			}
			if (!strncmp ("UWSGI_MODULE", uwsgi->hvec[i].iov_base, uwsgi->hvec[i].iov_len)) {
				wsgi_req->wsgi_module = uwsgi->hvec[i + 1].iov_base;
				wsgi_req->wsgi_module_len = uwsgi->hvec[i + 1].iov_len;
			}
			if (!strncmp ("UWSGI_CALLABLE", uwsgi->hvec[i].iov_base, uwsgi->hvec[i].iov_len)) {
				wsgi_req->wsgi_callable = uwsgi->hvec[i + 1].iov_base;
				wsgi_req->wsgi_callable_len = uwsgi->hvec[i + 1].iov_len;
			}
		}



		if (wsgi_req->wsgi_script_len > 0 || (wsgi_req->wsgi_callable_len > 0 && wsgi_req->wsgi_module_len > 0)) {
			if ((wsgi_req->app_id = init_uwsgi_app (NULL, NULL)) == -1) {
				internal_server_error (uwsgi->poll.fd, "wsgi application not found");
				goto clean;
			}
		}
	}


	if (wsgi_req->app_id == -1) {
		internal_server_error (uwsgi->poll.fd, "wsgi application not found");
		goto clean;
	}


	wi = &uwsgi->wsgi_apps[wsgi_req->app_id];

	if (uwsgi->single_interpreter == 0) {
		if (!wi->interpreter) {
			internal_server_error (uwsgi->poll.fd, "wsgi application's %d interpreter not found");
			goto clean;
		}

		// set the interpreter
		PyThreadState_Swap (wi->interpreter);
	}


#endif


	if (wsgi_req->protocol_len < 5) {
		fprintf (stderr, "INVALID PROTOCOL: %.*s", wsgi_req->protocol_len, wsgi_req->protocol);
		internal_server_error (uwsgi->poll.fd, "invalid HTTP protocol !!!");
		goto clean;
	}
	if (strncmp (wsgi_req->protocol, "HTTP/", 5)) {
		fprintf (stderr, "INVALID PROTOCOL: %.*s", wsgi_req->protocol_len, wsgi_req->protocol);
		internal_server_error (uwsgi->poll.fd, "invalid HTTP protocol !!!");
		goto clean;
	}


	for (i = 0; i < wsgi_req->var_cnt; i += 2) {
		/*fprintf(stderr,"%.*s: %.*s\n", uwsgi->hvec[i].iov_len, uwsgi->hvec[i].iov_base, uwsgi->hvec[i+1].iov_len, uwsgi->hvec[i+1].iov_base); */
		pydictkey = PyString_FromStringAndSize (uwsgi->hvec[i].iov_base, uwsgi->hvec[i].iov_len);
		pydictvalue = PyString_FromStringAndSize (uwsgi->hvec[i + 1].iov_base, uwsgi->hvec[i + 1].iov_len);
		PyDict_SetItem (wi->wsgi_environ, pydictkey, pydictvalue);
		Py_DECREF (pydictkey);
		Py_DECREF (pydictvalue);
	}

	if (wsgi_req->modifier == UWSGI_MODIFIER_MANAGE_PATH_INFO) {
		pydictkey = PyDict_GetItemString (wi->wsgi_environ, "SCRIPT_NAME");
		if (pydictkey) {
			if (PyString_Check (pydictkey)) {
				pydictvalue = PyDict_GetItemString (wi->wsgi_environ, "PATH_INFO");
				if (pydictvalue) {
					if (PyString_Check (pydictvalue)) {
						path_info = PyString_AsString (pydictvalue);
						PyDict_SetItemString (wi->wsgi_environ, "PATH_INFO", PyString_FromString (path_info + PyString_Size (pydictkey)));
					}
				}
			}
		}
	}


	// set wsgi vars

	wsgi_socket = PyFile_FromFile (wsgi_file, "wsgi_input", "r", NULL);
	PyDict_SetItemString (wi->wsgi_environ, "wsgi.input", wsgi_socket);
	Py_DECREF (wsgi_socket);

#ifndef ROCK_SOLID
	PyDict_SetItemString (wi->wsgi_environ, "wsgi.file_wrapper", wi->wsgi_sendfile);
#endif

	zero = PyTuple_New (2);
	PyTuple_SetItem (zero, 0, PyInt_FromLong (1));
	PyTuple_SetItem (zero, 1, PyInt_FromLong (0));
	PyDict_SetItemString (wi->wsgi_environ, "wsgi.version", zero);
	Py_DECREF (zero);

	zero = PyFile_FromFile (stderr, "wsgi_input", "w", NULL);
	PyDict_SetItemString (wi->wsgi_environ, "wsgi.errors", zero);
	Py_DECREF (zero);

	PyDict_SetItemString (wi->wsgi_environ, "wsgi.run_once", Py_False);

	PyDict_SetItemString (wi->wsgi_environ, "wsgi.multithread", Py_False);
	if (uwsgi->numproc == 1) {
		PyDict_SetItemString (wi->wsgi_environ, "wsgi.multiprocess", Py_False);
	}
	else {
		PyDict_SetItemString (wi->wsgi_environ, "wsgi.multiprocess", Py_True);
	}

	zero = PyString_FromString ("http");
	PyDict_SetItemString (wi->wsgi_environ, "wsgi.url_scheme", zero);
	Py_DECREF (zero);

#ifdef UNBIT
	if (wsgi_req->unbit_flags & (unsigned long long) 1) {
		if (uri_to_hex () <= 0) {
			tmp_filename[0] = 0;
		}
	}
#endif


	// call
#ifndef ROCK_SOLID
	if (uwsgi->enable_profiler == 1) {
		wsgi_result = PyEval_CallObject (wi->wsgi_cprofile_run, wi->wsgi_args);
		if (PyErr_Occurred ()) {
			PyErr_Print ();
		}
		if (wsgi_result) {
			Py_DECREF (wsgi_result);
			wsgi_result = PyDict_GetItemString (wi->pymain_dict, "uwsgi_out");
		}
	}
	else {
#endif

		wsgi_result = PyEval_CallObject (wi->wsgi_callable, wi->wsgi_args);

		if (PyErr_Occurred ()) {
			PyErr_Print ();
		}
#ifndef ROCK_SOLID
	}
#endif




	if (wsgi_result) {


#ifndef ROCK_SOLID
		if (wsgi_req->sendfile_fd > -1) {
			wsgi_req->response_size = uwsgi_sendfile(uwsgi, wsgi_req->sendfile_fd, uwsgi->poll.fd);
		}
		else {

#endif

			wsgi_chunks = PyObject_GetIter (wsgi_result);
			if (wsgi_chunks) {
				while ((wchunk = PyIter_Next (wsgi_chunks))) {
					if (PyString_Check (wchunk)) {
						if ((i = write (uwsgi->poll.fd, PyString_AsString (wchunk), PyString_Size (wchunk))) < 0) {
							perror ("write()");
						}
						wsgi_req->response_size += i;
#ifdef UNBIT
						if (save_to_disk >= 0) {
							if (write (save_to_disk, PyString_AsString (wchunk), PyString_Size (wchunk)) < 0) {
								perror ("write()");
								close (save_to_disk);
								save_to_disk = -1;
								unlinkat (tmp_dir_fd, tmp_filename, 0);
							}
						}
#endif
					}
					else {
						fprintf (stderr, "invalid output returned by the wsgi callable !!!\n");
					}
					Py_DECREF (wchunk);
				}

				if (PyErr_Occurred ()) {
					PyErr_Print ();
				}

#ifdef UNBIT
				else if (save_to_disk >= 0) {
					close (save_to_disk);
					save_to_disk = -1;
					fprintf (stderr, "[uWSGI cacher] output of request %llu (%.*s) on pid %d written to cache file %s\n", uwsgi->workers[0].requests + 1, wsgi_req->uri_len, wsgi_req->uri, uwsgi->mypid, tmp_filename);
				}
#endif
				Py_DECREF (wsgi_chunks);
			}
#ifndef ROCK_SOLID
		}
		if (uwsgi->enable_profiler == 0) {
#endif
			Py_DECREF (wsgi_result);
#ifndef ROCK_SOLID
		}
#endif
	}



	PyDict_Clear (wi->wsgi_environ);
#ifndef ROCK_SOLID
	wi->requests++;
#endif
	PyErr_Clear ();
	if (uwsgi->options[UWSGI_OPTION_HARAKIRI] > 0) {
		set_harakiri (0);
	}
#ifndef ROCK_SOLID
	if (uwsgi->single_interpreter == 0) {
		// restoring main interpreter
		PyThreadState_Swap (uwsgi->main_thread);
	}
#endif
      clean:
	fclose (wsgi_file);
#ifndef ROCK_SOLID
	if (uwsgi->has_threads && uwsgi->options[UWSGI_OPTION_THREADS] == 1) {
		uwsgi->_save = PyEval_SaveThread ();
		uwsgi->i_have_gil = 0;
	}
#endif
	uwsgi->workers[uwsgi->mywid].requests++;

	return 0;

}

void uwsgi_after_request_wsgi (struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, char *buffer) {

	if (uwsgi->options[UWSGI_OPTION_LOGGING])
		log_request(wsgi_req) ;
}

#ifndef ROCK_SOLID
static int uwsgi_sendfile(struct uwsgi_server *uwsgi, int fd, int sockfd) {

	int rlen,i ;

#ifdef __sun__
	struct stat stat_buf;
        if (fstat(fd, &stat_buf)) {
        	perror("fstat()");
                return 0;
        }
        else {
        	rlen = stat_buf.st_size ;
        }
#else
        rlen = lseek(fd, 0, SEEK_END) ;
#endif

	if (rlen > 0) {
        	lseek(fd, 0, SEEK_SET) ;
#if !defined(__linux__) && !defined(__sun__)
        #if defined(__FreeBSD__) || defined(__DragonFly__)

		if (sendfile(fd, sockfd, 0, 0, NULL, (off_t *) &rlen, 0)) {
                	perror("sendfile()");
                }
        #elif __APPLE__
                if (sendfile(fd, sockfd, 0, (off_t *) &rlen, NULL, 0)) {
                	perror("sendfile()");
                }
        #else
        	char *no_sendfile_buf[4096] ;
                int jlen = 0 ;
		rlen = 0 ;
                i = 0 ;
                while(i < rlen) {
                	jlen = read(fd, no_sendfile_buf, 4096);
                        if (jlen<=0) {
                        	perror("read()");
                                break;
                        }
                        i += jlen;
                        jlen = write(sockfd, no_sendfile_buf, jlen);
                        if (jlen<=0) {
                        	perror("write()");
                                break;
                        }
			rlen += jlen;
                }
        #endif
#else
		i = 0 ;
        	rlen = sendfile(sockfd, fd, (off_t *) &i, rlen) ;
#endif

	}
	Py_DECREF(uwsgi->py_sendfile);

	return rlen;
}
#endif
