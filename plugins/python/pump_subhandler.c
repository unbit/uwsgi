#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;
extern PyTypeObject uwsgi_InputType;


extern struct http_status_codes hsc[];


void *uwsgi_request_subhandler_pump(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {

	PyObject *zero;

	int i;
        PyObject *pydictkey, *pydictvalue;

	char *port = memchr(wsgi_req->host, ':', wsgi_req->host_len);
	if (port) {

		zero = PyString_FromStringAndSize(wsgi_req->host, (port-wsgi_req->host));
		PyDict_SetItemString(wsgi_req->async_environ, "server_name", zero);
		Py_DECREF(zero);

		zero = PyString_FromStringAndSize(port, wsgi_req->host_len-((port+1)-wsgi_req->host));
		PyDict_SetItemString(wsgi_req->async_environ, "server_port", zero);
		Py_DECREF(zero);
	}
	else {

		zero = PyString_FromStringAndSize(wsgi_req->host, wsgi_req->host_len);
		PyDict_SetItemString(wsgi_req->async_environ, "server_name", zero);
		Py_DECREF(zero);

		zero = PyString_FromStringAndSize("80", 2);
		PyDict_SetItemString(wsgi_req->async_environ, "server_port", zero);
		Py_DECREF(zero);
	}

	zero = PyString_FromStringAndSize(wsgi_req->remote_addr, wsgi_req->remote_addr_len);
	PyDict_SetItemString(wsgi_req->async_environ, "remote_addr", zero);
	Py_DECREF(zero);

	zero = PyString_FromStringAndSize(wsgi_req->path_info, wsgi_req->path_info_len);
	PyDict_SetItemString(wsgi_req->async_environ, "uri", zero);
	Py_DECREF(zero);

	if (wsgi_req->query_string_len > 0) {
		zero = PyString_FromStringAndSize(wsgi_req->query_string, wsgi_req->query_string_len);
		PyDict_SetItemString(wsgi_req->async_environ, "query_string", zero);
		Py_DECREF(zero);
	}

	zero = PyString_FromStringAndSize(uwsgi_lower(wsgi_req->method, wsgi_req->method_len), wsgi_req->method_len);
	PyDict_SetItemString(wsgi_req->async_environ, "method", zero);
	Py_DECREF(zero);

	if (wsgi_req->post_cl > 0) {
		PyDict_SetItemString(wsgi_req->async_environ, "content_length", PyInt_FromLong(wsgi_req->post_cl));
		if (wsgi_req->content_type_len > 0) {
			zero = PyString_FromStringAndSize(wsgi_req->content_type, wsgi_req->content_type_len);
                	PyDict_SetItemString(wsgi_req->async_environ, "content_type", zero);
                	Py_DECREF(zero);
		}
	}



	PyObject *headers = PyDict_New();

        for (i = 0; i < wsgi_req->var_cnt; i += 2) {
#ifdef UWSGI_DEBUG
                uwsgi_debug("%.*s: %.*s\n", wsgi_req->hvec[i].iov_len, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i+1].iov_len, wsgi_req->hvec[i+1].iov_base);
#endif
		if (wsgi_req->hvec[i].iov_len < 6) continue;
		if (!uwsgi_startswith(wsgi_req->hvec[i].iov_base, "HTTP_", 5)) {
			(void) uwsgi_lower(wsgi_req->hvec[i].iov_base+5, wsgi_req->hvec[i].iov_len-5);
#ifdef PYTHREE
                	pydictkey = PyUnicode_DecodeLatin1(wsgi_req->hvec[i].iov_base+5, wsgi_req->hvec[i].iov_len-5, NULL);
                	pydictvalue = PyUnicode_DecodeLatin1(wsgi_req->hvec[i + 1].iov_base, wsgi_req->hvec[i + 1].iov_len, NULL);
#else
                	pydictkey = PyString_FromStringAndSize(wsgi_req->hvec[i].iov_base+5, wsgi_req->hvec[i].iov_len-5);
                	pydictvalue = PyString_FromStringAndSize(wsgi_req->hvec[i + 1].iov_base, wsgi_req->hvec[i + 1].iov_len);
#endif
			PyObject *old_value = PyDict_GetItem(headers, pydictkey);
			if (old_value) {
				if (PyString_Check(old_value)) {
					PyObject *new_value = PyList_New(0);
					PyList_Append(new_value, old_value);
					old_value = new_value;
                			PyDict_SetItem(headers, pydictkey, old_value);
					Py_DECREF(old_value);
				}
				PyList_Append(old_value, pydictvalue);
			}
			else {
                		PyDict_SetItem(headers, pydictkey, pydictvalue);
			}
                	Py_DECREF(pydictkey);
                	Py_DECREF(pydictvalue);
		}
        }

	PyDict_SetItemString(wsgi_req->async_environ, "headers", headers);
	Py_DECREF(headers);

        // if async_post is mapped as a file, directly use it as wsgi.input
        if (wsgi_req->async_post) {
#ifdef PYTHREE
                wsgi_req->async_input = PyFile_FromFd(fileno((FILE *)wsgi_req->async_post), "pump_body", "rb", 0, NULL, NULL, NULL, 0);
#else
                wsgi_req->async_input = PyFile_FromFile(wsgi_req->async_post, "pump_body", "r", NULL);
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

        PyDict_SetItemString(wsgi_req->async_environ, "body", wsgi_req->async_input);


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
	PyDict_SetItemString(wsgi_req->async_environ, "scheme", zero);
	Py_DECREF(zero);


	wsgi_req->async_app = wi->callable;

	// export .env only in non-threaded mode
        if (uwsgi.threads < 2) {
        	PyDict_SetItemString(up.embedded_dict, "env", wsgi_req->async_environ);
        }

        PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.version", wi->uwsgi_version);

        if (uwsgi.cores > 1) {
                PyDict_SetItemString(wsgi_req->async_environ, "uwsgi.core", PyInt_FromLong(wsgi_req->async_id));
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


int uwsgi_response_subhandler_pump(struct wsgi_request *wsgi_req) {

	PyObject *pychunk;
	ssize_t wsize;
	int i;

	struct http_status_codes *http_sc;
	char sc[4];

	// ok its a yield
	if (!wsgi_req->async_placeholder) {
		if (PyDict_Check((PyObject *)wsgi_req->async_result)) {


			PyObject *status = PyDict_GetItemString((PyObject *)wsgi_req->async_result, "status");
			if (!status) {
				uwsgi_log("invalid Pump response (status code).\n"); 
				goto clear; 
			}

			PyObject *headers = PyDict_GetItemString((PyObject *)wsgi_req->async_result, "headers");
			if (!headers) {
				uwsgi_log("invalid Pump response (headers).\n"); 
				goto clear; 
			}


			wsgi_req->async_placeholder =  PyDict_GetItemString((PyObject *)wsgi_req->async_result, "body");
			if (!wsgi_req->async_placeholder) {
				uwsgi_log("invalid Pump response (body).\n"); 
				goto clear; 
			}

			// get the status code
			if (!PyInt_Check(status)) {
				uwsgi_log("invalid Pump response (status code).\n"); 
				goto clear; 
			}

			if (uwsgi_num2str2n(PyInt_AsLong(status), sc, 4) != 3) {
				uwsgi_log("invalid Pump response (status code).\n"); 
				goto clear; 
			}

			int found = 0;
			for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
                		if (http_sc->key[0] == sc[0] && http_sc->key[1] == sc[1] && http_sc->key[2] == sc[2]) {
                        		wsgi_req->hvec[4].iov_base = (char *) http_sc->message;
                        		wsgi_req->hvec[4].iov_len = http_sc->message_size;
					found = 1;
                        		break;
                		}
        		}
		
			if (!found) {
				uwsgi_log("invalid Pump response (status code).\n"); 
				goto clear; 
			}

			wsgi_req->hvec[0].iov_base = wsgi_req->protocol;
			wsgi_req->hvec[0].iov_len = wsgi_req->protocol_len;
			wsgi_req->hvec[1].iov_base = " ";
			wsgi_req->hvec[1].iov_len = 1;
			wsgi_req->hvec[2].iov_base = sc;
			wsgi_req->hvec[2].iov_len = 3;
			wsgi_req->hvec[3].iov_base = " ";
			wsgi_req->hvec[3].iov_len = 1;
			wsgi_req->hvec[5].iov_base = "\r\n";
			wsgi_req->hvec[5].iov_len = 2;

			UWSGI_RELEASE_GIL
                	wsize = wsgi_req->socket->proto_writev_header(wsgi_req, wsgi_req->hvec, 6);
                	UWSGI_GET_GIL
                	if (wsize < 0) {
                        	uwsgi_error("writev()");
                	}
                	wsgi_req->headers_size += wsize;

			PyObject *hhkey, *hhvalue;
#ifdef UWSGI_PYTHON_OLD
			int hhpos = 0;
#else
			Py_ssize_t hhpos = 0;
#endif
			while (PyDict_Next(headers, &hhpos, &hhkey, &hhvalue)) {
				if (!PyString_Check(hhkey)) continue;

				wsgi_req->hvec[0].iov_base = PyString_AsString(hhkey);
				wsgi_req->hvec[0].iov_len = PyString_Size(hhkey);	
				((char*)wsgi_req->hvec[0].iov_base)[0] = toupper((int) ((char*)wsgi_req->hvec[0].iov_base)[0]);

				wsgi_req->hvec[1].iov_base = ": ";
                        	wsgi_req->hvec[1].iov_len = 2;

				wsgi_req->hvec[3].iov_base = "\r\n";
                        	wsgi_req->hvec[3].iov_len = 2;
				if (PyList_Check(hhvalue)) {
					for(i=0;i<PyList_Size(hhvalue);i++) {
						PyObject *item = PyList_GetItem(hhvalue, i);
						if (PyString_Check(item)) {
							wsgi_req->hvec[2].iov_base = PyString_AsString(item);
                                        		wsgi_req->hvec[2].iov_len = PyString_Size(item);
                                        		UWSGI_RELEASE_GIL
                                        		wsize = wsgi_req->socket->proto_writev_header(wsgi_req, wsgi_req->hvec, 4);
                                        		UWSGI_GET_GIL
                                        		if (wsize < 0) {
                                                		uwsgi_error("writev()");
                                        		}
                                        		wsgi_req->headers_size += wsize;
						}
					}	
				}
				else if (PyString_Check(hhvalue)) {
					wsgi_req->hvec[2].iov_base = PyString_AsString(hhvalue);
                                	wsgi_req->hvec[2].iov_len = PyString_Size(hhvalue);
					UWSGI_RELEASE_GIL
                        		wsize = wsgi_req->socket->proto_writev_header(wsgi_req, wsgi_req->hvec, 4);
                        		UWSGI_GET_GIL
                        		if (wsize < 0) {
                                		uwsgi_error("writev()");
                        		}
                        		wsgi_req->headers_size += wsize;
				}
			}

			wsgi_req->socket->proto_write(wsgi_req, "\r\n", 2);
			Py_INCREF((PyObject *)wsgi_req->async_placeholder);

			if (PyString_Check((PyObject *)wsgi_req->async_placeholder)) {
                		if ((wsize = wsgi_req->socket->proto_write(wsgi_req, PyString_AsString(wsgi_req->async_placeholder), PyString_Size(wsgi_req->async_placeholder))) < 0) {
                        		uwsgi_error("write()");
                        		goto clear;
                		}
                		wsgi_req->response_size += wsize;
                		goto clear;
        		}
#ifdef PYTHREE
			else if ((wsgi_req->sendfile_fd = PyObject_AsFileDescriptor((PyObject *)wsgi_req->async_placeholder)) > -1) {
#else
			else if (PyFile_Check((PyObject *)wsgi_req->async_placeholder)) {
				wsgi_req->sendfile_fd = fileno(PyFile_AsFile((PyObject *)wsgi_req->async_placeholder));
#endif
                		wsize = uwsgi_sendfile(wsgi_req);
				if (wsize < 0) {
					goto clear;
				}
                		wsgi_req->response_size += wsize;
				goto clear;
			}

			PyObject *tmp = (PyObject *)wsgi_req->async_placeholder;

			wsgi_req->async_placeholder = PyObject_GetIter( (PyObject *)wsgi_req->async_placeholder );

			Py_DECREF(tmp);

			if (!wsgi_req->async_placeholder) {
				goto clear;
			}
#ifdef UWSGI_ASYNC
			if (uwsgi.async > 1) {
				return UWSGI_AGAIN;
			}
#endif
		}
		else {
			uwsgi_log("invalid Pump response.\n"); 
			goto clear; 
		}
	}



	pychunk = PyIter_Next(wsgi_req->async_placeholder);

	if (!pychunk) {
		if (PyErr_Occurred()) PyErr_Print();
		goto clear;
	}


	if (PyString_Check(pychunk)) {
		if ((wsize = wsgi_req->socket->proto_write(wsgi_req,  PyString_AsString(pychunk), PyString_Size(pychunk))) < 0) {
			uwsgi_error("write()");
			Py_DECREF(pychunk);
			goto clear;
		}
		wsgi_req->response_size += wsize;
	}


	Py_DECREF(pychunk);
	return UWSGI_AGAIN;

clear:
	Py_XDECREF((PyObject *)wsgi_req->async_placeholder);

	Py_DECREF((PyObject *)wsgi_req->async_result);
	PyErr_Clear();

	return UWSGI_OK;
}

