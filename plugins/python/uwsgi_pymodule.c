#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

PyObject *py_uwsgi_signal_wait(PyObject * self, PyObject * args) {

        struct wsgi_request *wsgi_req = py_current_wsgi_req();
	int wait_for_specific_signal = 0;
	uint8_t uwsgi_signal = 0;
	int received_signal;

	wsgi_req->signal_received = -1;

	if (PyTuple_Size(args) > 0) {
		if (!PyArg_ParseTuple(args, "|B:", &uwsgi_signal)) {
                	return NULL;
        	}
		wait_for_specific_signal = 1;	
	}

	UWSGI_RELEASE_GIL;

	if (wait_for_specific_signal) {
		received_signal = uwsgi_signal_wait(uwsgi_signal);
	}
	else {
		received_signal = uwsgi_signal_wait(-1);
	}

	if (received_signal < 0) {
		UWSGI_GET_GIL;
		return PyErr_Format(PyExc_SystemError, "error waiting for signal");
	}

        wsgi_req->signal_received = received_signal;

	UWSGI_GET_GIL;

        return PyString_FromString("");
}

PyObject *py_uwsgi_signal_received(PyObject * self, PyObject * args) {

        struct wsgi_request *wsgi_req = py_current_wsgi_req();

        return PyInt_FromLong(wsgi_req->signal_received);
}


char *uwsgi_encode_pydict(PyObject * pydict, uint16_t * size) {

	int i;
	PyObject *zero, *key, *val;
	uint16_t keysize, valsize;


	char *buf, *bufptr;

	PyObject *vars = PyDict_Items(pydict);

	if (!vars) {
		PyErr_Print();
		return NULL;
	}

	*size = 0;

	// calc the packet size
	// try to fallback whenever possible
	for (i = 0; i < PyList_Size(vars); i++) {
		zero = PyList_GetItem(vars, i);
		if (!zero) {
			PyErr_Print();
			continue;
		}

		if (!PyTuple_Check(zero)) {
			uwsgi_log("invalid python dictionary item\n");
			continue;
		}

		if (PyTuple_Size(zero) < 2) {
			uwsgi_log("invalid python dictionary item\n");
			continue;
		}
		key = PyTuple_GetItem(zero, 0);
		val = PyTuple_GetItem(zero, 1);

		if (!PyString_Check(key) || !PyString_Check(val)) {
			continue;
		}


		keysize = PyString_Size(key);
		valsize = PyString_Size(val);

		*size += (keysize + 2 + valsize + 2);

		// do not DECREF here !!!
		//Py_DECREF(zero);
	}

	if (*size <= 4) {
		uwsgi_log("empty python dictionary\n");
		return NULL;
	}

	// remember to free this memory !!!
	buf = malloc(*size);
	if (!buf) {
		uwsgi_error("malloc()");
		return NULL;
	}

	bufptr = buf;

	for (i = 0; i < PyList_Size(vars); i++) {
		zero = PyList_GetItem(vars, i);
		if (!zero) {
			PyErr_Print();
			continue;
		}

		if (!PyTuple_Check(zero)) {
			uwsgi_log("invalid python dictionary item\n");
			Py_DECREF(zero);
			continue;
		}

		if (PyTuple_Size(zero) < 2) {
			uwsgi_log("invalid python dictionary item\n");
			Py_DECREF(zero);
			continue;
		}
		key = PyTuple_GetItem(zero, 0);
		val = PyTuple_GetItem(zero, 1);


		if (!key || !val) {
			PyErr_Print();
			continue;
		}

		if (!PyString_Check(key) || !PyString_Check(val)) {
			Py_DECREF(zero);
			continue;
		}


		keysize = PyString_Size(key);
		valsize = PyString_Size(val);
		if (bufptr + keysize + 2 + valsize + 2 <= buf + *size) {

			*bufptr++ = (uint8_t) (keysize & 0xff);
        		*bufptr++ = (uint8_t) ((keysize >> 8) & 0xff);
			memcpy(bufptr, PyString_AsString(key), keysize);
			bufptr += keysize;

			*bufptr++ = (uint8_t) (valsize & 0xff);
        		*bufptr++ = (uint8_t) ((valsize >> 8) & 0xff);
			memcpy(bufptr, PyString_AsString(val), valsize);
			bufptr += valsize;
		}

		Py_DECREF(zero);

	}

	return buf;

}

PyObject *py_uwsgi_listen_queue(PyObject * self, PyObject * args) {

	return PyInt_FromLong(uwsgi.shared->options[UWSGI_OPTION_BACKLOG_STATUS]);
}

PyObject *py_uwsgi_close(PyObject * self, PyObject * args) {

	int fd;

	if (!PyArg_ParseTuple(args, "i:close", &fd)) {
		return NULL;
	}

	close(fd);


	Py_INCREF(Py_None);
	return Py_None;

}

PyObject *py_uwsgi_add_cron(PyObject * self, PyObject * args) {

	uint8_t uwsgi_signal;
	int minute, hour, day, month, week;

	if (!PyArg_ParseTuple(args, "Biiiii:add_cron", &uwsgi_signal, &minute, &hour, &day, &month, &week)) {
                return NULL;
        }

	if (uwsgi_signal_add_cron(uwsgi_signal, minute, hour, day, month, week)) {
		return PyErr_Format(PyExc_ValueError, "unable to add cron");
	}

	Py_INCREF(Py_True);
	return Py_True;
}


PyObject *py_uwsgi_add_probe(PyObject * self, PyObject * args) {

        uint8_t uwsgi_signal;
	int timeout = 0;
	int freq = 0;
        char *probe, *probe_args;

        if (!PyArg_ParseTuple(args, "Bss|ii:add_probe", &uwsgi_signal, &probe, &probe_args, &timeout, &freq)) {
                return NULL;
        }

        if (uwsgi_add_probe(uwsgi_signal, probe, probe_args, timeout, freq))
                return PyErr_Format(PyExc_ValueError, "unable to add probe");

        Py_INCREF(Py_None);
        return Py_None;
}

	

PyObject *py_uwsgi_add_timer(PyObject * self, PyObject * args) {

	uint8_t uwsgi_signal;
	int secs;

	if (!PyArg_ParseTuple(args, "Bi:add_timer", &uwsgi_signal, &secs)) {
		return NULL;
	}

	if (uwsgi_add_timer(uwsgi_signal, secs))
		return PyErr_Format(PyExc_ValueError, "unable to add timer");

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_add_rb_timer(PyObject * self, PyObject * args) {

        uint8_t uwsgi_signal;
        int secs;
	int iterations = 0;

        if (!PyArg_ParseTuple(args, "Bi|i:add_rb_timer", &uwsgi_signal, &secs, &iterations)) {
                return NULL;
        }

        if (uwsgi_signal_add_rb_timer(uwsgi_signal, secs, iterations))
                return PyErr_Format(PyExc_ValueError, "unable to add rb_timer");

        Py_INCREF(Py_None);
        return Py_None;
}



PyObject *py_uwsgi_add_file_monitor(PyObject * self, PyObject * args) {

	uint8_t uwsgi_signal;
	char *filename;

	if (!PyArg_ParseTuple(args, "Bs:add_file_monitor", &uwsgi_signal, &filename)) {
		return NULL;
	}

	if (uwsgi_add_file_monitor(uwsgi_signal, filename))
		return PyErr_Format(PyExc_ValueError, "unable to add file monitor");

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_call(PyObject * self, PyObject * args) {

	char *func;
	uint16_t size = 0;
	PyObject *py_func;
	int argc = PyTuple_Size(args);
	int i;
	char *argv[256];
	uint16_t argvs[256];

	// TODO better error reporting
	if (argc < 1)
		goto clear;

	py_func = PyTuple_GetItem(args, 0);

	if (!PyString_Check(py_func))
		goto clear;

	func = PyString_AsString(py_func);

	for (i = 0; i < (argc - 1); i++) {
		PyObject *py_str = PyTuple_GetItem(args, i + 1);
		if (!PyString_Check(py_str)) {
			goto clear;
		}
		argv[i] = PyString_AsString(py_str);
		argvs[i] = PyString_Size(py_str);
	}

	UWSGI_RELEASE_GIL;
	// response must always be freed
	char *response = uwsgi_do_rpc(NULL, func, argc - 1, argv, argvs, &size);
	UWSGI_GET_GIL;

	if (response) {
		PyObject *ret = PyString_FromStringAndSize(response, size);
		free(response);
		return ret;
	}

	Py_INCREF(Py_None);
	return Py_None;

      clear:

	return PyErr_Format(PyExc_ValueError, "unable to call rpc function");

}

PyObject *py_uwsgi_rpc_list(PyObject * self, PyObject * args) {

	uint64_t i;
	PyObject *rpc_list = PyTuple_New(uwsgi.shared->rpc_count[uwsgi.mywid]);

	int pos = (uwsgi.mywid * uwsgi.rpc_max);
	for (i = 0; i < uwsgi.shared->rpc_count[uwsgi.mywid]; i++) {
		if (uwsgi.rpc_table[pos + i].name[0] != 0) {
			PyTuple_SetItem(rpc_list, i, PyString_FromString(uwsgi.rpc_table[pos + i].name));
		}
	}

	return rpc_list;

}

PyObject *py_uwsgi_rpc(PyObject * self, PyObject * args) {

	char *node = NULL, *func;
	uint16_t size = 0;
	PyObject *py_node, *py_func;

	int argc = PyTuple_Size(args);
	char *argv[256];
	uint16_t argvs[256];

	int i;

	// TODO better error reporting
	if (argc < 2)
		goto clear;

	py_node = PyTuple_GetItem(args, 0);

	if (PyString_Check(py_node)) {
		node = PyString_AsString(py_node);
	}

	py_func = PyTuple_GetItem(args, 1);

	if (!PyString_Check(py_func))
		goto clear;

	func = PyString_AsString(py_func);

	for (i = 0; i < (argc - 2); i++) {
		PyObject *py_str = PyTuple_GetItem(args, i + 2);
		if (!PyString_Check(py_str))
			goto clear;
		argv[i] = PyString_AsString(py_str);
		argvs[i] = PyString_Size(py_str);
	}

	UWSGI_RELEASE_GIL;
	char *response = uwsgi_do_rpc(node, func, argc - 2, argv, argvs, &size);
	UWSGI_GET_GIL;

	if (response) {
                PyObject *ret = PyString_FromStringAndSize(response, size);
                free(response);
                return ret;
        }

	Py_INCREF(Py_None);
        return Py_None;

      clear:

        return PyErr_Format(PyExc_ValueError, "unable to call rpc function");

}

PyObject *py_uwsgi_register_rpc(PyObject * self, PyObject * args) {

	uint8_t argc = 0;
	char *name;
	PyObject *func;

	if (!PyArg_ParseTuple(args, "sO|B:register_rpc", &name, &func, &argc)) {
		return NULL;
	}


	if (uwsgi_register_rpc(name, 0, argc, func)) {
		return PyErr_Format(PyExc_ValueError, "unable to register rpc function");
	}

	Py_INCREF(Py_True);
	return Py_True;
}

PyObject *py_uwsgi_signal_registered(PyObject * self, PyObject * args) {
	uint8_t uwsgi_signal;

	if (!PyArg_ParseTuple(args, "B:signal_registered", &uwsgi_signal)) {
                return NULL;
        }

	if (uwsgi_signal_registered(uwsgi_signal)) {
		Py_INCREF(Py_True);
		return Py_True;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

#ifdef UWSGI_SSL
PyObject *py_uwsgi_i_am_the_lord(PyObject * self, PyObject * args) {
	char *legion_name = NULL;

        if (!PyArg_ParseTuple(args, "s:i_am_the_lord", &legion_name)) {
                return NULL;
        }

        if (uwsgi_legion_i_am_the_lord(legion_name)) {
                Py_INCREF(Py_True);
                return Py_True;
        }

        Py_INCREF(Py_False);
        return Py_False;
}

PyObject *py_uwsgi_lord_scroll(PyObject * self, PyObject * args) {
        char *legion_name = NULL;

        if (!PyArg_ParseTuple(args, "s:lord_scroll", &legion_name)) {
                return NULL;
        }

	uint16_t rlen = 0;
	char *buf = uwsgi_legion_lord_scroll(legion_name, &rlen);
	if (!buf) {
        	Py_INCREF(Py_None);
        	return Py_None;
	}

	PyObject *ret = PyString_FromStringAndSize(buf, rlen);
	free(buf);
        return ret;
}

static void scrolls_items(uint16_t pos, char *key, uint16_t keylen, void *data) {
	PyObject *list = (PyObject *) data;
	PyObject *zero = PyString_FromStringAndSize(key, keylen);
	PyList_Append(list, zero);
	Py_DECREF(zero);
}

PyObject *py_uwsgi_scrolls(PyObject * self, PyObject * args) {
        char *legion_name = NULL;

        if (!PyArg_ParseTuple(args, "s:scrolls", &legion_name)) {
                return NULL;
        }

	uint64_t rlen = 0;
        char *buf = uwsgi_legion_scrolls(legion_name, &rlen);
	if (!buf) goto end;
	PyObject *list = PyList_New(0);
	if (uwsgi_hooked_parse_array(buf, rlen, scrolls_items, list)) {
		goto error;
	}
	free(buf);
	return list;
error:
	free(buf);
end:
	Py_INCREF(Py_None);
	return Py_None;
}


#endif

PyObject *py_uwsgi_register_signal(PyObject * self, PyObject * args) {

	uint8_t uwsgi_signal;
	char *signal_kind;
	PyObject *handler;

	if (!PyArg_ParseTuple(args, "BsO:register_signal", &uwsgi_signal, &signal_kind, &handler)) {
		return NULL;
	}

	if (uwsgi_register_signal(uwsgi_signal, signal_kind, handler, 0)) {
		return PyErr_Format(PyExc_ValueError, "unable to register signal");
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_signal(PyObject * self, PyObject * args) {

	uint8_t uwsgi_signal;
	char *remote = NULL;

	if (!PyArg_ParseTuple(args, "B|s:signal", &uwsgi_signal, &remote)) {
		return NULL;
	}

	if (remote) {
#ifdef UWSGI_DEBUG
		uwsgi_log("sending signal %d to node %s\n", uwsgi_signal, remote);
#endif
		int ret = uwsgi_remote_signal_send(remote, uwsgi_signal);
		if (ret == 1) goto clear;
		if (ret == -1)
			return PyErr_Format(PyExc_IOError, "unable to deliver signal %d to node %s", uwsgi_signal, remote);
		if (ret == 0)
			return PyErr_Format(PyExc_ValueError, "node %s rejected signal %d", remote, uwsgi_signal);
	}
	else {
#ifdef UWSGI_DEBUG
		uwsgi_log("sending signal %d to master\n", uwsgi_signal);
#endif
		uwsgi_signal_send(uwsgi.signal_socket, uwsgi_signal);
	}

clear:
	Py_INCREF(Py_None);
	return Py_None;

}

PyObject *py_uwsgi_log_this(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = py_current_wsgi_req();

	wsgi_req->log_this = 1;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_alarm(PyObject * self, PyObject * args) {
	char *alarm = NULL;
	char *msg = NULL;
	Py_ssize_t msg_len = 0;
	if (!PyArg_ParseTuple(args, "ss#:alarm", &alarm, &msg, &msg_len)) {
                return NULL;
        }	

	uwsgi_alarm_trigger(alarm, msg, msg_len);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_get_logvar(PyObject * self, PyObject * args) {

	char *key = NULL;
        Py_ssize_t keylen = 0;
        struct wsgi_request *wsgi_req = py_current_wsgi_req();

	if (!PyArg_ParseTuple(args, "s#:get_logvar", &key, &keylen)) {
                return NULL;
        }

	struct uwsgi_logvar *lv = uwsgi_logvar_get(wsgi_req, key, keylen);

	if (lv) {
		return PyString_FromStringAndSize(lv->val, lv->vallen);
	}

        Py_INCREF(Py_None);
        return Py_None;
}

PyObject *py_uwsgi_set_logvar(PyObject * self, PyObject * args) {

        char *key = NULL;
        Py_ssize_t keylen = 0;
        char *val = NULL;
        Py_ssize_t vallen = 0;
        struct wsgi_request *wsgi_req = py_current_wsgi_req();

        if (!PyArg_ParseTuple(args, "s#s#:set_logvar", &key, &keylen, &val, &vallen)) {
                return NULL;
        }

        uwsgi_logvar_add(wsgi_req, key, keylen, val, vallen);

        Py_INCREF(Py_None);
        return Py_None;
}

PyObject *py_uwsgi_recv_block(PyObject * self, PyObject * args) {

	char buf[4096];
	char *bufptr;
	ssize_t rlen = 0, len;
	int fd, size, remains, ret, timeout = -1;


	if (!PyArg_ParseTuple(args, "ii|i:recv_block", &fd, &size, &timeout)) {
		return NULL;
	}

	if (fd < 0)
		goto clear;

	UWSGI_RELEASE_GIL
		// security check
		if (size > 4096)
		size = 4096;

	remains = size;

	bufptr = buf;
	while (remains > 0) {
		uwsgi_log("%d %d %d\n", remains, size, timeout);
		ret = uwsgi_waitfd(fd, timeout);
		if (ret > 0) {
			len = read(fd, bufptr, UMIN(remains, size));
			if (len > 0) {
				bufptr += len;
				rlen += len;
				remains -= len;
			}
			else {
				break;
			}
		}
		else {
			uwsgi_log("error waiting for block data\n");
			break;
		}
	}

	UWSGI_GET_GIL if (rlen == size) {
		return PyString_FromStringAndSize(buf, rlen);
	}

      clear:

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_recv(PyObject * self, PyObject * args) {

	int fd, max_size = 4096;
	char buf[4096];
	ssize_t rlen;


	if (!PyArg_ParseTuple(args, "i|i:recv", &fd, &max_size)) {
		return NULL;
	}

	UWSGI_RELEASE_GIL
		// security check
		if (max_size > 4096)
		max_size = 4096;

	rlen = read(fd, buf, max_size);

	UWSGI_GET_GIL if (rlen > 0) {
		return PyString_FromStringAndSize(buf, rlen);
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_is_connected(PyObject * self, PyObject * args) {

	int fd, soopt;
	socklen_t solen = sizeof(int);

	if (!PyArg_ParseTuple(args, "i:is_connected", &fd)) {
		return NULL;
	}

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *) (&soopt), &solen) < 0) {
		uwsgi_error("getsockopt()");
		goto clear;
	}
	/* is something bad ? */
	if (soopt)
		goto clear;

	Py_INCREF(Py_True);
	return Py_True;

      clear:

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *py_uwsgi_send(PyObject * self, PyObject * args) {

	PyObject *data;
	PyObject *arg1, *arg2;

	struct wsgi_request *wsgi_req = py_current_wsgi_req();

	int uwsgi_fd = wsgi_req->fd;

	if (!PyArg_ParseTuple(args, "O|O:send", &arg1, &arg2)) {
		return NULL;
	}

	if (PyTuple_Size(args) > 1) {
		uwsgi_fd = PyInt_AsLong(arg1);
		data = arg2;
	}
	else {
		data = arg1;
	}

	UWSGI_RELEASE_GIL if (write(uwsgi_fd, PyString_AsString(data), PyString_Size(data)) < 0) {
		uwsgi_error("write()");
		UWSGI_GET_GIL Py_INCREF(Py_None);
		return Py_None;
	}

	UWSGI_GET_GIL Py_INCREF(Py_True);
	return Py_True;

}

#ifdef UWSGI_ROUTING
static PyObject *py_uwsgi_route(PyObject * self, PyObject * args) {
	struct wsgi_request *wsgi_req = py_current_wsgi_req();
	char *router_name = NULL;
	char *router_args = NULL;

	if (!PyArg_ParseTuple(args, "ss:route", &router_name, &router_args)) {
                return NULL;
        }

	int ret = uwsgi_route_api_func(wsgi_req, router_name, uwsgi_str(router_args));
	return PyInt_FromLong(ret);
}
#endif

PyObject *py_uwsgi_offload(PyObject * self, PyObject * args) {
/*
	size_t len = 0;
	char *filename = NULL;
	struct wsgi_request *wsgi_req = py_current_wsgi_req();

	if (!PyArg_ParseTuple(args, "s|i:offload_transfer", &filename, &len)) {
                return NULL;
        }

	if (!wsgi_req->socket->can_offload) {
		return PyErr_Format(PyExc_ValueError, "The current socket does not support offloading");
	}

	if (!wsgi_req->headers_sent) {
		UWSGI_RELEASE_GIL
        	if (uwsgi_response_write_headers_do(wsgi_req)) {
			UWSGI_GET_GIL
			return PyErr_Format(PyExc_ValueError, "unable to send headers before offload transfer");
		}
		UWSGI_GET_GIL
	}


	UWSGI_RELEASE_GIL
        if (uwsgi_offload_request_sendfile_do(wsgi_req, filename, -1, len)) {
		UWSGI_GET_GIL
		return PyErr_Format(PyExc_ValueError, "unable to offload the request");
	}
	UWSGI_GET_GIL

*/

	return PyString_FromString("");
}

PyObject *py_uwsgi_advanced_sendfile(PyObject * self, PyObject * args) {

	PyObject *what;
	char *filename;
	size_t chunk = 0;
	off_t pos = 0;
	size_t filesize = 0;
	struct wsgi_request *wsgi_req = py_current_wsgi_req();

	int fd = -1;

	if (!PyArg_ParseTuple(args, "O|iii:sendfile", &what, &chunk, &pos, &filesize)) {
		return NULL;
	}


	if (PyString_Check(what)) {

		filename = PyString_AsString(what);

		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			uwsgi_error_open(filename);
			goto clear;
		}

	}
#ifdef PYTHREE
	else if (PyUnicode_Check(what)) {
		filename = PyBytes_AsString(PyUnicode_AsASCIIString(what));

		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			uwsgi_error_open(filename);
			goto clear;
		}
	}
#endif
	else {
		fd = PyObject_AsFileDescriptor(what);
		if (fd < 0)
			goto clear;

		// check for mixing file_wrapper and sendfile
		if (fd == wsgi_req->sendfile_fd) {
			Py_INCREF(what);
		}
	}

	UWSGI_RELEASE_GIL
	// fd is closed by the following function
	uwsgi_response_sendfile_do(wsgi_req, fd, pos, filesize);
	UWSGI_GET_GIL
	// revert to old values
	uwsgi_py_check_write_errors {
        	uwsgi_py_write_exception(wsgi_req);
		return NULL;
        }

	Py_INCREF(Py_True);
	return Py_True;

      clear:
	Py_INCREF(Py_None);
	return Py_None;

}


PyObject *py_uwsgi_async_sleep(PyObject * self, PyObject * args) {

	float timeout;
	int sec_timeout;

	if (!PyArg_ParseTuple(args, "f:async_sleep", &timeout)) {
		return NULL;
	}

	sec_timeout = (int) timeout;

	if (sec_timeout > 0) {
		async_add_timeout(uwsgi.wsgi_req, sec_timeout);
	}

	return PyString_FromString("");
}

PyObject *py_uwsgi_warning(PyObject * self, PyObject * args) {
	char *message;
	int len;

	if (!PyArg_ParseTuple(args, "s:set_warning_message", &message)) {
		return NULL;
	}

	len = strlen(message);
	if (len > 80) {
		uwsgi_log("- warning message must be max 80 chars, it will be truncated -");
		memcpy(uwsgi.shared->warning_message, message, 80);
		uwsgi.shared->warning_message[80] = 0;
	}
	else {
		memcpy(uwsgi.shared->warning_message, message, len);
		uwsgi.shared->warning_message[len] = 0;
	}

	Py_INCREF(Py_True);
	return Py_True;
}

PyObject *py_uwsgi_log(PyObject * self, PyObject * args) {
	char *logline;

	if (!PyArg_ParseTuple(args, "s:log", &logline)) {
		return NULL;
	}

	uwsgi_log("%s\n", logline);

	Py_INCREF(Py_True);
	return Py_True;
}

PyObject *py_uwsgi_set_user_harakiri(PyObject * self, PyObject * args) {
	int sec = 0;
	if (!PyArg_ParseTuple(args, "i:set_user_harakiri", &sec)) {
                return NULL;
        }

	set_user_harakiri(sec);

        Py_INCREF(Py_None);
        return Py_None;
}

PyObject *py_uwsgi_i_am_the_spooler(PyObject * self, PyObject * args) {
	if (uwsgi.i_am_a_spooler) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_is_locked(PyObject * self, PyObject * args) {

        int lock_num = 0;

        // the spooler cannot lock resources
        if (uwsgi.i_am_a_spooler) {
                return PyErr_Format(PyExc_ValueError, "The spooler cannot lock/unlock resources");
        }

        if (!PyArg_ParseTuple(args, "|i:is_locked", &lock_num)) {
                return NULL;
        }

        if (lock_num < 0 || lock_num > uwsgi.locks) {
                return PyErr_Format(PyExc_ValueError, "Invalid lock number");
        }

	UWSGI_RELEASE_GIL

        if (uwsgi_lock_check(uwsgi.user_lock[lock_num]) == 0) {
		UWSGI_GET_GIL
		Py_INCREF(Py_False);
		return Py_False;
	}

	UWSGI_GET_GIL

        Py_INCREF(Py_True);
        return Py_True;
}


PyObject *py_uwsgi_lock(PyObject * self, PyObject * args) {

	int lock_num = 0;

	// the spooler cannot lock resources
	if (uwsgi.i_am_a_spooler) {
		return PyErr_Format(PyExc_ValueError, "The spooler cannot lock/unlock resources");
	}

	if (!PyArg_ParseTuple(args, "|i:lock", &lock_num)) {
                return NULL;
        }

	if (lock_num < 0 || lock_num > uwsgi.locks) {
		return PyErr_Format(PyExc_ValueError, "Invalid lock number");
	}

	UWSGI_RELEASE_GIL
	uwsgi_lock(uwsgi.user_lock[lock_num]);
	UWSGI_GET_GIL

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_unlock(PyObject * self, PyObject * args) {

	int lock_num = 0;

	if (uwsgi.i_am_a_spooler) {
		return PyErr_Format(PyExc_ValueError, "The spooler cannot lock/unlock resources");
	}

	if (!PyArg_ParseTuple(args, "|i:unlock", &lock_num)) {
                return NULL;
        }

        if (lock_num < 0 || lock_num > uwsgi.locks) {
                return PyErr_Format(PyExc_ValueError, "Invalid lock number");
        }

	uwsgi_unlock(uwsgi.user_lock[lock_num]);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_connection_fd(PyObject * self, PyObject * args) {
	struct wsgi_request *wsgi_req = py_current_wsgi_req();
	return PyInt_FromLong(wsgi_req->fd);
}

PyObject *py_uwsgi_websocket_handshake(PyObject * self, PyObject * args) {
        char *key = NULL;
        Py_ssize_t key_len = 0;

        char *origin = NULL;
        Py_ssize_t origin_len = 0;

        if (!PyArg_ParseTuple(args, "s#|s#:websocket_handshake", &key, &key_len, &origin, &origin_len)) {
                return NULL;
        }

	struct wsgi_request *wsgi_req = py_current_wsgi_req();

	UWSGI_RELEASE_GIL
	int ret = uwsgi_websocket_handshake(wsgi_req, key, key_len, origin, origin_len);
	UWSGI_GET_GIL

	if (ret) {
		return PyErr_Format(PyExc_IOError, "unable to complete websocket handshake");
	}

	Py_INCREF(Py_None);
        return Py_None;
}

PyObject *py_uwsgi_websocket_send(PyObject * self, PyObject * args) {
	char *message = NULL;
        Py_ssize_t message_len = 0;

        if (!PyArg_ParseTuple(args, "s#:websocket_send", &message, &message_len)) {
                return NULL;
        }

	struct wsgi_request *wsgi_req = py_current_wsgi_req();

	UWSGI_RELEASE_GIL	
	int ret  = uwsgi_websocket_send(wsgi_req, message, message_len);
	UWSGI_GET_GIL	
	if (ret < 0) {
		return PyErr_Format(PyExc_IOError, "unable to send websocket message");
	}
	Py_INCREF(Py_None);
        return Py_None;
}

PyObject *py_uwsgi_websocket_recv(PyObject * self, PyObject * args) {
	struct wsgi_request *wsgi_req = py_current_wsgi_req();
	UWSGI_RELEASE_GIL	
	struct uwsgi_buffer *ub = uwsgi_websocket_recv(wsgi_req);
	UWSGI_GET_GIL	
	if (!ub) {
		return PyErr_Format(PyExc_IOError, "unable to receive websocket message");
	}

	PyObject *ret = PyString_FromStringAndSize(ub->buf, ub->pos);
	uwsgi_buffer_destroy(ub);
	return ret;
}

PyObject *py_uwsgi_websocket_recv_nb(PyObject * self, PyObject * args) {
        struct wsgi_request *wsgi_req = py_current_wsgi_req();
        UWSGI_RELEASE_GIL
        struct uwsgi_buffer *ub = uwsgi_websocket_recv_nb(wsgi_req);
        UWSGI_GET_GIL
        if (!ub) {
                return PyErr_Format(PyExc_IOError, "unable to receive websocket message");
        }

        PyObject *ret = PyString_FromStringAndSize(ub->buf, ub->pos);
        uwsgi_buffer_destroy(ub);
        return ret;
}


PyObject *py_uwsgi_embedded_data(PyObject * self, PyObject * args) {

	char *name;
	char *symbol;
	void *sym_ptr_start = NULL;
	void *sym_ptr_end = NULL;

	if (!PyArg_ParseTuple(args, "s:embedded_data", &name)) {
		return NULL;
	}

	symbol = uwsgi_concat3("_binary_", name, "_start");
	sym_ptr_start = dlsym(RTLD_DEFAULT, symbol);
	free(symbol);
	if (!sym_ptr_start)
		return PyErr_Format(PyExc_ValueError, "unable to find symbol %s", name);



	symbol = uwsgi_concat3("_binary_", name, "_end");
	sym_ptr_end = dlsym(RTLD_DEFAULT, symbol);
	free(symbol);
	if (!sym_ptr_end)
		return PyErr_Format(PyExc_ValueError, "unable to find symbol %s", name);

	return PyString_FromStringAndSize(sym_ptr_start, sym_ptr_end - sym_ptr_start);

}

PyObject *py_uwsgi_setprocname(PyObject * self, PyObject * args) {
	char *name = NULL;

	if (!PyArg_ParseTuple(args, "s:setprocname", &name)) {
                return NULL;
        }

	uwsgi_set_processname(name);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_ready(PyObject * self, PyObject * args) {

	if (ushared->ready) {
		Py_INCREF(Py_True);
		return Py_True;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_in_farm(PyObject * self, PyObject * args) {

	char *farm_name = NULL;
	int i;

	if (!PyArg_ParseTuple(args, "|s:in_farm", &farm_name)) {
                return NULL;
        }

	if (uwsgi.muleid == 0) goto none;

	for(i=0;i<uwsgi.farms_cnt;i++) {
		if (!farm_name) {
			if (uwsgi_farm_has_mule(&uwsgi.farms[i], uwsgi.muleid)) {
				Py_INCREF(Py_True);
				return Py_True;
			}
		}
		else {
			if (!strcmp(farm_name, uwsgi.farms[i].name)) {
				if (uwsgi_farm_has_mule(&uwsgi.farms[i], uwsgi.muleid)) {
					Py_INCREF(Py_True);
					return Py_True;
				}
			}
		}
	}
none:

	Py_INCREF(Py_None);
	return Py_None;
   
}

PyObject *py_uwsgi_farm_msg(PyObject * self, PyObject * args) {

        char *message = NULL;
        Py_ssize_t message_len = 0;
	char *farm_name = NULL;
        ssize_t len;
	int i;

        if (!PyArg_ParseTuple(args, "ss#:farm_msg", &farm_name, &message, &message_len)) {
                return NULL;
        }

	for(i=0;i<uwsgi.farms_cnt;i++) {
	
		if (!strcmp(farm_name, uwsgi.farms[i].name)) {
			UWSGI_RELEASE_GIL
                	len = write(uwsgi.farms[i].queue_pipe[0], message, message_len);
			UWSGI_GET_GIL
                	if (len <= 0) {
                        	uwsgi_error("write()");
                	}
			break;
		}
	
        }

        Py_INCREF(Py_None);
        return Py_None;

}


PyObject *py_uwsgi_mule_msg(PyObject * self, PyObject * args) {

	char *message = NULL;
	Py_ssize_t message_len = 0;
	PyObject *mule_obj = NULL;
	int fd = -1;
	int mule_id = -1;

	if (!PyArg_ParseTuple(args, "s#|O:mule_msg", &message, &message_len, &mule_obj)) {
                return NULL;
        }

	if (uwsgi.mules_cnt < 1)
		return PyErr_Format(PyExc_ValueError, "no mule configured");

	if (mule_obj == NULL) {
		UWSGI_RELEASE_GIL
		mule_send_msg(uwsgi.shared->mule_queue_pipe[0], message, message_len);
		UWSGI_GET_GIL
	}
	else {
		if (PyString_Check(mule_obj)) {
			struct uwsgi_farm *uf = get_farm_by_name(PyString_AsString(mule_obj));
			if (uf == NULL) {
				return PyErr_Format(PyExc_ValueError, "unknown farm");
			}
			fd = uf->queue_pipe[0];
		}
		else if (PyInt_Check(mule_obj)) {
			mule_id = PyInt_AsLong(mule_obj);
			if (mule_id < 0 && mule_id > uwsgi.mules_cnt) {
				return PyErr_Format(PyExc_ValueError, "invalid mule number");
			}
			if (mule_id == 0) {
				fd = uwsgi.shared->mule_queue_pipe[0];
			}
			else {
				fd = uwsgi.mules[mule_id-1].queue_pipe[0];
			}
		}
		else {
			return PyErr_Format(PyExc_ValueError, "invalid mule");
		}

		if (fd > -1) {
			UWSGI_RELEASE_GIL
			mule_send_msg(fd, message, message_len);
			UWSGI_GET_GIL
		}
	}

	Py_INCREF(Py_None);
	return Py_None;
	
}

PyObject *py_uwsgi_mule_get_msg(PyObject * self, PyObject * args, PyObject *kwargs) {

	ssize_t len = 0;
	// this buffer is configurable (default 64k)
	char *message;
	PyObject *py_manage_signals = NULL;
	PyObject *py_manage_farms = NULL;
	size_t buffer_size = 65536;
	int timeout = -1;
	int manage_signals = 1, manage_farms = 1;

	static char *kwlist[] = {"signals", "buffer_size", "timeout", "farms", NULL};

	if (uwsgi.muleid == 0) {
		return PyErr_Format(PyExc_ValueError, "you can receive mule messages only in a mule !!!");
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OOii:mule_get_msg", kwlist, &py_manage_signals, &py_manage_farms, &buffer_size, &timeout)) {
		return NULL;
	}

	// signals and farms are managed by default
	if (py_manage_signals == Py_None || py_manage_signals == Py_False) {
		manage_signals = 0;
	}

	if (py_manage_farms == Py_None || py_manage_farms == Py_False) {
		manage_farms = 0;
	}

	message = uwsgi_malloc(buffer_size);
	
	UWSGI_RELEASE_GIL;
	len = uwsgi_mule_get_msg(manage_signals, manage_farms, message, buffer_size, timeout) ;
	UWSGI_GET_GIL;

	if (len < 0) {
		free(message);
		Py_INCREF(Py_None);
        	return Py_None;
	}

	PyObject *msg = PyString_FromStringAndSize(message, len);
	free(message);
	return msg;
}

PyObject *py_uwsgi_farm_get_msg(PyObject * self, PyObject * args) {

        ssize_t len = 0;
        // this buffer will be configurable
        char message[65536];
	int i, count = 0, pos = 0, ret;
	struct pollfd *farmpoll;

        if (uwsgi.muleid == 0) {
                return PyErr_Format(PyExc_ValueError, "you can receive farm messages only in a mule !!!");
        }
        UWSGI_RELEASE_GIL;
	for(i=0;i<uwsgi.farms_cnt;i++) {	
		if (uwsgi_farm_has_mule(&uwsgi.farms[i], uwsgi.muleid)) count++;
	}
	farmpoll = uwsgi_malloc( sizeof(struct pollfd) * count);
	for(i=0;i<uwsgi.farms_cnt;i++) {
		if (uwsgi_farm_has_mule(&uwsgi.farms[i], uwsgi.muleid)) {
			farmpoll[pos].fd = uwsgi.farms[i].queue_pipe[1];
			farmpoll[pos].events = POLLIN;
			pos++;
		}
	}

	ret = poll(farmpoll, count, -1);
	if (ret <= 0) {
		uwsgi_error("poll()");
		free(farmpoll);
		Py_INCREF(Py_None);
		return Py_None;
	}

	for(i=0;i<count;i++) {
		if (farmpoll[i].revents & POLLIN) {
        		len = read(farmpoll[i].fd, message, 65536);
			break;
		}
	}
        UWSGI_GET_GIL;
        if (len <= 0) {
                uwsgi_error("read()");
		free(farmpoll);
                Py_INCREF(Py_None);
                return Py_None;
        }

	free(farmpoll);
        return PyString_FromStringAndSize(message, len);
}


PyObject *py_uwsgi_extract(PyObject * self, PyObject * args) {

        char *name;
	size_t len;
	char *buf;

        if (!PyArg_ParseTuple(args, "s:extract", &name)) {
                return NULL;
        }

	buf = uwsgi_open_and_read(name, &len, 0, NULL);
	if (buf && len > 0) {
        	return PyString_FromStringAndSize(buf, len);
	}
	if (buf)
		free(buf);
	Py_INCREF(Py_None);
	return Py_None;

}


PyObject *py_uwsgi_sharedarea_inclong(PyObject * self, PyObject * args) {
	uint64_t pos = 0;
	uint64_t value = 1;
	uint64_t current_value = 0;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "l|l:sharedarea_inclong", &pos, &value)) {
		return NULL;
	}

	if (pos + 8 >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}
	
	UWSGI_RELEASE_GIL

	uwsgi_wlock(uwsgi.sa_lock);

	memcpy(&current_value, uwsgi.sharedarea + pos, 8);
	value = current_value + value;
	memcpy(uwsgi.sharedarea + pos, &value, 8);

        uwsgi_rwunlock(uwsgi.sa_lock);
	UWSGI_GET_GIL

	return PyInt_FromLong(value);

}

PyObject *py_uwsgi_sharedarea_writelong(PyObject * self, PyObject * args) {
	uint64_t pos = 0;
	uint64_t value = 0;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "ll:sharedarea_writelong", &pos, &value)) {
		return NULL;
	}

	if (pos + 8 >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	UWSGI_RELEASE_GIL

	uwsgi_wlock(uwsgi.sa_lock);

	memcpy(uwsgi.sharedarea + pos, &value, 8);

        uwsgi_rwunlock(uwsgi.sa_lock);

	UWSGI_GET_GIL

	return PyInt_FromLong(value);

}

PyObject *py_uwsgi_sharedarea_write(PyObject * self, PyObject * args) {
	uint64_t pos = 0;
	char *value;
	Py_ssize_t value_len = 0;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "ls#:sharedarea_write", &pos, &value, &value_len)) {
		return NULL;
	}

	if (pos + value_len >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	UWSGI_RELEASE_GIL

	uwsgi_wlock(uwsgi.sa_lock);

	memcpy(uwsgi.sharedarea + pos, value, value_len);


	uwsgi_rwunlock(uwsgi.sa_lock);

	UWSGI_GET_GIL

	return PyInt_FromLong(value_len);
	

}

PyObject *py_uwsgi_sharedarea_writebyte(PyObject * self, PyObject * args) {
	uint64_t pos = 0;
	char value;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}


	if (!PyArg_ParseTuple(args, "lb:sharedarea_writebyte", &pos, &value)) {
		return NULL;
	}

	if (pos >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	UWSGI_RELEASE_GIL

	uwsgi_wlock(uwsgi.sa_lock);

	uwsgi.sharedarea[pos] = value;


	uwsgi_rwunlock(uwsgi.sa_lock);

	UWSGI_GET_GIL

	return PyInt_FromLong(value);

}

PyObject *py_uwsgi_sharedarea_readlong(PyObject * self, PyObject * args) {
	uint64_t pos = 0;
	uint64_t value;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "l:sharedarea_readlong", &pos)) {
		return NULL;
	}

	if (pos + 8 >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	UWSGI_RELEASE_GIL

	uwsgi_wlock(uwsgi.sa_lock);

	memcpy(&value, uwsgi.sharedarea + pos, 8);


	uwsgi_rwunlock(uwsgi.sa_lock);

	UWSGI_GET_GIL

	return PyLong_FromLong(value);

}


PyObject *py_uwsgi_sharedarea_readbyte(PyObject * self, PyObject * args) {
	uint64_t pos = 0;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "l:sharedarea_readbyte", &pos)) {
		return NULL;
	}

	if (pos >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	UWSGI_RELEASE_GIL

	uwsgi_wlock(uwsgi.sa_lock);

	char value = uwsgi.sharedarea[pos];

	uwsgi_rwunlock(uwsgi.sa_lock);

	UWSGI_GET_GIL

	return PyInt_FromLong(value);

}

PyObject *py_uwsgi_sharedarea_read(PyObject * self, PyObject * args) {
	uint64_t pos = 0;
	uint64_t len = 1;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "l|l:sharedarea_read", &pos, &len)) {
		return NULL;
	}

	if (pos + len >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	PyObject *ret = PyString_FromStringAndSize(NULL, len);
#ifdef PYTHREE
	char *storage = PyBytes_AsString(ret);
#else
	char *storage = PyString_AS_STRING(ret);
#endif

	UWSGI_RELEASE_GIL

	uwsgi_wlock(uwsgi.sa_lock);

	memcpy(storage, uwsgi.sharedarea + pos, len);

	uwsgi_rwunlock(uwsgi.sa_lock);

	UWSGI_GET_GIL

	return ret;
}

PyObject *py_uwsgi_spooler_freq(PyObject * self, PyObject * args) {

	if (!PyArg_ParseTuple(args, "i", &uwsgi.shared->spooler_frequency)) {
		return NULL;
	}

	Py_INCREF(Py_True);
	return Py_True;

}

PyObject *py_uwsgi_spooler_jobs(PyObject * self, PyObject * args) {

	DIR *sdir;
	struct dirent *dp;
	char *abs_path;
	struct stat sf_lstat;

	PyObject *jobslist = PyList_New(0);

	struct uwsgi_spooler *uspool = uwsgi.spoolers;

	sdir = opendir(uspool->dir);

	if (sdir) {
		while ((dp = readdir(sdir)) != NULL) {
			if (!strncmp("uwsgi_spoolfile_on_", dp->d_name, 19)) {
				abs_path = malloc(strlen(uspool->dir) + 1 + strlen(dp->d_name) + 1);
				if (!abs_path) {
					uwsgi_error("malloc()");
					closedir(sdir);
					goto clear;
				}

				memset(abs_path, 0, strlen(uspool->dir) + 1 + strlen(dp->d_name) + 1);

				memcpy(abs_path, uspool->dir, strlen(uspool->dir));
				memcpy(abs_path + strlen(uspool->dir), "/", 1);
				memcpy(abs_path + strlen(uspool->dir) + 1, dp->d_name, strlen(dp->d_name));


				if (lstat(abs_path, &sf_lstat)) {
					free(abs_path);
					continue;
				}
				if (!S_ISREG(sf_lstat.st_mode)) {
					free(abs_path);
					continue;
				}
				if (!access(abs_path, R_OK | W_OK)) {
					if (PyList_Append(jobslist, PyString_FromString(abs_path))) {
						PyErr_Print();
					}
				}
				free(abs_path);
			}
		}
		closedir(sdir);
	}

      clear:
	return jobslist;

}


PyObject *py_uwsgi_send_spool(PyObject * self, PyObject * args, PyObject *kw) {
	PyObject *spool_dict, *spool_vars;
	PyObject *zero, *key, *val;
	uint16_t keysize, valsize;
	char *cur_buf;
	int i;
	char spool_filename[1024];
	struct wsgi_request *wsgi_req = py_current_wsgi_req();
	char *priority = NULL;
	long numprio = 0;
	time_t at = 0;
	char *body = NULL;
	size_t body_len= 0;

	// this is a counter for non-request-related tasks (like threads or greenlet)
	static int internal_counter = 0xffff;

	struct uwsgi_spooler *uspool = uwsgi.spoolers;

	spool_dict = PyTuple_GetItem(args, 0);

	if (spool_dict) {

		if (!PyDict_Check(spool_dict)) {
			return PyErr_Format(PyExc_ValueError, "The argument of spooler callable must be a dictionary");
		}
	}
	else {
		// clear the error
		PyErr_Clear();
		spool_dict = kw;
	}

	
	if (!spool_dict) {
		return PyErr_Format(PyExc_ValueError, "The argument of spooler callable must be a dictionary");
	}

	// TODO if "spooler"  is a num, get the spooler by id, otherwise get it by directory
	PyObject *py_spooler = uwsgi_py_dict_get(spool_dict, "spooler");
	if (py_spooler) {
		if (PyString_Check(py_spooler)) {
			uspool = uwsgi_get_spooler_by_name(PyString_AsString(py_spooler));
			if (!uspool) {
				return PyErr_Format(PyExc_ValueError, "Unknown spooler requested");
			}
		}
	}

	PyObject *pyprio = uwsgi_py_dict_get(spool_dict, "priority");
	if (pyprio) {
		if (PyInt_Check(pyprio)) {
			numprio = PyInt_AsLong(pyprio);
			uwsgi_py_dict_del(spool_dict, "priority");
		}
	}

	PyObject *pyat = uwsgi_py_dict_get(spool_dict, "at");
	if (pyat) {
		if (PyInt_Check(pyat)) {
			at = (time_t) PyInt_AsLong(pyat);
			uwsgi_py_dict_del(spool_dict, "at");
		}
		else if (PyLong_Check(pyat)) {
			at = (time_t) PyLong_AsLong(pyat);
			uwsgi_py_dict_del(spool_dict, "at");
		}
		else if (PyFloat_Check(pyat)) {
			at = (time_t) PyFloat_AsDouble(pyat);
			uwsgi_py_dict_del(spool_dict, "at");
		}
	}

	PyObject *pybody = uwsgi_py_dict_get(spool_dict, "body");
	if (pybody) {
		if (PyString_Check(pybody)) {
			body = PyString_AsString(pybody);
			body_len = PyString_Size(pybody);
			uwsgi_py_dict_del(spool_dict, "body");
		}
	}

	spool_vars = PyDict_Items(spool_dict);
	if (!spool_vars) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	char *spool_buffer = uwsgi_malloc(UMAX16);

	cur_buf = spool_buffer;

	for (i = 0; i < PyList_Size(spool_vars); i++) {
		zero = PyList_GetItem(spool_vars, i);
		if (zero) {
			if (PyTuple_Check(zero)) {
				key = PyTuple_GetItem(zero, 0);
				val = PyTuple_GetItem(zero, 1);

#ifdef UWSGI_DEBUG
				uwsgi_log("ob_type %s %s\n", key->ob_type->tp_name, val->ob_type->tp_name);
#endif

				if (PyString_Check(key) && PyString_Check(val)) {


					keysize = PyString_Size(key);
					valsize = PyString_Size(val);
					if (cur_buf + keysize + 2 + valsize + 2 <= spool_buffer + UMAX16) {

						*cur_buf++ = (uint8_t) (keysize & 0xff);
        					*cur_buf++ = (uint8_t) ((keysize >> 8) & 0xff);

						memcpy(cur_buf, PyString_AsString(key), keysize);
						cur_buf += keysize;

						*cur_buf++ = (uint8_t) (valsize & 0xff);
        					*cur_buf++ = (uint8_t) ((valsize >> 8) & 0xff);

						memcpy(cur_buf, PyString_AsString(val), valsize);
						cur_buf += valsize;
					}
					else {
						Py_DECREF(zero);
						free(spool_buffer);	
						return PyErr_Format(PyExc_ValueError, "spooler packet cannot be more than %d bytes", UMAX16);
					}
				}
				else {
					Py_DECREF(zero);
					free(spool_buffer);
					return PyErr_Format(PyExc_ValueError, "spooler callable dictionary must contains only strings");
				}
			}
			else {
				free(spool_buffer);
				Py_DECREF(zero);
				Py_INCREF(Py_None);
				return Py_None;
			}
		}
		else {
			free(spool_buffer);
			Py_INCREF(Py_None);
			return Py_None;
		}
	}


	if (numprio) {
		priority = uwsgi_num2str(numprio);
	} 

	int async_id;

	if (wsgi_req) {
		async_id = wsgi_req->async_id;
	}
	else {
		// the GIL is protecting this counter...
		async_id = internal_counter;
		internal_counter++;
	}

	UWSGI_RELEASE_GIL

	i = spool_request(uspool, spool_filename, uwsgi.workers[0].requests + 1, async_id, spool_buffer, cur_buf - spool_buffer, priority, at, body, body_len);

	UWSGI_GET_GIL
	
	if (priority) {
		free(priority);
	}
		
	free(spool_buffer);


	Py_DECREF(spool_vars);

	if (i > 0) {
		char *slash = uwsgi_get_last_char(spool_filename, '/');
		if (slash) {
			return PyString_FromString(slash+1);
		}
		return PyString_FromString(spool_filename);
	}
	return PyErr_Format(PyExc_ValueError, "unable to spool job");
}

PyObject *py_uwsgi_spooler_pid(PyObject * self, PyObject * args) {
	struct uwsgi_spooler *uspool = uwsgi.spoolers;
	if (!uwsgi.spoolers) return PyInt_FromLong(0);
	return PyInt_FromLong(uspool->pid);
}


PyObject *py_uwsgi_get_option(PyObject * self, PyObject * args) {
	int opt_id;

	if (!PyArg_ParseTuple(args, "i:get_option", &opt_id)) {
		return NULL;
	}

	return PyInt_FromLong(uwsgi.shared->options[(uint8_t) opt_id]);
}

PyObject *py_uwsgi_set_option(PyObject * self, PyObject * args) {
	int opt_id;
	int value;

	if (!PyArg_ParseTuple(args, "ii:set_option", &opt_id, &value)) {
		return NULL;
	}

	uwsgi.shared->options[(uint8_t) opt_id] = (uint32_t) value;
	return PyInt_FromLong(value);
}

PyObject *py_uwsgi_has_hook(PyObject * self, PyObject * args) {
	int modifier1;

	if (!PyArg_ParseTuple(args, "i:has_hook", &modifier1)) {
		return NULL;
	}

	/*
	   if (uwsgi.shared->hooks[modifier1] != unconfigured_hook) {
	   Py_INCREF(Py_True);
	   return Py_True;
	   }
	 */

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_connect(PyObject * self, PyObject * args) {

	char *socket_name = NULL;
	int timeout = 0;
	if (!PyArg_ParseTuple(args, "s|i:connect", &socket_name, &timeout)) {
		return NULL;
	}

	return PyInt_FromLong(uwsgi_connect(socket_name, timeout, 0));
}

PyObject *py_uwsgi_async_connect(PyObject * self, PyObject * args) {

	char *socket_name = NULL;
	if (!PyArg_ParseTuple(args, "s:async_connect", &socket_name)) {
		return NULL;
	}

	return PyInt_FromLong(uwsgi_connect(socket_name, 0, 1));
}

/* uWSGI masterpid */
PyObject *py_uwsgi_masterpid(PyObject * self, PyObject * args) {
	if (uwsgi.master_process) {
		return PyInt_FromLong(uwsgi.workers[0].pid);
	}
	return PyInt_FromLong(0);
}

	/* uWSGI total_requests */
PyObject *py_uwsgi_total_requests(PyObject * self, PyObject * args) {
	return PyLong_FromUnsignedLongLong(uwsgi.workers[0].requests);
}

	/* uWSGI workers */
PyObject *py_uwsgi_workers(PyObject * self, PyObject * args) {

	PyObject *worker_dict, *apps_dict, *apps_tuple, *zero;
	int i, j;
	struct uwsgi_app *ua;

	for (i = 0; i < uwsgi.numproc; i++) {
		worker_dict = PyTuple_GetItem(up.workers_tuple, i);
		if (!worker_dict) {
			goto clear;
		}

		apps_tuple = PyDict_GetItemString(worker_dict, "apps");
		if (apps_tuple) {
			Py_DECREF(apps_tuple);
		}	

		PyDict_Clear(worker_dict);

		zero = PyInt_FromLong(uwsgi.workers[i + 1].id);
		if (PyDict_SetItemString(worker_dict, "id", zero)) {
			goto clear;
		}
		Py_DECREF(zero);


		zero = PyInt_FromLong(uwsgi.workers[i + 1].pid);
		if (PyDict_SetItemString(worker_dict, "pid", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromUnsignedLongLong(uwsgi.workers[i + 1].requests);
		if (PyDict_SetItemString(worker_dict, "requests", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromUnsignedLongLong(uwsgi.workers[i + 1].delta_requests);
		if (PyDict_SetItemString(worker_dict, "delta_requests", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromUnsignedLongLong(uwsgi.workers[i + 1].signals);
		if (PyDict_SetItemString(worker_dict, "signals", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromUnsignedLongLong(uwsgi_worker_exceptions(i+1));
		if (PyDict_SetItemString(worker_dict, "exceptions", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		if (uwsgi.workers[i + 1].cheaped) {
			zero = PyString_FromString("cheap");
		}
		else if (uwsgi.workers[i + 1].suspended && !uwsgi_worker_is_busy(i+1)) {
			zero = PyString_FromString("pause");
		}
		else {
			if (uwsgi.workers[i + 1].sig) {
				zero = PyString_FromFormat("sig%d",uwsgi.workers[i + 1].signum);
			}
			else if (uwsgi_worker_is_busy(i+1)) {
				zero = PyString_FromString("busy");
			}
			else {
				zero = PyString_FromString("idle");
			}
		}
		if (PyDict_SetItemString(worker_dict, "status", zero)) {
                        goto clear;
                }

		Py_DECREF(zero);

		zero = PyLong_FromUnsignedLongLong(uwsgi.workers[i + 1].rss_size);
		if (PyDict_SetItemString(worker_dict, "rss", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromUnsignedLongLong(uwsgi.workers[i + 1].vsz_size);
		if (PyDict_SetItemString(worker_dict, "vsz", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromUnsignedLongLong(uwsgi.workers[i + 1].running_time);
		if (PyDict_SetItemString(worker_dict, "running_time", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromLong(uwsgi.workers[i + 1].last_spawn);
		if (PyDict_SetItemString(worker_dict, "last_spawn", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromUnsignedLongLong(uwsgi.workers[i + 1].respawn_count-1);
		if (PyDict_SetItemString(worker_dict, "respawn_count", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromUnsignedLongLong(uwsgi.workers[i + 1].tx);
		if (PyDict_SetItemString(worker_dict, "tx", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromUnsignedLongLong(uwsgi.workers[i + 1].avg_response_time);
		if (PyDict_SetItemString(worker_dict, "avg_rt", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		apps_tuple = PyTuple_New(uwsgi.workers[i+1].apps_cnt);

		for(j=0;j<uwsgi.workers[i+1].apps_cnt;j++) {
			apps_dict = PyDict_New();
			ua = &uwsgi.workers[i+1].apps[j];

			zero = PyInt_FromLong(j);
			PyDict_SetItemString(apps_dict, "id", zero);
			Py_DECREF(zero);

			zero = PyInt_FromLong(ua->modifier1);
			PyDict_SetItemString(apps_dict, "modifier1", zero);
			Py_DECREF(zero);

			zero = PyString_FromStringAndSize(ua->mountpoint, ua->mountpoint_len);
			PyDict_SetItemString(apps_dict, "mountpoint", zero);
			Py_DECREF(zero);

			zero = PyInt_FromLong((long) ua->startup_time);
			PyDict_SetItemString(apps_dict, "startup_time", zero);
			Py_DECREF(zero);

			zero = PyInt_FromLong((long)ua->interpreter);
			PyDict_SetItemString(apps_dict, "interpreter", zero);
			Py_DECREF(zero);

			zero = PyInt_FromLong((long)ua->callable);
			PyDict_SetItemString(apps_dict, "callable", zero);
			Py_DECREF(zero);

			zero = PyLong_FromUnsignedLongLong(ua->requests);
			PyDict_SetItemString(apps_dict, "requests", zero);
			Py_DECREF(zero);

			zero = PyLong_FromUnsignedLongLong(ua->exceptions);
			PyDict_SetItemString(apps_dict, "exceptions", zero);
			Py_DECREF(zero);

			if (ua->chdir) {
				zero = PyString_FromString(ua->chdir);
			}
			else {
				zero = PyString_FromString("");
			}
			PyDict_SetItemString(apps_dict, "chdir", zero);
			Py_DECREF(zero);

			PyTuple_SetItem(apps_tuple, j, apps_dict);
		}
	

		PyDict_SetItemString(worker_dict, "apps", apps_tuple);

	}


	Py_INCREF(up.workers_tuple);
	return up.workers_tuple;

      clear:
	PyErr_Print();
	PyErr_Clear();
	Py_INCREF(Py_None);
	return Py_None;

}


	/* uWSGI reload */
PyObject *py_uwsgi_reload(PyObject * self, PyObject * args) {

	if (kill(uwsgi.workers[0].pid, SIGHUP)) {
		uwsgi_error("kill()");
		Py_INCREF(Py_None);
		return Py_None;
	}

	Py_INCREF(Py_True);
	return Py_True;
}

/* uWSGI stop */
PyObject *py_uwsgi_stop(PyObject * self, PyObject * args) {

        if (kill(uwsgi.workers[0].pid, SIGQUIT)) {
                uwsgi_error("kill()");
                Py_INCREF(Py_None);
                return Py_None;
        }

        Py_INCREF(Py_True);
        return Py_True;
}


	/* blocking hint */
PyObject *py_uwsgi_set_blocking(PyObject * self, PyObject * args) {

	if (uwsgi.master_process) {
		Py_INCREF(Py_True);
		return Py_True;
	}


	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *py_uwsgi_request_id(PyObject * self, PyObject * args) {
	return PyLong_FromUnsignedLongLong(uwsgi.workers[uwsgi.mywid].requests);
}

PyObject *py_uwsgi_worker_id(PyObject * self, PyObject * args) {
	return PyInt_FromLong(uwsgi.mywid);
}

PyObject *py_uwsgi_mule_id(PyObject * self, PyObject * args) {
	return PyInt_FromLong(uwsgi.muleid);
}

PyObject *py_uwsgi_logsize(PyObject * self, PyObject * args) {
	return PyLong_FromUnsignedLongLong(uwsgi.shared->logsize);
}

PyObject *py_uwsgi_mem(PyObject * self, PyObject * args) {

	uint64_t rss=0, vsz = 0;
	PyObject *ml = PyTuple_New(2);

	get_memusage(&rss, &vsz);

	PyTuple_SetItem(ml, 0, PyLong_FromUnsignedLongLong(rss));
	PyTuple_SetItem(ml, 1, PyLong_FromUnsignedLongLong(vsz));

	return ml;

}

PyObject *py_uwsgi_cl(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = py_current_wsgi_req();

	return PyLong_FromUnsignedLongLong(wsgi_req->post_cl);

}

PyObject *py_uwsgi_disconnect(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = py_current_wsgi_req();

#ifdef UWSGI_DEBUG
	uwsgi_log("disconnecting worker %d (pid :%d) from session...\n", uwsgi.mywid, uwsgi.mypid);
#endif

	if (wsgi_req->socket) {
		wsgi_req->socket->proto_close(wsgi_req);
	}
	wsgi_req->fd_closed = 1;

	Py_INCREF(Py_True);
	return Py_True;
}

PyObject *py_uwsgi_parse_file(PyObject * self, PyObject * args) {

	char *filename;
	int fd;
	ssize_t len;
	char *buffer, *ptrbuf, *bufferend, *keybuf;
	uint16_t strsize = 0, keysize = 0;

	struct uwsgi_header uh;
	PyObject *zero;

	if (!PyArg_ParseTuple(args, "s:parsefile", &filename)) {
		return NULL;
	}

	UWSGI_RELEASE_GIL

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_error_open(filename);
		UWSGI_GET_GIL
		goto clear;
	}

	len = read(fd, &uh, 4);
	if (len != 4) {
		uwsgi_error("read()");
		UWSGI_GET_GIL
		goto clear2;
	}

	buffer = malloc(uh.pktsize);
	if (!buffer) {
		uwsgi_error("malloc()");
		UWSGI_GET_GIL
		goto clear2;
	}
	len = read(fd, buffer, uh.pktsize);
	if (len != uh.pktsize) {
		uwsgi_error("read()");
		free(buffer);
		UWSGI_GET_GIL
		goto clear2;
	}

	UWSGI_GET_GIL

	ptrbuf = buffer;
	bufferend = ptrbuf + uh.pktsize;

	if (!uh.modifier1 || uh.modifier1 == UWSGI_MODIFIER_SPOOL_REQUEST) {
		zero = PyDict_New();

		while (ptrbuf < bufferend) {
			if (ptrbuf + 2 < bufferend) {
				memcpy(&strsize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
				strsize = uwsgi_swap16(strsize);
#endif
				/* key cannot be null */
				if (!strsize) {
					uwsgi_log("uwsgi key cannot be null.\n");
					goto clear3;
				}

				ptrbuf += 2;
				if (ptrbuf + strsize < bufferend) {
					// var key
					keybuf = ptrbuf;
					keysize = strsize;
					ptrbuf += strsize;
					// value can be null (even at the end) so use <=
					if (ptrbuf + 2 <= bufferend) {
						memcpy(&strsize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
						strsize = uwsgi_swap16(strsize);
#endif
						ptrbuf += 2;
						if (ptrbuf + strsize <= bufferend) {
							PyDict_SetItem(zero, PyString_FromStringAndSize(keybuf, keysize), PyString_FromStringAndSize(ptrbuf, strsize));
							ptrbuf += strsize;
						}
						else {
							goto clear3;
						}
					}
					else {
						goto clear3;
					}
				}
			}
			else {
				goto clear3;
			}
		}

		close(fd);
		free(buffer);
		return zero;

	}

	free(buffer);
	goto clear2;

      clear3:
	Py_DECREF(zero);
	free(buffer);
      clear2:
	close(fd);
      clear:
	Py_INCREF(Py_None);
	return Py_None;

}

static PyMethodDef uwsgi_spooler_methods[] = {
#ifdef PYTHREE
	{"send_to_spooler", (PyCFunction) py_uwsgi_send_spool, METH_VARARGS | METH_KEYWORDS, ""},
	{"spool", (PyCFunction) py_uwsgi_send_spool, METH_VARARGS | METH_KEYWORDS, ""},
#else
	{"send_to_spooler", (PyCFunction) py_uwsgi_send_spool, METH_KEYWORDS, ""},
	{"spool", (PyCFunction) py_uwsgi_send_spool, METH_KEYWORDS, ""},
#endif
	{"set_spooler_frequency", py_uwsgi_spooler_freq, METH_VARARGS, ""},
	{"spooler_jobs", py_uwsgi_spooler_jobs, METH_VARARGS, ""},
	{"spooler_pid", py_uwsgi_spooler_pid, METH_VARARGS, ""},
	{NULL, NULL},
};


PyObject *py_uwsgi_suspend(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = py_current_wsgi_req();

	if (uwsgi.schedule_to_main) uwsgi.schedule_to_main(wsgi_req);

	Py_INCREF(Py_True);
	return Py_True;

}

static PyMethodDef uwsgi_advanced_methods[] = {
	{"reload", py_uwsgi_reload, METH_VARARGS, ""},
	{"stop", py_uwsgi_stop, METH_VARARGS, ""},
	{"workers", py_uwsgi_workers, METH_VARARGS, ""},
	{"masterpid", py_uwsgi_masterpid, METH_VARARGS, ""},
	{"total_requests", py_uwsgi_total_requests, METH_VARARGS, ""},
	{"getoption", py_uwsgi_get_option, METH_VARARGS, ""},
	{"get_option", py_uwsgi_get_option, METH_VARARGS, ""},
	{"setoption", py_uwsgi_set_option, METH_VARARGS, ""},
	{"set_option", py_uwsgi_set_option, METH_VARARGS, ""},
	{"sorry_i_need_to_block", py_uwsgi_set_blocking, METH_VARARGS, ""},
	{"request_id", py_uwsgi_request_id, METH_VARARGS, ""},
	{"worker_id", py_uwsgi_worker_id, METH_VARARGS, ""},
	{"mule_id", py_uwsgi_mule_id, METH_VARARGS, ""},
	{"log", py_uwsgi_log, METH_VARARGS, ""},
	{"log_this_request", py_uwsgi_log_this, METH_VARARGS, ""},
	{"set_logvar", py_uwsgi_set_logvar, METH_VARARGS, ""},
	{"get_logvar", py_uwsgi_get_logvar, METH_VARARGS, ""},
	{"alarm", py_uwsgi_alarm, METH_VARARGS, ""},
	{"disconnect", py_uwsgi_disconnect, METH_VARARGS, ""},
	{"lock", py_uwsgi_lock, METH_VARARGS, ""},
	{"is_locked", py_uwsgi_is_locked, METH_VARARGS, ""},
	{"unlock", py_uwsgi_unlock, METH_VARARGS, ""},
	{"cl", py_uwsgi_cl, METH_VARARGS, ""},

	{"setprocname", py_uwsgi_setprocname, METH_VARARGS, ""},

	{"listen_queue", py_uwsgi_listen_queue, METH_VARARGS, ""},

	{"register_signal", py_uwsgi_register_signal, METH_VARARGS, ""},
	{"signal", py_uwsgi_signal, METH_VARARGS, ""},
	{"signal_wait", py_uwsgi_signal_wait, METH_VARARGS, ""},
	{"signal_registered", py_uwsgi_signal_registered, METH_VARARGS, ""},
	{"signal_received", py_uwsgi_signal_received, METH_VARARGS, ""},
	{"add_file_monitor", py_uwsgi_add_file_monitor, METH_VARARGS, ""},
	{"add_timer", py_uwsgi_add_timer, METH_VARARGS, ""},
	{"add_probe", py_uwsgi_add_probe, METH_VARARGS, ""},
	{"add_rb_timer", py_uwsgi_add_rb_timer, METH_VARARGS, ""},
	{"add_cron", py_uwsgi_add_cron, METH_VARARGS, ""},

#ifdef UWSGI_ROUTING
	{"route", py_uwsgi_route, METH_VARARGS, ""},
#endif

	{"register_rpc", py_uwsgi_register_rpc, METH_VARARGS, ""},
	{"rpc", py_uwsgi_rpc, METH_VARARGS, ""},
	{"rpc_list", py_uwsgi_rpc_list, METH_VARARGS, ""},
	{"call", py_uwsgi_call, METH_VARARGS, ""},
	{"sendfile", py_uwsgi_advanced_sendfile, METH_VARARGS, ""},
	{"offload", py_uwsgi_offload, METH_VARARGS, ""},
	{"set_warning_message", py_uwsgi_warning, METH_VARARGS, ""},
	{"mem", py_uwsgi_mem, METH_VARARGS, ""},
	{"has_hook", py_uwsgi_has_hook, METH_VARARGS, ""},
	{"logsize", py_uwsgi_logsize, METH_VARARGS, ""},
#ifdef UWSGI_SSL
	{"i_am_the_lord", py_uwsgi_i_am_the_lord, METH_VARARGS, ""},
	{"lord_scroll", py_uwsgi_lord_scroll, METH_VARARGS, ""},
	{"scrolls", py_uwsgi_scrolls, METH_VARARGS, ""},
#endif
	{"async_sleep", py_uwsgi_async_sleep, METH_VARARGS, ""},
	{"async_connect", py_uwsgi_async_connect, METH_VARARGS, ""},

	{"green_schedule", py_uwsgi_suspend, METH_VARARGS, ""},
	{"suspend", py_uwsgi_suspend, METH_VARARGS, ""},
	{"wait_fd_read", py_eventfd_read, METH_VARARGS, ""},
	{"wait_fd_write", py_eventfd_write, METH_VARARGS, ""},

	{"connect", py_uwsgi_connect, METH_VARARGS, ""},
	{"connection_fd", py_uwsgi_connection_fd, METH_VARARGS, ""},
	{"is_connected", py_uwsgi_is_connected, METH_VARARGS, ""},
	{"send", py_uwsgi_send, METH_VARARGS, ""},
	{"recv", py_uwsgi_recv, METH_VARARGS, ""},
	{"recv_block", py_uwsgi_recv_block, METH_VARARGS, ""},
	{"close", py_uwsgi_close, METH_VARARGS, ""},
	{"i_am_the_spooler", py_uwsgi_i_am_the_spooler, METH_VARARGS, ""},

	{"parsefile", py_uwsgi_parse_file, METH_VARARGS, ""},
	{"embedded_data", py_uwsgi_embedded_data, METH_VARARGS, ""},
	{"extract", py_uwsgi_extract, METH_VARARGS, ""},

	{"mule_msg", py_uwsgi_mule_msg, METH_VARARGS, ""},
	{"farm_msg", py_uwsgi_farm_msg, METH_VARARGS, ""},
	{"mule_get_msg", (PyCFunction) py_uwsgi_mule_get_msg, METH_VARARGS|METH_KEYWORDS, ""},
	{"farm_get_msg", py_uwsgi_farm_get_msg, METH_VARARGS, ""},
	{"in_farm", py_uwsgi_in_farm, METH_VARARGS, ""},

	{"ready", py_uwsgi_ready, METH_VARARGS, ""},

	{"set_user_harakiri", py_uwsgi_set_user_harakiri, METH_VARARGS, ""},
	//{"call_hook", py_uwsgi_call_hook, METH_VARARGS, ""},

	{"websocket_recv", py_uwsgi_websocket_recv, METH_VARARGS, ""},
	{"websocket_recv_nb", py_uwsgi_websocket_recv_nb, METH_VARARGS, ""},
	{"websocket_send", py_uwsgi_websocket_send, METH_VARARGS, ""},
	{"websocket_handshake", py_uwsgi_websocket_handshake, METH_VARARGS, ""},

	{NULL, NULL},
};


static PyMethodDef uwsgi_sa_methods[] = {
	{"sharedarea_read", py_uwsgi_sharedarea_read, METH_VARARGS, ""},
	{"sharedarea_write", py_uwsgi_sharedarea_write, METH_VARARGS, ""},
	{"sharedarea_readbyte", py_uwsgi_sharedarea_readbyte, METH_VARARGS, ""},
	{"sharedarea_writebyte", py_uwsgi_sharedarea_writebyte, METH_VARARGS, ""},
	{"sharedarea_readlong", py_uwsgi_sharedarea_readlong, METH_VARARGS, ""},
	{"sharedarea_writelong", py_uwsgi_sharedarea_writelong, METH_VARARGS, ""},
	{"sharedarea_inclong", py_uwsgi_sharedarea_inclong, METH_VARARGS, ""},
	{NULL, NULL},
};

PyObject *py_uwsgi_cache_clear(PyObject * self, PyObject * args) {

        char *cache = NULL;

        if (!PyArg_ParseTuple(args, "|s:cache_clear", &cache)) {
                return NULL;
        }

        UWSGI_RELEASE_GIL
        if (!uwsgi_cache_magic_clear(cache)) {
                UWSGI_GET_GIL
                Py_INCREF(Py_True);
                return Py_True;
        }
        UWSGI_GET_GIL

        Py_INCREF(Py_None);
        return Py_None;
}


PyObject *py_uwsgi_cache_del(PyObject * self, PyObject * args) {

	char *key;
        Py_ssize_t keylen = 0;
        char *cache = NULL;

        if (!PyArg_ParseTuple(args, "s#|s:cache_del", &key, &keylen, &cache)) {
                return NULL;
        }

        UWSGI_RELEASE_GIL
        if (!uwsgi_cache_magic_del(key, keylen, cache)) {
                UWSGI_GET_GIL
                Py_INCREF(Py_True);
                return Py_True;
        }
        UWSGI_GET_GIL

        Py_INCREF(Py_None);
        return Py_None;


}


PyObject *py_uwsgi_cache_set(PyObject * self, PyObject * args) {

	char *key;
	char *value;
	Py_ssize_t vallen = 0;
	Py_ssize_t keylen = 0;
	char *remote = NULL;

	uint64_t expires = 0;

	if (!PyArg_ParseTuple(args, "s#s#|is:cache_set", &key, &keylen, &value, &vallen, &expires, &remote)) {
		return NULL;
	}

	UWSGI_RELEASE_GIL
	if (uwsgi_cache_magic_set(key, keylen, value, vallen, expires, 0, remote)) {
		UWSGI_GET_GIL
		Py_INCREF(Py_None);
		return Py_None;
	}
	UWSGI_GET_GIL

	Py_INCREF(Py_True);
	return Py_True;

}

PyObject *py_uwsgi_cache_update(PyObject * self, PyObject * args) {

	char *key;
        char *value;
        Py_ssize_t vallen = 0;
        Py_ssize_t keylen = 0;
        char *remote = NULL;

        uint64_t expires = 0;

        if (!PyArg_ParseTuple(args, "s#s#|is:cache_update", &key, &keylen, &value, &vallen, &expires, &remote)) {
                return NULL;
        }

        UWSGI_RELEASE_GIL
        if (uwsgi_cache_magic_set(key, keylen, value, vallen, expires, UWSGI_CACHE_FLAG_UPDATE, remote)) {
                UWSGI_GET_GIL
                Py_INCREF(Py_None);
                return Py_None;
        }
        UWSGI_GET_GIL

        Py_INCREF(Py_True);
        return Py_True;

}



PyObject *py_uwsgi_cache_exists(PyObject * self, PyObject * args) {

	char *key;
        Py_ssize_t keylen = 0;
        char *cache = NULL;

        if (!PyArg_ParseTuple(args, "s#|s:cache_exists", &key, &keylen, &cache)) {
                return NULL;
        }

        UWSGI_RELEASE_GIL
        if (uwsgi_cache_magic_exists(key, keylen, cache)) {
		UWSGI_GET_GIL
		Py_INCREF(Py_True);
		return Py_True;
	}
        UWSGI_GET_GIL

        Py_INCREF(Py_None);
        return Py_None;
}

PyObject *py_uwsgi_queue_push(PyObject * self, PyObject * args) {

	Py_ssize_t msglen = 0;
	char *message ;
	PyObject *res;

	if (!PyArg_ParseTuple(args, "s#:queue_push", &message, &msglen)) {
                return NULL;
        }
	
	if (uwsgi.queue_size) {
		UWSGI_RELEASE_GIL
                uwsgi_wlock(uwsgi.queue_lock);
                if (uwsgi_queue_push(message, msglen)) {
                	uwsgi_rwunlock(uwsgi.queue_lock);
			UWSGI_GET_GIL
			Py_INCREF(Py_True);
                        res = Py_True;
                }
                else {
                	uwsgi_rwunlock(uwsgi.queue_lock);
			UWSGI_GET_GIL
                        Py_INCREF(Py_None);
                        res = Py_None;
                }
                return res;
        }

        Py_INCREF(Py_None);
        return Py_None;
	
}

PyObject *py_uwsgi_queue_set(PyObject * self, PyObject * args) {

        Py_ssize_t msglen = 0;
	uint64_t pos = 0;
        char *message ;
        PyObject *res;

        if (!PyArg_ParseTuple(args, "ls#:queue_set", &pos, &message, &msglen)) {
                return NULL;
        }

        if (uwsgi.queue_size) {
		UWSGI_RELEASE_GIL
                uwsgi_wlock(uwsgi.queue_lock);
                if (uwsgi_queue_set(pos, message, msglen)) {
                	uwsgi_rwunlock(uwsgi.queue_lock);
			UWSGI_GET_GIL
                        Py_INCREF(Py_True);
                        res = Py_True;
                }
                else {
                	uwsgi_rwunlock(uwsgi.queue_lock);
			UWSGI_GET_GIL
                        Py_INCREF(Py_None);
                        res = Py_None;
                }
                return res;
        }

        Py_INCREF(Py_None);
        return Py_None;

}


PyObject *py_uwsgi_queue_slot(PyObject * self, PyObject * args) {

	return PyLong_FromUnsignedLongLong(uwsgi.queue_header->pos);
}

PyObject *py_uwsgi_queue_pull_slot(PyObject * self, PyObject * args) {

	return PyLong_FromUnsignedLongLong(uwsgi.queue_header->pull_pos);
}


PyObject *py_uwsgi_queue_pull(PyObject * self, PyObject * args) {

	char *message;
	uint64_t size;
	PyObject *res;
	char *storage;

	if (uwsgi.queue_size) {
		UWSGI_RELEASE_GIL
		uwsgi_wlock(uwsgi.queue_lock);

		message = uwsgi_queue_pull(&size);

                if (!message || size == 0) {
                	uwsgi_rwunlock(uwsgi.queue_lock);
			UWSGI_GET_GIL
                        Py_INCREF(Py_None);
                        return Py_None;
                }

                storage = uwsgi_malloc(size);
		memcpy(storage, message, size);

                uwsgi_rwunlock(uwsgi.queue_lock);
		UWSGI_GET_GIL

		res = PyString_FromStringAndSize(storage, size);
		free(storage);
                return res;
	}

	Py_INCREF(Py_None);     
        return Py_None;

}

PyObject *py_uwsgi_queue_pop(PyObject * self, PyObject * args) {

        char *message;
        uint64_t size;
        PyObject *res;
	char *storage;

        if (uwsgi.queue_size) {

		UWSGI_RELEASE_GIL
                uwsgi_wlock(uwsgi.queue_lock);

                message = uwsgi_queue_pop(&size);
		if (!message || size == 0) {
                	uwsgi_rwunlock(uwsgi.queue_lock);
			UWSGI_GET_GIL
                        Py_INCREF(Py_None);
			return Py_None;
		}

		storage = uwsgi_malloc(size);
                memcpy(storage, message, size);

                uwsgi_rwunlock(uwsgi.queue_lock);
		UWSGI_GET_GIL

		res = PyString_FromStringAndSize(storage, size);
		free(storage);
                return res;
        }

        Py_INCREF(Py_None);
        return Py_None;

}


PyObject *py_uwsgi_queue_get(PyObject * self, PyObject * args) {

	long index = 0;
	uint64_t size = 0;
	char *message;
	PyObject *res;
	char *storage;

	if (!PyArg_ParseTuple(args, "l:queue_get", &index)) {
                return NULL;
        }

	if (uwsgi.queue_size) {
		UWSGI_RELEASE_GIL
		uwsgi_rlock(uwsgi.queue_lock);

		message = uwsgi_queue_get(index, &size);
                if (!message || size == 0) {
			uwsgi_rwunlock(uwsgi.queue_lock);
			UWSGI_GET_GIL
                        Py_INCREF(Py_None);
			return Py_None;
		}

		storage = uwsgi_malloc(size);
                memcpy(storage, message, size);

		uwsgi_rwunlock(uwsgi.queue_lock);
		UWSGI_GET_GIL

                res = PyString_FromStringAndSize(storage, size);
		free(storage);
		return res;
	}	

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_queue_last(PyObject * self, PyObject * args) {

        long i, num = 0;
        uint64_t size = 0;
        char *message;
        PyObject *res = NULL;
	uint64_t base;
	char *storage;

        if (!PyArg_ParseTuple(args, "|l:queue_last", &num)) {
                return NULL;
        }

        if (uwsgi.queue_size) {

		if (num > 0) {
			res = PyList_New(0);
		}

		UWSGI_RELEASE_GIL
                uwsgi_rlock(uwsgi.queue_lock);

		if (uwsgi.queue_header->pos > 0) {
			base = uwsgi.queue_header->pos-1;
		}
		else {
			base = uwsgi.queue_size-1;
		}

		if (num == 0) {
                	message = uwsgi_queue_get(base, &size);
                	if (!message || size == 0) {
                		uwsgi_rwunlock(uwsgi.queue_lock);
				UWSGI_GET_GIL
                        	Py_INCREF(Py_None);
				return Py_None;
			}

			storage = uwsgi_malloc(size);
                        memcpy(storage, message, size);

                	uwsgi_rwunlock(uwsgi.queue_lock);
			UWSGI_GET_GIL

			res = PyString_FromStringAndSize(storage, size);
			free(storage);
			return res;
		}

		if (num > (long)uwsgi.queue_size) num = uwsgi.queue_size;

		char **queue_items = uwsgi_malloc(sizeof(char *) * num);
		uint64_t *queue_items_size = uwsgi_malloc(sizeof(uint64_t) * num);
		long item_pos = 0;
		while(num) {
                	message = uwsgi_queue_get(base, &size);
                	if (!message || size == 0) {
				queue_items[item_pos] = NULL;
				queue_items_size[item_pos] = 0;
                	}
			else {
				queue_items[item_pos] = uwsgi_malloc(size);
				memcpy(queue_items[item_pos], message, size);
				queue_items_size[item_pos] = size;
			}
			item_pos++;
			if (base > 0) {
				base--;
			}
			else {
				base = uwsgi.queue_size-1;
			}
			num--;
		}

                uwsgi_rwunlock(uwsgi.queue_lock);
		UWSGI_GET_GIL

		for(i=0;i<item_pos;i++) {
			if (queue_items[i]) {
				PyObject *zero = PyString_FromStringAndSize(queue_items[i], queue_items_size[i]);
				PyList_Append(res, zero);
				Py_DECREF(zero);
				free(queue_items[i]);
			}
			else {
				Py_INCREF(Py_None);
				PyList_Append(res, Py_None);
			}
		}
		free(queue_items);
		free(queue_items_size);
                return res;
        }

        Py_INCREF(Py_None);
        return Py_None;
}


PyObject *py_uwsgi_cache_get(PyObject * self, PyObject * args) {

	char *key;
	Py_ssize_t keylen = 0;
	char *cache = NULL;

	if (!PyArg_ParseTuple(args, "s#|s:cache_get", &key, &keylen, &cache)) {
		return NULL;
	}

	uint64_t vallen = 0;
	UWSGI_RELEASE_GIL
	char *value = uwsgi_cache_magic_get(key, keylen, &vallen, cache);
	UWSGI_GET_GIL
	if (value) {
		// in python 3.x we return bytes
		PyObject *ret = PyString_FromStringAndSize(value, vallen);
		free(value);
		return ret;
	}

	Py_INCREF(Py_None);
	return Py_None;

}

static PyMethodDef uwsgi_cache_methods[] = {
	{"cache_get", py_uwsgi_cache_get, METH_VARARGS, ""},
	{"cache_set", py_uwsgi_cache_set, METH_VARARGS, ""},
	{"cache_update", py_uwsgi_cache_update, METH_VARARGS, ""},
	{"cache_del", py_uwsgi_cache_del, METH_VARARGS, ""},
	{"cache_exists", py_uwsgi_cache_exists, METH_VARARGS, ""},
	{"cache_clear", py_uwsgi_cache_clear, METH_VARARGS, ""},
	{NULL, NULL},
};

static PyMethodDef uwsgi_queue_methods[] = {
	{"queue_get", py_uwsgi_queue_get, METH_VARARGS, ""},
	{"queue_set", py_uwsgi_queue_set, METH_VARARGS, ""},
	{"queue_last", py_uwsgi_queue_last, METH_VARARGS, ""},
	{"queue_push", py_uwsgi_queue_push, METH_VARARGS, ""},
	{"queue_pull", py_uwsgi_queue_pull, METH_VARARGS, ""},
	{"queue_pop", py_uwsgi_queue_pop, METH_VARARGS, ""},
	{"queue_slot", py_uwsgi_queue_slot, METH_VARARGS, ""},
	{"queue_pull_slot", py_uwsgi_queue_pull_slot, METH_VARARGS, ""},
	{NULL, NULL},
};



void init_uwsgi_module_spooler(PyObject * current_uwsgi_module) {
	PyMethodDef *uwsgi_function;
	PyObject *uwsgi_module_dict;

	uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
	if (!uwsgi_module_dict) {
		uwsgi_log("could not get uwsgi module __dict__\n");
		exit(1);
	}

	for (uwsgi_function = uwsgi_spooler_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
		PyObject *func = PyCFunction_New(uwsgi_function, NULL);
		PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
		Py_DECREF(func);
	}
}

void init_uwsgi_module_advanced(PyObject * current_uwsgi_module) {
	PyMethodDef *uwsgi_function;
	PyObject *uwsgi_module_dict;

	uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
	if (!uwsgi_module_dict) {
		uwsgi_log("could not get uwsgi module __dict__\n");
		exit(1);
	}

	for (uwsgi_function = uwsgi_advanced_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
		PyObject *func = PyCFunction_New(uwsgi_function, NULL);
		PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
		Py_DECREF(func);
	}

}

void init_uwsgi_module_cache(PyObject * current_uwsgi_module) {
	PyMethodDef *uwsgi_function;
	PyObject *uwsgi_module_dict;

	uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
	if (!uwsgi_module_dict) {
		uwsgi_log("could not get uwsgi module __dict__\n");
		exit(1);
	}

	for (uwsgi_function = uwsgi_cache_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
		PyObject *func = PyCFunction_New(uwsgi_function, NULL);
		PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
		Py_DECREF(func);
	}
}

void init_uwsgi_module_queue(PyObject * current_uwsgi_module) {
        PyMethodDef *uwsgi_function;
        PyObject *uwsgi_module_dict;

        uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
        if (!uwsgi_module_dict) {
                uwsgi_log("could not get uwsgi module __dict__\n");
                exit(1);
        }

        for (uwsgi_function = uwsgi_queue_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
                PyObject *func = PyCFunction_New(uwsgi_function, NULL);
                PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
                Py_DECREF(func);
        }

	PyDict_SetItemString(uwsgi_module_dict, "queue_size", PyLong_FromUnsignedLongLong(uwsgi.queue_size));
}


void init_uwsgi_module_sharedarea(PyObject * current_uwsgi_module) {
	PyMethodDef *uwsgi_function;
	PyObject *uwsgi_module_dict;

	uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
	if (!uwsgi_module_dict) {
		uwsgi_log("could not get uwsgi module __dict__\n");
		exit(1);
	}

	for (uwsgi_function = uwsgi_sa_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
		PyObject *func = PyCFunction_New(uwsgi_function, NULL);
		PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
		Py_DECREF(func);
	}
}

PyObject *py_snmp_set_counter32(PyObject * self, PyObject * args) {

                   uint8_t oid_num;
                   uint32_t oid_val = 0;

                   if (!PyArg_ParseTuple(args, "bI:snmp_set_counter32", &oid_num, &oid_val)) {
                   return NULL;
                   }

                   if (oid_num > 100 || oid_num < 1)
                   goto clear;

                   UWSGI_RELEASE_GIL
                   uwsgi_wlock(uwsgi.snmp_lock);

                   uwsgi.shared->snmp_value[oid_num - 1].type = SNMP_COUNTER32;
                   uwsgi.shared->snmp_value[oid_num - 1].val = oid_val;

                   uwsgi_rwunlock(uwsgi.snmp_lock);
                   UWSGI_GET_GIL

                   Py_INCREF(Py_True);
                   return Py_True;

clear:

		Py_INCREF(Py_None);
		return Py_None;
}

PyObject *py_snmp_set_counter64(PyObject * self, PyObject * args) {

	uint8_t oid_num;
	uint64_t oid_val = 0;

	if (!PyArg_ParseTuple(args, "bK:snmp_set_counter64", &oid_num, &oid_val)) {
		return NULL;
	}

	if (oid_num > 100 || oid_num < 1)
	goto clear;

	UWSGI_RELEASE_GIL
	uwsgi_wlock(uwsgi.snmp_lock);

	uwsgi.shared->snmp_value[oid_num - 1].type = SNMP_COUNTER64;
	uwsgi.shared->snmp_value[oid_num - 1].val = oid_val;

	uwsgi_rwunlock(uwsgi.snmp_lock);
	UWSGI_GET_GIL

	Py_INCREF(Py_True);
	return Py_True;

clear:

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_snmp_set_gauge(PyObject * self, PyObject * args) {

	uint8_t oid_num;
	uint32_t oid_val = 0;

	if (!PyArg_ParseTuple(args, "bI:snmp_set_gauge", &oid_num, &oid_val)) {
		return NULL;
	}

	if (oid_num > 100 || oid_num < 1)
		goto clear;

	UWSGI_RELEASE_GIL
	uwsgi_wlock(uwsgi.snmp_lock);

	uwsgi.shared->snmp_value[oid_num - 1].type = SNMP_GAUGE;
	uwsgi.shared->snmp_value[oid_num - 1].val = oid_val;

	uwsgi_rwunlock(uwsgi.snmp_lock);
	UWSGI_GET_GIL

	Py_INCREF(Py_True);
	return Py_True;

clear:

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_snmp_incr_counter32(PyObject * self, PyObject * args) {

	uint8_t oid_num;
	uint32_t oid_val = 1;

	if (!PyArg_ParseTuple(args, "bI:snmp_incr_counter32", &oid_num, &oid_val)) {
		PyErr_Clear();
		if (!PyArg_ParseTuple(args, "b:snmp_incr_counter32", &oid_num)) {
			return NULL;
		}
	}

	if (oid_num > 100 || oid_num < 1)
		goto clear;

	UWSGI_RELEASE_GIL
	uwsgi_wlock(uwsgi.snmp_lock);

	uwsgi.shared->snmp_value[oid_num - 1].type = SNMP_COUNTER32;
	uwsgi.shared->snmp_value[oid_num - 1].val = uwsgi.shared->snmp_value[oid_num - 1].val + oid_val;

	uwsgi_rwunlock(uwsgi.snmp_lock);
	UWSGI_GET_GIL

	Py_INCREF(Py_True);
	return Py_True;

clear:

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_snmp_incr_counter64(PyObject * self, PyObject * args) {

	uint8_t oid_num;
	uint64_t oid_val = 1;

	if (!PyArg_ParseTuple(args, "bI:snmp_incr_counter64", &oid_num, &oid_val)) {
		PyErr_Clear();
		if (!PyArg_ParseTuple(args, "b:snmp_incr_counter64", &oid_num)) {
			return NULL;
		}
	}

	if (oid_num > 100 || oid_num < 1)
		goto clear;

	UWSGI_RELEASE_GIL
	uwsgi_wlock(uwsgi.snmp_lock);

	uwsgi.shared->snmp_value[oid_num - 1].type = SNMP_COUNTER64;
	uwsgi.shared->snmp_value[oid_num - 1].val = uwsgi.shared->snmp_value[oid_num - 1].val + oid_val;

	uwsgi_rwunlock(uwsgi.snmp_lock);
	UWSGI_GET_GIL

	Py_INCREF(Py_True);
	return Py_True;

clear:

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_snmp_incr_gauge(PyObject * self, PyObject * args) {

	uint8_t oid_num;
	uint64_t oid_val = 1;

	if (!PyArg_ParseTuple(args, "bI:snmp_incr_gauge", &oid_num, &oid_val)) {
		PyErr_Clear();
		if (!PyArg_ParseTuple(args, "b:snmp_incr_gauge", &oid_num)) {
			return NULL;
		}
	}

	if (oid_num > 100 || oid_num < 1)
		goto clear;

	UWSGI_RELEASE_GIL
	uwsgi_wlock(uwsgi.snmp_lock);

	uwsgi.shared->snmp_value[oid_num - 1].type = SNMP_GAUGE;
	uwsgi.shared->snmp_value[oid_num - 1].val = uwsgi.shared->snmp_value[oid_num - 1].val + oid_val;

	uwsgi_rwunlock(uwsgi.snmp_lock);
	UWSGI_GET_GIL

	Py_INCREF(Py_True);
	return Py_True;

clear:

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_snmp_decr_counter32(PyObject * self, PyObject * args) {

	uint8_t oid_num;
	uint32_t oid_val = 1;

	if (!PyArg_ParseTuple(args, "bI:snmp_incr_counter32", &oid_num, &oid_val)) {
		PyErr_Clear();
		if (!PyArg_ParseTuple(args, "b:snmp_incr_counter32", &oid_num)) {
			return NULL;
		}
	}

	if (oid_num > 100 || oid_num < 1)
		goto clear;

	UWSGI_RELEASE_GIL
	uwsgi_wlock(uwsgi.snmp_lock);

	uwsgi.shared->snmp_value[oid_num - 1].type = SNMP_COUNTER32;
	uwsgi.shared->snmp_value[oid_num - 1].val = uwsgi.shared->snmp_value[oid_num - 1].val - oid_val;

	uwsgi_rwunlock(uwsgi.snmp_lock);
	UWSGI_GET_GIL

	Py_INCREF(Py_True);
	return Py_True;

clear:

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_snmp_decr_counter64(PyObject * self, PyObject * args) {

	uint8_t oid_num;
	uint64_t oid_val = 1;

	if (!PyArg_ParseTuple(args, "bI:snmp_incr_counter64", &oid_num, &oid_val)) {
		PyErr_Clear();
		if (!PyArg_ParseTuple(args, "b:snmp_incr_counter64", &oid_num)) {
			return NULL;
		}
	}

	if (oid_num > 100 || oid_num < 1)
		goto clear;

	UWSGI_RELEASE_GIL
	uwsgi_wlock(uwsgi.snmp_lock);

	uwsgi.shared->snmp_value[oid_num - 1].type = SNMP_COUNTER64;
	uwsgi.shared->snmp_value[oid_num - 1].val = uwsgi.shared->snmp_value[oid_num - 1].val - oid_val;

	uwsgi_rwunlock(uwsgi.snmp_lock);
	UWSGI_GET_GIL

	Py_INCREF(Py_True);
	return Py_True;

clear:

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_snmp_decr_gauge(PyObject * self, PyObject * args) {

	uint8_t oid_num;
	uint64_t oid_val = 1;

	if (!PyArg_ParseTuple(args, "bI:snmp_incr_gauge", &oid_num, &oid_val)) {
		PyErr_Clear();
		if (!PyArg_ParseTuple(args, "b:snmp_incr_gauge", &oid_num)) {
			return NULL;
		}
	}

	if (oid_num > 100 || oid_num < 1)
		goto clear;
       
	UWSGI_RELEASE_GIL
	uwsgi_wlock(uwsgi.snmp_lock);

	uwsgi.shared->snmp_value[oid_num - 1].type = SNMP_GAUGE;
	uwsgi.shared->snmp_value[oid_num - 1].val = uwsgi.shared->snmp_value[oid_num - 1].val - oid_val;

	uwsgi_rwunlock(uwsgi.snmp_lock);
	UWSGI_GET_GIL

	Py_INCREF(Py_True);
	return Py_True;

clear:

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_snmp_set_community(PyObject * self, PyObject * args) {

        char *snmp_community;

        if (!PyArg_ParseTuple(args, "s:snmp_set_community", &snmp_community)) {
                return NULL;
        }

        if (strlen(snmp_community) > 72) {
                uwsgi_log( "*** warning the supplied SNMP community string will be truncated to 72 chars ***\n");
                memcpy(uwsgi.shared->snmp_community, snmp_community, 72);
        }
        else {
                memcpy(uwsgi.shared->snmp_community, snmp_community, strlen(snmp_community) + 1);
        }

        Py_INCREF(Py_True);
        return Py_True;

}


static PyMethodDef uwsgi_snmp_methods[] = {
        {"snmp_set_counter32", py_snmp_set_counter32, METH_VARARGS, ""},
        {"snmp_set_counter64", py_snmp_set_counter64, METH_VARARGS, ""},
        {"snmp_set_gauge", py_snmp_set_gauge, METH_VARARGS, ""},
        {"snmp_incr_counter32", py_snmp_incr_counter32, METH_VARARGS, ""},
        {"snmp_incr_counter64", py_snmp_incr_counter64, METH_VARARGS, ""},
        {"snmp_incr_gauge", py_snmp_incr_gauge, METH_VARARGS, ""},
        {"snmp_decr_counter32", py_snmp_decr_counter32, METH_VARARGS, ""},
        {"snmp_decr_counter64", py_snmp_decr_counter64, METH_VARARGS, ""},
        {"snmp_decr_gauge", py_snmp_decr_gauge, METH_VARARGS, ""},
        {"snmp_set_community", py_snmp_set_community, METH_VARARGS, ""},
        {NULL, NULL},
};

void init_uwsgi_module_snmp(PyObject * current_uwsgi_module) {

        PyMethodDef *uwsgi_function;

	PyObject *uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
        if (!uwsgi_module_dict) {
                uwsgi_log("could not get uwsgi module __dict__\n");
                exit(1);
        }

        for (uwsgi_function = uwsgi_snmp_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
                PyObject *func = PyCFunction_New(uwsgi_function, NULL);
                PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
                Py_DECREF(func);
        }

        uwsgi_log( "SNMP python functions initialized.\n");
}
