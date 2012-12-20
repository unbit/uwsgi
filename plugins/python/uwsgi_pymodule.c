#ifdef UWSGI_EMBEDDED

#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

PyObject *py_uwsgi_signal_wait(PyObject * self, PyObject * args) {

        struct wsgi_request *wsgi_req = current_wsgi_req();
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

        struct wsgi_request *wsgi_req = current_wsgi_req();

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

#ifdef __linux__
	return PyInt_FromLong(uwsgi.shared->options[UWSGI_OPTION_BACKLOG_STATUS]);
#else
	return NULL;
#endif
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

	if (size > 0) {
		PyObject *ret = PyString_FromStringAndSize(response, size);
		free(response);
		return ret;
	}

	free(response);
	Py_INCREF(Py_None);
	return Py_None;

      clear:

	return PyErr_Format(PyExc_ValueError, "unable to call rpc function");

}

PyObject *py_uwsgi_rpc_list(PyObject * self, PyObject * args) {

	int i;
	PyObject *rpc_list = PyTuple_New(uwsgi.shared->rpc_count);

	for (i = 0; i < uwsgi.shared->rpc_count; i++) {
		if (uwsgi.shared->rpc_table[i].name[0] != 0) {
			PyTuple_SetItem(rpc_list, i, PyString_FromString(uwsgi.shared->rpc_table[i].name));
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

	if (size > 0) {
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

	struct wsgi_request *wsgi_req = current_wsgi_req();

	wsgi_req->log_this = 1;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_get_logvar(PyObject * self, PyObject * args) {

	char *key = NULL;
        Py_ssize_t keylen = 0;
        struct wsgi_request *wsgi_req = current_wsgi_req();

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
        struct wsgi_request *wsgi_req = current_wsgi_req();

        if (!PyArg_ParseTuple(args, "s#s#:set_logvar", &key, &keylen, &val, &vallen)) {
                return NULL;
        }

        uwsgi_logvar_add(wsgi_req, key, keylen, val, vallen);

        Py_INCREF(Py_None);
        return Py_None;
}



PyObject *py_uwsgi_recv_frame(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	char *bufptr;
	char prefix = 0x00;
	char suffix = 0xff;
	int i;
	char frame[4096];
	char *frame_ptr;
	int frame_size = 0;
	int fd;
	int rlen;

	int found_start = 0;
	char *null1, *null2;


	if (!PyArg_ParseTuple(args, "icc:recv_frame", &fd, &null1, &null2)) {
		return NULL;
	}

      get_data:
	frame_ptr = frame;
	if (wsgi_req->frame_len > 0) {
		// we have already some data buffered
		// search for the prefix and adjust frame_pos
		bufptr = wsgi_req->buffer + wsgi_req->frame_pos;
		for (i = 0; i < wsgi_req->frame_len; i++) {
			if (bufptr[i] == prefix) {
				bufptr++;
				found_start = 1;
				break;
			}
			bufptr++;
			wsgi_req->frame_pos++;
		}

		wsgi_req->frame_len -= i;
		if (found_start) {
			// we have found the prefix, copy it in the frame area until suffix or end of the buffer
			for (i = 0; i < wsgi_req->frame_len; i++) {
				uwsgi_log("%d %d\n", bufptr[i], frame_size);
				if (bufptr[i] == suffix) {
					wsgi_req->frame_len -= i;
					goto return_a_frame;
				}
				*frame_ptr++ = bufptr[i];
				frame_size++;
				wsgi_req->frame_pos++;
			}
		}
	}

	// we have already get the prefix ?
	if (found_start) {

		// wait for more data
	      read_more_data:
		rlen = uwsgi_waitfd(fd, -1);
		if (rlen > 0) {
			wsgi_req->frame_pos = 0;
			wsgi_req->frame_len = read(fd, wsgi_req->buffer, uwsgi.buffer_size);
			bufptr = wsgi_req->buffer;
			for (i = 0; i < wsgi_req->frame_len; i++) {
				if (bufptr[i] == suffix) {
					goto return_a_frame;
				}
				*frame_ptr++ = bufptr[i];
				frame_size++;
			}
			goto read_more_data;
		}
		else if (rlen == 0) {
			uwsgi_log("timeout waiting for frame\n");
		}

	}
	else {
		// read a whole frame directly from the socket
		rlen = uwsgi_waitfd(fd, -1);
		if (rlen > 0) {
			wsgi_req->frame_pos = 0;
			wsgi_req->frame_len = read(fd, wsgi_req->buffer, uwsgi.buffer_size);
			uwsgi_log("read %d bytes %.*s\n", wsgi_req->frame_len, wsgi_req->frame_len, wsgi_req->buffer);
			if (wsgi_req->frame_len == 0)
				goto return_a_frame;
			goto get_data;
		}
		else if (rlen == 0) {
			uwsgi_log("timeout waiting for frame\n");
		}

	}
      return_a_frame:
	uwsgi_log("returning a frame\n");
	return PyString_FromStringAndSize(frame, frame_size);

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

	struct wsgi_request *wsgi_req = current_wsgi_req();

	int uwsgi_fd = wsgi_req->poll.fd;

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

PyObject *py_uwsgi_offload_transfer(PyObject * self, PyObject * args) {
	size_t len = 0;
	char *filename = NULL;
	struct wsgi_request *wsgi_req = current_wsgi_req();

	if (!PyArg_ParseTuple(args, "s|i:offload_transfer", &filename, &len)) {
                return NULL;
        }

	if (!wsgi_req->socket->can_offload) {
		return PyErr_Format(PyExc_ValueError, "The current socket does not support offloading");
	}

	if (!wsgi_req->headers_sent) {
        	if (uwsgi_python_do_send_headers(wsgi_req)) {
			return PyErr_Format(PyExc_ValueError, "unable to send headers before offload transfer");
		}
	}


	UWSGI_RELEASE_GIL
        if (uwsgi_offload_request_sendfile_do(wsgi_req, filename, len)) {
		UWSGI_GET_GIL
		return PyErr_Format(PyExc_ValueError, "Unable to offload the request");
	}
	UWSGI_GET_GIL

	return PyString_FromString("");
}

PyObject *py_uwsgi_advanced_sendfile(PyObject * self, PyObject * args) {

	PyObject *what;
	char *filename;
	size_t chunk = 0;
	off_t pos = 0;
	size_t filesize = 0;
	struct wsgi_request *wsgi_req = current_wsgi_req();

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

	int tmp_fd = wsgi_req->sendfile_fd;
	size_t tmp_filesize = wsgi_req->sendfile_fd_size;
	size_t tmp_chunk = wsgi_req->sendfile_fd_chunk;
	off_t tmp_pos = wsgi_req->sendfile_fd_pos;

	wsgi_req->sendfile_fd = fd;
	wsgi_req->sendfile_fd_size = filesize;
	wsgi_req->sendfile_fd_chunk = chunk;
	wsgi_req->sendfile_fd_pos = pos;

	// do sendfile
	if (uwsgi.async > 1) {
		ssize_t sf_len = uwsgi_sendfile(wsgi_req);
		if (sf_len > 0) {
			wsgi_req->response_size += sf_len;
			while((size_t)wsgi_req->sendfile_fd_pos < wsgi_req->sendfile_fd_size) {
				sf_len = uwsgi_sendfile(wsgi_req);
				if (sf_len <= 0) break;
				wsgi_req->response_size += sf_len;
			}
		}
	}
	else {
		wsgi_req->response_size += uwsgi_sendfile(wsgi_req);
	}

	// revert to old values
	wsgi_req->sendfile_fd = tmp_fd;
	wsgi_req->sendfile_fd_size = tmp_filesize;
	wsgi_req->sendfile_fd_chunk = tmp_chunk;
	wsgi_req->sendfile_fd_pos = tmp_pos;
	

	close(fd);
	Py_INCREF(Py_True);
	return Py_True;

      clear:
	Py_INCREF(Py_None);
	return Py_None;

}

#ifdef UWSGI_ASYNC


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
#endif

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
#ifdef UWSGI_SPOOLER
	if (uwsgi.i_am_a_spooler) {
		Py_INCREF(Py_True);
		return Py_True;
	}
#endif

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_is_locked(PyObject * self, PyObject * args) {

        int lock_num = 0;

        // the spooler cannot lock resources
#ifdef UWSGI_SPOOLER
        if (uwsgi.i_am_a_spooler) {
                return PyErr_Format(PyExc_ValueError, "The spooler cannot lock/unlock resources");
        }
#endif

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
#ifdef UWSGI_SPOOLER
	if (uwsgi.i_am_a_spooler) {
		return PyErr_Format(PyExc_ValueError, "The spooler cannot lock/unlock resources");
	}
#endif

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

#ifdef UWSGI_SPOOLER
	if (uwsgi.i_am_a_spooler) {
		return PyErr_Format(PyExc_ValueError, "The spooler cannot lock/unlock resources");
	}
#endif

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
	struct wsgi_request *wsgi_req = current_wsgi_req();
	return PyInt_FromLong(wsgi_req->poll.fd);
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
	int len;
	char *buf;

        if (!PyArg_ParseTuple(args, "s:extract", &name)) {
                return NULL;
        }

	buf = uwsgi_open_and_read(name, &len, 0, NULL);
	if (buf && len > 0) {
        	return PyString_FromStringAndSize(buf, len);
	}
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

#ifdef UWSGI_SPOOLER
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
	struct wsgi_request *wsgi_req = current_wsgi_req();
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
#endif

PyObject *py_uwsgi_send_multi_message(PyObject * self, PyObject * args) {


	int i;
	int clen;
	int pret;
	int managed;
	struct pollfd *multipoll;
	char *buffer;

	PyObject *arg_cluster;

	PyObject *cluster_node;

	PyObject *arg_host, *arg_port, *arg_message;

	PyObject *arg_modifier1, *arg_modifier2, *arg_timeout;

	PyObject *retobject;


	arg_cluster = PyTuple_GetItem(args, 0);
	if (!PyTuple_Check(arg_cluster)) {
		Py_INCREF(Py_None);
		return Py_None;
	}


	arg_modifier1 = PyTuple_GetItem(args, 1);
	if (!PyInt_Check(arg_modifier1)) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	arg_modifier2 = PyTuple_GetItem(args, 2);
	if (!PyInt_Check(arg_modifier2)) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	arg_timeout = PyTuple_GetItem(args, 3);
	if (!PyInt_Check(arg_timeout)) {
		Py_INCREF(Py_None);
		return Py_None;
	}


	/* iterate cluster */
	clen = PyTuple_Size(arg_cluster);
	multipoll = malloc(clen * sizeof(struct pollfd));
	if (!multipoll) {
		uwsgi_error("malloc");
		Py_INCREF(Py_None);
		return Py_None;
	}


	buffer = malloc(uwsgi.buffer_size * clen);
	if (!buffer) {
		uwsgi_error("malloc");
		free(multipoll);
		Py_INCREF(Py_None);
		return Py_None;
	}


	for (i = 0; i < clen; i++) {
		multipoll[i].events = POLLIN;

		cluster_node = PyTuple_GetItem(arg_cluster, i);
		arg_host = PyTuple_GetItem(cluster_node, 0);
		if (!PyString_Check(arg_host)) {
			goto clear;
		}

		arg_port = PyTuple_GetItem(cluster_node, 1);
		if (!PyInt_Check(arg_port)) {
			goto clear;
		}

		arg_message = PyTuple_GetItem(cluster_node, 2);
		if (!arg_message) {
			goto clear;
		}


#ifndef UWSGI_PYPY
	PyObject *marshalled;
		switch (PyInt_AsLong(arg_modifier1)) {
		case UWSGI_MODIFIER_MESSAGE_MARSHAL:
			marshalled = PyMarshal_WriteObjectToString(arg_message, 1);
			if (!marshalled) {
				PyErr_Print();
				goto clear;
			}
			multipoll[i].fd = uwsgi_enqueue_message(PyString_AsString(arg_host), PyInt_AsLong(arg_port), PyInt_AsLong(arg_modifier1), PyInt_AsLong(arg_modifier2), PyString_AsString(marshalled), PyString_Size(marshalled), PyInt_AsLong(arg_timeout));
			Py_DECREF(marshalled);
			if (multipoll[i].fd < 0) {
				goto multiclear;
			}
			break;
		}
#endif


	}

	managed = 0;
	retobject = PyTuple_New(clen);
	if (!retobject) {
		PyErr_Print();
		goto multiclear;
	}

	while (managed < clen) {
		pret = poll(multipoll, clen, PyInt_AsLong(arg_timeout) * 1000);
		if (pret < 0) {
			uwsgi_error("poll()");
			goto megamulticlear;
		}
		else if (pret == 0) {
			uwsgi_log("timeout on multiple send !\n");
			goto megamulticlear;
		}
		else {
			// TODO fix
/*
			for (i = 0; i < clen; i++) {
				if (multipoll[i].revents & POLLIN) {
					if (!uwsgi_parse_packet(&multipoll[i], PyInt_AsLong(arg_timeout), &uh, &buffer[i], uwsgi_proto_uwsgi_parser)) {
						goto megamulticlear;
					}
					else {
						if (PyTuple_SetItem(retobject, i, PyMarshal_ReadObjectFromString(&buffer[i], uh.pktsize))) {
							PyErr_Print();
							goto megamulticlear;
						}
						close(multipoll[i].fd);
						managed++;
					}
				}
			}
*/
		}
	}

	free(buffer);

	return retobject;

      megamulticlear:

	Py_DECREF(retobject);

      multiclear:

	for (i = 0; i < clen; i++) {
		close(multipoll[i].fd);
	}
      clear:

	free(multipoll);
	free(buffer);

	Py_INCREF(Py_None);
	return Py_None;

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

#ifdef UWSGI_MULTICAST
PyObject *py_uwsgi_multicast(PyObject * self, PyObject * args) {

	char *host, *message;
	Py_ssize_t message_len;
	ssize_t ret;
	char *uwsgi_message;

	if (!PyArg_ParseTuple(args, "ss#:send_multicast_message", &host, &message, &message_len)) {
		return NULL;
	}

	uwsgi_message = uwsgi_malloc(message_len+4);
	memcpy(uwsgi_message+4, message, message_len);
	UWSGI_RELEASE_GIL
	ret = send_udp_message(UWSGI_MODIFIER_MULTICAST, 0, host, uwsgi_message, message_len);
	UWSGI_GET_GIL
	free(uwsgi_message);

	if (ret <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	Py_INCREF(Py_True);
	return Py_True;

}
#endif

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

struct uwsgi_Iter;

typedef struct uwsgi_Iter {
	PyObject_HEAD int fd;
	int timeout;
	int close;
	int started;
	int has_cl;
	uint16_t size;
	uint16_t sent;
	uint8_t modifier1;
	uint8_t modifier2;
	PyObject *(*func) (struct uwsgi_Iter *);
} uwsgi_Iter;


PyObject *uwsgi_Iter_iter(PyObject * self) {
	Py_INCREF(self);
	return self;
}

PyObject *py_fcgi_iterator(uwsgi_Iter * ui) {

	uint16_t size = 0;
	char body[0xffff];
	size = fcgi_get_record(ui->fd, body);

	if (size) {
		return PyString_FromStringAndSize(body, size);
	}

	return NULL;
}

PyObject *uwsgi_Iter_next(PyObject * self) {
	int rlen;
	uwsgi_Iter *ui = (uwsgi_Iter *) self;
	char buf[4096];
	int i = 4;
	struct uwsgi_header uh;
	char *ub = (char *) &uh;
	PyObject *ptr;

	UWSGI_RELEASE_GIL if (ui->func) {

		ptr = ui->func(ui);
		if (ptr) {
			return ptr;
		}
	}


	else {

		if (!ui->started) {
			memset(&uh, 0, 4);
			while (i) {
				rlen = uwsgi_waitfd(ui->fd, ui->timeout);
				if (rlen > 0) {
					rlen = read(ui->fd, ub, i);
					if (rlen <= 0) {
						goto clear;
					}
					else {
						i -= rlen;
						ub += rlen;
					}
				}
				else {
					goto clear;
				}
			}

			ui->started = 1;

			if (uh.modifier1 == 'H') {
				ui->size = 0;
				UWSGI_GET_GIL return PyString_FromStringAndSize((char *) &uh, 4);
			}
			else {
				ui->has_cl = 1;
				ui->size = uh.pktsize;
				ui->sent = 0;
			}
		}

		if (ui->sent >= ui->size && ui->has_cl) {
			goto clear;
		}

		rlen = uwsgi_waitfd(ui->fd, ui->timeout);
		if (rlen > 0) {
			if (ui->has_cl) {
				rlen = read(ui->fd, buf, UMIN((ui->size - ui->sent), 4096));
			}
			else {
				rlen = read(ui->fd, buf, 4096);
			}
			if (rlen < 0) {
				uwsgi_error("read()");
			}
			else if (rlen > 0) {
				ui->sent += rlen;
				UWSGI_GET_GIL return PyString_FromStringAndSize(buf, rlen);
			}
		}
		else if (rlen == 0) {
			uwsgi_log("uwsgi request timed out waiting for response\n");
		}
	}

	if (ui->close) {
		close(ui->fd);
	}

      clear:
	UWSGI_GET_GIL PyErr_SetNone(PyExc_StopIteration);

	return NULL;
}

static PyTypeObject uwsgi_IterType = {
	PyVarObject_HEAD_INIT(NULL, 0)
		"uwsgi._Iter",	/*tp_name */
	sizeof(uwsgi_Iter),	/*tp_basicsize */
	0,			/*tp_itemsize */
	0,			/*tp_dealloc */
	0,			/*tp_print */
	0,			/*tp_getattr */
	0,			/*tp_setattr */
	0,			/*tp_compare */
	0,			/*tp_repr */
	0,			/*tp_as_number */
	0,			/*tp_as_sequence */
	0,			/*tp_as_mapping */
	0,			/*tp_hash */
	0,			/*tp_call */
	0,			/*tp_str */
	0,			/*tp_getattro */
	0,			/*tp_setattro */
	0,			/*tp_as_buffer */
#if defined(Py_TPFLAGS_HAVE_ITER)
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,
#else
	Py_TPFLAGS_DEFAULT,
#endif
	"uwsgi response iterator object.",	/* tp_doc */
	0,			/* tp_traverse */
	0,			/* tp_clear */
	0,			/* tp_richcompare */
	0,			/* tp_weaklistoffset */
	uwsgi_Iter_iter,	/* tp_iter: __iter__() method */
	uwsgi_Iter_next		/* tp_iternext: next() method */
};


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

PyObject *py_uwsgi_async_send_message(PyObject * self, PyObject * args) {

	PyObject *pyobj = NULL;

	int uwsgi_fd;
	int modifier1 = 0;
	int modifier2 = 0;

	char *encoded;
	uint16_t esize = 0;

	if (!PyArg_ParseTuple(args, "iiiO:async_send_message", &uwsgi_fd, &modifier1, &modifier2, &pyobj)) {
		return NULL;
	}

	if (uwsgi_fd < 0)
		goto clear;

	// now check for the type of object to send (fallback to marshal)
	if (PyDict_Check(pyobj)) {
		encoded = uwsgi_encode_pydict(pyobj, &esize);
		if (esize > 0) {
			UWSGI_RELEASE_GIL uwsgi_send_message(uwsgi_fd, (uint8_t) modifier1, (uint8_t) modifier2, encoded, esize, -1, 0, 0);
			free(encoded);
		}
	}
	else if (PyString_Check(pyobj)) {
		encoded = PyString_AsString(pyobj);
		esize = PyString_Size(pyobj);
		UWSGI_RELEASE_GIL uwsgi_send_message(uwsgi_fd, (uint8_t) modifier1, (uint8_t) modifier2, encoded, esize, -1, 0, 0);
	}
#ifndef UWSGI_PYPY
	else {
		PyObject *marshalled = PyMarshal_WriteObjectToString(pyobj, 1);
		if (!marshalled) {
			PyErr_Print();
			goto clear;
		}

		encoded = PyString_AsString(marshalled);
		esize = PyString_Size(marshalled);
		UWSGI_RELEASE_GIL uwsgi_send_message(uwsgi_fd, (uint8_t) modifier1, (uint8_t) modifier2, encoded, esize, -1, 0, 0);
	}
#endif

      UWSGI_GET_GIL clear:

	Py_INCREF(Py_None);
	return Py_None;

}

PyObject *py_uwsgi_fcgi(PyObject * self, PyObject * args) {

	char *node;
	PyObject *dict;
	int fd;
	int i;
	int stdin_fd = -1;
	int stdin_size = 0;
	ssize_t len;
	char stdin_buf[0xffff];
	uwsgi_Iter *ui;
	PyObject *zero, *key, *val;

	if (!PyArg_ParseTuple(args, "sO|ii:fcgi", &node, &dict, &stdin_fd, &stdin_size)) {
		return NULL;
	}

	fd = uwsgi_connect(node, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], 0);

	if (fd < 0)
		goto clear2;

	if (!PyDict_Check(dict))
		goto clear;

	fcgi_send_record(fd, 1, 8, FCGI_BEGIN_REQUEST);

	PyObject *vars = PyDict_Items(dict);

	if (!vars)
		goto clear;

	for (i = 0; i < PyList_Size(vars); i++) {
		zero = PyList_GetItem(vars, i);
		if (!zero) {
			PyErr_Print();
			continue;
		}

		key = PyTuple_GetItem(zero, 0);
		val = PyTuple_GetItem(zero, 1);

		if (!PyString_Check(key) || !PyString_Check(val))
			continue;

		fcgi_send_param(fd, PyString_AsString(key), PyString_Size(key), PyString_AsString(val), PyString_Size(val));
	}

	fcgi_send_record(fd, 4, 0, "");

	if (stdin_fd > -1 && stdin_size) {
		while (stdin_size) {
			len = read(stdin_fd, stdin_buf, UMIN(0xffff, stdin_size));
			if (len < 0) {
				uwsgi_error("read()");
				break;
			}
			fcgi_send_record(fd, 5, len, stdin_buf);
			stdin_size -= len;
		}
	}
	fcgi_send_record(fd, 5, 0, "");

	// request sent, return the iterator response
	ui = PyObject_New(uwsgi_Iter, &uwsgi_IterType);
	if (!ui) {
		PyErr_Print();
		goto clear;
	}

	ui->fd = fd;
	ui->timeout = -1;
	ui->close = 1;
	ui->started = 0;
	ui->has_cl = 0;
	ui->sent = 0;
	ui->size = 0;
	ui->func = py_fcgi_iterator;

	return (PyObject *) ui;

      clear:
	close(fd);

      clear2:
	Py_INCREF(Py_None);
	return Py_None;

}

PyObject *py_uwsgi_route(PyObject * self, PyObject * args) {
	
	char *addr = NULL;
	struct wsgi_request *wsgi_req = current_wsgi_req();

	if (!PyArg_ParseTuple(args, "s:route", &addr)) {
                return NULL;
        }

	UWSGI_RELEASE_GIL;

	int uwsgi_fd = uwsgi_connect(addr, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], 0);

	UWSGI_GET_GIL;

	if (uwsgi_fd < 0) {
		return PyErr_Format(PyExc_IOError, "unable to connect to host %s", addr);
	}

	UWSGI_RELEASE_GIL
	if (uwsgi_send_message(uwsgi_fd, wsgi_req->uh.modifier1, wsgi_req->uh.modifier2, wsgi_req->buffer, wsgi_req->uh.pktsize, wsgi_req->poll.fd, wsgi_req->post_cl, 0) < 0) {
		UWSGI_GET_GIL
		return PyErr_Format(PyExc_IOError, "unable to send uwsgi request to host %s", addr);
	}
	UWSGI_GET_GIL

	// request sent, return the iterator response
        uwsgi_Iter *ui = PyObject_New(uwsgi_Iter, &uwsgi_IterType);
        if (!ui) {
                uwsgi_log("unable to create uwsgi response object, better to reap the process\n");
		exit(1);
        }

        ui->fd = uwsgi_fd;
        ui->timeout = uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT];
        ui->close = 1;
        ui->started = 0;
        ui->has_cl = 0;
        ui->sent = 0;
        ui->size = 0;
        ui->func = NULL;

	// mark a route request
	wsgi_req->status = -17;

        return (PyObject *) ui;
}

PyObject *py_uwsgi_send_message(PyObject * self, PyObject * args) {

	PyObject *destination = NULL, *pyobj = NULL;

	int modifier1 = 0;
	int modifier2 = 0;
	int timeout = uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT];
	int fd = -1;
	int cl = 0;

	int uwsgi_fd = -1;
	char *encoded;
	uint16_t esize = 0;
	int close_fd = 0;

	uwsgi_Iter *ui;

	if (!PyArg_ParseTuple(args, "OiiO|iii:send_message", &destination, &modifier1, &modifier2, &pyobj, &timeout, &fd, &cl)) {
		return NULL;
	}

	// first of all get the fd for the destination
	if (PyInt_Check(destination)) {
		uwsgi_fd = PyInt_AsLong(destination);
	}
	else if (PyString_Check(destination)) {
		UWSGI_RELEASE_GIL
		uwsgi_fd = uwsgi_connect(PyString_AsString(destination), timeout, 0);
		UWSGI_GET_GIL
		close_fd = 1;
	}

	if (uwsgi_fd < 0)
		goto clear;


	// now check for the type of object to send (fallback to marshal)
	if (PyDict_Check(pyobj)) {
		encoded = uwsgi_encode_pydict(pyobj, &esize);
		if (esize > 0) {
			UWSGI_RELEASE_GIL uwsgi_send_message(uwsgi_fd, (uint8_t) modifier1, (uint8_t) modifier2, encoded, esize, fd, cl, timeout);
			free(encoded);
		}
	}
	else if (PyString_Check(pyobj)) {
		encoded = PyString_AsString(pyobj);
		esize = PyString_Size(pyobj);
		UWSGI_RELEASE_GIL uwsgi_send_message(uwsgi_fd, (uint8_t) modifier1, (uint8_t) modifier2, encoded, esize, fd, cl, timeout);
	}
#ifndef UWSGI_PYPY
	else {
		PyObject *marshalled = PyMarshal_WriteObjectToString(pyobj, 1);
		if (!marshalled) {
			PyErr_Print();
			goto clear;
		}

		encoded = PyString_AsString(marshalled);
		esize = PyString_Size(marshalled);
		UWSGI_RELEASE_GIL uwsgi_send_message(uwsgi_fd, (uint8_t) modifier1, (uint8_t) modifier2, encoded, esize, fd, cl, timeout);
	}
#endif

	UWSGI_GET_GIL

	// if it is a fd passing request, return None
	if (fd >=0 && cl == -1) {
		Py_INCREF(Py_None);
		return Py_None;
	}
		// request sent, return the iterator response
		ui = PyObject_New(uwsgi_Iter, &uwsgi_IterType);
	if (!ui) {
		PyErr_Print();
		goto clear2;
	}

	ui->fd = uwsgi_fd;
	ui->timeout = timeout;
	ui->close = close_fd;
	ui->started = 0;
	ui->has_cl = 0;
	ui->sent = 0;
	ui->size = 0;
	ui->func = NULL;

	return (PyObject *) ui;

      clear2:
	if (close_fd)
		close(uwsgi_fd);
      clear:

	Py_INCREF(Py_None);
	return Py_None;

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

		zero = PyLong_FromUnsignedLongLong(uwsgi.workers[i + 1].exceptions);
		if (PyDict_SetItemString(worker_dict, "exceptions", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		if (uwsgi.workers[i + 1].cheaped) {
			zero = PyString_FromString("cheap");
		}
		else if (uwsgi.workers[i + 1].suspended && !uwsgi.workers[i + 1].busy) {
			zero = PyString_FromString("pause");
		}
		else {
			if (uwsgi.workers[i + 1].sig) {
				zero = PyString_FromFormat("sig%d",uwsgi.workers[i + 1].signum);
			}
			else if (uwsgi.workers[i + 1].busy) {
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
		Py_DECREF(apps_tuple);

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

	struct wsgi_request *wsgi_req = current_wsgi_req();

	return PyLong_FromUnsignedLongLong(wsgi_req->post_cl);

}

PyObject *py_uwsgi_disconnect(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

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

PyObject *py_uwsgi_grunt(PyObject * self, PyObject * args) {

	pid_t grunt_pid;
	struct wsgi_request *wsgi_req = current_wsgi_req();

	if (uwsgi.grunt) {
		uwsgi_log("spawning a grunt from worker %d (pid :%d)...\n", uwsgi.mywid, uwsgi.mypid);
	}
	else {
		uwsgi_log("grunt support is disabled !!!\n");
		goto clear;
	}

	// use a normal fork here
	grunt_pid = fork();
	if (grunt_pid < 0) {
		uwsgi_error("fork()");
		goto clear;
	}
	// now i am a grunt, avoid it making mess
	else if (grunt_pid == 0) {
		// it will no more accepts requests
		uwsgi_close_all_sockets();
		// create a new session
		setsid();
		// exit on SIGPIPE
		signal(SIGPIPE, (void *) &end_me);
		// here we create a new worker. Each grunt will race on this datas, so do not rely on them
		uwsgi.mywid = uwsgi.numproc + 1;
		uwsgi.mypid = getpid();
		memset(&uwsgi.workers[uwsgi.mywid], 0, sizeof(struct uwsgi_worker));
		// this is pratically useless...
		uwsgi.workers[uwsgi.mywid].id = uwsgi.mywid;
		// this field will be overwrite after each call
		uwsgi.workers[uwsgi.mywid].pid = uwsgi.mypid;

		// reset the random seed
		uwsgi_python_reset_random_seed();
		// TODO
		// manage thread in grunt processes
		Py_INCREF(Py_True);
		return Py_True;
	}

	// close connection on the original worker
	if (PyTuple_Size(args) == 0) {
		if (wsgi_req->socket) {
			wsgi_req->socket->proto_close(wsgi_req);
		}
		wsgi_req->fd_closed = 1;
	}

      clear:
	Py_INCREF(Py_None);
	return Py_None;
}

#ifdef UWSGI_SPOOLER
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
#endif


PyObject *py_uwsgi_suspend(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	if (uwsgi.schedule_to_main) uwsgi.schedule_to_main(wsgi_req);

	Py_INCREF(Py_True);
	return Py_True;

}

#ifdef UWSGI_MULTICAST
PyObject *py_uwsgi_cluster(PyObject * self, PyObject * args) {

	if (uwsgi.cluster) {
		return PyString_FromString(uwsgi.cluster);
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_cluster_node_name(PyObject * self, PyObject * args) {

	struct uwsgi_cluster_node *ucn;
	int i;
	char *node = NULL;

	if (!PyArg_ParseTuple(args, "|s:cluster_node_name", &node)) {
		return NULL;
	}

	if (node == NULL) {
		return PyString_FromString(uwsgi.hostname);
	}

	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
		ucn = &uwsgi.shared->nodes[i];
		if (ucn->name[0] != 0) {
#ifdef UWSGI_DEBUG
			uwsgi_log("node_name: %s %s\n", node, ucn->name);
#endif
			if (!strcmp(ucn->name, node)) {
				return PyString_FromString(ucn->nodename);
			}
		}
	}

	Py_INCREF(Py_None);
	return Py_None;

}
PyObject *py_uwsgi_cluster_nodes(PyObject * self, PyObject * args) {

	struct uwsgi_cluster_node *ucn;
	int i;

	PyObject *clist = PyList_New(0);

	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
		ucn = &uwsgi.shared->nodes[i];
		if (ucn->name[0] != 0) {
			if (ucn->status == UWSGI_NODE_OK) {
				PyList_Append(clist, PyString_FromString(ucn->name));
			}
		}
	}

	return clist;

}

PyObject *py_uwsgi_cluster_best_node(PyObject * self, PyObject * args) {

	char *node = uwsgi_cluster_best_node();
	if (node == NULL)
		goto clear;
	if (node[0] == 0)
		goto clear;
	return PyString_FromString(node);

      clear:

	Py_INCREF(Py_None);
	return Py_None;
}


#endif


static PyMethodDef uwsgi_advanced_methods[] = {
	{"send_message", py_uwsgi_send_message, METH_VARARGS, ""},
	{"route", py_uwsgi_route, METH_VARARGS, ""},
	{"send_multi_message", py_uwsgi_send_multi_message, METH_VARARGS, ""},
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
	{"disconnect", py_uwsgi_disconnect, METH_VARARGS, ""},
	{"grunt", py_uwsgi_grunt, METH_VARARGS, ""},
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

	{"register_rpc", py_uwsgi_register_rpc, METH_VARARGS, ""},
	{"rpc", py_uwsgi_rpc, METH_VARARGS, ""},
	{"rpc_list", py_uwsgi_rpc_list, METH_VARARGS, ""},
	{"call", py_uwsgi_call, METH_VARARGS, ""},
	{"sendfile", py_uwsgi_advanced_sendfile, METH_VARARGS, ""},
	{"offload_transfer", py_uwsgi_offload_transfer, METH_VARARGS, ""},
	{"set_warning_message", py_uwsgi_warning, METH_VARARGS, ""},
	{"mem", py_uwsgi_mem, METH_VARARGS, ""},
	{"has_hook", py_uwsgi_has_hook, METH_VARARGS, ""},
	{"logsize", py_uwsgi_logsize, METH_VARARGS, ""},
#ifdef UWSGI_MULTICAST
	{"send_multicast_message", py_uwsgi_multicast, METH_VARARGS, ""},
	{"cluster_nodes", py_uwsgi_cluster_nodes, METH_VARARGS, ""},
	{"cluster_node_name", py_uwsgi_cluster_node_name, METH_VARARGS, ""},
	{"cluster", py_uwsgi_cluster, METH_VARARGS, ""},
	{"cluster_best_node", py_uwsgi_cluster_best_node, METH_VARARGS, ""},
#endif
#ifdef UWSGI_ASYNC
	{"async_sleep", py_uwsgi_async_sleep, METH_VARARGS, ""},
	{"async_connect", py_uwsgi_async_connect, METH_VARARGS, ""},
	{"async_send_message", py_uwsgi_async_send_message, METH_VARARGS, ""},

	{"green_schedule", py_uwsgi_suspend, METH_VARARGS, ""},
	{"suspend", py_uwsgi_suspend, METH_VARARGS, ""},
	{"wait_fd_read", py_eventfd_read, METH_VARARGS, ""},
	{"wait_fd_write", py_eventfd_write, METH_VARARGS, ""},
#endif

	{"connect", py_uwsgi_connect, METH_VARARGS, ""},
	{"connection_fd", py_uwsgi_connection_fd, METH_VARARGS, ""},
	{"is_connected", py_uwsgi_is_connected, METH_VARARGS, ""},
	{"send", py_uwsgi_send, METH_VARARGS, ""},
	{"recv", py_uwsgi_recv, METH_VARARGS, ""},
	{"recv_block", py_uwsgi_recv_block, METH_VARARGS, ""},
	{"recv_frame", py_uwsgi_recv_frame, METH_VARARGS, ""},
	{"close", py_uwsgi_close, METH_VARARGS, ""},
	{"i_am_the_spooler", py_uwsgi_i_am_the_spooler, METH_VARARGS, ""},

	{"fcgi", py_uwsgi_fcgi, METH_VARARGS, ""},

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

	uint64_t i;
        // skip the first slot
        for (i = 1; i < uwsgi.cache_max_items; i++) {
		UWSGI_RELEASE_GIL
                uwsgi_wlock(uwsgi.cache_lock);
                uwsgi_cache_del(NULL, 0, i, 0);
                uwsgi_rwunlock(uwsgi.cache_lock);
		UWSGI_GET_GIL
	}

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *py_uwsgi_cache_del(PyObject * self, PyObject * args) {

	char *key;
	Py_ssize_t keylen = 0;
	char *remote = NULL;

	if (!PyArg_ParseTuple(args, "s#|s:cache_del", &key, &keylen, &remote)) {
		return NULL;
	}

	if (remote && strlen(remote) > 0) {
		UWSGI_RELEASE_GIL
		uwsgi_simple_send_string(remote, 111, 2, key, keylen, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);	
		UWSGI_GET_GIL
	}
	else if (uwsgi.cache_max_items) {
		UWSGI_RELEASE_GIL
		uwsgi_wlock(uwsgi.cache_lock);
		if (uwsgi_cache_del(key, keylen, 0, 0)) {
			uwsgi_rwunlock(uwsgi.cache_lock);
			UWSGI_GET_GIL
			Py_INCREF(Py_None);
			return Py_None;
		}
		uwsgi_rwunlock(uwsgi.cache_lock);
		UWSGI_GET_GIL
	}

	Py_INCREF(Py_True);
	return Py_True;

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

	if ((uint64_t)vallen > uwsgi.cache_blocksize) {
		return PyErr_Format(PyExc_ValueError, "uWSGI cache items size must be < %llu, requested %llu bytes", (unsigned long long)uwsgi.cache_blocksize, (unsigned long long) vallen);
	}

	if (remote && strlen(remote) > 0) {
		UWSGI_RELEASE_GIL
		uwsgi_simple_send_string2(remote, 111, 1, key, keylen, value, vallen, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);	
		UWSGI_GET_GIL
	}
	else if (uwsgi.cache_max_items) {
		UWSGI_RELEASE_GIL
		uwsgi_wlock(uwsgi.cache_lock);
		if (uwsgi_cache_set(key, keylen, value, vallen, expires, 0)) {
			uwsgi_rwunlock(uwsgi.cache_lock);
			UWSGI_GET_GIL
			Py_INCREF(Py_None);
			return Py_None;
		}
		uwsgi_rwunlock(uwsgi.cache_lock);
		UWSGI_GET_GIL
	}

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

        if ((uint64_t)vallen > uwsgi.cache_blocksize) {
                return PyErr_Format(PyExc_ValueError, "uWSGI cache items size must be < %llu, requested %llu bytes", (unsigned long long)uwsgi.cache_blocksize, (unsigned long long) vallen);
        }

        if (remote && strlen(remote) > 0) {
		UWSGI_RELEASE_GIL
                uwsgi_simple_send_string2(remote, 111, 1, key, keylen, value, vallen, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		UWSGI_GET_GIL
        }
        else if (uwsgi.cache_max_items) {
		UWSGI_RELEASE_GIL
                uwsgi_wlock(uwsgi.cache_lock);
                if (uwsgi_cache_set(key, keylen, value, vallen, expires, UWSGI_CACHE_FLAG_UPDATE)) {
                        uwsgi_rwunlock(uwsgi.cache_lock);
			UWSGI_GET_GIL
                        Py_INCREF(Py_None);
                        return Py_None;
                }
                uwsgi_rwunlock(uwsgi.cache_lock);
		UWSGI_GET_GIL
        }

        Py_INCREF(Py_True);
        return Py_True;

}



PyObject *py_uwsgi_cache_exists(PyObject * self, PyObject * args) {

	char *key;
	Py_ssize_t keylen = 0;
	char *remote = NULL;
	uint16_t valsize;
	// TODO remove this
	char buffer[0xffff];

	if (!PyArg_ParseTuple(args, "s#|s:cache_exists", &key, &keylen, &remote)) {
		return NULL;
	}
	
	if (remote && strlen(remote) > 0) {
		// TODO FIX THIS !!!
		UWSGI_RELEASE_GIL
		uwsgi_simple_message_string(remote, 111, 0, key, keylen, buffer, &valsize, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		UWSGI_GET_GIL
		if (valsize > 0) {
			Py_INCREF(Py_True);
			return Py_True;
		}	
        }
	else if (uwsgi.cache_max_items) {
		UWSGI_RELEASE_GIL
		uwsgi_rlock(uwsgi.cache_lock);
		if (uwsgi_cache_exists(key, keylen)) {
			uwsgi_rwunlock(uwsgi.cache_lock);
			UWSGI_GET_GIL
			Py_INCREF(Py_True);
			return Py_True;
		}
		uwsgi_rwunlock(uwsgi.cache_lock);
		UWSGI_GET_GIL
	}

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
	uint64_t valsize;
	uint16_t valsize16;
	Py_ssize_t keylen = 0;
	char *value = NULL;
	char *remote = NULL;
	char buffer[0xffff];
	PyObject *ret;

#ifdef UWSGI_DEBUG
	struct timeval tv, tv2;
#endif

	if (!PyArg_ParseTuple(args, "s#|s:cache_get", &key, &keylen, &remote)) {
		return NULL;
	}

	if (remote && strlen(remote) > 0) {
		UWSGI_RELEASE_GIL
		uwsgi_simple_message_string(remote, 111, 0, key, keylen, buffer, &valsize16, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		UWSGI_GET_GIL
		if (valsize16 > 0) {
			value = buffer;
			valsize = valsize16;
		}
	}
	else if (uwsgi.cache_max_items) {
#ifdef UWSGI_DEBUG
		gettimeofday(&tv, NULL); 
#endif
		UWSGI_RELEASE_GIL
		uwsgi_rlock(uwsgi.cache_lock);
		value = uwsgi_cache_get(key, keylen, &valsize);
		if (!value) {
			uwsgi_rwunlock(uwsgi.cache_lock);
			UWSGI_GET_GIL
			Py_INCREF(Py_None);
			return Py_None;
		}
		char *storage = uwsgi_malloc(valsize);
#ifdef UWSGI_DEBUG
		gettimeofday(&tv2, NULL); 
		if ((tv2.tv_sec* (1000*1000) + tv2.tv_usec) - (tv.tv_sec* (1000*1000) + tv.tv_usec) > 30000) {
			uwsgi_log("[slow] cache get done in %d microseconds (%llu bytes value)\n", (tv2.tv_sec* (1000*1000) + tv2.tv_usec) - (tv.tv_sec* (1000*1000) + tv.tv_usec), (unsigned long long) valsize);
		}
#endif
		memcpy(storage, value, valsize);
		uwsgi_rwunlock(uwsgi.cache_lock);
		UWSGI_GET_GIL
		ret = PyString_FromStringAndSize(storage, valsize);
		free(storage);
		return ret;
	}

	if (value) {
		return PyString_FromStringAndSize(value, valsize);
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



#ifdef UWSGI_SPOOLER
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
#endif

void init_uwsgi_module_advanced(PyObject * current_uwsgi_module) {
	PyMethodDef *uwsgi_function;
	PyObject *uwsgi_module_dict;

	uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
	if (!uwsgi_module_dict) {
		uwsgi_log("could not get uwsgi module __dict__\n");
		exit(1);
	}

	uwsgi_IterType.tp_new = PyType_GenericNew;
	if (PyType_Ready(&uwsgi_IterType) < 0) {
		PyErr_Print();
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

#ifdef UWSGI_SNMP
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
#endif


#endif
