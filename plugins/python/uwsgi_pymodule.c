#ifdef UWSGI_EMBEDDED

#include "uwsgi_python.h"

char *spool_buffer = NULL;

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

PyObject *py_uwsgi_signal_wait(PyObject * self, PyObject * args) {

        struct wsgi_request *wsgi_req = current_wsgi_req();

        wsgi_req->sigwait = 1;

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
#ifdef __BIG_ENDIAN__
			keysize = uwsgi_swap16(keysize);
#endif
			memcpy(bufptr, &keysize, 2);
			bufptr += 2;
#ifdef __BIG_ENDIAN__
			keysize = uwsgi_swap16(keysize);
#endif
			memcpy(bufptr, PyString_AsString(key), keysize);
			bufptr += keysize;
#ifdef __BIG_ENDIAN__
			valsize = uwsgi_swap16(valsize);
#endif
			memcpy(bufptr, &valsize, 2);
			bufptr += 2;
#ifdef __BIG_ENDIAN__
			valsize = uwsgi_swap16(valsize);
#endif
			memcpy(bufptr, PyString_AsString(val), valsize);
			bufptr += valsize;
		}

		Py_DECREF(zero);

	}

	return buf;

}

PyObject *py_uwsgi_listen_queue(PyObject * self, PyObject * args) {

#ifdef __linux__
	return PyInt_FromLong(uwsgi.shared->ti.tcpi_unacked);
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

	char buffer[0xffff];
	char *func;
	uint16_t size = 0;
	PyObject *py_func;
	int argc = PyTuple_Size(args);
	int i;
	char *argv[0xff];

	// TODO better error reporting
	if (argc < 1)
		goto clear;

	py_func = PyTuple_GetItem(args, 0);

	if (!PyString_Check(py_func))
		goto clear;

	func = PyString_AsString(py_func);

	for (i = 0; i < (argc - 1); i++) {
		argv[i] = PyString_AsString(PyTuple_GetItem(args, i + 1));
	}

	size = uwsgi_rpc(func, argc - 1, argv, buffer);

	if (size > 0) {
		return PyString_FromStringAndSize(buffer, size);
	}

      clear:

	Py_INCREF(Py_None);
	return Py_None;
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

	char buffer[0xffff];
	char *node, *func;
	uint16_t size = 0;
	PyObject *py_node, *py_func;
	struct wsgi_request rpc_req;
	int argc = PyTuple_Size(args);
	char *argv[0xff];
	int i, fd;
	uint16_t pktsize = 0, ulen;
	char *bufptr;
	int rlen;
	int rpc_args = 0;


	// TODO better error reporting
	if (argc < 2)
		goto clear;

	py_node = PyTuple_GetItem(args, 0);

	if (PyString_Check(py_node)) {
		node = PyString_AsString(py_node);
	}
	else {
		node = "";
	}

	py_func = PyTuple_GetItem(args, 1);

	if (!PyString_Check(py_func))
		goto clear;

	func = PyString_AsString(py_func);

	for (i = 0; i < (argc - 2); i++) {
		argv[i] = PyString_AsString(PyTuple_GetItem(args, i + 2));
		rpc_args++;
	}

	if (!strcmp(node, "")) {
		if (!rpc_args) {
			size = uwsgi_rpc(func, 0, NULL, buffer);
		}
		else {
			size = uwsgi_rpc(func, rpc_args, argv, buffer);
		}
	}
	else {


		// connect to node
		fd = uwsgi_connect(node, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], 0);

		if (fd < 0)
			goto clear;
		// prepare a uwsgi array

		pktsize = 2 + strlen(func);
		for (i = 0; i < argc - 2; i++) {
			pktsize += 2 + strlen(argv[i]);
		}

		memset(&rpc_req, 0, sizeof(struct wsgi_request));

		rpc_req.uh.modifier1 = 173;
		rpc_req.uh.pktsize = pktsize;
		rpc_req.uh.modifier2 = 0;

		bufptr = buffer;

		ulen = strlen(func);
		*bufptr++ = (uint8_t) (ulen & 0xff);
		*bufptr++ = (uint8_t) ((ulen >> 8) & 0xff);
		memcpy(bufptr, func, ulen);
		bufptr += ulen;

		for (i = 0; i < argc - 2; i++) {
			ulen = strlen(argv[i]);
			*bufptr++ = (uint8_t) (ulen & 0xff);
			*bufptr++ = (uint8_t) ((ulen >> 8) & 0xff);
			memcpy(bufptr, argv[i], ulen);
			bufptr += ulen;
		}

		if (write(fd, &rpc_req.uh, 4) != 4) {
			uwsgi_error("write()");
			close(fd);
			goto clear;
		}

		if (write(fd, buffer, pktsize) != pktsize) {
			uwsgi_error("write()");
			close(fd);
			goto clear;
		}

		rlen = uwsgi_waitfd(fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (rlen > 0) {
			rpc_req.poll.fd = fd;
			rpc_req.poll.events = POLLIN;
			rpc_req.buffer = buffer;
			if (uwsgi_parse_packet(&rpc_req, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT])) {
				size = rpc_req.uh.pktsize;
			}
		}

	}

	if (size > 0) {
		return PyString_FromStringAndSize(buffer, size);
	}

      clear:

	Py_INCREF(Py_None);
	return Py_None;
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

PyObject *py_uwsgi_attach_daemon(PyObject * self, PyObject * args) {

	char *command = NULL;

	if (!PyArg_ParseTuple(args, "s:attach_daemon", &command)) {
		return NULL;
	}

	if (uwsgi_attach_daemon(command)) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	Py_INCREF(Py_True);
	return Py_True;
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
	ssize_t rlen;

	if (!PyArg_ParseTuple(args, "B:signal", &uwsgi_signal)) {
		return NULL;
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("sending %d to master\n", uwsgi_signal);
#endif

	rlen = write(uwsgi.signal_socket, &uwsgi_signal, 1);
	if (rlen != 1) {
		uwsgi_error("write()");
	}


	Py_INCREF(Py_None);
	return Py_None;

}

PyObject *py_uwsgi_log_this(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	wsgi_req->log_this = 1;

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

	int uwsgi_fd = uwsgi.wsgi_req->poll.fd;

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

#ifdef UWSGI_SENDFILE
PyObject *py_uwsgi_advanced_sendfile(PyObject * self, PyObject * args) {

	PyObject *what;
	char *filename;
	size_t chunk;
	off_t pos = 0;
	size_t filesize = 0;
	struct stat stat_buf;
	struct wsgi_request *wsgi_req = current_wsgi_req();

	int fd = -1;

	if (!PyArg_ParseTuple(args, "O|iii:sendfile", &what, &chunk, &pos, &filesize)) {
		return NULL;
	}

	if (PyString_Check(what)) {

		filename = PyString_AsString(what);

		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			uwsgi_error("open");
			goto clear;
		}

	}
	else {
		fd = PyObject_AsFileDescriptor(what);
		if (fd < 0)
			goto clear;

		// check for mixing file_wrapper and sendfile
		if (fd == wsgi_req->sendfile_fd) {
			Py_INCREF(what);
		}
	}

	if (!filesize) {
		if (fstat(fd, &stat_buf)) {
			uwsgi_error("fstat()");
			goto clear2;
		}
		else {
			filesize = stat_buf.st_size;
		}

	}

	if (!filesize)
		goto clear2;

	if (!chunk)
		chunk = 4096;

	uwsgi.wsgi_req->response_size += uwsgi_do_sendfile(wsgi_req->poll.fd, fd, filesize, chunk, &pos, 0);

	close(fd);
	Py_INCREF(Py_True);
	return Py_True;

      clear2:
	close(fd);
      clear:
	Py_INCREF(Py_None);
	return Py_None;

}
#endif

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

PyObject *py_uwsgi_lock(PyObject * self, PyObject * args) {

	// the spooler, the master process or single process environment cannot lock resources
#ifdef UWSGI_SPOOLER
	if (uwsgi.numproc > 1 && uwsgi.mypid != uwsgi.workers[0].pid && uwsgi.mypid != uwsgi.shared->spooler_pid) {
#else
	if (uwsgi.numproc > 1 && uwsgi.mypid != uwsgi.workers[0].pid) {
#endif
		uwsgi_lock(uwsgi.user_lock);
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_unlock(PyObject * self, PyObject * args) {

	uwsgi_unlock(uwsgi.user_lock);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_sharedarea_inclong(PyObject * self, PyObject * args) {
	int pos = 0;
	long value = 0;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "ii:sharedarea_inclong", &pos, &value)) {
		return NULL;
	}

	if (pos + 4 >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	memcpy(&value, uwsgi.sharedarea + pos, 4);
	value++;
	memcpy(uwsgi.sharedarea + pos, &value, 4);

	return PyInt_FromLong(value);

}

PyObject *py_uwsgi_sharedarea_writelong(PyObject * self, PyObject * args) {
	int pos = 0;
	long value;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "ii:sharedarea_writelong", &pos, &value)) {
		return NULL;
	}

	if (pos + 4 >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	memcpy(uwsgi.sharedarea + pos, &value, 4);

	return PyInt_FromLong(value);

}

PyObject *py_uwsgi_sharedarea_write(PyObject * self, PyObject * args) {
	int pos = 0;
	char *value;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "is:sharedarea_write", &pos, &value)) {
		return NULL;
	}

	if (pos + (int) strlen(value) >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	memcpy(uwsgi.sharedarea + pos, value, strlen(value));

	return PyInt_FromLong(strlen(value));

}

PyObject *py_uwsgi_sharedarea_writebyte(PyObject * self, PyObject * args) {
	int pos = 0;
	char value;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}


	if (!PyArg_ParseTuple(args, "ib:sharedarea_writebyte", &pos, &value)) {
		return NULL;
	}

	if (pos >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	uwsgi.sharedarea[pos] = value;

	return PyInt_FromLong(uwsgi.sharedarea[pos]);

}

PyObject *py_uwsgi_sharedarea_readlong(PyObject * self, PyObject * args) {
	int pos = 0;
	long value;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "i:sharedarea_readlong", &pos)) {
		return NULL;
	}

	if (pos + 4 >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	memcpy(&value, uwsgi.sharedarea + pos, 4);

	return PyInt_FromLong(value);

}


PyObject *py_uwsgi_sharedarea_readbyte(PyObject * self, PyObject * args) {
	int pos = 0;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "i:sharedarea_readbyte", &pos)) {
		return NULL;
	}

	if (pos >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	return PyInt_FromLong(uwsgi.sharedarea[pos]);

}

PyObject *py_uwsgi_sharedarea_read(PyObject * self, PyObject * args) {
	int pos = 0;
	int len = 1;

	if (uwsgi.sharedareasize <= 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (!PyArg_ParseTuple(args, "i|i:sharedarea_read", &pos, &len)) {
		return NULL;
	}

	if (pos + len >= uwsgi.page_size * uwsgi.sharedareasize) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	return PyString_FromStringAndSize(uwsgi.sharedarea + pos, len);
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

	sdir = opendir(uwsgi.spool_dir);

	if (sdir) {
		while ((dp = readdir(sdir)) != NULL) {
			if (!strncmp("uwsgi_spoolfile_on_", dp->d_name, 19)) {
				abs_path = malloc(strlen(uwsgi.spool_dir) + 1 + strlen(dp->d_name) + 1);
				if (!abs_path) {
					uwsgi_error("malloc()");
					closedir(sdir);
					goto clear;
				}

				memset(abs_path, 0, strlen(uwsgi.spool_dir) + 1 + strlen(dp->d_name) + 1);

				memcpy(abs_path, uwsgi.spool_dir, strlen(uwsgi.spool_dir));
				memcpy(abs_path + strlen(uwsgi.spool_dir), "/", 1);
				memcpy(abs_path + strlen(uwsgi.spool_dir) + 1, dp->d_name, strlen(dp->d_name));


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

	spool_vars = PyDict_Items(spool_dict);
	if (!spool_vars) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	cur_buf = spool_buffer;

	for (i = 0; i < PyList_Size(spool_vars); i++) {
		zero = PyList_GetItem(spool_vars, i);
		if (zero) {
			if (PyTuple_Check(zero)) {
				key = PyTuple_GetItem(zero, 0);
				val = PyTuple_GetItem(zero, 1);

				if (PyString_Check(key) && PyString_Check(val)) {


					keysize = PyString_Size(key);
					valsize = PyString_Size(val);
					if (cur_buf + keysize + 2 + valsize + 2 <= spool_buffer + uwsgi.buffer_size) {

#ifdef __BIG_ENDIAN__
						keysize = uwsgi_swap16(keysize);
#endif
						memcpy(cur_buf, &keysize, 2);
						cur_buf += 2;
#ifdef __BIG_ENDIAN__
						keysize = uwsgi_swap16(keysize);
#endif
						memcpy(cur_buf, PyString_AsString(key), keysize);
						cur_buf += keysize;
#ifdef __BIG_ENDIAN__
						valsize = uwsgi_swap16(valsize);
#endif
						memcpy(cur_buf, &valsize, 2);
						cur_buf += 2;
#ifdef __BIG_ENDIAN__
						valsize = uwsgi_swap16(valsize);
#endif
						memcpy(cur_buf, PyString_AsString(val), valsize);
						cur_buf += valsize;
					}
					else {
						Py_DECREF(zero);
						return PyErr_Format(PyExc_ValueError, "spooler packet cannot be more than %d bytes", uwsgi.buffer_size);
					}
				}
				else {
					Py_DECREF(zero);
					return PyErr_Format(PyExc_ValueError, "spooler callable dictionary must contains only strings");
				}
			}
			else {
				Py_DECREF(zero);
				Py_INCREF(Py_None);
				return Py_None;
			}
		}
		else {
			Py_INCREF(Py_None);
			return Py_None;
		}
	}

	i = spool_request(spool_filename, uwsgi.workers[0].requests + 1, wsgi_req->async_id, spool_buffer, cur_buf - spool_buffer);

	Py_DECREF(spool_vars);

	if (i > 0) {
		Py_INCREF(Py_True);
		return Py_True;
	}
	Py_INCREF(Py_None);
	return Py_None;
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

	PyObject *marshalled;
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

PyObject *py_uwsgi_load_plugin(PyObject * self, PyObject * args) {
	int modifier;
	char *plugin_name = NULL;
	char *pargs = NULL;

	if (!PyArg_ParseTuple(args, "is|s:load_plugin", &modifier, &plugin_name, &pargs)) {
		return NULL;
	}

	if (uwsgi_load_plugin(modifier, plugin_name, pargs, 1)) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	Py_INCREF(Py_True);
	return Py_True;
}

#ifdef UWSGI_MULTICAST
PyObject *py_uwsgi_multicast(PyObject * self, PyObject * args) {

	char *host, *message;
	ssize_t ret;

	if (!PyArg_ParseTuple(args, "ss:send_multicast_message", &host, &message)) {
		return NULL;
	}

	ret = send_udp_message(UWSGI_MODIFIER_MULTICAST, host, message, strlen(message));

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

	PyObject *pyobj = NULL, *marshalled = NULL;

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
	else {
		marshalled = PyMarshal_WriteObjectToString(pyobj, 1);
		if (!marshalled) {
			PyErr_Print();
			goto clear;
		}

		encoded = PyString_AsString(marshalled);
		esize = PyString_Size(marshalled);
		UWSGI_RELEASE_GIL uwsgi_send_message(uwsgi_fd, (uint8_t) modifier1, (uint8_t) modifier2, encoded, esize, -1, 0, 0);
	}

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

PyObject *py_uwsgi_send_message(PyObject * self, PyObject * args) {

	PyObject *destination = NULL, *pyobj = NULL, *marshalled = NULL;

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
		uwsgi_fd = uwsgi_connect(PyString_AsString(destination), timeout, 0);
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
	else {
		marshalled = PyMarshal_WriteObjectToString(pyobj, 1);
		if (!marshalled) {
			PyErr_Print();
			goto clear;
		}

		encoded = PyString_AsString(marshalled);
		esize = PyString_Size(marshalled);
		UWSGI_RELEASE_GIL uwsgi_send_message(uwsgi_fd, (uint8_t) modifier1, (uint8_t) modifier2, encoded, esize, fd, cl, timeout);
	}

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
	return PyInt_FromLong(uwsgi.workers[0].requests);
}

	/* uWSGI workers */
PyObject *py_uwsgi_workers(PyObject * self, PyObject * args) {

	PyObject *worker_dict, *zero;
	int i;

	for (i = 0; i < uwsgi.numproc; i++) {
		worker_dict = PyTuple_GetItem(up.workers_tuple, i);
		if (!worker_dict) {
			goto clear;
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

		zero = PyInt_FromLong(uwsgi.workers[i + 1].requests);
		if (PyDict_SetItemString(worker_dict, "requests", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyInt_FromLong(uwsgi.workers[i + 1].exceptions);
		if (PyDict_SetItemString(worker_dict, "exceptions", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyInt_FromLong(uwsgi.workers[i + 1].rss_size);
		if (PyDict_SetItemString(worker_dict, "rss", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyInt_FromLong(uwsgi.workers[i + 1].vsz_size);
		if (PyDict_SetItemString(worker_dict, "vsz", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyFloat_FromDouble(uwsgi.workers[i + 1].running_time);
		if (PyDict_SetItemString(worker_dict, "running_time", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromLong(uwsgi.workers[i + 1].last_spawn);
		if (PyDict_SetItemString(worker_dict, "last_spawn", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		zero = PyLong_FromLong(uwsgi.workers[i + 1].respawn_count);
		if (PyDict_SetItemString(worker_dict, "respawn_count", zero)) {
			goto clear;
		}
		Py_DECREF(zero);

		/* return a tuple of current status ! (in_request, blocking, locking, )

		   zero = PyLong_FromLong(uwsgi.workers[i+1].in_request);
		   if (PyDict_SetItemString(worker_dict, "in_request", zero)) {
		   goto clear;
		   }
		   Py_DECREF(zero);
		 */

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
	return PyInt_FromLong(uwsgi.workers[uwsgi.mywid].requests);
}

PyObject *py_uwsgi_worker_id(PyObject * self, PyObject * args) {
	return PyInt_FromLong(uwsgi.mywid);
}

PyObject *py_uwsgi_logsize(PyObject * self, PyObject * args) {
	return PyInt_FromLong(uwsgi.shared->logsize);
}

PyObject *py_uwsgi_mem(PyObject * self, PyObject * args) {

	PyObject *ml = PyTuple_New(2);

	get_memusage();

	PyTuple_SetItem(ml, 0, PyLong_FromLong(uwsgi.workers[uwsgi.mywid].rss_size));
	PyTuple_SetItem(ml, 1, PyLong_FromLong(uwsgi.workers[uwsgi.mywid].vsz_size));

	return ml;

}

PyObject *py_uwsgi_cl(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	return PyLong_FromLong(wsgi_req->post_cl);

}

PyObject *py_uwsgi_disconnect(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

#ifdef UWSGI_DEBUG
	uwsgi_log("disconnecting worker %d (pid :%d) from session...\n", uwsgi.mywid, uwsgi.mypid);
#endif

	fclose(wsgi_req->async_post);
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

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_error_open(filename);
		goto clear;
	}

	len = read(fd, &uh, 4);
	if (len != 4) {
		uwsgi_error("read()");
		goto clear2;
	}

	buffer = malloc(uh.pktsize);
	if (!buffer) {
		uwsgi_error("malloc()");
		goto clear2;
	}
	len = read(fd, buffer, uh.pktsize);
	if (len != uh.pktsize) {
		uwsgi_error("read()");
		free(buffer);
		goto clear2;
	}

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

	grunt_pid = fork();
	if (grunt_pid < 0) {
		uwsgi_error("fork()");
		goto clear;
	}
	else if (grunt_pid == 0) {
		uwsgi_close_all_sockets();
		// create a new session
		setsid();
		// exit on SIGPIPE
		signal(SIGPIPE, (void *) &end_me);
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

	// close connection on the worker
	if (PyTuple_Size(args) == 0) {
		fclose(wsgi_req->async_post);
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
	{"send_multi_message", py_uwsgi_send_multi_message, METH_VARARGS, ""},
	{"reload", py_uwsgi_reload, METH_VARARGS, ""},
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
	{"log", py_uwsgi_log, METH_VARARGS, ""},
	{"log_this_request", py_uwsgi_log_this, METH_VARARGS, ""},
	{"disconnect", py_uwsgi_disconnect, METH_VARARGS, ""},
	{"grunt", py_uwsgi_grunt, METH_VARARGS, ""},
	{"load_plugin", py_uwsgi_load_plugin, METH_VARARGS, ""},
	{"lock", py_uwsgi_lock, METH_VARARGS, ""},
	{"unlock", py_uwsgi_unlock, METH_VARARGS, ""},
	{"cl", py_uwsgi_cl, METH_VARARGS, ""},

	{"listen_queue", py_uwsgi_listen_queue, METH_VARARGS, ""},

	{"attach_daemon", py_uwsgi_attach_daemon, METH_VARARGS, ""},

	{"register_signal", py_uwsgi_register_signal, METH_VARARGS, ""},
	{"signal", py_uwsgi_signal, METH_VARARGS, ""},
	{"signal_wait", py_uwsgi_signal_wait, METH_VARARGS, ""},
	{"signal_received", py_uwsgi_signal_received, METH_VARARGS, ""},
	{"add_file_monitor", py_uwsgi_add_file_monitor, METH_VARARGS, ""},
	{"add_timer", py_uwsgi_add_timer, METH_VARARGS, ""},
	{"add_rb_timer", py_uwsgi_add_rb_timer, METH_VARARGS, ""},
	{"add_cron", py_uwsgi_add_cron, METH_VARARGS, ""},

	{"register_rpc", py_uwsgi_register_rpc, METH_VARARGS, ""},
	{"rpc", py_uwsgi_rpc, METH_VARARGS, ""},
	{"rpc_list", py_uwsgi_rpc_list, METH_VARARGS, ""},
	{"call", py_uwsgi_call, METH_VARARGS, ""},
#ifdef UWSGI_SENDFILE
	{"sendfile", py_uwsgi_advanced_sendfile, METH_VARARGS, ""},
#endif
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
	{"is_connected", py_uwsgi_is_connected, METH_VARARGS, ""},
	{"send", py_uwsgi_send, METH_VARARGS, ""},
	{"recv", py_uwsgi_recv, METH_VARARGS, ""},
	{"recv_block", py_uwsgi_recv_block, METH_VARARGS, ""},
	{"recv_frame", py_uwsgi_recv_frame, METH_VARARGS, ""},
	{"close", py_uwsgi_close, METH_VARARGS, ""},

	{"fcgi", py_uwsgi_fcgi, METH_VARARGS, ""},

	{"parsefile", py_uwsgi_parse_file, METH_VARARGS, ""},
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

PyObject *py_uwsgi_cache_del(PyObject * self, PyObject * args) {

	char *key;
	Py_ssize_t keylen = 0;
	char *remote = NULL;

	if (!PyArg_ParseTuple(args, "s#|s:cache_del", &key, &keylen, &remote)) {
		return NULL;
	}

	if (remote && strlen(remote) > 0) {
		uwsgi_simple_send_string(remote, 111, 2, key, keylen, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);	
	}
	else if (uwsgi.cache_max_items) {
		uwsgi_wlock(uwsgi.cache_lock);
		if (uwsgi_cache_del(key, strlen(key))) {
			uwsgi_rwunlock(uwsgi.cache_lock);
			Py_INCREF(Py_None);
			return Py_None;
		}
		uwsgi_rwunlock(uwsgi.cache_lock);
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
		return PyErr_Format(PyExc_ValueError, "uWSGI cache items size must be < %llu, requested %d bytes", (unsigned long long)uwsgi.cache_blocksize, (int) vallen);
	}

	if (remote && strlen(remote) > 0) {
		uwsgi_simple_send_string2(remote, 111, 1, key, keylen, value, vallen, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);	
	}
	else if (uwsgi.cache_max_items) {
		uwsgi_wlock(uwsgi.cache_lock);
		if (uwsgi_cache_set(key, keylen, value, vallen, expires, 0)) {
			uwsgi_rwunlock(uwsgi.cache_lock);
			Py_INCREF(Py_None);
			return Py_None;
		}
		uwsgi_rwunlock(uwsgi.cache_lock);
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
		uwsgi_simple_message_string(remote, 111, 0, key, keylen, buffer, &valsize, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (valsize > 0) {
			Py_INCREF(Py_True);
			return Py_True;
		}	
        }
	else if (uwsgi_cache_exists(key, strlen(key))) {
		Py_INCREF(Py_True);
		return Py_True;
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
                uwsgi_wlock(uwsgi.queue_lock);
                if (uwsgi_queue_push(message, msglen)) {
			Py_INCREF(Py_True);
                        res = Py_True;
                }
                else {
                        Py_INCREF(Py_None);
                        res = Py_None;
                }
                uwsgi_rwunlock(uwsgi.queue_lock);
                return res;
        }

        Py_INCREF(Py_None);
        return Py_None;
	
}

PyObject *py_uwsgi_queue_slot(PyObject * self, PyObject * args) {

	return PyInt_FromLong(uwsgi.shared->queue_pos);
}

PyObject *py_uwsgi_queue_pull(PyObject * self, PyObject * args) {

	char *message;
	uint64_t size;
	PyObject *res;

	if (!PyArg_ParseTuple(args, ":queue_pull")) {
                return NULL;
        }

	if (uwsgi.queue_size) {
		uwsgi_wlock(uwsgi.queue_lock);
		message = uwsgi_queue_pull(&size);
		if (message) {
                        res = PyString_FromStringAndSize(message, size);
                }
                else {
                        Py_INCREF(Py_None);
                        res = Py_None;
                }
                uwsgi_rwunlock(uwsgi.queue_lock);
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

	if (!PyArg_ParseTuple(args, "l:queue_get", &index)) {
                return NULL;
        }

	if (uwsgi.queue_size) {
		uwsgi_rlock(uwsgi.queue_lock);
		message = uwsgi_queue_get(index, &size);
		if (message) {
			res = PyString_FromStringAndSize(message, size);
		}
		else {
			Py_INCREF(Py_None);
			res = Py_None;
		}
		uwsgi_rwunlock(uwsgi.queue_lock);
		return res;
	}	

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_queue_last(PyObject * self, PyObject * args) {

        long num = 0;
        uint64_t size = 0;
        char *message;
        PyObject *res, *zero;
	uint64_t base;

        if (!PyArg_ParseTuple(args, "l:queue_last", &num)) {
                return NULL;
        }

        if (uwsgi.queue_size) {
		res = PyList_New(0);
                uwsgi_rlock(uwsgi.queue_lock);
		if (uwsgi.shared->queue_pos > 0) {
			base = uwsgi.shared->queue_pos-1;
		}
		else {
			base = uwsgi.queue_size-1;
		}
		if (num > (long)uwsgi.queue_size) num = uwsgi.queue_size;
		while(num) {
                	message = uwsgi_queue_get(base, &size);
                	if (message && size) {
                        	zero = PyString_FromStringAndSize(message, size);
				PyList_Append(res, zero);
				Py_DECREF(zero);
                	}
                	else {
                		uwsgi_rwunlock(uwsgi.queue_lock);
				return res;
                	}
			if (base > 0) {
				base--;
			}
			else {
				base = uwsgi.queue_size-1;
			}
			num--;
		}
                uwsgi_rwunlock(uwsgi.queue_lock);
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
	PyObject *res;

#ifdef UWSGI_DEBUG
	struct timeval tv, tv2;
#endif

	if (!PyArg_ParseTuple(args, "s#|s:cache_get", &key, &keylen, &remote)) {
		return NULL;
	}

	if (remote && strlen(remote) > 0) {
		uwsgi_simple_message_string(remote, 111, 0, key, keylen, buffer, &valsize16, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (valsize16 > 0) {
			value = buffer;
		}
	}
	else if (uwsgi.cache_max_items) {
#ifdef UWSGI_DEBUG
		gettimeofday(&tv, NULL); 
#endif
		uwsgi_rlock(uwsgi.cache_lock);
		value = uwsgi_cache_get(key, keylen, &valsize);
		if (!value) {
			uwsgi_rwunlock(uwsgi.cache_lock);
			Py_INCREF(Py_None);
			return Py_None;
		}
		res = PyString_FromStringAndSize(value, valsize);
#ifdef UWSGI_DEBUG
		gettimeofday(&tv2, NULL); 
		if ((tv2.tv_sec* (1000*1000) + tv2.tv_usec) - (tv.tv_sec* (1000*1000) + tv.tv_usec) > 30000) {
			uwsgi_log("[slow] cache get done in %d microseconds (%llu bytes value)\n", (tv2.tv_sec* (1000*1000) + tv2.tv_usec) - (tv.tv_sec* (1000*1000) + tv.tv_usec), (unsigned long long) valsize);
		}
#endif
		uwsgi_rwunlock(uwsgi.cache_lock);
		return res;
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
	{"cache_del", py_uwsgi_cache_del, METH_VARARGS, ""},
	{"cache_exists", py_uwsgi_cache_exists, METH_VARARGS, ""},
	{NULL, NULL},
};

static PyMethodDef uwsgi_queue_methods[] = {
	{"queue_get", py_uwsgi_queue_get, METH_VARARGS, ""},
	{"queue_last", py_uwsgi_queue_last, METH_VARARGS, ""},
	{"queue_push", py_uwsgi_queue_push, METH_VARARGS, ""},
	{"queue_pull", py_uwsgi_queue_pull, METH_VARARGS, ""},
	{"queue_slot", py_uwsgi_queue_slot, METH_VARARGS, ""},
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

	spool_buffer = malloc(uwsgi.buffer_size);
	if (!spool_buffer) {
		uwsgi_error("malloc()");
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

#endif
