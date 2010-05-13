#ifdef UWSGI_EMBEDDED

#include "uwsgi.h"

char *spool_buffer = NULL;

extern struct uwsgi_server uwsgi;

#ifdef __APPLE__
#define UWSGI_LOCK OSSpinLockLock((OSSpinLock *) uwsgi.sharedareamutex);
#define UWSGI_UNLOCK OSSpinLockUnlock((OSSpinLock *) uwsgi.sharedareamutex);
#elif defined(__linux__) || defined(__sun__) || defined(__FreeBSD__)
#define UWSGI_LOCK pthread_mutex_lock((pthread_mutex_t *) uwsgi.sharedareamutex + sizeof(pthread_mutexattr_t));
#define UWSGI_UNLOCK pthread_mutex_unlock((pthread_mutex_t *) uwsgi.sharedareamutex + sizeof(pthread_mutexattr_t));
#else
#define UWSGI_LOCK if (flock(uwsgi.serverfd, LOCK_EX)) { uwsgi_error("flock()"); }
#define UWSGI_UNLOCK if (flock(uwsgi.serverfd, LOCK_UN)) { uwsgi_error("flock()"); }
#endif

#define UWSGI_LOGBASE "[- uWSGI -"

PyObject *py_uwsgi_send(PyObject * self, PyObject * args) {
	
	char *data;

	if (!PyArg_ParseTuple(args, "s:send", &data)) {
                return NULL;
        }

	if (write(uwsgi.wsgi_req->poll.fd, data, strlen(data)) < 0) {
		uwsgi_error("write()");
		Py_INCREF(Py_None);
		return Py_None;
	}

	Py_INCREF(Py_True);
	return Py_True;
	
}

#ifdef UWSGI_ASYNC


PyObject *py_uwsgi_async_sleep(PyObject * self, PyObject * args) {

	float timeout ;
	time_t sec_timeout ;

	if (!PyArg_ParseTuple(args, "f:async_sleep", &timeout)) {
                return NULL;
        }

	sec_timeout = (time_t) timeout ;

	if (sec_timeout > 0) {
		async_set_timeout(uwsgi.wsgi_req, sec_timeout);
	}

	return PyString_FromString("") ;
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
		uwsgi_log( "- warning message must be max 80 chars, it will be truncated -");
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
	time_t tt;

	if (!PyArg_ParseTuple(args, "s:log", &logline)) {
		return NULL;
	}

	tt = time(NULL);
	if (logline[strlen(logline)] != '\n') {
		uwsgi_log( UWSGI_LOGBASE " %.*s] %s\n", 24, ctime(&tt), logline);
	}
	else {
		uwsgi_log( UWSGI_LOGBASE " %.*s] %s", 24, ctime(&tt), logline);
	}

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
		UWSGI_LOCK
		UWSGI_SET_LOCKING;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_unlock(PyObject * self, PyObject * args) {

	UWSGI_UNLOCK 
	UWSGI_UNSET_LOCKING;

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

	if (pos + strlen(value) >= uwsgi.page_size * uwsgi.sharedareasize) {
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


PyObject *py_uwsgi_send_spool(PyObject * self, PyObject * args) {
	PyObject *spool_dict, *spool_vars;
	PyObject *zero, *key, *val;
	uint16_t keysize, valsize;
	char *cur_buf;
	int i;
	char spool_filename[1024];

	spool_dict = PyTuple_GetItem(args, 0);
	if (!PyDict_Check(spool_dict)) {
		Py_INCREF(Py_None);
		return Py_None;
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
						Py_INCREF(Py_None);
						return Py_None;
					}
				}
				else {
					Py_DECREF(zero);
					Py_INCREF(Py_None);
					return Py_None;
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

	i = spool_request(&uwsgi, spool_filename, uwsgi.workers[0].requests + 1, spool_buffer, cur_buf - spool_buffer);
	if (i > 0) {
		return Py_True;
	}

	Py_DECREF(spool_vars);
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
	struct uwsgi_header uh;
	PyObject *arg_cluster;

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

		PyObject *cluster_node = PyTuple_GetItem(arg_cluster, i);
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
			uwsgi_log( "timeout on multiple send !\n");
			goto megamulticlear;
		}
		else {
			for (i = 0; i < clen; i++) {
				if (multipoll[i].revents & POLLIN) {
					if (!uwsgi_parse_response(&multipoll[i], PyInt_AsLong(arg_timeout), &uh, &buffer[i])) {
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
		}
	}

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
	uint8_t modifier;
	char *plugin_name = NULL;
	char *pargs = NULL;

	void *plugin_handle;
	int (*plugin_init) (struct uwsgi_server *, char *);
	int (*plugin_request) (struct uwsgi_server *, struct wsgi_request *);
	void (*plugin_after_request) (struct uwsgi_server *, struct wsgi_request *);

	if (!PyArg_ParseTuple(args, "is|s:load_plugin", &modifier, &plugin_name, &pargs)) {
		return NULL;
	}

	plugin_handle = dlopen(plugin_name, RTLD_NOW | RTLD_GLOBAL);
	if (!plugin_handle) {
		uwsgi_log( "%s\n", dlerror());
	}
	else {
		plugin_init = dlsym(plugin_handle, "uwsgi_init");
		if (plugin_init) {
			if ((*plugin_init) (&uwsgi, pargs)) {
				uwsgi_log( "plugin initialization returned error\n");
				if (dlclose(plugin_handle)) {
					uwsgi_log( "unable to unload plugin\n");
				}

				Py_INCREF(Py_None);
				return Py_None;
			}
		}

		plugin_request = dlsym(plugin_handle, "uwsgi_request");
		if (plugin_request) {
			uwsgi.shared->hooks[modifier] = plugin_request;
			plugin_after_request = dlsym(plugin_handle, "uwsgi_after_request");
			if (plugin_after_request) {
				uwsgi.shared->after_hooks[modifier] = plugin_after_request;
			}
			Py_INCREF(Py_True);
			return Py_True;

		}
		else {
			uwsgi_log( "%s\n", dlerror());
		}
	}

	Py_INCREF(Py_None);
	return Py_None;
}

#ifdef UWSGI_MULTICAST
PyObject *py_uwsgi_multicast(PyObject * self, PyObject * args) {

	char *host, *message ;
	ssize_t ret ;

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

PyObject *py_uwsgi_send_message(PyObject * self, PyObject * args) {

	PyObject *arg_message = NULL;

	const char *arg_host = NULL;
	int arg_port = 0;
	int arg_modifier1 = 0;
	int arg_modifier2 = 0;
	int arg_timeout = 0;

	PyObject *marshalled;
	PyObject *retobject;

	if (!PyArg_ParseTuple(args, "siiiO|i:send_uwsgi_message", &arg_host, &arg_port, &arg_modifier1, &arg_modifier2, &arg_message, &arg_timeout)) {
		return NULL;
	}

	switch (arg_modifier1) {
	case UWSGI_MODIFIER_MESSAGE_MARSHAL:
		marshalled = PyMarshal_WriteObjectToString(arg_message, 1);
		if (!marshalled) {
			PyErr_Print();
			Py_INCREF(Py_None);
			return Py_None;
		}
		retobject = uwsgi_send_message(arg_host, arg_port, arg_modifier1, arg_modifier2, PyString_AsString(marshalled), PyString_Size(marshalled), arg_timeout);
		Py_DECREF(marshalled);
		if (!retobject) {
			PyErr_Print();
			PyErr_Clear();
		}
		else {
			return retobject;
		}
		break;
	case UWSGI_MODIFIER_ADMIN_REQUEST:
		if (PyString_Check(arg_message)) {
			retobject = uwsgi_send_message(arg_host, arg_port, arg_modifier1, arg_modifier2, PyString_AsString(arg_message), PyString_Size(arg_message), arg_timeout);
			if (!retobject) {
				PyErr_Print();
				PyErr_Clear();
			}
			else {
				return retobject;
			}
		}
		break;
	default:
		break;
	}


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
		worker_dict = PyTuple_GetItem(uwsgi.workers_tuple, i);
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


	Py_INCREF(uwsgi.workers_tuple);
	return uwsgi.workers_tuple;

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
		uwsgi.workers[uwsgi.mywid].status |= UWSGI_STATUS_BLOCKING;
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

PyObject *py_uwsgi_disconnect(PyObject * self, PyObject * args) {
	uwsgi_log( "detaching uWSGI from current connection...\n");

	struct wsgi_request *wsgi_req = current_wsgi_req(&uwsgi);

	fclose(wsgi_req->async_post);
	wsgi_req->fd_closed = 1 ;

	Py_INCREF(Py_True);
	return Py_True;
}

#ifdef UWSGI_SPOOLER
static PyMethodDef uwsgi_spooler_methods[] = {
	{"send_to_spooler", py_uwsgi_send_spool, METH_VARARGS, ""},
	{"set_spooler_frequency", py_uwsgi_spooler_freq, METH_VARARGS, ""},
	{NULL, NULL},
};
#endif

static PyMethodDef uwsgi_advanced_methods[] = {
	{"send_uwsgi_message", py_uwsgi_send_message, METH_VARARGS, ""},
	{"send_multi_uwsgi_message", py_uwsgi_send_multi_message, METH_VARARGS, ""},
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
	{"disconnect", py_uwsgi_disconnect, METH_VARARGS, ""},
	{"load_plugin", py_uwsgi_load_plugin, METH_VARARGS, ""},
	{"lock", py_uwsgi_lock, METH_VARARGS, ""},
	{"unlock", py_uwsgi_unlock, METH_VARARGS, ""},
	{"send", py_uwsgi_send, METH_VARARGS, ""},
	{"set_warning_message", py_uwsgi_warning, METH_VARARGS, ""},
#ifdef UWSGI_MULTICAST
	{"send_multicast_message", py_uwsgi_multicast, METH_VARARGS, ""},
#endif
#ifdef UWSGI_ASYNC
	{"async_sleep", py_uwsgi_async_sleep, METH_VARARGS, ""},
#endif
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



#ifdef UWSGI_SPOOLER
void init_uwsgi_module_spooler(PyObject * current_uwsgi_module) {
	PyMethodDef *uwsgi_function;
	PyObject *uwsgi_module_dict;

	uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
	if (!uwsgi_module_dict) {
		uwsgi_log( "could not get uwsgi module __dict__\n");
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
		uwsgi_log( "could not get uwsgi module __dict__\n");
		exit(1);
	}

	for (uwsgi_function = uwsgi_advanced_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
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
		uwsgi_log( "could not get uwsgi module __dict__\n");
		exit(1);
	}

	for (uwsgi_function = uwsgi_sa_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
		PyObject *func = PyCFunction_New(uwsgi_function, NULL);
		PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
		Py_DECREF(func);
	}
}

#endif
