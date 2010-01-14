#ifndef ROCK_SOLID

#include "uwsgi.h"

char *spool_buffer = NULL ;

extern struct uwsgi_server uwsgi;

#ifdef __APPLE__
#define LOCK_SHAREDAREA OSSpinLockLock((OSSpinLock *) uwsgi.sharedareamutex);
#define UNLOCK_SHAREDAREA OSSpinLockUnlock((OSSpinLock *) uwsgi.sharedareamutex);
#else
#ifndef __OpenBSD__
#define LOCK_SHAREDAREA pthread_mutex_lock((pthread_mutex_t *) uwsgi.sharedareamutex + sizeof(pthread_mutexattr_t));
#define UNLOCK_SHAREDAREA pthread_mutex_unlock((pthread_mutex_t *) uwsgi.sharedareamutex + sizeof(pthread_mutexattr_t));
#else
#define LOCK_SHAREDAREA
#define UNLOCK_SHAREDAREA
#endif
#endif

PyObject *py_uwsgi_sharedarea_inclong(PyObject *self, PyObject *args) {
	PyObject *arg0 ;
	int pos = 0 ;
	long value ;

        if (uwsgi.sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	if (pos+4 >= uwsgi.page_size*uwsgi.sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	LOCK_SHAREDAREA
	memcpy(&value, uwsgi.sharedarea+pos, 4);
	value++;
	memcpy(uwsgi.sharedarea+pos, &value,4);
	UNLOCK_SHAREDAREA

        return PyInt_FromLong(value);
	
}

PyObject *py_uwsgi_sharedarea_writelong(PyObject *self, PyObject *args) {
	PyObject *arg0,*arg1 ;
	int pos = 0 ;
	long value ;

        if (uwsgi.sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	if (pos+4 >= uwsgi.page_size*uwsgi.sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	arg1 = PyTuple_GetItem(args, 1);
        if (!PyInt_Check(arg1)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	LOCK_SHAREDAREA
        value = (long) PyInt_AsLong(arg1);
	memcpy(uwsgi.sharedarea+pos, &value,4);
	UNLOCK_SHAREDAREA

        return PyInt_FromLong(value);
	
}

PyObject *py_uwsgi_sharedarea_write(PyObject *self, PyObject *args) {
	PyObject *arg0,*arg1 ;
	int pos = 0 ;
	char *value ;

        if (uwsgi.sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	arg1 = PyTuple_GetItem(args, 1);
        if (!PyString_Check(arg1)) {
		/* PyErr_SetString(PyExc_TypeError,"the second argument of sharedarea_write must be a string"); */
                Py_INCREF(Py_None);
                return Py_None;
        }

	value = PyString_AsString(arg1);

	if (pos+strlen(value) >= uwsgi.page_size*uwsgi.sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	LOCK_SHAREDAREA
	memcpy(uwsgi.sharedarea+pos, value,strlen(value));
	UNLOCK_SHAREDAREA

        return PyInt_FromLong(strlen(value));
	
}

PyObject *py_uwsgi_sharedarea_writebyte(PyObject *self, PyObject *args) {
	PyObject *arg0,*arg1 ;
	int pos = 0 ;
	char value ;

        if (uwsgi.sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	if (pos >= uwsgi.page_size*uwsgi.sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	arg1 = PyTuple_GetItem(args, 1);
        if (!PyInt_Check(arg1)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        value = (char) PyInt_AsLong(arg1);
	uwsgi.sharedarea[pos] = value;

        return PyInt_FromLong(uwsgi.sharedarea[pos]);
	
}

PyObject *py_uwsgi_sharedarea_readlong(PyObject *self, PyObject *args) {
	PyObject *arg0 ;
	int pos = 0 ;
	long value ;

        if (uwsgi.sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	if (pos+4 >= uwsgi.page_size*uwsgi.sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	LOCK_SHAREDAREA
	memcpy(&value, uwsgi.sharedarea+pos, 4);
	UNLOCK_SHAREDAREA

        return PyInt_FromLong(value);
	
}


PyObject *py_uwsgi_sharedarea_readbyte(PyObject *self, PyObject *args) {
	PyObject *arg0 ;
	int pos = 0 ;

        if (uwsgi.sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	if (pos >= uwsgi.page_size*uwsgi.sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        return PyInt_FromLong(uwsgi.sharedarea[pos]);
	
}

PyObject *py_uwsgi_sharedarea_read(PyObject *self, PyObject *args) {
        PyObject *arg0, *arg1;

        int len = 1 ;
        int pos = 0 ;

        if (uwsgi.sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }
        arg1 = PyTuple_GetItem(args, 1);
        if (PyInt_Check(arg1)) {
                len = PyInt_AsLong(arg1);
        }

        pos = PyInt_AsLong(arg0);

        if (pos+len >= uwsgi.page_size*uwsgi.sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	return PyString_FromStringAndSize(uwsgi.sharedarea+pos, len);
}

PyObject *py_uwsgi_send_spool(PyObject *self, PyObject *args) {
	PyObject *spool_dict, *spool_vars ;
	PyObject *zero, *key, *val;
	uint16_t keysize, valsize ;
	char *cur_buf ;
	int i ;
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
	
	cur_buf = spool_buffer ;

	for(i=0;i<PyList_Size(spool_vars);i++) {
		zero = PyList_GetItem(spool_vars, i);
		if (zero) {
			if (PyTuple_Check(zero)) {
				key = PyTuple_GetItem(zero, 0);
				val = PyTuple_GetItem(zero, 1);

				if (PyString_Check(key) && PyString_Check(val)) {

				
					keysize = PyString_Size(key) ;
					valsize= PyString_Size(val) ;
					if (cur_buf + keysize + 2 + valsize + 2 <= spool_buffer + uwsgi.buffer_size) {

						#ifdef __BIG_ENDIAN__
                                        		keysize = uwsgi_swap16(keysize);
                                        	#endif 
							memcpy(cur_buf, &keysize, 2);
							cur_buf+=2;
						#ifdef __BIG_ENDIAN__
                                        		keysize = uwsgi_swap16(keysize);
                                        	#endif 
							memcpy(cur_buf, PyString_AsString(key), keysize);
							cur_buf += keysize;
						#ifdef __BIG_ENDIAN__
                                        		valsize = uwsgi_swap16(valsize);
                                        	#endif 
							memcpy(cur_buf, &valsize, 2);
							cur_buf+=2;
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

	i = spool_request(spool_filename, uwsgi.workers[0].requests+1, spool_buffer, cur_buf - spool_buffer) ;
	if (i > 0) {
		return Py_True;
	}

	Py_DECREF(spool_vars);
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_send_multi_message(PyObject *self, PyObject *args) {


	int i ;
	int clen ;
	int pret;
	int managed ;
	struct pollfd *multipoll ;
	char *buffer ;
	struct uwsgi_header uh;
	PyObject *arg_cluster ;

        PyObject *arg_host, *arg_port, *arg_message;

	PyObject *arg_modifier1, *arg_modifier2, *arg_timeout;

        PyObject *marshalled ;
        PyObject *retobject ;


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
	multipoll = malloc(clen*sizeof(struct pollfd));
	if (!multipoll) {
		perror("malloc");
		Py_INCREF(Py_None);
                return Py_None;
	}

	
	buffer = malloc(uwsgi.buffer_size*clen);
	if (!buffer) {
		perror("malloc");
		free(multipoll);
		Py_INCREF(Py_None);
                return Py_None;
	}

	
	for(i=0;i<clen;i++) {
		multipoll[i].events = POLLIN ;

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


        	switch(PyInt_AsLong(arg_modifier1)) {
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

	managed = 0 ;
	retobject = PyTuple_New(clen);
	if (!retobject) {
		PyErr_Print();
		goto multiclear;
	}

	while(managed < clen) {
		pret = poll(multipoll, clen, PyInt_AsLong(arg_timeout)*1000);
		if (pret < 0) {
			perror("poll()");
			goto megamulticlear;	
		}	
		else if (pret == 0) {
			fprintf(stderr,"timeout on multiple send !\n");
			goto megamulticlear;	
		}
		else {
			for(i=0;i<clen;i++) {
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

	for(i=0;i<clen;i++) {
		close(multipoll[i].fd);
	}
clear:

	free(multipoll);
	free(buffer);

        Py_INCREF(Py_None);
        return Py_None;

}



PyObject *py_uwsgi_send_message(PyObject *self, PyObject *args) {

	PyObject *arg_host, *arg_port, *arg_modifier1, *arg_modifier2, *arg_message, *arg_timeout;
	PyObject *marshalled ;
	PyObject *retobject ;

	arg_host = PyTuple_GetItem(args, 0);
	if (!PyString_Check(arg_host)) {
                Py_INCREF(Py_None);
                return Py_None;
	}

	arg_port = PyTuple_GetItem(args, 1);
	if (!PyInt_Check(arg_port)) {
                Py_INCREF(Py_None);
                return Py_None;
	}

	arg_modifier1 = PyTuple_GetItem(args, 2);
	if (!PyInt_Check(arg_modifier1)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	arg_modifier2 = PyTuple_GetItem(args, 3);
	if (!PyInt_Check(arg_modifier2)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	arg_message = PyTuple_GetItem(args, 4);
	if (!arg_message) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	arg_timeout = PyTuple_GetItem(args, 5);
	if (!PyInt_Check(arg_timeout)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	

	switch(PyInt_AsLong(arg_modifier1)) {
		case UWSGI_MODIFIER_MESSAGE_MARSHAL:
			marshalled = PyMarshal_WriteObjectToString(arg_message, 1);
			if (!marshalled) {
				PyErr_Print();
				Py_INCREF(Py_None);
        			return Py_None;
			}
			retobject = uwsgi_send_message(PyString_AsString(arg_host), PyInt_AsLong(arg_port), PyInt_AsLong(arg_modifier1), PyInt_AsLong(arg_modifier2), PyString_AsString(marshalled), PyString_Size(marshalled), PyInt_AsLong(arg_timeout));
			Py_DECREF(marshalled);
			if (!retobject) {
				PyErr_Print();
				PyErr_Clear();
			}
			else {
				return retobject ;
			}
			break;
	}


	Py_INCREF(Py_None);
	return Py_None;
	
}

/* uWSGI masterpid */
PyObject *py_uwsgi_masterpid(PyObject *self, PyObject *args) {
	if (uwsgi.master_process) {
		return PyInt_FromLong(uwsgi.workers[0].pid) ;
	}
	return PyInt_FromLong(0);
}

/* uWSGI total_requests */
PyObject *py_uwsgi_total_requests(PyObject *self, PyObject *args) {
	return PyInt_FromLong(uwsgi.workers[0].requests) ;
}

/* uWSGI workers */
PyObject *py_uwsgi_workers(PyObject *self, PyObject *args) {

	PyObject *worker_dict, *zero;
	int i ;

	for(i=0;i<uwsgi.numproc;i++) {
		worker_dict = PyTuple_GetItem(uwsgi.workers_tuple, i) ;
		if (!worker_dict) {
			fprintf(stderr,"NON TROVO IL DICT %d\n", i);
			goto clear;
		}

		PyDict_Clear(worker_dict);

		zero = PyInt_FromLong(uwsgi.workers[i+1].id);
		if (PyDict_SetItemString(worker_dict, "id", zero)) {
                	goto clear;
        	}
		Py_DECREF(zero);

		zero = PyInt_FromLong(uwsgi.workers[i+1].pid);
		if (PyDict_SetItemString(worker_dict, "pid", zero)) {
                	goto clear;
        	}
		Py_DECREF(zero);

		zero = PyInt_FromLong(uwsgi.workers[i+1].requests);
		if (PyDict_SetItemString(worker_dict, "requests", zero)) {
                	goto clear;
        	}
		Py_DECREF(zero);

		zero = PyInt_FromLong(uwsgi.workers[i+1].rss_size);
		if (PyDict_SetItemString(worker_dict, "rss", zero)) {
                	goto clear;
        	}
		Py_DECREF(zero);

		zero = PyInt_FromLong(uwsgi.workers[i+1].vsz_size);
		if (PyDict_SetItemString(worker_dict, "vsz", zero)) {
                	goto clear;
        	}
		Py_DECREF(zero);

		zero = PyFloat_FromDouble(uwsgi.workers[i+1].running_time);
		if (PyDict_SetItemString(worker_dict, "running_time", zero)) {
                	goto clear;
        	}
		Py_DECREF(zero);
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
PyObject *py_uwsgi_reload(PyObject *self, PyObject *args) {
	
	if (kill(uwsgi.workers[0].pid, SIGHUP)) {
		perror("kill()");
		Py_INCREF(Py_None);
        	return Py_None;
	}

	Py_INCREF(Py_True);
       	return Py_True;
}


static PyMethodDef uwsgi_spooler_methods[] = {
  {"send_to_spooler", py_uwsgi_send_spool, METH_VARARGS, ""},
  {NULL, NULL},
};

static PyMethodDef uwsgi_advanced_methods[] = {
  {"send_uwsgi_message", py_uwsgi_send_message, METH_VARARGS, ""},
  {"send_multi_uwsgi_message", py_uwsgi_send_multi_message, METH_VARARGS, ""},
  {"reload", py_uwsgi_reload, METH_VARARGS, ""},
  {"workers", py_uwsgi_workers, METH_VARARGS, ""},
  {"masterpid", py_uwsgi_masterpid, METH_VARARGS, ""},
  {"total_requests", py_uwsgi_total_requests, METH_VARARGS, ""},
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



void init_uwsgi_module_spooler(PyObject *current_uwsgi_module) {
	PyMethodDef *uwsgi_function;
	PyObject *uwsgi_module_dict;

	uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
        if (!uwsgi_module_dict) {
        	fprintf(stderr,"could not get uwsgi module __dict__\n");
                exit(1);
        }

	spool_buffer = malloc(uwsgi.buffer_size);
        if (!spool_buffer) {
                perror("malloc()");
                exit(1);
        }


        for (uwsgi_function = uwsgi_spooler_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
                PyObject *func = PyCFunction_New(uwsgi_function, NULL);
                PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
        	Py_DECREF(func);
        }
}

void init_uwsgi_module_advanced(PyObject *current_uwsgi_module) {
	PyMethodDef *uwsgi_function;
	PyObject *uwsgi_module_dict;

	uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
        if (!uwsgi_module_dict) {
        	fprintf(stderr,"could not get uwsgi module __dict__\n");
                exit(1);
        }

        for (uwsgi_function = uwsgi_advanced_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
                PyObject *func = PyCFunction_New(uwsgi_function, NULL);
                PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
        	Py_DECREF(func);
        }
}

void init_uwsgi_module_sharedarea(PyObject *current_uwsgi_module) {
	PyMethodDef *uwsgi_function;
	PyObject *uwsgi_module_dict;

	uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
        if (!uwsgi_module_dict) {
        	fprintf(stderr,"could not get uwsgi module __dict__\n");
                exit(1);
        }

        for (uwsgi_function = uwsgi_sa_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
                PyObject *func = PyCFunction_New(uwsgi_function, NULL);
                PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
        	Py_DECREF(func);
        }
}

#endif
