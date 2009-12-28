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

	if (pos+4 >= getpagesize()*uwsgi.sharedareasize) {
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

	if (pos+4 >= getpagesize()*uwsgi.sharedareasize) {
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

	if (pos+strlen(value) >= getpagesize()*uwsgi.sharedareasize) {
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

	if (pos >= getpagesize()*uwsgi.sharedareasize) {
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

	if (pos+4 >= getpagesize()*uwsgi.sharedareasize) {
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

	if (pos >= getpagesize()*uwsgi.sharedareasize) {
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

        if (pos+len >= getpagesize()*uwsgi.sharedareasize) {
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

	i = spool_request(spool_filename, uwsgi.requests+1, spool_buffer, cur_buf - spool_buffer) ;
	if (i > 0) {
		return Py_True;
	}

	Py_DECREF(spool_vars);
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_uwsgi_send_message(PyObject *self, PyObject *args) {

	PyObject *arg_host, *arg_port, *arg_modifier1, *arg_modifier2, *arg_message, *arg_timeout;

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

	fprintf(stderr,"sending message to %s:%lu\n", PyString_AsString(arg_host), PyInt_AsLong(arg_port));


	Py_INCREF(Py_None);
	return Py_None;
	
}


static PyMethodDef uwsgi_spooler_methods[] = {
  {"send_to_spooler", py_uwsgi_send_spool, METH_VARARGS, ""},
  {NULL, NULL},
};

static PyMethodDef uwsgi_advanced_methods[] = {
  {"send_uwsgi_message", py_uwsgi_send_message, METH_VARARGS, ""},
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
