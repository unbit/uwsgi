#include "uwsgi.h"

extern char *sharedarea ;
extern void *sharedareamutex ;
extern int sharedareasize ;

#ifdef __APPLE__
#define LOCK_SHAREDAREA OSSpinLockLock((OSSpinLock *) sharedareamutex)
#define UNLOCK_SHAREDAREA OSSpinLockUnlock((OSSpinLock *) sharedareamutex)
#else
#ifdef __OpenBSD__
	__noop()
#else
#define LOCK_SHAREDAREA pthread_mutex_lock((pthread_mutex_t *) sharedareamutex + sizeof(pthread_mutexattr_t))
#define UNLOCK_SHAREDAREA pthread_mutex_unlock((pthread_mutex_t *) sharedareamutex + sizeof(pthread_mutexattr_t))
#endif
#endif

PyObject *py_uwsgi_sharedarea_inclong(PyObject *self, PyObject *args) {
	PyObject *arg0 ;
	int pos = 0 ;
	long value ;

        if (sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	if (pos+4 >= getpagesize()*sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	LOCK_SHAREDAREA;
	memcpy(&value, sharedarea+pos, 4);
	value++;
	memcpy(sharedarea+pos, &value,4);
	UNLOCK_SHAREDAREA;

        return PyInt_FromLong(value);
	
}

PyObject *py_uwsgi_sharedarea_writelong(PyObject *self, PyObject *args) {
	PyObject *arg0,*arg1 ;
	int pos = 0 ;
	long value ;

        if (sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	if (pos+4 >= getpagesize()*sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	arg1 = PyTuple_GetItem(args, 1);
        if (!PyInt_Check(arg1)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	LOCK_SHAREDAREA;
        value = (long) PyInt_AsLong(arg1);
	memcpy(sharedarea+pos, &value,4);
	UNLOCK_SHAREDAREA;

        return PyInt_FromLong(value);
	
}

PyObject *py_uwsgi_sharedarea_write(PyObject *self, PyObject *args) {
	PyObject *arg0,*arg1 ;
	int pos = 0 ;
	char *value ;

        if (sharedareasize <= 0) {
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

	if (pos+strlen(value) >= getpagesize()*sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	LOCK_SHAREDAREA;
	memcpy(sharedarea+pos, value,strlen(value));
	UNLOCK_SHAREDAREA;

        return PyInt_FromLong(strlen(value));
	
}

PyObject *py_uwsgi_sharedarea_writebyte(PyObject *self, PyObject *args) {
	PyObject *arg0,*arg1 ;
	int pos = 0 ;
	char value ;

        if (sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	if (pos >= getpagesize()*sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	arg1 = PyTuple_GetItem(args, 1);
        if (!PyInt_Check(arg1)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        value = (char) PyInt_AsLong(arg1);
	sharedarea[pos] = value;

        return PyInt_FromLong(sharedarea[pos]);
	
}

PyObject *py_uwsgi_sharedarea_readlong(PyObject *self, PyObject *args) {
	PyObject *arg0 ;
	int pos = 0 ;
	long value ;

        if (sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	if (pos+4 >= getpagesize()*sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	LOCK_SHAREDAREA;
	memcpy(&value, sharedarea+pos, 4);
	UNLOCK_SHAREDAREA;

        return PyInt_FromLong(value);
	
}


PyObject *py_uwsgi_sharedarea_readbyte(PyObject *self, PyObject *args) {
	PyObject *arg0 ;
	int pos = 0 ;

        if (sharedareasize <= 0) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        arg0 = PyTuple_GetItem(args, 0);
        if (!PyInt_Check(arg0)) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	pos = PyInt_AsLong(arg0);

	if (pos >= getpagesize()*sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

        return PyInt_FromLong(sharedarea[pos]);
	
}

PyObject *py_uwsgi_sharedarea_read(PyObject *self, PyObject *args) {
        PyObject *arg0, *arg1;

        int len = 1 ;
        int pos = 0 ;

        if (sharedareasize <= 0) {
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

        if (pos+len >= getpagesize()*sharedareasize) {
                Py_INCREF(Py_None);
                return Py_None;
        }

	return PyString_FromStringAndSize(sharedarea+pos, len);
}



static PyMethodDef uwsgi_methods[] = {
  {"sharedarea_read", py_uwsgi_sharedarea_read, METH_VARARGS, ""},
  {"sharedarea_write", py_uwsgi_sharedarea_write, METH_VARARGS, ""},
  {"sharedarea_readbyte", py_uwsgi_sharedarea_readbyte, METH_VARARGS, ""},
  {"sharedarea_writebyte", py_uwsgi_sharedarea_writebyte, METH_VARARGS, ""},
  {"sharedarea_readlong", py_uwsgi_sharedarea_readlong, METH_VARARGS, ""},
  {"sharedarea_writelong", py_uwsgi_sharedarea_writelong, METH_VARARGS, ""},
  {"sharedarea_inclong", py_uwsgi_sharedarea_inclong, METH_VARARGS, ""},
  {NULL, NULL},
};

void init_uwsgi_module_sharedarea(PyObject *current_uwsgi_module) {
	PyMethodDef *uwsgi_function;
	PyObject *uwsgi_module_dict;

	uwsgi_module_dict = PyModule_GetDict(current_uwsgi_module);
        if (!uwsgi_module_dict) {
        	fprintf(stderr,"could not get uwsgi module __dict__\n");
                exit(1);
        }

        for (uwsgi_function = uwsgi_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
                PyObject *func = PyCFunction_New(uwsgi_function, NULL);
                PyDict_SetItemString(uwsgi_module_dict, uwsgi_function->ml_name, func);
        	Py_DECREF(func);
        }
}

PyMethodDef null_methods[] = {
  {NULL, NULL},
};

