#include "uwsgi.h"

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

	pthread_mutex_lock((pthread_mutex_t *) sharedareamutex + sizeof(pthread_mutexattr_t));
	memcpy(&value, sharedarea+pos, 4);
	value++;
	memcpy(sharedarea+pos, &value,4);
	pthread_mutex_unlock((pthread_mutex_t *) sharedareamutex + sizeof(pthread_mutexattr_t));

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

	pthread_mutex_lock((pthread_mutex_t *) sharedareamutex + sizeof(pthread_mutexattr_t));
        value = (long) PyInt_AsLong(arg1);
	memcpy(sharedarea+pos, &value,4);
	pthread_mutex_unlock((pthread_mutex_t *) sharedareamutex + sizeof(pthread_mutexattr_t));

        return PyInt_FromLong(value);
	
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

	pthread_mutex_lock((pthread_mutex_t *) sharedareamutex + sizeof(pthread_mutexattr_t));
	memcpy(&value, sharedarea+pos, 4);
	pthread_mutex_unlock((pthread_mutex_t *) sharedareamutex + sizeof(pthread_mutexattr_t));

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



PyMethodDef uwsgi_methods[] = {
  {"sharedarea_read", py_uwsgi_sharedarea_read, METH_VARARGS, ""},
  {"sharedarea_readbyte", py_uwsgi_sharedarea_readbyte, METH_VARARGS, ""},
  {"sharedarea_writebyte", py_uwsgi_sharedarea_writebyte, METH_VARARGS, ""},
  {"sharedarea_readlong", py_uwsgi_sharedarea_readlong, METH_VARARGS, ""},
  {"sharedarea_writelong", py_uwsgi_sharedarea_writelong, METH_VARARGS, ""},
  {"sharedarea_inclong", py_uwsgi_sharedarea_inclong, METH_VARARGS, ""},
  {NULL, NULL},
};

PyMethodDef null_methods[] = {
  {NULL, NULL},
};

