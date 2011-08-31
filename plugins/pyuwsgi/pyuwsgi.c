#include "../python/uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

extern char **environ;

PyObject *u_run(PyObject *self, PyObject *args) {

        char **argv;
        size_t size = 2;
        int i;

        if (PyTuple_Size(args) < 1) {
		return PyErr_Format(PyExc_ValueError, "you have to specify at least one uWSGI option to run() it");
	}

	PyObject *the_arg = PyTuple_GetItem(args, 0);

	if (PyList_Check(the_arg)) {
        	size = PyList_Size(the_arg) + 2;
	}
	else if (PyTuple_Check(the_arg)) {
        	size = PyTuple_Size(the_arg) + 2;
	}
	else if (PyString_Check(the_arg)) {
		size = 3;
	}

        argv = uwsgi_malloc(sizeof(char *) * size);
        memset(argv, 0, sizeof(char *) * size);

        // will be overwritten
        argv[0] = "uwsgi";

	if (PyList_Check(the_arg)) {
        	for(i=0;i<PyList_Size(the_arg);i++) {
                	argv[i+1] = PyString_AsString( PyList_GetItem(the_arg, i) );
        	}
	}
	else if (PyTuple_Check(the_arg)) {
        	for(i=0;i<PyTuple_Size(the_arg);i++) {
                	argv[i+1] = PyString_AsString( PyTuple_GetItem(the_arg, i) );
        	}
	}
	else if (PyString_Check(the_arg)) {
		argv[1] = PyString_AsString( the_arg );
	}

        uwsgi_init(size-1, argv, environ);

        Py_INCREF(Py_None);
        return Py_None;
}

PyMethodDef methods[] = {
    {"run", u_run, METH_VARARGS, "run the uWSGI server"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initpyuwsgi()
{
    (void) Py_InitModule("pyuwsgi", methods);
}


int pyuwsgi_init() { return 0; }

struct uwsgi_plugin pyuwsgi_plugin = {

        .name = "pyuwsgi",
        .init = pyuwsgi_init,
};

