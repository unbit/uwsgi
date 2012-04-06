#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

int manage_python_response(struct wsgi_request *wsgi_req) {
	// use standard WSGI response parse
	return uwsgi_response_subhandler_wsgi(wsgi_req);
}

char *uwsgi_python_get_exception_type(PyObject *exc) {
	char *class_name = NULL;
#if !defined(PYTHREE) && !defined(UWSGI_PYPY)
	if (PyClass_Check(exc)) {
		class_name = PyString_AsString( ((PyClassObject*)(exc))->cl_name );
	}
	else {
#endif
		class_name = (char *) ((PyTypeObject*)exc)->tp_name;
#if !defined(PYTHREE) && !defined(UWSGI_PYPY)
	}
#endif

	if (class_name) {
		char *dot = strrchr(class_name, '.');
		if (dot) class_name = dot+1;

		PyObject *module_name = PyObject_GetAttrString(exc, "__module__");
		if (module_name) {
			char *mod_name = PyString_AsString(module_name);
			if (mod_name && strcmp(mod_name, "exceptions") ) {
				char *ret = uwsgi_concat3(mod_name, ".", class_name);
				Py_DECREF(module_name);
				return ret;
			}
			Py_DECREF(module_name);
			return uwsgi_str(class_name);
		}
	}

	return NULL;
}

char *uwsgi_python_get_exception_value(PyObject *value) {
	return PyString_AsString( PyObject_Str(value) );
}

char *uwsgi_python_get_exception_repr(PyObject *exc, PyObject *value) {
	char *exc_type = uwsgi_python_get_exception_type(exc);
	char *exc_value = uwsgi_python_get_exception_value(value);

	if (exc_type && exc_value) {
		return uwsgi_concat3(exc_type, ": ", exc_value);
	}

	return NULL;
}

int uwsgi_python_manage_exceptions(void) {
	PyObject *type = NULL;
	PyObject *value = NULL;
	PyObject *traceback = NULL;

	char *exc_type = NULL;
	char *exc_value = NULL;
	char *exc_repr = NULL;

	PyErr_Fetch(&type, &value, &traceback);
	PyErr_NormalizeException(&type, &value, &traceback);

	if (uwsgi.reload_on_exception_type) {
		exc_type = uwsgi_python_get_exception_type(type);
	}

	if (uwsgi.reload_on_exception_value) {
		exc_value = uwsgi_python_get_exception_value(value);
	}

	if (uwsgi.reload_on_exception_repr) {
		exc_repr = uwsgi_python_get_exception_repr(type, value);
	}

	int ret = uwsgi_manage_exception(exc_type, exc_value, exc_repr);

	// free memory allocated for strcmp
	if (exc_type) free(exc_type);
	if (exc_repr) free(exc_repr);

	PyErr_Restore(type, value, traceback);

	return ret;
}

PyObject *python_call(PyObject *callable, PyObject *args, int catch, struct wsgi_request *wsgi_req) {

	//uwsgi_log("ready to call %p %p\n", callable, args);

	PyObject *pyret = PyEval_CallObject(callable, args);

	//uwsgi_log("called\n");

	if (PyErr_Occurred()) {


		int do_exit = uwsgi_python_manage_exceptions();

		if (PyErr_ExceptionMatches(PyExc_MemoryError)) {
			uwsgi_log("Memory Error detected !!!\n");
		}

		// this can be in a spooler or in the master
		if (uwsgi.mywid > 0) {
			uwsgi.workers[uwsgi.mywid].exceptions++;
			if (wsgi_req) {
				uwsgi_apps[wsgi_req->app_id].exceptions++;
			}
		}
		if (!catch) {
			PyErr_Print();
		}

		if (do_exit) {
			exit(UWSGI_EXCEPTION_CODE);
		}
	}

#ifdef UWSGI_DEBUG
	if (pyret) {
		uwsgi_debug("called %p %p %d\n", callable, args, pyret->ob_refcnt);
	}
#endif

	return pyret;
}

int uwsgi_python_call(struct wsgi_request *wsgi_req, PyObject *callable, PyObject *args) {

	wsgi_req->async_result = python_call(callable, args, 0, wsgi_req);

	if (wsgi_req->async_result) {
		while ( manage_python_response(wsgi_req) != UWSGI_OK) {
#ifdef UWSGI_ASYNC
			if (uwsgi.async > 1) {
				return UWSGI_AGAIN;
			}
#endif
		}
	}

	return UWSGI_OK;
}

void init_pyargv() {

	char *ap;

	char *argv0 = "uwsgi";

	if (up.pyrun) {
		argv0 = up.pyrun;
	}

#ifdef PYTHREE
	wchar_t *pname = uwsgi_calloc(sizeof(wchar_t) * (strlen(argv0)+1));
	mbstowcs(pname, argv0, strlen(argv0)+1);
#else
	char *pname = argv0;
#endif

	up.argc = 1;
	if (up.argv) {
		char *tmp_ptr = uwsgi_str(up.argv);
#ifdef __sun__
                // FIX THIS !!!
                ap = strtok(tmp_ptr, " ");
                while ((ap = strtok(NULL, " ")) != NULL) {
#else
                while ((ap = strsep(&tmp_ptr, " \t")) != NULL) {
#endif
			if (*ap != '\0') {
				up.argc++;
			}
		}

		free(tmp_ptr);
	}

#ifdef PYTHREE
	up.py_argv = uwsgi_calloc(sizeof(wchar_t *) * up.argc+1);
#else
	up.py_argv = uwsgi_calloc(sizeof(char *) * up.argc+1);
#endif

	up.py_argv[0] = pname;


	if (up.argv) {

		char *py_argv_copy = uwsgi_str(up.argv);
		up.argc = 1;
#ifdef PYTHREE
		wchar_t *wcargv = uwsgi_calloc( sizeof( wchar_t ) * (strlen(py_argv_copy)+1));
#endif

#ifdef __sun__
		// FIX THIS !!!
		ap = strtok(py_argv_copy, " ");
		while ((ap = strtok(NULL, " ")) != NULL) {
#else
		while ((ap = strsep(&py_argv_copy, " \t")) != NULL) {
#endif
				if (*ap != '\0') {
#ifdef PYTHREE
					mbstowcs( wcargv + strlen(ap), ap, strlen(ap));
					up.py_argv[up.argc] = wcargv + strlen(ap);
#else
					up.py_argv[up.argc] = ap;
#endif
					up.argc++;
				}
		}

	}

	PySys_SetArgv(up.argc, up.py_argv);

	PyObject *sys_dict = get_uwsgi_pydict("sys");
	if (!sys_dict) {
		uwsgi_log("unable to load python sys module !!!\n");
		exit(1);
	}
#ifdef PYTHREE
	PyDict_SetItemString(sys_dict, "executable", PyUnicode_FromString(uwsgi.binary_path));
#else
	PyDict_SetItemString(sys_dict, "executable", PyString_FromString(uwsgi.binary_path));
#endif


}
