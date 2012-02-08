#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

int manage_python_response(struct wsgi_request *wsgi_req) {
	// use standard WSGI response parse
	return uwsgi_response_subhandler_wsgi(wsgi_req);
}

PyObject *python_call(PyObject *callable, PyObject *args, int catch, struct wsgi_request *wsgi_req) {

	PyObject *pyret;

	//uwsgi_log("ready to call %p %p\n", callable, args);

	pyret =  PyEval_CallObject(callable, args);

	//uwsgi_log("called\n");

	if (PyErr_Occurred()) {
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
	wchar_t *pname = uwsgi_calloc(strlen(argv0)+1);
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

		up.argc = 1;
#ifdef PYTHREE
		wchar_t *wcargv = uwsgi_calloc( sizeof( wchar_t ) * (strlen(up.argv)+1));
#endif

#ifdef __sun__
		// FIX THIS !!!
		ap = strtok(up.argv, " ");
		while ((ap = strtok(NULL, " ")) != NULL) {
#else
		while ((ap = strsep(&up.argv, " \t")) != NULL) {
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
