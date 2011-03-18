#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

int manage_python_response(struct wsgi_request *wsgi_req) {
	// use standard WSGI response parse
	return uwsgi_response_subhandler_wsgi(wsgi_req);
}

PyObject *python_call(PyObject *callable, PyObject *args, int catch) {

	PyObject *pyret;

	pyret =  PyEval_CallObject(callable, args);

	if (PyErr_Occurred()) {
		if (PyErr_ExceptionMatches(PyExc_MemoryError)) {
			uwsgi_log("Memory Error detected !!!\n");
		}
		uwsgi.workers[uwsgi.mywid].exceptions++;
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

	wsgi_req->async_result = python_call(callable, args, 0);

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

#ifdef PYTHREE
	wchar_t pname[6];
	mbstowcs(pname, "uwsgi", 6);
	up.py_argv[0] = pname;
#else
	up.py_argv[0] = "uwsgi";
#endif

	if (up.argv != NULL && !up.argc) {
		up.argc++;
#ifdef PYTHREE
		wchar_t *wcargv = malloc( sizeof( wchar_t ) * (strlen(up.argv)+1));
		if (!wcargv) {
			uwsgi_error("malloc()");
			exit(1);
		}
		memset(wcargv, 0, sizeof( wchar_t ) * (strlen(up.argv)+1));
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
				if (up.argc + 1 > MAX_PYARGV)
					break;
			}
		}

		PySys_SetArgv(up.argc, up.py_argv);


}
