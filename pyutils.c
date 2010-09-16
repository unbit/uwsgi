#include "uwsgi.h"


int manage_python_response(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	// use standard WSGI response parse
	return uwsgi_response_subhandler_wsgi(uwsgi, wsgi_req);
}

PyObject *python_call(PyObject *callable, PyObject *args, int catch) {
	
	PyObject *pyret;

	pyret =  PyEval_CallObject(callable, args);
	if (PyErr_Occurred()) {
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



int uwsgi_python_call(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, PyObject *callable, PyObject *args) {
	
	wsgi_req->async_result = python_call(callable, args, 0);

	if (wsgi_req->async_result) {
		while ( manage_python_response(uwsgi, wsgi_req) != UWSGI_OK) {
#ifdef UWSGI_ASYNC
			if (uwsgi->async > 1) {
				return UWSGI_AGAIN;
			}
#endif
		}
	}

	return UWSGI_OK;
}

void init_pyargv(struct uwsgi_server *uwsgi) {
	
    char *ap;

#ifdef PYTHREE
	wchar_t pname[6];
        mbstowcs(pname, "uwsgi", 6);
        uwsgi->py_argv[0] = pname;
#else
        uwsgi->py_argv[0] = "uwsgi";
#endif

        if (uwsgi->pyargv != NULL && !uwsgi->pyargc) {
		uwsgi->pyargc++;
#ifdef PYTHREE
        	wchar_t *wcargv = malloc( sizeof( wchar_t ) * (strlen(uwsgi->pyargv)+1));
        	if (!wcargv) {
                	uwsgi_error("malloc()");
                	exit(1);
        	}
        	memset(wcargv, 0, sizeof( wchar_t ) * (strlen(uwsgi->pyargv)+1));
#endif
                
#ifdef __sun__
                // FIX THIS !!!
                ap = strtok(uwsgi->pyargv, " ");
                while ((ap = strtok(NULL, " ")) != NULL) {
#else
                while ((ap = strsep(&uwsgi->pyargv, " \t")) != NULL) {
#endif
                        if (*ap != '\0') {
#ifdef PYTHREE
                                mbstowcs( wcargv + strlen(ap), ap, strlen(ap));
                                uwsgi->py_argv[uwsgi->pyargc] = wcargv + strlen(ap);
#else
                                uwsgi->py_argv[uwsgi->pyargc] = ap;
#endif
                                uwsgi->pyargc++;
                        }
                        if (uwsgi->pyargc + 1 > MAX_PYARGV)
                                break;
                }
        }

        PySys_SetArgv(uwsgi->pyargc, uwsgi->py_argv);
}
