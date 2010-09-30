#include "uwsgi.h"

/* notes


exit(1) on every malloc error: apps can be dinamically loaded so on memory problem
it is better to let the master process manager respawn the worker.


*/

#ifdef UWSGI_SENDFILE
PyMethodDef uwsgi_sendfile_method[] = {{"uwsgi_sendfile", py_uwsgi_sendfile, METH_VARARGS, ""}};
#endif

#ifdef UWSGI_ASYNC
PyMethodDef uwsgi_eventfd_read_method[] = { {"uwsgi_eventfd_read", py_eventfd_read, METH_VARARGS, ""}};
PyMethodDef uwsgi_eventfd_write_method[] = { {"uwsgi_eventfd_write", py_eventfd_write, METH_VARARGS, ""}};
#endif

void init_uwsgi_py_interpreter(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	
        // Initialize a new environment for the new interpreter

        uwsgi_log("setting new interpreter\n");
        wi->interpreter = Py_NewInterpreter();
        if (!wi->interpreter) {
        	uwsgi_log( "unable to initialize the new python interpreter\n");
                exit(1);
        }
        PyThreadState_Swap(wi->interpreter);
        init_pyargv(uwsgi);

#ifdef UWSGI_EMBEDDED
        // we need to inizialize an embedded module for every interpreter
        init_uwsgi_embedded_module();
#endif
        init_uwsgi_vars();
}


int init_uwsgi_app(int loader, char *arg1, struct uwsgi_server *uwsgi, PyObject *my_callable, int new_interpreter) {

	PyObject *wsgi_module, *wsgi_dict;
	PyObject *zero;

	int id = uwsgi->apps_cnt;

	char *tmpstr;

#ifdef UWSGI_ASYNC
	int i;
#endif

	char *mountpoint;

	struct uwsgi_app *wi;
	struct wsgi_request *wsgi_req = uwsgi->wsgi_req;

	if (wsgi_req->script_name_len == 0) {
		wsgi_req->script_name = "";
		if (!uwsgi->vhost) id = 0;
	}
	else if (wsgi_req->script_name_len == 1) {
		if (wsgi_req->script_name[0] == '/') {
			if (!uwsgi->vhost) id = 0;
		}
	}

	
	if (uwsgi->vhost && wsgi_req->host_len > 0) {
		mountpoint = uwsgi_concat3n(wsgi_req->host, wsgi_req->host_len, "|", 1, wsgi_req->script_name, wsgi_req->script_name_len);
        }
        else {
		mountpoint = uwsgi_strncopy(wsgi_req->script_name, wsgi_req->script_name_len);
	}

	if (uwsgi_get_app_id(uwsgi, mountpoint, strlen(mountpoint)) != -1) {
		uwsgi_log( "mountpoint %.*s already configured. skip.\n", strlen(mountpoint), mountpoint);
		return -1;
	}


	wi = &uwsgi->apps[id];

	memset(wi, 0, sizeof(struct uwsgi_app));
	wi->mountpoint = mountpoint;
	wi->mountpoint_len = strlen(mountpoint);

	// dynamic chdir ?
	if (wsgi_req->chdir_len > 0) {
		wi->chdir = uwsgi_strncopy(wsgi_req->chdir, wsgi_req->chdir_len);
#ifdef UWSGI_DEBUG
		uwsgi_debug("chdir to %s\n", wi->chdir);
#endif
		if (chdir(wi->chdir)) {
			uwsgi_error("chdir()");
		}
	}
	
	// Initialize a new environment for the new interpreter

	if (new_interpreter) {
        	uwsgi_log("setting new interpreter\n");
        	wi->interpreter = Py_NewInterpreter();
        	if (!wi->interpreter) {
                	uwsgi_log( "unable to initialize the new python interpreter\n");
                	exit(1);
        	}
        	PyThreadState_Swap(wi->interpreter);
        	init_pyargv(uwsgi);

#ifdef UWSGI_EMBEDDED
        	// we need to inizialize an embedded module for every interpreter
        	init_uwsgi_embedded_module();
#endif
        	init_uwsgi_vars();
	}


	wi->wsgi_callable = uwsgi->loaders[loader](arg1)

	if (my_callable) {
		wi->wsgi_callable = my_callable;
                Py_INCREF(my_callable);
	}
	else {
		// put dynamic loading handlers here
		
		// MANAGE UWSGI_SCRIPT
		if (wsgi_req->wsgi_script_len > 0) {
			wsgi_req->wsgi_callable = strchr(wsgi_req->wsgi_script, ':');
			if (wsgi_req->wsgi_callable) {
				wsgi_req->wsgi_callable[0] = 0;
				wsgi_req->wsgi_callable++;
				wsgi_req->wsgi_callable_len = wsgi_req->wsgi_script_len - strlen(wsgi_req->wsgi_script) - 1;
				wsgi_req->wsgi_script_len = strlen(wsgi_req->wsgi_script);
			}

			tmpstr = uwsgi_strncopy(wsgi_req->wsgi_script, wsgi_req->wsgi_script_len);
		}
		// MANAGE UWSGI_MODULE
		else if (wsgi_req->wsgi_module_len > 0) {
			tmpstr = uwsgi_strncopy(wsgi_req->wsgi_module, wsgi_req->wsgi_module_len);
		}
		else {
			uwsgi_log("ERROR: invalid dynamic app (please specify at least UWSGI_SCRIPT or UWSGI_MODULE/UWSGI_CALLABLE)\n");
			goto doh;
		}		

		wsgi_module = PyImport_ImportModule(tmpstr);
		free(tmpstr);
		if (!wsgi_module) goto doh;

		wsgi_dict = PyModule_GetDict(wsgi_module);
		if (!wsgi_dict) goto doh;

		if (!wsgi_req->wsgi_callable_len) {
			wsgi_req->wsgi_callable = "application";
			wsgi_req->wsgi_callable_len = 11;
		}

		tmpstr = uwsgi_strncopy(wsgi_req->wsgi_callable, wsgi_req->wsgi_callable_len);
		wi->wsgi_callable = PyDict_GetItemString(wsgi_dict, tmpstr);
		free(tmpstr);
	}

	if (!wi->wsgi_callable) {
		uwsgi_log("unable to find \"%.*s\" callable\n", wsgi_req->wsgi_callable_len, wsgi_req->wsgi_callable);
		goto doh;
	}

#ifdef UWSGI_ASYNC
	wi->wsgi_environ = malloc(sizeof(PyObject*)*uwsgi->async);
	if (!wi->wsgi_environ) {
		uwsgi_error("malloc()");
		exit(1);
	}

	for(i=0;i<uwsgi->async;i++) {
		wi->wsgi_environ[i] = PyDict_New();
		if (!wi->wsgi_environ[i]) {
			uwsgi_log("unable to allocate new env dictionary for app\n");
			exit(1);
		}
	}
#else
	wi->wsgi_environ = PyDict_New();
        if (!wi->wsgi_environ) {
		uwsgi_log("unable to allocate new env dictionary for app\n");
		exit(1);
        }
#endif


	// check function args
	// by defaut it is a WSGI app
	wi->argc = 2;
	zero = PyObject_GetAttrString(wi->wsgi_callable, "__code__");
	if (!zero) {
		zero = PyObject_GetAttrString(wi->wsgi_callable, "__call__");
		if (zero) {
			zero = PyObject_GetAttrString(wi->wsgi_callable, "__code__");
		}
		else {
			uwsgi_log("WARNING: unable to get the number of callable args. Fallback to WSGI\n");
		}
	}

	if (zero) {
		zero = PyObject_GetAttrString(zero, "co_argcount");
		wi->argc = (int) PyInt_AsLong(zero);
	}

	if (wi->argc == 2) {
#ifdef UWSGI_DEBUG
		uwsgi_log("-- WSGI callable detected --\n");
#endif
		wi->request_subhandler = uwsgi_request_subhandler_wsgi;
		wi->response_subhandler = uwsgi_response_subhandler_wsgi;
	}
#ifdef UWSGI_WEB3
	else if (wi->argc == 1) {
#ifdef UWSGI_DEBUG
		uwsgi_log("-- Web3 callable detected --\n");
#endif
		wi->request_subhandler = uwsgi_request_subhandler_web3;
		wi->response_subhandler = uwsgi_response_subhandler_web3;
	}
#endif
	else {
		uwsgi_log("-- INVALID callable detected --\n");
		goto doh;
	}

#ifdef UWSGI_ASYNC
        wi->wsgi_args = malloc(sizeof(PyObject*)*uwsgi->async);
        if (!wi->wsgi_args) {
                uwsgi_error("malloc()");
		exit(1);
        }

        for(i=0;i<uwsgi->async;i++) {
                wi->wsgi_args[i] = PyTuple_New(wi->argc);
                if (!wi->wsgi_args[i]) {
			uwsgi_log("unable to allocate new tuple for app args\n");
			exit(1);
                }

		// add start_response on WSGI app
		if (wi->argc == 2) {
			if (PyTuple_SetItem(wi->wsgi_args[i], 1, uwsgi->wsgi_spitout)) {
				uwsgi_log("unable to set start_response in args tuple\n");
				exit(1);
			}
		}
        }
#else

		wi->wsgi_args = PyTuple_New(wi->argc);
		if (wi->argc == 2) {
			if (PyTuple_SetItem(wi->wsgi_args, 1, uwsgi->wsgi_spitout)) {
				uwsgi_log("unable to set start_response in args tuple\n");
				exit(1);
			}
		}
#endif

	if (wi->argc == 2) {
#ifdef UWSGI_SENDFILE
		// prepare sendfile() for WSGI app
		wi->wsgi_sendfile = PyCFunction_New(uwsgi_sendfile_method, NULL);
#endif

#ifdef UWSGI_ASYNC
		wi->wsgi_eventfd_read = PyCFunction_New(uwsgi_eventfd_read_method, NULL);
		wi->wsgi_eventfd_write = PyCFunction_New(uwsgi_eventfd_write_method, NULL);
#endif
	}

	if (new_interpreter) {
		PyThreadState_Swap(uwsgi->main_thread);
	}

	if (wi->argc == 1) {
		uwsgi_log( "Web3 application %d (SCRIPT_NAME=%.*s) ready", id, wi->mountpoint_len, wi->mountpoint);
	}
	else {
		uwsgi_log( "WSGI application %d (SCRIPT_NAME=%.*s) ready", id, wi->mountpoint_len, wi->mountpoint);
	}

	if (id == 0) {
		uwsgi_log(" (default app)");
		uwsgi->default_app = 0;
		if (uwsgi->vhost) uwsgi->apps_cnt++;
	}
	else {
		uwsgi->apps_cnt++;
	}

	uwsgi_log("\n");

	return id;

doh:
	PyErr_Print();
	if (new_interpreter) {
		Py_EndInterpreter(wi->interpreter);
		PyThreadState_Swap(uwsgi->main_thread);
	}
	return -1;
}


/* trying to emulate Graham's mod_wsgi, this will allows easy and fast migrations */
PyObject *uwsgi_file_loader(char *filename) {

        FILE *wsgifile;
        struct _node *wsgi_file_node = NULL;
        PyObject *wsgi_compiled_node, *wsgi_file_module, *wsgi_file_dict;
        PyObject *wsgi_file_callable;
        int ret;

        wsgifile = fopen(filename, "r");
        if (!wsgifile) {
                uwsgi_error("fopen()");
                exit(1);
        }

        wsgi_file_node = PyParser_SimpleParseFile(wsgifile, filename, Py_file_input);
        if (!wsgi_file_node) {
                PyErr_Print();
                uwsgi_log( "failed to parse file %s\n", filename);
                exit(1);
        }

        fclose(wsgifile);

        wsgi_compiled_node = (PyObject *) PyNode_Compile(wsgi_file_node, filename);

        if (!wsgi_compiled_node) {
                PyErr_Print();
                uwsgi_log( "failed to compile wsgi file %s\n", filename);
                exit(1);
        }

        wsgi_file_module = PyImport_ExecCodeModule("uwsgi_wsgi_file", wsgi_compiled_node);
        if (!wsgi_file_module) {
                PyErr_Print();
                exit(1);
        }

        Py_DECREF(wsgi_compiled_node);

        wsgi_file_dict = PyModule_GetDict(wsgi_file_module);
        if (!wsgi_file_dict) {
                PyErr_Print();
                exit(1);
        }


        wsgi_file_callable = PyDict_GetItemString(wsgi_file_dict, "application");
        if (!wsgi_file_callable) {
                PyErr_Print();
                uwsgi_log( "unable to find \"application\" callable in file %s\n", filename);
                exit(1);
        }

        if (!PyFunction_Check(wsgi_file_callable) && !PyCallable_Check(wsgi_file_callable)) {
                uwsgi_log( "\"application\" must be a callable object in file %s\n", filename);
                exit(1);
        }


	return wsgi_file_callable;

}

