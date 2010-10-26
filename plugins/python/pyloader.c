#include "uwsgi_python.h"

/* notes

   exit(1) on every malloc error: apps can be dinamically loaded so on memory problem
   it is better to let the master process manager respawn the worker.
   */

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

#ifdef UWSGI_SENDFILE
PyMethodDef uwsgi_sendfile_method[] = {{"uwsgi_sendfile", py_uwsgi_sendfile, METH_VARARGS, ""}};
#endif

#ifdef UWSGI_ASYNC
PyMethodDef uwsgi_eventfd_read_method[] = { {"uwsgi_eventfd_read", py_eventfd_read, METH_VARARGS, ""}};
PyMethodDef uwsgi_eventfd_write_method[] = { {"uwsgi_eventfd_write", py_eventfd_write, METH_VARARGS, ""}};
#endif

int init_uwsgi_app(int loader, void *arg1, struct wsgi_request *wsgi_req, int new_interpreter) {

	PyObject *zero;

	int id = uwsgi.apps_cnt;

#ifdef UWSGI_ASYNC
	int i;
#endif

	char *mountpoint;

	struct uwsgi_app *wi;


	if (wsgi_req->script_name_len == 0) {
		wsgi_req->script_name = "";
		if (!uwsgi.vhost) id = 0;
	}
	else if (wsgi_req->script_name_len == 1) {
		if (wsgi_req->script_name[0] == '/') {
			if (!uwsgi.vhost) id = 0;
		}
	}


	if (uwsgi.vhost && wsgi_req->host_len > 0) {
		mountpoint = uwsgi_concat3n(wsgi_req->host, wsgi_req->host_len, "|", 1, wsgi_req->script_name, wsgi_req->script_name_len);
	}
	else {
		mountpoint = uwsgi_strncopy(wsgi_req->script_name, wsgi_req->script_name_len);
	}

	if (uwsgi_get_app_id(mountpoint, strlen(mountpoint)) != -1) {
		uwsgi_log( "mountpoint %.*s already configured. skip.\n", strlen(mountpoint), mountpoint);
		free(mountpoint);
		return -1;
	}


	wi = &uwsgi.apps[id];

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

	if (new_interpreter && id) {
		wi->interpreter = Py_NewInterpreter();
		if (!wi->interpreter) {
			uwsgi_log( "unable to initialize the new python interpreter\n");
			exit(1);
		}
		PyThreadState_Swap(wi->interpreter);
		init_pyargv();

#ifdef UWSGI_EMBEDDED
		// we need to inizialize an embedded module for every interpreter
		init_uwsgi_embedded_module();
#endif
		init_uwsgi_vars();

	}
	else {
		wi->interpreter = up.main_thread;
	}


	wi->callable = up.loaders[loader](arg1);

	if (!wi->callable) {
		uwsgi_log("unable to load app SCRIPT_NAME=%s\n", mountpoint);
		goto doh;
	}

#ifdef UWSGI_ASYNC
	wi->environ = malloc(sizeof(PyObject*)*uwsgi.cores);
	if (!wi->environ) {
		uwsgi_error("malloc()");
		exit(1);
	}

	for(i=0;i<uwsgi.cores;i++) {
		wi->environ[i] = PyDict_New();
		if (!wi->environ[i]) {
			uwsgi_log("unable to allocate new env dictionary for app\n");
			exit(1);
		}
	}
#else
	wi->environ = PyDict_New();
	if (!wi->environ) {
		uwsgi_log("unable to allocate new env dictionary for app\n");
		exit(1);
	}
#endif


	// check function args
	// by defaut it is a WSGI app
	wi->argc = 2;
	zero = PyObject_GetAttrString(wi->callable, "__code__");
	if (!zero) {
		zero = PyObject_GetAttrString(wi->callable, "__call__");
		if (zero) {
			zero = PyObject_GetAttrString(wi->callable, "__code__");
		}
		else {
			uwsgi_log("WARNING: unable to get the number of callable args. Fallback to WSGI\n");
		}
	}

	// avoid __code__ attr error propagation
	PyErr_Clear();

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
	wi->args = malloc(sizeof(PyObject*)*uwsgi.cores);
	if (!wi->args) {
		uwsgi_error("malloc()");
		exit(1);
	}

	for(i=0;i<uwsgi.cores;i++) {
		wi->args[i] = PyTuple_New(wi->argc);
		if (!wi->args[i]) {
			uwsgi_log("unable to allocate new tuple for app args\n");
			exit(1);
		}

		// add start_response on WSGI app
		if (wi->argc == 2) {
			if (PyTuple_SetItem(wi->args[i], 1, up.wsgi_spitout)) {
				uwsgi_log("unable to set start_response in args tuple\n");
				exit(1);
			}
		}
	}
#else

	wi->wsgi_args = PyTuple_New(wi->argc);
	if (wi->argc == 2) {
		if (PyTuple_SetItem(wi->wsgi_args, 1, up.wsgi_spitout)) {
			uwsgi_log("unable to set start_response in args tuple\n");
			exit(1);
		}
	}
#endif

	if (wi->argc == 2) {
#ifdef UWSGI_SENDFILE
		// prepare sendfile() for WSGI app
		wi->sendfile = PyCFunction_New(uwsgi_sendfile_method, NULL);
#endif

#ifdef UWSGI_ASYNC
		wi->eventfd_read = PyCFunction_New(uwsgi_eventfd_read_method, NULL);
		wi->eventfd_write = PyCFunction_New(uwsgi_eventfd_write_method, NULL);
#endif
	}

	if (new_interpreter && id) {
		// if we have multiple threads we need to initialize a PyThreadState for each one
		if (uwsgi.threads > 1) {
			for(i=0;i<uwsgi.threads;i++) {
				uwsgi.workers[uwsgi.mywid].cores[i]->ts[id] = PyThreadState_New( ((PyThreadState *)wi->interpreter)->interp);
				if (!uwsgi.workers[uwsgi.mywid].cores[i]->ts[id]) {
					uwsgi_log("unable to allocate new PyThreadState structure for app %s", mountpoint);
					goto doh;
				}
			}
			PyThreadState_Swap((PyThreadState *) pthread_getspecific(up.upt_save_key));
		}
		else {
			PyThreadState_Swap(up.main_thread);
		}
	}

	if (wi->argc == 1) {
		uwsgi_log( "Web3 application %d (SCRIPT_NAME=%.*s) ready on interpreter %p", id, wi->mountpoint_len, wi->mountpoint, wi->interpreter);
	}
	else {
		uwsgi_log( "WSGI application %d (SCRIPT_NAME=%.*s) ready on interpreter %p", id, wi->mountpoint_len, wi->mountpoint, wi->interpreter);
	}

	if (id == 0) {
		uwsgi_log(" (default app)");
		uwsgi.default_app = 0;
		if (uwsgi.vhost) uwsgi.apps_cnt++;
	}
	else {
		uwsgi.apps_cnt++;
	}

	uwsgi_log("\n");

	return id;

doh:
	free(mountpoint);
	PyErr_Print();
	if (new_interpreter && id) {
		Py_EndInterpreter(wi->interpreter);
		if (uwsgi.threads > 1) {
			PyThreadState_Swap((PyThreadState *) pthread_getspecific(up.upt_save_key));
		}
		else {
			PyThreadState_Swap(up.main_thread);
		}
	}
	return -1;
}

char *get_uwsgi_pymodule(char *module) {

	char *quick_callable;

	if ( (quick_callable = strchr(module, ':')) ) {
		quick_callable[0] = 0;
		quick_callable++;
		return quick_callable;
	}

	return NULL;
}

PyObject *get_uwsgi_pydict(char *module) {

	PyObject *wsgi_module, *wsgi_dict;

	wsgi_module = PyImport_ImportModule(module);
	if (!wsgi_module) {
		PyErr_Print();
		return NULL;
	}

	wsgi_dict = PyModule_GetDict(wsgi_module);
	if (!wsgi_dict) {
		PyErr_Print();
		return NULL;
	}

	return wsgi_dict;

}

PyObject *uwsgi_uwsgi_loader(void *arg1) {

	PyObject *wsgi_dict;

	char *quick_callable;

	PyObject *tmp_callable;

	char *module = (char *) arg1;

	quick_callable = get_uwsgi_pymodule(module);
	if (quick_callable == NULL) {
		if (up.callable) {
			quick_callable = up.callable;
		}
		else {
			quick_callable = "application";
		}
	}

	wsgi_dict = get_uwsgi_pydict(module);
	if (!wsgi_dict) {
		return NULL;
	}

	// quick callable -> thanks gunicorn for the idea
	// we have extended the concept a bit...
	if (quick_callable[strlen(quick_callable) -2 ] == '(' && quick_callable[strlen(quick_callable) -1] ==')') {
		quick_callable[strlen(quick_callable) -2 ] = 0;
		tmp_callable = PyDict_GetItemString(wsgi_dict, quick_callable);
		if (tmp_callable) {
			return python_call(tmp_callable, PyTuple_New(0), 0);
		}
	}

	return PyDict_GetItemString(wsgi_dict, quick_callable);

}

/* this is the mount loader, it loads app on mountpoint automagically */
PyObject *uwsgi_mount_loader(void *arg1) {

	PyObject *callable = NULL;
	char *what = (char *) arg1;

	if ( !strcmp(what+strlen(what)-3, ".py") || !strcmp(what+strlen(what)-3, ".wsgi")) {
		callable = uwsgi_file_loader((void *)what);
	}
#ifdef UWSGI_PASTE
	else if (!strcmp(what+strlen(what)-4, ".ini")) {
		callable = uwsgi_paste_loader((void *)what);
	}
#endif
	else {
		callable = uwsgi_uwsgi_loader((void *)what);
	}

	return callable;
}


/* this is the dynamic loader, it loads app ireading nformation from a wsgi_request */
PyObject *uwsgi_dyn_loader(void *arg1) {

	PyObject *callable = NULL;
	char *tmpstr;

	struct wsgi_request *wsgi_req = (struct wsgi_request *) arg1;

	// MANAGE UWSGI_SCRIPT
	if (wsgi_req->script_len > 0) {
		tmpstr = uwsgi_strncopy(wsgi_req->script, wsgi_req->script_len);
		callable = uwsgi_uwsgi_loader((void *)tmpstr);
		free(tmpstr);
	}
	// MANAGE UWSGI_MODULE
	else if (wsgi_req->module_len > 0) {
		if (wsgi_req->callable_len > 0) {
			tmpstr = uwsgi_concat3n(wsgi_req->module, wsgi_req->module_len, ":", 1, wsgi_req->callable, wsgi_req->callable_len);
		}
		else {
			tmpstr = uwsgi_strncopy(wsgi_req->module, wsgi_req->module_len);
		}
		callable = uwsgi_uwsgi_loader((void *)tmpstr);
		free(tmpstr);
	}
	// MANAGE UWSGI_FILE
	else if (wsgi_req->file_len > 0) {
		tmpstr = uwsgi_strncopy(wsgi_req->file, wsgi_req->file_len);
		callable = uwsgi_file_loader((void *)tmpstr);
		free(tmpstr);
	}
#ifdef UWSGI_PASTE
	// MANAGE UWSGI_PASTE
	else if (wsgi_req->wsgi_paste_len > 0) {
		tmpstr = uwsgi_strncopy(wsgi_req->paste, wsgi_req->paste_len);
		callable = uwsgi_paste_loader((void *)tmpstr);
		free(tmpstr);
	}
#endif

	return callable;
}


/* trying to emulate Graham's mod_wsgi, this will allows easy and fast migrations */
PyObject *uwsgi_file_loader(void *arg1) {

	char *filename = (char *) arg1;
	FILE *wsgifile;
	struct _node *wsgi_file_node = NULL;
	PyObject *wsgi_compiled_node, *wsgi_file_module, *wsgi_file_dict;
	PyObject *wsgi_file_callable;

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

#ifdef UWSGI_PASTE
PyObject *uwsgi_paste_loader(void *arg1) {

	char *paste = (char *) arg1;
	PyObject *paste_module, *paste_dict, *paste_loadapp;
	PyObject *paste_arg, *paste_app;

	uwsgi_log( "Loading paste environment: %s\n", paste);
	paste_module = PyImport_ImportModule("paste.deploy");
	if (!paste_module) {
		PyErr_Print();
		exit(1);
	}

	paste_dict = PyModule_GetDict(paste_module);
	if (!paste_dict) {
		PyErr_Print();
		exit(1);
	}

	paste_loadapp = PyDict_GetItemString(paste_dict, "loadapp");
	if (!paste_loadapp) {
		PyErr_Print();
		exit(1);
	}

	paste_arg = PyTuple_New(1);
	if (!paste_arg) {
		PyErr_Print();
		exit(1);
	}

	if (PyTuple_SetItem(paste_arg, 0, PyString_FromString(paste))) {
		PyErr_Print();
		exit(1);
	}

	paste_app = PyEval_CallObject(paste_loadapp, paste_arg);
	if (!paste_app) {
		PyErr_Print();
		exit(1);
	}


	return paste_app;
}

#endif

PyObject *uwsgi_eval_loader(void *arg1) {

	char *code = (char *) arg1;

	PyObject *wsgi_eval_module, *wsgi_eval_callable = NULL;

	struct _node *wsgi_eval_node = NULL;
	PyObject *wsgi_compiled_node;

	wsgi_eval_node = PyParser_SimpleParseString(code, Py_file_input);
	if (!wsgi_eval_node) {
		PyErr_Print();
		uwsgi_log( "failed to parse <eval> code\n");
		exit(1);
	}

	wsgi_compiled_node = (PyObject *) PyNode_Compile(wsgi_eval_node, "uwsgi_eval_config");

	if (!wsgi_compiled_node) {
		PyErr_Print();
		uwsgi_log( "failed to compile eval code\n");
		exit(1);
	}


	wsgi_eval_module = PyImport_ExecCodeModule("uwsgi_eval_config", wsgi_compiled_node);
	if (!wsgi_eval_module) {
		PyErr_Print();
		exit(1);
	}


	Py_DECREF(wsgi_compiled_node);

	up.loader_dict = PyModule_GetDict(wsgi_eval_module);
	if (!up.loader_dict) {
		PyErr_Print();
		exit(1);
	}


	if (up.callable) {
		wsgi_eval_callable = PyDict_GetItemString(up.loader_dict, up.callable);
	}
	else {
		wsgi_eval_callable = PyDict_GetItemString(up.loader_dict, "application");
	}

	if (wsgi_eval_callable) {
		uwsgi_log( "found the \"%s\" callable\n", up.callable);
		if (!PyFunction_Check(wsgi_eval_callable) && !PyCallable_Check(wsgi_eval_callable)) {
			uwsgi_log( "you must define a callable object in your code\n");
			exit(1);
		}
	}

	return wsgi_eval_callable;

}

PyObject *uwsgi_callable_loader(void *arg1) {
	return (PyObject *) arg1;
}

PyObject *uwsgi_string_callable_loader(void *arg1) {
	char *callable = (char *) arg1;

	return PyDict_GetItem(up.loader_dict, UWSGI_PYFROMSTRING(callable));
}
