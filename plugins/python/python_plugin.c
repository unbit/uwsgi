#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
struct uwsgi_python up;

struct option uwsgi_python_options[] = {
	{"wsgi-file", required_argument, 0, LONG_ARGS_WSGI_FILE},
	{"file", required_argument, 0, LONG_ARGS_FILE_CONFIG},
	{"eval", required_argument, 0, LONG_ARGS_EVAL_CONFIG},
	{"module", required_argument, 0, 'w'},
	{"callable", required_argument, 0, LONG_ARGS_CALLABLE},
	{"test", required_argument, 0, 'j'},
	{"home", required_argument, 0, 'H'},
	{"pythonpath", required_argument, 0, LONG_ARGS_PYTHONPATH},
	{"python-path", required_argument, 0, LONG_ARGS_PYTHONPATH},
	{"pp", required_argument, 0, LONG_ARGS_PYTHONPATH},
	{"pyargv", required_argument, 0, LONG_ARGS_PYARGV},
	{"optimize", required_argument, 0, 'O'},
#ifdef UWSGI_PASTE
	{"paste", required_argument, 0, LONG_ARGS_PASTE},
#ifdef UWSGI_INI
	{"ini-paste", required_argument, 0, LONG_ARGS_INI_PASTE},
#endif
#endif
	{"catch-exceptions", no_argument, &up.catch_exceptions, 1},
	{"ignore-script-name", no_argument, &up.ignore_script_name, 1},
	{"no-site", no_argument, &Py_NoSiteFlag, 1},

	{0, 0, 0, 0},
};

/* this routine will be called after each fork to reinitialize the various locks */
void uwsgi_python_pthread_prepare(void) {
	pthread_mutex_lock(&up.lock_pyloaders);
}

void uwsgi_python_pthread_parent(void) {
	pthread_mutex_unlock(&up.lock_pyloaders);
}

void uwsgi_python_pthread_child(void) {
	pthread_mutex_init(&up.lock_pyloaders, NULL);
}

// fake method
PyMethodDef null_methods[] = {
	{ NULL, NULL},
};

PyMethodDef uwsgi_spit_method[] = { {"uwsgi_spit", py_uwsgi_spit, METH_VARARGS, ""} };
PyMethodDef uwsgi_write_method[] = { {"uwsgi_write", py_uwsgi_write, METH_VARARGS, ""} };

int uwsgi_python_init() {

	uwsgi_log("Python version: %s\n", Py_GetVersion());

	if (up.home != NULL) {
		uwsgi_log("Setting PythonHome to %s...\n", up.home);
#ifdef PYTHREE
		wchar_t *wpyhome;
		wpyhome = malloc((sizeof(wchar_t) * strlen(up.home)) + 2);
		if (!wpyhome) {
			uwsgi_error("malloc()");
			exit(1);
		}
		mbstowcs(wpyhome, up.home, strlen(up.home));
		Py_SetPythonHome(wpyhome);
		free(wpyhome);
#else
		Py_SetPythonHome(up.home);
#endif
	}

#ifdef PYTHREE
	wchar_t pname[6];
	mbstowcs(pname, "uWSGI", 6);
	Py_SetProgramName(pname);
#else

	Py_SetProgramName("uWSGI");
#endif


	Py_Initialize();

	Py_OptimizeFlag = up.optimize;

	up.wsgi_spitout = PyCFunction_New(uwsgi_spit_method, NULL);
	up.wsgi_writeout = PyCFunction_New(uwsgi_write_method, NULL);

	up.main_thread = PyThreadState_Get();


#ifdef UWSGI_MINTERPRETERS
	init_uwsgi_embedded_module();
#endif

	if (up.test_module != NULL) {
		if (PyImport_ImportModule(up.test_module)) {
			exit(0);
		}
		exit(1);
	}

	init_uwsgi_vars();

	// setup app loaders
#ifdef UWSGI_MINTERPRETERS
	up.loaders[LOADER_DYN] = uwsgi_dyn_loader;
#endif
	up.loaders[LOADER_UWSGI] = uwsgi_uwsgi_loader;
	up.loaders[LOADER_FILE] = uwsgi_file_loader;
#ifdef UWSGI_PASTE
	up.loaders[LOADER_PASTE] = uwsgi_paste_loader;
#endif
	up.loaders[LOADER_EVAL] = uwsgi_eval_loader;
	up.loaders[LOADER_MOUNT] = uwsgi_mount_loader;
	up.loaders[LOADER_CALLABLE] = uwsgi_callable_loader;
	up.loaders[LOADER_STRING_CALLABLE] = uwsgi_string_callable_loader;

	// by default set a fake GIL (little impact on performance)
	up.gil_get = gil_fake_get;
	up.gil_release = gil_fake_release;

	return 1;

}

void uwsgi_python_post_fork() {

	PyObject *random_module, *random_dict, *random_seed;

	// reinitialize the random seed (thanks Jonas Borgström)
	random_module = PyImport_ImportModule("random");
	if (random_module) {
		random_dict = PyModule_GetDict(random_module);
		if (random_dict) {
			random_seed = PyDict_GetItemString(random_dict, "seed");
			if (random_seed) {
				PyObject *random_args = PyTuple_New(1);
				// pass no args
				PyTuple_SetItem(random_args, 0, Py_None);
				PyEval_CallObject( random_seed, random_args );
				if (PyErr_Occurred()) {
					PyErr_Print();
				}
			}
		}
	}

#ifdef UWSGI_EMBEDDED
	// call the post_fork_hook
	PyObject *uwsgi_dict = get_uwsgi_pydict("uwsgi");
	if (uwsgi_dict) {
		PyObject *pfh = PyDict_GetItemString(uwsgi_dict, "post_fork_hook");
		if (pfh) {
			python_call(pfh, PyTuple_New(0), 0);
		}
	}
	PyErr_Clear();
#endif

	UWSGI_RELEASE_GIL

}

void init_uwsgi_vars() {

	int i;
	PyObject *pysys, *pysys_dict, *pypath;

#ifdef UWSGI_MINTERPRETERS
	char venv_version[15];
	PyObject *site_module;
#endif

	/* add cwd to pythonpath */
	pysys = PyImport_ImportModule("sys");
	if (!pysys) {
		PyErr_Print();
		exit(1);
	}
	pysys_dict = PyModule_GetDict(pysys);
	pypath = PyDict_GetItemString(pysys_dict, "path");
	if (!pypath) {
		PyErr_Print();
		exit(1);
	}

#ifdef UWSGI_MINTERPRETERS
	// simulate a pythonhome directive
	if (uwsgi.wsgi_req->pyhome_len > 0) {

		PyObject *venv_path = UWSGI_PYFROMSTRINGSIZE(uwsgi.wsgi_req->pyhome, uwsgi.wsgi_req->pyhome_len);

#ifdef UWSGI_DEBUG
		uwsgi_debug("setting dynamic virtualenv to %.*s\n", uwsgi.wsgi_req->pyhome_len, uwsgi.wsgi_req->pyhome);
#endif

		PyDict_SetItemString(pysys_dict, "prefix", venv_path);
		PyDict_SetItemString(pysys_dict, "exec_prefix", venv_path);

		venv_version[14] = 0;
		if (snprintf(venv_version, 15, "/lib/python%d.%d", PY_MAJOR_VERSION, PY_MINOR_VERSION) == -1) {
			return;
		}

		// check here
		PyString_Concat( &venv_path, PyString_FromString(venv_version) );

		if ( PyList_Insert(pypath, 0, venv_path) ) {
			PyErr_Print();
		}

		site_module = PyImport_ImportModule("site");
		if (site_module) {
			PyImport_ReloadModule(site_module);
		}

	}
#endif

	if (PyList_Insert(pypath, 0, UWSGI_PYFROMSTRING(".") ) != 0) {
		PyErr_Print();
	}

	for (i = 0; i < up.python_path_cnt; i++) {
		if (PyList_Insert(pypath, 0, UWSGI_PYFROMSTRING(up.python_path[i]) ) != 0) {
			PyErr_Print();
		}
		else {
			uwsgi_log( "added %s to pythonpath.\n", up.python_path[i]);
		}
	}

}


void uwsgi_uwsgi_config(char *module) {

#ifdef UWSGI_EMBEDDED
	PyObject *uwsgi_module, *uwsgi_dict;
#endif
	PyObject *applications;
	PyObject *app_list;
	Py_ssize_t i;
	PyObject *app_mnt, *app_app = NULL;
	char *quick_callable;

	quick_callable = get_uwsgi_pymodule(module);
	if (quick_callable == NULL) {
		if (up.callable) {
			quick_callable = up.callable;
		}
		else {
			quick_callable = "application";
		}
	}

	up.loader_dict = get_uwsgi_pydict(module);
	if (!up.loader_dict) {
		exit(1);
	}

	uwsgi_log( "...getting the applications list from the '%s' module...\n", module);

#ifdef UWSGI_EMBEDDED
	uwsgi_module = PyImport_ImportModule("uwsgi");
	if (!uwsgi_module) {
		PyErr_Print();
		exit(1);
	}

	uwsgi_dict = PyModule_GetDict(uwsgi_module);
	if (!uwsgi_dict) {
		PyErr_Print();
		exit(1);
	}

	applications = PyDict_GetItemString(uwsgi_dict, "applications");
	if (!PyDict_Check(applications)) {
		uwsgi_log( "uwsgi.applications dictionary is not defined, trying with the \"applications\" one...\n");
#endif
		applications = PyDict_GetItemString(up.loader_dict, "applications");
		if (!applications) {
			uwsgi_log( "applications dictionary is not defined, trying with the \"application\" callable.\n");
			quick_callable = uwsgi_concat3(module, ":", quick_callable);
			if (init_uwsgi_app(LOADER_UWSGI, (void *) quick_callable, uwsgi.wsgi_req, 0)  < 0) {
				uwsgi_log( "...goodbye cruel world...\n");
				exit(1);
			}
			free(quick_callable);
			return;
		}
#ifdef UWSGI_EMBEDDED
	}
#endif

	if (!PyDict_Check(applications)) {
		uwsgi_log( "The 'applications' object must be a dictionary.\n");
		exit(1);
	}

	app_list = PyDict_Keys(applications);
	if (!app_list) {
		PyErr_Print();
		exit(1);
	}
	if (PyList_Size(app_list) < 1) {
		uwsgi_log( "You must define an app.\n");
		exit(1);
	}

	for (i = 0; i < PyList_Size(app_list); i++) {
		app_mnt = PyList_GetItem(app_list, i);

		if (!PyString_Check(app_mnt)) {
			uwsgi_log( "the app mountpoint must be a bytestring.\n");
			exit(1);
		}


		uwsgi.wsgi_req->script_name = PyString_AsString(app_mnt);
		uwsgi.wsgi_req->script_name_len = strlen(uwsgi.wsgi_req->script_name);

		app_app = PyDict_GetItem(applications, app_mnt);

		if (!PyString_Check(app_app) && !PyFunction_Check(app_app) && !PyCallable_Check(app_app)) {
			uwsgi_log( "the app callable must be a string, a function or a callable. (found %s)\n", app_app->ob_type->tp_name);
			exit(1);
		}

#ifdef PYTHREE
		if (PyUnicode_Check(app_app)) {
#else
			if (PyString_Check(app_app)) {
#endif
				if (init_uwsgi_app(LOADER_STRING_CALLABLE, (void *) PyString_AsString(app_app), uwsgi.wsgi_req, 0)  < 0) {
					uwsgi_log( "...goodbye cruel world...\n");
					exit(1);
				}


			}
			else {
				if (init_uwsgi_app(LOADER_CALLABLE, (void *) app_app, uwsgi.wsgi_req, 0)  < 0) {
					uwsgi_log( "...goodbye cruel world...\n");
					exit(1);
				}
			}

			Py_DECREF(app_mnt);
			Py_DECREF(app_app);
		}

	}


#ifdef PYTHREE
	static PyModuleDef uwsgi_module3 = {
		PyModuleDef_HEAD_INIT,
		"uwsgi",
		NULL,
		-1,
		null_methods,
	};
	PyObject *init_uwsgi3(void) {
		return PyModule_Create(&uwsgi_module3);
	}
#endif


#ifdef UWSGI_EMBEDDED
	void init_uwsgi_embedded_module() {
		PyObject *new_uwsgi_module, *zero;
		int i;

		/* initialize for stats */
		up.workers_tuple = PyTuple_New(uwsgi.numproc);
		for (i = 0; i < uwsgi.numproc; i++) {
			zero = PyDict_New();
			Py_INCREF(zero);
			PyTuple_SetItem(up.workers_tuple, i, zero);
		}



#ifdef PYTHREE
		PyImport_AppendInittab("uwsgi", init_uwsgi3);
		new_uwsgi_module = PyImport_AddModule("uwsgi");
#else
		new_uwsgi_module = Py_InitModule("uwsgi", null_methods);
#endif
		if (new_uwsgi_module == NULL) {
			uwsgi_log( "could not initialize the uwsgi python module\n");
			exit(1);
		}

		up.embedded_dict = PyModule_GetDict(new_uwsgi_module);
		if (!up.embedded_dict) {
			uwsgi_log( "could not get uwsgi module __dict__\n");
			exit(1);
		}

		if (PyDict_SetItemString(up.embedded_dict, "version", PyString_FromString(UWSGI_VERSION))) {
			PyErr_Print();
			exit(1);
		}

		if (uwsgi.mode) {
			if (PyDict_SetItemString(up.embedded_dict, "mode", PyString_FromString(uwsgi.mode))) {
				PyErr_Print();
				exit(1);
			}
		}

		if (uwsgi.pidfile) {
			if (PyDict_SetItemString(up.embedded_dict, "pidfile", PyString_FromString(uwsgi.pidfile))) {
				PyErr_Print();
				exit(1);
			}
		}


		if (PyDict_SetItemString(up.embedded_dict, "SPOOL_RETRY", PyInt_FromLong(17))) {
			PyErr_Print();
			exit(1);
		}

		if (PyDict_SetItemString(up.embedded_dict, "numproc", PyInt_FromLong(uwsgi.numproc))) {
			PyErr_Print();
			exit(1);
		}

		PyObject *py_opt_dict = PyDict_New();
		for(i=0;i<uwsgi.exported_opts_cnt;i++) {
			if (PyDict_Contains(py_opt_dict, PyString_FromString(uwsgi.exported_opts[i]->key)) ) {
				PyObject *py_opt_item = PyDict_GetItemString(py_opt_dict, uwsgi.exported_opts[i]->key);
				if (PyList_Check(py_opt_item)) {
					PyList_Append(py_opt_item, PyString_FromString( uwsgi.exported_opts[i]->value ));
				}
				else {
					PyObject *py_opt_list = PyList_New(0);
					PyList_Append(py_opt_list, py_opt_item);
					if (uwsgi.exported_opts[i]->value == NULL) {
						PyList_Append(py_opt_list, Py_True);
					}
					else {
						PyList_Append(py_opt_list, PyString_FromString(uwsgi.exported_opts[i]->value));
					}

					PyDict_SetItemString(py_opt_dict, uwsgi.exported_opts[i]->key, py_opt_list);
				}
			}
			else {	
				if (uwsgi.exported_opts[i]->value == NULL) {
					PyDict_SetItemString(py_opt_dict, uwsgi.exported_opts[i]->key, Py_True);
				}
				else {
					PyDict_SetItemString(py_opt_dict, uwsgi.exported_opts[i]->key, PyString_FromString(uwsgi.exported_opts[i]->value));
				}
			}
		}

		if (PyDict_SetItemString(up.embedded_dict, "opt", py_opt_dict)) {
                       	PyErr_Print();
                       	exit(1);
                }

#ifdef UNBIT
		if (PyDict_SetItemString(up.embedded_dict, "unbit", Py_True)) {
#else
			if (PyDict_SetItemString(up.embedded_dict, "unbit", Py_None)) {
#endif
				PyErr_Print();
				exit(1);
			}

			if (PyDict_SetItemString(up.embedded_dict, "buffer_size", PyInt_FromLong(uwsgi.buffer_size))) {
				PyErr_Print();
				exit(1);
			}

			if (PyDict_SetItemString(up.embedded_dict, "started_on", PyInt_FromLong(uwsgi.start_tv.tv_sec))) {
				PyErr_Print();
				exit(1);
			}

			if (PyDict_SetItemString(up.embedded_dict, "start_response", up.wsgi_spitout)) {
				PyErr_Print();
				exit(1);
			}

			if (PyDict_SetItemString(up.embedded_dict, "fastfuncs", PyList_New(256))) {
				PyErr_Print();
				exit(1);
			}


			if (PyDict_SetItemString(up.embedded_dict, "applications", Py_None)) {
				PyErr_Print();
				exit(1);
			}

			if (uwsgi.is_a_reload) {
				if (PyDict_SetItemString(up.embedded_dict, "is_a_reload", Py_True)) {
					PyErr_Print();
					exit(1);
				}
			}
			else {
				if (PyDict_SetItemString(up.embedded_dict, "is_a_reload", Py_False)) {
					PyErr_Print();
					exit(1);
				}
			}

			up.embedded_args = PyTuple_New(2);
			if (!up.embedded_args) {
				PyErr_Print();
				exit(1);
			}

			if (PyDict_SetItemString(up.embedded_dict, "message_manager_marshal", Py_None)) {
				PyErr_Print();
				exit(1);
			}

			up.fastfuncslist = PyDict_GetItemString(up.embedded_dict, "fastfuncs");
			if (!up.fastfuncslist) {
				PyErr_Print();
				exit(1);
			}

			init_uwsgi_module_advanced(new_uwsgi_module);

#ifdef UWSGI_SPOOLER
			if (uwsgi.spool_dir != NULL) {
				init_uwsgi_module_spooler(new_uwsgi_module);
			}
#endif


			if (uwsgi.sharedareasize > 0 && uwsgi.sharedarea) {
				init_uwsgi_module_sharedarea(new_uwsgi_module);
			}
		}
#endif



int uwsgi_python_magic(char *mountpoint, char *lazy) {

	char *qc = strchr(lazy, ':');
	if (qc) {
		qc[0] = 0;
		up.callable = qc + 1;
	}

	if (!strcmp(lazy+strlen(lazy)-3, ".py")) {
		up.file_config = lazy;
		return 1;
	}
	else if (!strcmp(lazy+strlen(lazy)-5, ".wsgi")) {
		up.file_config = lazy;
		return 1;
	}
	else if (qc && strchr(lazy,'.')) {
		up.wsgi_config = lazy;
		return 1;
	}	

	// reset lazy
	if (qc) {
		qc[0] = ':';
	}
	return 0;

}

		int uwsgi_python_manage_options(int i, char *optarg) {

			switch(i) {
				case 'w':
					up.wsgi_config = optarg;
					return 1;
				case LONG_ARGS_WSGI_FILE:
				case LONG_ARGS_FILE_CONFIG:
					up.file_config = optarg;
					return 1;
				case LONG_ARGS_PYTHONPATH:
					uwsgi_log("found PYTHONPATH\n");
					if (up.python_path_cnt < MAX_PYTHONPATH) {
						up.python_path[up.python_path_cnt] = optarg;
						up.python_path_cnt++;
					}
					else {
						uwsgi_log( "you can specify at most %d --pythonpath options\n", MAX_PYTHONPATH);
					}
					return 1;
				case LONG_ARGS_PYARGV:
					up.argv = optarg;
					return 1;
				case 'j':
					up.test_module = optarg;
					return 1;
				case 'H':
					up.home = optarg;
					return 1;
				case 'O':
					up.optimize = atoi(optarg);
					return 1;
				case LONG_ARGS_CALLABLE:
					up.callable = optarg;
					return 1;
			}

			return 0;
		}

		void uwsgi_python_init_app() {

			if (up.wsgi_config != NULL) {
				init_uwsgi_app(LOADER_UWSGI, up.wsgi_config, uwsgi.wsgi_req, 0);
			}

			if (up.file_config != NULL) {
				init_uwsgi_app(LOADER_FILE, up.file_config, uwsgi.wsgi_req, 0);
			}
#ifdef UWSGI_PASTE
			if (up.paste != NULL) {
				init_uwsgi_app(LOADER_PASTE, up.paste, uwsgi.wsgi_req, 0);
			}
#endif
			if (up.eval != NULL) {
				init_uwsgi_app(LOADER_EVAL, up.eval, uwsgi.wsgi_req, 0);
			}

		}

		void uwsgi_python_enable_threads() {

			PyEval_InitThreads();
			if (pthread_key_create(&up.upt_save_key, NULL)) {
				uwsgi_error("pthread_key_create()");
				exit(1);
			}
			pthread_setspecific(up.upt_save_key, (void *) PyThreadState_Get());
			pthread_mutex_init(&up.lock_pyloaders, NULL);
			pthread_atfork(uwsgi_python_pthread_prepare, uwsgi_python_pthread_parent, uwsgi_python_pthread_child);
			up.gil_get = gil_real_get;
			up.gil_release = gil_real_release;

			uwsgi_log("threads support enabled\n");
		}

		void uwsgi_python_init_thread(int core_id) {

			// set a new ThreadState for each thread
			PyThreadState *pts;
			pts = PyThreadState_New(up.main_thread->interp);
			pthread_setspecific(up.upt_save_key, (void *) pts);

		}

		int uwsgi_python_xml(char *node, char *content) {

			if (!strcmp("script", node)) {
				return init_uwsgi_app(LOADER_UWSGI, content, uwsgi.wsgi_req, uwsgi.single_interpreter-1);
			}
			else if (!strcmp("file", node)) {
				return init_uwsgi_app(LOADER_FILE, content, uwsgi.wsgi_req, uwsgi.single_interpreter-1);
			}
			else if (!strcmp("eval", node)) {
				return init_uwsgi_app(LOADER_EVAL, content, uwsgi.wsgi_req, uwsgi.single_interpreter-1);
			}
			else if (!strcmp("module", node)) {
				uwsgi.wsgi_req->module = content;
				uwsgi.wsgi_req->module_len = strlen(content);
				return 1;
			}
			else if (!strcmp("pyhome", node)) {
				uwsgi.wsgi_req->pyhome = content;
				uwsgi.wsgi_req->pyhome_len = strlen(content);
				return 1;
			}
			else if (!strcmp("callable", node)) {
				uwsgi.wsgi_req->callable = content;
				uwsgi.wsgi_req->callable_len = strlen(content);
				return init_uwsgi_app(LOADER_DYN, uwsgi.wsgi_req, uwsgi.wsgi_req, uwsgi.single_interpreter-1);
			}

			return 0;
		}

void uwsgi_python_suspend(struct wsgi_request *wsgi_req) {

	PyThreadState* tstate = PyThreadState_GET();

	uwsgi_log("suspending python\n");
        up.current_recursion_depth = tstate->recursion_depth;
        up.current_frame = tstate->frame;

}

void uwsgi_python_resume(struct wsgi_request *wsgi_req) {

	PyThreadState* tstate = PyThreadState_GET();

	uwsgi_log("resuming python\n");
	tstate->recursion_depth = up.current_recursion_depth;
        tstate->frame = up.current_frame;

}

		struct uwsgi_plugin python_plugin = {

			.name = "python",
			.modifier1 = 0,
			.init = uwsgi_python_init,
			.post_fork = uwsgi_python_post_fork,
			.options = uwsgi_python_options,
			.manage_opt = uwsgi_python_manage_options,
			.short_options = "w:O:H:j:",
			.request = uwsgi_request_wsgi,
			.after_request = uwsgi_after_request_wsgi,
			.init_apps = uwsgi_python_init_app,
			.enable_threads = uwsgi_python_enable_threads,
			.init_thread = uwsgi_python_init_thread,
			.manage_xml = uwsgi_python_xml,

			.magic = uwsgi_python_magic,

			.suspend = uwsgi_python_suspend,
			.resume = uwsgi_python_resume,	
			//.spooler = uwsgi_python_spooler,
			/*
			   .help = uwsgi_python_help,
			   */

		};

