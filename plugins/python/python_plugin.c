#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
struct uwsgi_python up;

extern PyTypeObject uwsgi_InputType;

struct option uwsgi_python_options[] = {
	{"wsgi-file", required_argument, 0, LONG_ARGS_WSGI_FILE},
	{"file", required_argument, 0, LONG_ARGS_FILE_CONFIG},
	{"eval", required_argument, 0, LONG_ARGS_EVAL_CONFIG},
	{"module", required_argument, 0, 'w'},
	{"callable", required_argument, 0, LONG_ARGS_CALLABLE},
	{"test", required_argument, 0, 'j'},
	{"home", required_argument, 0, 'H'},
	{"virtualenv", required_argument, 0, 'H'},
	{"venv", required_argument, 0, 'H'},
	{"pyhome", required_argument, 0, 'H'},
	{"pythonpath", required_argument, 0, LONG_ARGS_PYTHONPATH},
	{"python-path", required_argument, 0, LONG_ARGS_PYTHONPATH},
	{"pymodule-alias", required_argument, 0, LONG_ARGS_PYMODULE_ALIAS},
	{"pp", required_argument, 0, LONG_ARGS_PYTHONPATH},
	{"pyargv", required_argument, 0, LONG_ARGS_PYARGV},
	{"optimize", required_argument, 0, 'O'},
	{"paste", required_argument, 0, LONG_ARGS_PASTE},
#ifdef UWSGI_INI
	{"ini-paste", required_argument, 0, LONG_ARGS_INI_PASTE},
#endif
	{"catch-exceptions", no_argument, &up.catch_exceptions, 1},
	{"ignore-script-name", no_argument, &up.ignore_script_name, 1},
	{"pep3333-input", no_argument, &up.pep3333_input, 1},
	{"reload-os-env", no_argument, &up.reload_os_env, 1},
	{"no-site", no_argument, &Py_NoSiteFlag, 1},

	{0, 0, 0, 0},
};

struct uwsgi_help_item uwsgi_python_help[] = {

{"module <module>" ,"name of python config module"},
{"optimize <n>", "set python optimization level to <n>"},
{"home <path>", "set python home/virtualenv"},
{"pyhome <path>", "set python home/virtualenv"},
{"virtualenv <path>", "set python home/virtualenv"},
{"venv <path>", "set python home/virtualenv"},
{"callable <callable>", "set the callable (default 'application')"},
{"paste <config:/egg:>", "load applications using paste.deploy.loadapp()"},
{"pythonpath <dir>", "add <dir> to PYTHONPATH"},
{"python-path <dir>", "add <dir> to PYTHONPATH"},
{"pp <dir>", "add <dir> to PYTHONPATH"},
{"pyargv <args>", "assign args to python sys.argv"},
{"wsgi-file <file>", "load the <file> wsgi file"},
{"file <file>", "use python file instead of python module for configuration"},
{"eval <code>", "evaluate code for app configuration"},
{"ini-paste <inifile>", "path of ini config file that contains paste configuration"},


 { 0, 0},
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
	{NULL, NULL},
};

PyMethodDef uwsgi_spit_method[] = { {"uwsgi_spit", py_uwsgi_spit, METH_VARARGS, ""} };
PyMethodDef uwsgi_write_method[] = { {"uwsgi_write", py_uwsgi_write, METH_VARARGS, ""} };

int uwsgi_python_init() {

	char *pyversion = strchr(Py_GetVersion(), '\n');
        uwsgi_log("Python version: %.*s %s\n", pyversion-Py_GetVersion(), Py_GetVersion(), Py_GetCompiler()+1);

	if (up.home != NULL) {
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
		uwsgi_log("Set PythonHome to %s\n", up.home);
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

        // by default set a fake GIL (little impact on performance)
        up.gil_get = gil_fake_get;
        up.gil_release = gil_fake_release;

        up.swap_ts = simple_swap_ts;
        up.reset_ts = simple_reset_ts;
	

	uwsgi_log("Python main interpreter initialized at %p\n", up.main_thread);

	// add the hacky modifier1 30
	uwsgi.p[30]->request = uwsgi.p[0]->request;

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
				PyEval_CallObject(random_seed, random_args);
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

PyObject *uwsgi_pyimport_by_filename(char *name, char *filename) {

	FILE *pyfile;
	struct _node *py_file_node = NULL;
	PyObject *py_compiled_node, *py_file_module;
	int is_a_package = 0;
	struct stat pystat;
	char *real_filename = filename;


	if (strncmp(filename, "http://", 7)) {

		pyfile = fopen(filename, "r");
		if (!pyfile) {
			uwsgi_log("failed to open python file %s\n", filename);
			exit(1);
		}

		if (fstat(fileno(pyfile), &pystat)) {
			uwsgi_error("fstat()");
			exit(1);
		}

		if (S_ISDIR(pystat.st_mode)) {
			is_a_package = 1;
			fclose(pyfile);
			real_filename = uwsgi_concat2(filename, "/__init__.py");
			pyfile = fopen(real_filename, "r");
			if (!pyfile) {
				uwsgi_error_open(real_filename);
				exit(1);
			}
		}

		py_file_node = PyParser_SimpleParseFile(pyfile, real_filename, Py_file_input);
		if (!py_file_node) {
			PyErr_Print();
			uwsgi_log("failed to parse file %s\n", real_filename);
			exit(1);
		}

		fclose(pyfile);
	}
	else {
		int pycontent_size = 0;
		char *pycontent = uwsgi_open_and_read(filename, &pycontent_size, 1, NULL);

		if (pycontent) {
			py_file_node = PyParser_SimpleParseString(pycontent, Py_file_input);
			if (!py_file_node) {
				PyErr_Print();
				uwsgi_log("failed to parse url %s\n", real_filename);
				exit(1);
			}
		}
	}

	py_compiled_node = (PyObject *) PyNode_Compile(py_file_node, real_filename);

	if (!py_compiled_node) {
		PyErr_Print();
		uwsgi_log("failed to compile python file %s\n", real_filename);
		exit(1);
	}

	py_file_module = PyImport_ExecCodeModule(name, py_compiled_node);
	if (!py_file_module) {
		PyErr_Print();
		exit(1);
	}

	Py_DECREF(py_compiled_node);

	if (is_a_package) {
		PyObject *py_file_module_dict = PyModule_GetDict(py_file_module);
		if (py_file_module_dict) {
			PyDict_SetItemString(py_file_module_dict, "__path__", Py_BuildValue("[O]", PyString_FromString(filename)));
		}
		free(real_filename);
	}

	return py_file_module;

}


void init_uwsgi_vars() {

	int i;
	PyObject *pysys, *pysys_dict, *pypath;

	PyObject *modules = PyImport_GetModuleDict();
	PyObject *tmp_module;

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
		PyString_Concat(&venv_path, PyString_FromString(venv_version));

		if (PyList_Insert(pypath, 0, venv_path)) {
			PyErr_Print();
		}

		site_module = PyImport_ImportModule("site");
		if (site_module) {
			PyImport_ReloadModule(site_module);
		}

	}
#endif

	if (PyList_Insert(pypath, 0, UWSGI_PYFROMSTRING(".")) != 0) {
		PyErr_Print();
	}

	for (i = 0; i < up.python_path_cnt; i++) {
		if (PyList_Insert(pypath, 0, UWSGI_PYFROMSTRING(up.python_path[i])) != 0) {
			PyErr_Print();
		}
		else {
			uwsgi_log("added %s to pythonpath.\n", up.python_path[i]);
		}
	}

	for (i = 0; i < up.pymodule_alias_cnt; i++) {
		// split key=value
		char *value = strchr(up.pymodule_alias[i], '=');
		if (!value) {
			uwsgi_log("invalid pymodule-alias syntax\n");
			continue;
		}
		value[0] = 0;
		if (!strchr(value + 1, '/')) {
			// this is a standard pymodule
			tmp_module = PyImport_ImportModule(value + 1);
			if (!tmp_module) {
				PyErr_Print();
				exit(1);
			}

			PyDict_SetItemString(modules, up.pymodule_alias[i], tmp_module);
		}
		else {
			// this is a filepath that need to be mapped
			tmp_module = uwsgi_pyimport_by_filename(up.pymodule_alias[i], value + 1);
		}
		uwsgi_log("mapped virtual pymodule \"%s\" to real pymodule \"%s\"\n", up.pymodule_alias[i], value + 1);
		// reset original value
		value[0] = '=';
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

	PyType_Ready(&uwsgi_InputType);

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
		uwsgi_log("could not initialize the uwsgi python module\n");
		exit(1);
	}

	up.embedded_dict = PyModule_GetDict(new_uwsgi_module);
	if (!up.embedded_dict) {
		uwsgi_log("could not get uwsgi module __dict__\n");
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


	if (PyDict_SetItemString(up.embedded_dict, "SPOOL_RETRY", PyInt_FromLong(-1))) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(up.embedded_dict, "SPOOL_OK", PyInt_FromLong(-2))) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(up.embedded_dict, "SPOOL_IGNORE", PyInt_FromLong(0))) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(up.embedded_dict, "numproc", PyInt_FromLong(uwsgi.numproc))) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(up.embedded_dict, "cores", PyInt_FromLong(uwsgi.cores))) {
		PyErr_Print();
		exit(1);
	}

	if (uwsgi.loop) {
		if (PyDict_SetItemString(up.embedded_dict, "loop", PyString_FromString(uwsgi.loop))) {
			PyErr_Print();
			exit(1);
		}
	}

	if (PyDict_SetItemString(up.embedded_dict, "KIND_NULL", PyInt_FromLong(KIND_NULL))) {
		PyErr_Print();
		exit(1);
	}
	if (PyDict_SetItemString(up.embedded_dict, "KIND_WORKER", PyInt_FromLong(KIND_WORKER))) {
		PyErr_Print();
		exit(1);
	}
	if (PyDict_SetItemString(up.embedded_dict, "KIND_EVENT", PyInt_FromLong(KIND_EVENT))) {
		PyErr_Print();
		exit(1);
	}
	if (PyDict_SetItemString(up.embedded_dict, "KIND_SPOOLER", PyInt_FromLong(KIND_SPOOLER))) {
		PyErr_Print();
		exit(1);
	}

/*
	if (PyDict_SetItemString(up.embedded_dict, "KIND_ERLANG", PyInt_FromLong(KIND_ERLANG))) {
		PyErr_Print();
		exit(1);
	}
*/

	if (PyDict_SetItemString(up.embedded_dict, "KIND_PROXY", PyInt_FromLong(KIND_PROXY))) {
		PyErr_Print();
		exit(1);
	}
	if (PyDict_SetItemString(up.embedded_dict, "KIND_MASTER", PyInt_FromLong(KIND_MASTER))) {
		PyErr_Print();
		exit(1);
	}

	PyObject *py_opt_dict = PyDict_New();
	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
		if (PyDict_Contains(py_opt_dict, PyString_FromString(uwsgi.exported_opts[i]->key))) {
			PyObject *py_opt_item = PyDict_GetItemString(py_opt_dict, uwsgi.exported_opts[i]->key);
			if (PyList_Check(py_opt_item)) {
				PyList_Append(py_opt_item, PyString_FromString(uwsgi.exported_opts[i]->value));
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

	init_uwsgi_module_cache(new_uwsgi_module);

	init_uwsgi_module_queue(new_uwsgi_module);

	if (up.extension) {
		up.extension();
	}
}
#endif



int uwsgi_python_magic(char *mountpoint, char *lazy) {

	char *qc = strchr(lazy, ':');
	if (qc) {
		qc[0] = 0;
		up.callable = qc + 1;
	}

	if (!strcmp(lazy + strlen(lazy) - 3, ".py")) {
		up.file_config = lazy;
		return 1;
	}
	else if (!strcmp(lazy + strlen(lazy) - 5, ".wsgi")) {
		up.file_config = lazy;
		return 1;
	}
	else if (qc && strchr(lazy, '.')) {
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

	switch (i) {
	case 'w':
		up.wsgi_config = optarg;
		return 1;
	case LONG_ARGS_WSGI_FILE:
	case LONG_ARGS_FILE_CONFIG:
		up.file_config = optarg;
		return 1;
	case LONG_ARGS_EVAL_CONFIG:
		up.eval = optarg;
		return 1;
	case LONG_ARGS_PYMODULE_ALIAS:
		if (up.pymodule_alias_cnt < MAX_PYMODULE_ALIAS) {
			up.pymodule_alias[up.pymodule_alias_cnt] = optarg;
			up.pymodule_alias_cnt++;
		}
		else {
			uwsgi_log("you can specify at most %d --pymodule-alias options\n", MAX_PYMODULE_ALIAS);
		}
		return 1;
	case LONG_ARGS_PYTHONPATH:
		if (up.python_path_cnt < MAX_PYTHONPATH) {
			up.python_path[up.python_path_cnt] = optarg;
			up.python_path_cnt++;
		}
		else {
			uwsgi_log("you can specify at most %d --pythonpath options\n", MAX_PYTHONPATH);
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


	case LONG_ARGS_INI_PASTE:
		uwsgi.ini = optarg;
		if (uwsgi.ini[0] != '/') {
			up.paste = uwsgi_concat4("config:", uwsgi.cwd, "/", uwsgi.ini);
		}
		else {
			up.paste = uwsgi_concat2("config:", uwsgi.ini);
		}
		return 1;
	case LONG_ARGS_PASTE:
		up.paste = optarg;
		return 1;



	}

	return 0;
}

int uwsgi_python_mount_app(char *mountpoint, char *app) {

	uwsgi.wsgi_req->script_name = mountpoint;
	uwsgi.wsgi_req->script_name_len = strlen(mountpoint);
	if (uwsgi.single_interpreter) {
		return init_uwsgi_app(LOADER_MOUNT, app, uwsgi.wsgi_req, up.main_thread);
	}
	return init_uwsgi_app(LOADER_MOUNT, app, uwsgi.wsgi_req, NULL);

}

void uwsgi_python_init_apps() {

	if (uwsgi.async > 1) {
		up.current_recursion_depth = uwsgi_malloc(sizeof(int)*uwsgi.async);
        	up.current_frame = uwsgi_malloc(sizeof(struct _frame)*uwsgi.async);
	}

	init_pyargv();
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
        up.loaders[LOADER_PASTE] = uwsgi_paste_loader;
        up.loaders[LOADER_EVAL] = uwsgi_eval_loader;
        up.loaders[LOADER_MOUNT] = uwsgi_mount_loader;
        up.loaders[LOADER_CALLABLE] = uwsgi_callable_loader;
        up.loaders[LOADER_STRING_CALLABLE] = uwsgi_string_callable_loader;


	if (up.wsgi_config != NULL) {
		init_uwsgi_app(LOADER_UWSGI, up.wsgi_config, uwsgi.wsgi_req, up.main_thread);
	}

	if (up.file_config != NULL) {
		init_uwsgi_app(LOADER_FILE, up.file_config, uwsgi.wsgi_req, up.main_thread);
	}
	if (up.paste != NULL) {
		init_uwsgi_app(LOADER_PASTE, up.paste, uwsgi.wsgi_req, up.main_thread);
	}
	if (up.eval != NULL) {
		init_uwsgi_app(LOADER_EVAL, up.eval, uwsgi.wsgi_req, up.main_thread);
	}

}

void uwsgi_python_enable_threads() {

	PyEval_InitThreads();
	if (pthread_key_create(&up.upt_save_key, NULL)) {
		uwsgi_error("pthread_key_create()");
		exit(1);
	}
	if (pthread_key_create(&up.upt_gil_key, NULL)) {
		uwsgi_error("pthread_key_create()");
		exit(1);
	}
	pthread_setspecific(up.upt_save_key, (void *) PyThreadState_Get());
	pthread_setspecific(up.upt_gil_key, (void *) PyThreadState_Get());
	pthread_mutex_init(&up.lock_pyloaders, NULL);
	pthread_atfork(uwsgi_python_pthread_prepare, uwsgi_python_pthread_parent, uwsgi_python_pthread_child);

	up.gil_get = gil_real_get;
	up.gil_release = gil_real_release;

	up.swap_ts = threaded_swap_ts;
	up.reset_ts = threaded_reset_ts;
	uwsgi_log("threads support enabled\n");
}

void uwsgi_python_init_thread(int core_id) {

	// set a new ThreadState for each thread
	PyThreadState *pts;
	pts = PyThreadState_New(up.main_thread->interp);
	pthread_setspecific(up.upt_save_key, (void *) pts);
	pthread_setspecific(up.upt_gil_key, (void *) pts);

}

int uwsgi_python_xml(char *node, char *content) {

	PyThreadState *interpreter = NULL;

	if (uwsgi.single_interpreter) {
		interpreter = up.main_thread;
	}

	if (!strcmp("script", node)) {
		return init_uwsgi_app(LOADER_UWSGI, content, uwsgi.wsgi_req, interpreter);
	}
	else if (!strcmp("file", node)) {
		return init_uwsgi_app(LOADER_FILE, content, uwsgi.wsgi_req, interpreter);
	}
	else if (!strcmp("eval", node)) {
		return init_uwsgi_app(LOADER_EVAL, content, uwsgi.wsgi_req, interpreter);
	}
	else if (!strcmp("wsgi", node)) {
		return init_uwsgi_app(LOADER_EVAL, content, uwsgi.wsgi_req, interpreter);
	}
	else if (!strcmp("module", node)) {
		uwsgi.wsgi_req->module = content;
		uwsgi.wsgi_req->module_len = strlen(content);
		uwsgi.wsgi_req->callable = strchr(uwsgi.wsgi_req->module, ':');
		if (uwsgi.wsgi_req->callable) {
			uwsgi.wsgi_req->callable[0] = 0;
			uwsgi.wsgi_req->callable++;
			uwsgi.wsgi_req->callable_len = strlen(uwsgi.wsgi_req->callable);
			uwsgi.wsgi_req->module_len = strlen(uwsgi.wsgi_req->module);
			return init_uwsgi_app(LOADER_DYN, uwsgi.wsgi_req, uwsgi.wsgi_req, interpreter);
		}
		else {
			return init_uwsgi_app(LOADER_UWSGI, content, uwsgi.wsgi_req, interpreter);
		}
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
		return init_uwsgi_app(LOADER_DYN, uwsgi.wsgi_req, uwsgi.wsgi_req, interpreter);
	}

	return 0;
}

void uwsgi_python_suspend(struct wsgi_request *wsgi_req) {

	PyThreadState *tstate = PyThreadState_GET();

	if (wsgi_req) {
		up.current_recursion_depth[wsgi_req->async_id] = tstate->recursion_depth;
		up.current_frame[wsgi_req->async_id] = tstate->frame;
	}
	else {
		up.current_main_recursion_depth = tstate->recursion_depth;
		up.current_main_frame = tstate->frame;
	}

}

int uwsgi_python_signal_handler(uint8_t sig, void *handler) {

	PyObject *args = PyTuple_New(1);
	PyObject *ret;

	if (!args)
		return -1;

	if (!handler) return -1;


	PyTuple_SetItem(args, 0, PyInt_FromLong(sig));

	ret = python_call(handler, args, 0);

	if (ret) {
		return 0;
	}

	return -1;
}

uint16_t uwsgi_python_rpc(void *func, uint8_t argc, char **argv, char *buffer) {

	uint8_t i;
	PyObject *pyargs = PyTuple_New(argc);
	PyObject *ret;
	char *rv;
	size_t rl;

	if (!pyargs)
		return 0;

	for (i = 0; i < argc; i++) {
		PyTuple_SetItem(pyargs, i, PyString_FromString(argv[i]));
	}

	ret = python_call((PyObject *) func, pyargs, 0);

	if (ret) {
		if (PyString_Check(ret)) {
			rv = PyString_AsString(ret);
			rl = strlen(rv);
			if (rl <= 0xffff) {
				memcpy(buffer, rv, rl);
				Py_DECREF(ret);
				return rl;
			}
		}
	}

	if (PyErr_Occurred())
		PyErr_Print();


	return 0;

}

void uwsgi_python_add_item(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	PyObject *pydict = (PyObject *) data;

	PyDict_SetItem(pydict, PyString_FromStringAndSize(key, keylen), PyString_FromStringAndSize(val, vallen));
}

int uwsgi_python_spooler(char *buf, uint16_t len) {

	PyObject *spool_dict = PyDict_New();
	PyObject *spool_func, *pyargs, *ret;

	if (!up.embedded_dict) {
		// ignore
		return 0;
	}

	spool_func = PyDict_GetItemString(up.embedded_dict, "spooler");
	if (!spool_func) {
		// ignore
		return 0;
	}

	if (uwsgi_hooked_parse(buf, len, uwsgi_python_add_item, spool_dict)) {
		// malformed packet, destroy it
		return -2;
	}

	pyargs = PyTuple_New(1);
	PyTuple_SetItem(pyargs, 0, spool_dict);
	
	ret = python_call(spool_func, pyargs, 0);
	if (ret) {
		if (!PyInt_Check(ret)) {
			// error, retry
			return -1;
		}	

		return PyInt_AsLong(ret);
	}
	
	if (PyErr_Occurred())
		PyErr_Print();

	// error, retry
	return -1;
}

void uwsgi_python_resume(struct wsgi_request *wsgi_req) {

	PyThreadState *tstate = PyThreadState_GET();

	if (wsgi_req) {
		tstate->recursion_depth = up.current_recursion_depth[wsgi_req->async_id];
		tstate->frame = up.current_frame[wsgi_req->async_id];
	}
	else {
		tstate->recursion_depth = up.current_main_recursion_depth;
		tstate->frame = up.current_main_frame;
	}

}

struct uwsgi_plugin python_plugin = {

	.name = "python",
	.alias = "python",
	.modifier1 = 0,
	.init = uwsgi_python_init,
	.post_fork = uwsgi_python_post_fork,
	.options = uwsgi_python_options,
	.manage_opt = uwsgi_python_manage_options,
	.short_options = "w:O:H:j:",
	.request = uwsgi_request_wsgi,
	.after_request = uwsgi_after_request_wsgi,
	.init_apps = uwsgi_python_init_apps,

	.mount_app = uwsgi_python_mount_app,

	.enable_threads = uwsgi_python_enable_threads,
	.init_thread = uwsgi_python_init_thread,
	.manage_xml = uwsgi_python_xml,

	.magic = uwsgi_python_magic,

	.suspend = uwsgi_python_suspend,
	.resume = uwsgi_python_resume,

	.signal_handler = uwsgi_python_signal_handler,
	.rpc = uwsgi_python_rpc,

	.spooler = uwsgi_python_spooler,

	.help = uwsgi_python_help,

};
