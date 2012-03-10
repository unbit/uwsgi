#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
struct uwsgi_python up;

extern struct http_status_codes hsc[];

#include <glob.h>

extern PyTypeObject uwsgi_InputType;

void uwsgi_opt_pythonpath(char *opt, char *value, void *foobar) {

	int i;
	glob_t g;

	if (glob(value, GLOB_MARK, NULL, &g)) {
		uwsgi_string_new_list(&up.python_path, value);
	}
	else {
		for (i = 0; i < (int) g.gl_pathc; i++) {
	        	uwsgi_string_new_list(&up.python_path, g.gl_pathv[i]);
	        }
	}
}

void uwsgi_opt_pyshell(char *opt, char *value, void *foobar) {

	uwsgi.honour_stdin = 1;
	up.pyshell = 1;

	if (!strcmp("pyshell-oneshot", opt)) {
		up.pyshell_oneshot = 1;
	}
}

void uwsgi_opt_pyrun(char *opt, char *value, void *foobar) {
	uwsgi.honour_stdin = 1;
	uwsgi.command_mode = 1;
	up.pyrun = value;
}

#ifdef UWSGI_INI
void uwsgi_opt_ini_paste(char *opt, char *value, void *foobar) {

	uwsgi_opt_load_ini(opt, value, NULL);

	if (value[0] != '/') {
		up.paste = uwsgi_concat4("config:", uwsgi.cwd, "/", value);
	}
	else {
		up.paste = uwsgi_concat2("config:", value);
        }

	if (!strcmp("ini-paste-logged", opt)) {
		up.paste_logger = 1;
	}
	
}
#endif

struct uwsgi_option uwsgi_python_options[] = {
	{"wsgi-file", required_argument, 0, "load .wsgi file", uwsgi_opt_set_str, &up.file_config, 0},
	{"file", required_argument, 0, "load .wsgi file", uwsgi_opt_set_str, &up.file_config, 0},
	{"eval", required_argument, 0, "eval python code", uwsgi_opt_set_str, &up.eval, 0},
	{"module", required_argument,'w', "load a WSGI module", uwsgi_opt_set_str, &up.wsgi_config, 0},
	{"wsgi", required_argument, 'w', "load a WSGI module", uwsgi_opt_set_str, &up.wsgi_config, 0},
	{"callable", required_argument, 0, "set default WSGI callable name", uwsgi_opt_set_str, &up.callable, 0},
	{"test", required_argument, 'J', "test a mdule import", uwsgi_opt_set_str, &up.test_module, 0},
	{"home", required_argument, 'H', "set PYTHONHOME/virtualenv", uwsgi_opt_set_str, &up.home, 0},
	{"virtualenv", required_argument, 'H', "set PYTHONHOME/virtualenv", uwsgi_opt_set_str, &up.home, 0},
	{"venv", required_argument, 'H', "set PYTHONHOME/virtualenv", uwsgi_opt_set_str, &up.home, 0},
	{"pyhome", required_argument, 'H', "set PYTHONHOME/virtualenv", uwsgi_opt_set_str, &up.home, 0},

	{"pythonpath", required_argument, 0, "add directory (or glob) to pythonpath", uwsgi_opt_pythonpath, NULL,  0},
	{"python-path", required_argument, 0, "add directory (or glob) to pythonpath", uwsgi_opt_pythonpath, NULL, 0},
	{"pp", required_argument, 0, "add directory (or glob) to pythonpath", uwsgi_opt_pythonpath, NULL, 0},

	{"pymodule-alias", required_argument, 0, "add a python alias module", uwsgi_opt_add_string_list, &up.pymodule_alias, 0},
	{"post-pymodule-alias", required_argument, 0, "add a python module alias after uwsgi module initialization", uwsgi_opt_add_string_list, &up.post_pymodule_alias, 0},

	{"import", required_argument, 0, "import a python module", uwsgi_opt_add_string_list, &up.import_list, 0},
	{"pyimport", required_argument, 0, "import a python module", uwsgi_opt_add_string_list, &up.import_list, 0},
	{"py-import", required_argument, 0, "import a python module", uwsgi_opt_add_string_list, &up.import_list, 0},
	{"python-import", required_argument, 0, "import a python module", uwsgi_opt_add_string_list, &up.import_list, 0},

	{"shared-import", required_argument, 0, "import a python module in all of the processes", uwsgi_opt_add_string_list, &up.shared_import_list, 0},
	{"shared-pyimport", required_argument, 0, "import a python module in all of the processes", uwsgi_opt_add_string_list, &up.shared_import_list, 0},
	{"shared-py-import", required_argument, 0, "import a python module in all of the processes", uwsgi_opt_add_string_list, &up.shared_import_list, 0},
	{"shared-python-import", required_argument, 0, "import a python module in all of the processes", uwsgi_opt_add_string_list, &up.shared_import_list, 0},

	{"spooler-import", required_argument, 0, "import a python module in the spooler", uwsgi_opt_add_string_list, &up.spooler_import_list},
	{"spooler-pyimport", required_argument, 0, "import a python module in the spooler", uwsgi_opt_add_string_list, &up.spooler_import_list},
	{"spooler-py-import", required_argument, 0, "import a python module in the spooler", uwsgi_opt_add_string_list, &up.spooler_import_list},
	{"spooler-python-import", required_argument, 0, "import a python module in the spooler", uwsgi_opt_add_string_list, &up.spooler_import_list},

	{"pyargv", required_argument, 0, "manually set sys.argv", uwsgi_opt_set_str, &up.argv, 0},
	{"optimize", required_argument, 'O', "set python optimization level", uwsgi_opt_set_int, &up.optimize, 0},

	{"paste", required_argument, 0, "load a paste.deploy config file", uwsgi_opt_set_str, &up.paste, 0},
	{"paste-logger", no_argument, 0, "enable paste fileConfig logger", uwsgi_opt_true, &up.paste_logger, 0},


	{"web3", required_argument, 0, "load a web3 app", uwsgi_opt_set_str, &up.web3, 0},
	{"pump", required_argument, 0, "load a pump app", uwsgi_opt_set_str, &up.pump, 0},
	{"wsgi-lite", required_argument, 0, "load a wsgi-lite app", uwsgi_opt_set_str, &up.wsgi_lite, 0},
#ifdef UWSGI_INI
	{"ini-paste", required_argument, 0, "load a paste.deploy config file containing uwsgi section", uwsgi_opt_ini_paste, NULL, UWSGI_OPT_IMMEDIATE},
	{"ini-paste-logged", required_argument, 0, "load a paste.deploy config file containing uwsgi section (load loggers too)", uwsgi_opt_ini_paste, NULL, UWSGI_OPT_IMMEDIATE},
#endif
	{"catch-exceptions", no_argument, 0, "report exception has http output (discouraged)", uwsgi_opt_true, &up.catch_exceptions, 0},
	{"ignore-script-name", no_argument, 0, "ignore SCRIPT_NAME", uwsgi_opt_true, &up.ignore_script_name, 0},
	{"reload-os-env", no_argument, 0, "force reload of os.environ at each request", uwsgi_opt_true, &up.reload_os_env, 0},
#ifndef UWSGI_PYPY
	{"no-site", no_argument, 0, "do not import site module", uwsgi_opt_true, &Py_NoSiteFlag, 0},
#endif
	{"pyshell", no_argument, 0, "run an interactive python shell in the uWSGI environment", uwsgi_opt_pyshell, NULL, 0},
	{"pyshell-oneshot", no_argument, 0, "run an interactive python shell in the uWSGI environment (one-shot variant)", uwsgi_opt_pyshell, NULL, 0},

	{"python", required_argument, 0, "run a python script in the uWSGI environment", uwsgi_opt_pyrun, NULL, 0},
	{"py", required_argument, 0, "run a python script in the uWSGI environment", uwsgi_opt_pyrun, NULL, 0},
	{"pyrun", required_argument, 0, "run a python script in the uWSGI environment", uwsgi_opt_pyrun, NULL, 0},

	{0, 0, 0, 0, 0, 0, 0},
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

PyMethodDef uwsgi_spit_method[] = { {"uwsgi_spit", py_uwsgi_spit, METH_VARARGS, ""} };
PyMethodDef uwsgi_write_method[] = { {"uwsgi_write", py_uwsgi_write, METH_VARARGS, ""} };

int uwsgi_python_init() {

#ifndef UWSGI_PYPY
	char *pyversion = strchr(Py_GetVersion(), '\n');
        uwsgi_log_initial("Python version: %.*s %s\n", pyversion-Py_GetVersion(), Py_GetVersion(), Py_GetCompiler()+1);
#else
	uwsgi_log_initial("PyPy version: %s\n", PYPY_VERSION);
#endif

#ifndef UWSGI_PYPY
	if (up.home != NULL) {
#ifdef PYTHREE
		wchar_t *wpyhome;
		wpyhome = malloc((sizeof(wchar_t) * strlen(up.home)) + sizeof(wchar_t) );
		if (!wpyhome) {
			uwsgi_error("malloc()");
			exit(1);
		}
		mbstowcs(wpyhome, up.home, strlen(up.home));
		Py_SetPythonHome(wpyhome);
		// do not free this memory !!!
		//free(wpyhome);
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


	Py_OptimizeFlag = up.optimize;

	Py_Initialize();


#endif

	up.wsgi_spitout = PyCFunction_New(uwsgi_spit_method, NULL);
	up.wsgi_writeout = PyCFunction_New(uwsgi_write_method, NULL);

	up.main_thread = PyThreadState_Get();

        // by default set a fake GIL (little impact on performance)
        up.gil_get = gil_fake_get;
        up.gil_release = gil_fake_release;

        up.swap_ts = simple_swap_ts;
        up.reset_ts = simple_reset_ts;
	

	uwsgi_log_initial("Python main interpreter initialized at %p\n", up.main_thread);

	return 1;

}

void uwsgi_python_reset_random_seed() {

#ifndef UWSGI_PYPY
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
#endif
}


void uwsgi_python_atexit() {

	// if hijacked do not run atexit hooks
	if (uwsgi.workers[uwsgi.mywid].hijacked)
		return;

	// if busy do not run atexit hooks
	if (uwsgi.workers[uwsgi.mywid].busy)
		return;

#ifdef UWSGI_ASYNC
	// managing atexit in async mode is a real pain...skip it for now
	if (uwsgi.async > 1)
		return;
#endif

	// this time we use this higher level function
	// as this code can be executed in a signal handler

	if (!Py_IsInitialized()) {
		return;
	}

	if (uwsgi.has_threads)
		PyGILState_Ensure();
	// no need to worry about freeing memory
	PyObject *uwsgi_dict = get_uwsgi_pydict("uwsgi");
	if (uwsgi_dict) {
		PyObject *ae = PyDict_GetItemString(uwsgi_dict, "atexit");
		if (ae) {
			python_call(ae, PyTuple_New(0), 0, NULL);
		}
	}

	// this part is a 1:1 copy of mod_wsgi 3.x
        // it is required to fix some atexit bug with python 3
	// and to shutdown useless threads complaints
	PyObject *module = PyImport_ImportModule("atexit");
	Py_XDECREF(module);

	if (uwsgi.threads > 1) {
		if (!PyImport_AddModule("dummy_threading"))
			PyErr_Clear();
	}

	Py_Finalize();
}

void uwsgi_python_post_fork() {

#ifdef UWSGI_SPOOLER
	if (uwsgi.i_am_a_spooler) {
		UWSGI_GET_GIL
	}	
#endif

	uwsgi_python_reset_random_seed();

#ifndef UWSGI_PYPY
#ifdef UWSGI_EMBEDDED
	// call the post_fork_hook
	PyObject *uwsgi_dict = get_uwsgi_pydict("uwsgi");
	if (uwsgi_dict) {
		PyObject *pfh = PyDict_GetItemString(uwsgi_dict, "post_fork_hook");
		if (pfh) {
			python_call(pfh, PyTuple_New(0), 0, NULL);
		}
	}
	PyErr_Clear();
#endif
#endif

UWSGI_RELEASE_GIL

}

PyObject *uwsgi_pyimport_by_filename(char *name, char *filename) {

#ifndef UWSGI_PYPY
	FILE *pyfile;
	struct _node *py_file_node = NULL;
	PyObject *py_compiled_node, *py_file_module;
	int is_a_package = 0;
	struct stat pystat;
	char *real_filename = filename;


	if (!uwsgi_check_scheme(filename)) {

		pyfile = fopen(filename, "r");
		if (!pyfile) {
			uwsgi_log("failed to open python file %s\n", filename);
			return NULL;
		}

		if (fstat(fileno(pyfile), &pystat)) {
			uwsgi_error("fstat()");
			return NULL;
		}

		if (S_ISDIR(pystat.st_mode)) {
			is_a_package = 1;
			fclose(pyfile);
			real_filename = uwsgi_concat2(filename, "/__init__.py");
			pyfile = fopen(real_filename, "r");
			if (!pyfile) {
				uwsgi_error_open(real_filename);
				free(real_filename);
				return NULL;
			}
		}

		py_file_node = PyParser_SimpleParseFile(pyfile, real_filename, Py_file_input);
		if (!py_file_node) {
			PyErr_Print();
			uwsgi_log("failed to parse file %s\n", real_filename);
			if (is_a_package)
				free(real_filename);
			fclose(pyfile);
			return NULL;
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
				return NULL;
			}
		}
	}

	py_compiled_node = (PyObject *) PyNode_Compile(py_file_node, real_filename);

	if (!py_compiled_node) {
		PyErr_Print();
		uwsgi_log("failed to compile python file %s\n", real_filename);
		return NULL;
	}

	py_file_module = PyImport_ExecCodeModule(name, py_compiled_node);
	if (!py_file_module) {
		PyErr_Print();
		return NULL;
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
#else
	return NULL;
#endif

}

void init_uwsgi_vars() {

	PyObject *pysys, *pysys_dict, *pypath;

	PyObject *modules = PyImport_GetModuleDict();
	PyObject *tmp_module;

	/* add cwd to pythonpath */
	pysys = PyImport_ImportModule("sys");
	if (!pysys) {
		PyErr_Print();
		exit(1);
	}
	pysys_dict = PyModule_GetDict(pysys);

#ifdef PYTHREE
	// fix stdout and stderr
	PyObject *new_stdprint = PyFile_NewStdPrinter(2);
	PyDict_SetItemString(pysys_dict, "stdout", new_stdprint);
	PyDict_SetItemString(pysys_dict, "__stdout__", new_stdprint);
	PyDict_SetItemString(pysys_dict, "stderr", new_stdprint);
	PyDict_SetItemString(pysys_dict, "__stderr__", new_stdprint);
#endif
	pypath = PyDict_GetItemString(pysys_dict, "path");
	if (!pypath) {
		PyErr_Print();
		exit(1);
	}

	if (PyList_Insert(pypath, 0, UWSGI_PYFROMSTRING(".")) != 0) {
		PyErr_Print();
	}

	struct uwsgi_string_list *uppp = up.python_path;
	while(uppp) {
		if (PyList_Insert(pypath, 0, UWSGI_PYFROMSTRING(uppp->value)) != 0) {
			PyErr_Print();
		}
		else {
			uwsgi_log("added %s to pythonpath.\n", uppp->value);
		}

		uppp = uppp->next;
	}

	struct uwsgi_string_list *uppma = up.pymodule_alias;
	while(uppma) {
		// split key=value
		char *value = strchr(uppma->value, '=');
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

			PyDict_SetItemString(modules, uppma->value, tmp_module);
		}
		else {
			// this is a filepath that need to be mapped
			tmp_module = uwsgi_pyimport_by_filename(uppma->value, value + 1);
			if (!tmp_module) {
				PyErr_Print();
				exit(1);
			}
		}
		uwsgi_log("mapped virtual pymodule \"%s\" to real pymodule \"%s\"\n", uppma->value, value + 1);
		// reset original value
		value[0] = '=';

		uppma = uppma->next;
	}

}



PyDoc_STRVAR(uwsgi_py_doc, "uWSGI api module.");


#ifdef PYTHREE
static PyModuleDef uwsgi_module3 = {
	PyModuleDef_HEAD_INIT,
	"uwsgi",
	uwsgi_py_doc,
	-1,
	NULL,
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
	new_uwsgi_module = Py_InitModule3("uwsgi", NULL, uwsgi_py_doc);
#endif
	if (new_uwsgi_module == NULL) {
		uwsgi_log("could not initialize the uwsgi python module\n");
		exit(1);
	}



	Py_INCREF((PyObject *) &uwsgi_InputType);

	up.embedded_dict = PyModule_GetDict(new_uwsgi_module);
	if (!up.embedded_dict) {
		uwsgi_log("could not get uwsgi module __dict__\n");
		exit(1);
	}

	// just for safety
	Py_INCREF(up.embedded_dict);

	if (PyDict_SetItemString(up.embedded_dict, "version", PyString_FromString(UWSGI_VERSION))) {
		PyErr_Print();
		exit(1);
	}

	PyObject *uwsgi_py_version_info = PyTuple_New(5);

	PyTuple_SetItem(uwsgi_py_version_info, 0, PyInt_FromLong(UWSGI_VERSION_BASE));
	PyTuple_SetItem(uwsgi_py_version_info, 1, PyInt_FromLong(UWSGI_VERSION_MAJOR));
	PyTuple_SetItem(uwsgi_py_version_info, 2, PyInt_FromLong(UWSGI_VERSION_MINOR));
	PyTuple_SetItem(uwsgi_py_version_info, 3, PyInt_FromLong(UWSGI_VERSION_REVISION));
	PyTuple_SetItem(uwsgi_py_version_info, 4, PyString_FromString(UWSGI_VERSION_CUSTOM));

	if (PyDict_SetItemString(up.embedded_dict, "version_info", uwsgi_py_version_info)) {
		PyErr_Print();
		exit(1);
	}



	if (PyDict_SetItemString(up.embedded_dict, "hostname", PyString_FromStringAndSize(uwsgi.hostname, uwsgi.hostname_len))) {
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

#ifdef UWSGI_SPOOLER
	if (uwsgi.spoolers) {
		int sc = 0;
		struct uwsgi_spooler *uspool = uwsgi.spoolers;
		while(uspool) { sc++; uspool = uspool->next;}

		PyObject *py_spooler_tuple = PyTuple_New(sc);

		uspool = uwsgi.spoolers;
		sc = 0;

		while(uspool) {
			PyTuple_SetItem(py_spooler_tuple, sc, PyString_FromString(uspool->dir));
			sc++;
			uspool = uspool->next;
		}

		if (PyDict_SetItemString(up.embedded_dict, "spoolers", py_spooler_tuple)) {
                	PyErr_Print();
                	exit(1);
        	}
	}
#endif



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

	if (PyDict_SetItemString(up.embedded_dict, "has_threads", PyInt_FromLong(uwsgi.has_threads))) {
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

	PyObject *py_opt_dict = PyDict_New();
	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
		if (PyDict_Contains(py_opt_dict, PyString_FromString(uwsgi.exported_opts[i]->key))) {
			PyObject *py_opt_item = PyDict_GetItemString(py_opt_dict, uwsgi.exported_opts[i]->key);
			if (PyList_Check(py_opt_item)) {
				if (uwsgi.exported_opts[i]->value == NULL) {
					PyList_Append(py_opt_item, Py_True);
				}
				else {
					PyList_Append(py_opt_item, PyString_FromString(uwsgi.exported_opts[i]->value));
				}
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

	PyObject *py_magic_table = PyDict_New();
	uint8_t mtk;
	for (i = 0; i <= 0xff; i++) {
		// a bit of magic :P
		mtk = i;
                if (uwsgi.magic_table[i]) {
			if (uwsgi.magic_table[i][0] != 0) {
				PyDict_SetItem(py_magic_table, PyString_FromStringAndSize((char *) &mtk, 1), PyString_FromString(uwsgi.magic_table[i]));
			}
		}
        }

	if (PyDict_SetItemString(up.embedded_dict, "magic_table", py_magic_table)) {
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

	init_uwsgi_module_advanced(new_uwsgi_module);

#ifdef UWSGI_SPOOLER
	if (uwsgi.spoolers) {
		init_uwsgi_module_spooler(new_uwsgi_module);
	}
#endif


	if (uwsgi.sharedareasize > 0 && uwsgi.sharedarea) {
		init_uwsgi_module_sharedarea(new_uwsgi_module);
	}

	if (uwsgi.cache_max_items > 0) {
		init_uwsgi_module_cache(new_uwsgi_module);
	}

	if (uwsgi.queue_size > 0) {
		init_uwsgi_module_queue(new_uwsgi_module);
	}

#ifdef UWSGI_SNMP
	if (uwsgi.snmp) {
		init_uwsgi_module_snmp(new_uwsgi_module);
	}
#endif

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

int uwsgi_python_mount_app(char *mountpoint, char *app, int regexp) {

	int id;

	if (strchr(app, ':') || uwsgi_endswith(app, ".py") || uwsgi_endswith(app, ".wsgi")) {
		uwsgi.wsgi_req->appid = mountpoint;
		uwsgi.wsgi_req->appid_len = strlen(mountpoint);
		if (uwsgi.single_interpreter) {
			id = init_uwsgi_app(LOADER_MOUNT, app, uwsgi.wsgi_req, up.main_thread, PYTHON_APP_TYPE_WSGI);
		}
		else {
			id = init_uwsgi_app(LOADER_MOUNT, app, uwsgi.wsgi_req, NULL, PYTHON_APP_TYPE_WSGI);
		}

#ifdef UWSGI_PCRE
	int i;
	if (regexp && id != -1) {
		struct uwsgi_app *ua = &uwsgi_apps[id];
		uwsgi_regexp_build(mountpoint, &ua->pattern, &ua->pattern_extra);
		if (uwsgi.mywid == 0) {
			for(i=1;i<=uwsgi.numproc;i++) {
				uwsgi.workers[i].apps[id].pattern = ua->pattern;
				uwsgi.workers[i].apps[id].pattern_extra = ua->pattern_extra;
			}
		}
	}
#endif

		return id;
	}
	return -1;

}

char *uwsgi_pythonize(char *orig) {

	char *name = uwsgi_concat2(orig, "");
	size_t i;
	size_t len = 0;

	if (!strncmp(name, "sym://", 6)) {
		name+=6;
	}
	else if (!strncmp(name, "http://", 7)) {
		name+=7;
	}
	else if (!strncmp(name, "data://", 7)) {
		name+=7;
	}

	len = strlen(name);
	for(i=0;i<len;i++) {
		if (name[i] == '.') {
			name[i] = '_';
		}
		else if (name[i] == '/') {
			name[i] = '_';
		}
	}


	if ((name[len-3] == '.' || name[len-3] == '_') && name[len-2] == 'p' && name[len-1] == 'y') {
		name[len-3] = 0;
	}

	return name;

}

void uwsgi_python_spooler_init(void) {

	struct uwsgi_string_list *upli = up.spooler_import_list;

	UWSGI_GET_GIL

        while(upli) {
                if (strchr(upli->value, '/') || uwsgi_endswith(upli->value, ".py")) {
                        uwsgi_pyimport_by_filename(uwsgi_pythonize(upli->value), upli->value);
                }
                else {
                        if (PyImport_ImportModule(upli->value) == NULL) {
                                PyErr_Print();
                        }
                }
                upli = upli->next;
        }

	UWSGI_RELEASE_GIL
	

}

// this hook will be executed by master (or worker1 when master is not requested, so COW is in place)
void uwsgi_python_preinit_apps() {

	init_pyargv();

#ifndef UWSGI_PYPY
#ifdef UWSGI_EMBEDDED
        init_uwsgi_embedded_module();
#endif
#endif

#ifdef __linux__
#ifndef UWSGI_PYPY
#ifdef UWSGI_EMBEDDED
	uwsgi_init_symbol_import();
#endif
#endif
#endif

        if (up.test_module != NULL) {
                if (PyImport_ImportModule(up.test_module)) {
                        exit(0);
                }
                exit(1);
        }

        init_uwsgi_vars();

	// load shared imports
	struct uwsgi_string_list *upli = up.shared_import_list;
	while(upli) {
		if (strchr(upli->value, '/') || uwsgi_endswith(upli->value, ".py")) {
			uwsgi_pyimport_by_filename(uwsgi_pythonize(upli->value), upli->value);
		}
		else {
			if (PyImport_ImportModule(upli->value) == NULL) {
				PyErr_Print();
			}
		}
		upli = upli->next;
	}

}

void uwsgi_python_init_apps() {

	struct http_status_codes *http_sc;

	// prepare for stack suspend/resume
	if (uwsgi.async > 1) {
		up.current_recursion_depth = uwsgi_malloc(sizeof(int)*uwsgi.async);
#ifndef UWSGI_PYPY
        	up.current_frame = uwsgi_malloc(sizeof(struct _frame)*uwsgi.async);
#endif
	}

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


	struct uwsgi_string_list *upli = up.import_list;
	while(upli) {
		if (strchr(upli->value, '/') || uwsgi_endswith(upli->value, ".py")) {
			uwsgi_pyimport_by_filename(uwsgi_pythonize(upli->value), upli->value);
		}
		else {
			if (PyImport_ImportModule(upli->value) == NULL) {
				PyErr_Print();
			}
		}
		upli = upli->next;
	}

	struct uwsgi_string_list *uppa = up.post_pymodule_alias;
	PyObject *modules = PyImport_GetModuleDict();
	PyObject *tmp_module;
	while(uppa) {
                // split key=value
                char *value = strchr(uppa->value, '=');
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

                        PyDict_SetItemString(modules, uppa->value, tmp_module);
                }
                else {
                        // this is a filepath that need to be mapped
                        tmp_module = uwsgi_pyimport_by_filename(uppa->value, value + 1);
                        if (!tmp_module) {
                                PyErr_Print();
                                exit(1);
                        }
                }
                uwsgi_log("mapped virtual pymodule \"%s\" to real pymodule \"%s\"\n", uppa->value, value + 1);
                // reset original value
                value[0] = '=';

		uppa = uppa->next;
        }


	if (up.wsgi_config != NULL) {
		init_uwsgi_app(LOADER_UWSGI, up.wsgi_config, uwsgi.wsgi_req, up.main_thread, PYTHON_APP_TYPE_WSGI);
	}

	if (up.file_config != NULL) {
		init_uwsgi_app(LOADER_FILE, up.file_config, uwsgi.wsgi_req, up.main_thread, PYTHON_APP_TYPE_WSGI);
	}
	if (up.paste != NULL) {
		init_uwsgi_app(LOADER_PASTE, up.paste, uwsgi.wsgi_req, up.main_thread, PYTHON_APP_TYPE_WSGI);
	}
	if (up.eval != NULL) {
		init_uwsgi_app(LOADER_EVAL, up.eval, uwsgi.wsgi_req, up.main_thread, PYTHON_APP_TYPE_WSGI);
	}
	if (up.web3 != NULL) {
		init_uwsgi_app(LOADER_UWSGI, up.web3, uwsgi.wsgi_req, up.main_thread, PYTHON_APP_TYPE_WEB3);
	}
	if (up.pump != NULL) {
		init_uwsgi_app(LOADER_UWSGI, up.pump, uwsgi.wsgi_req, up.main_thread, PYTHON_APP_TYPE_PUMP);
		// filling http status codes
        	for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
                	http_sc->message_size = (int) strlen(http_sc->message);
        	}
	}
	if (up.wsgi_lite != NULL) {
		init_uwsgi_app(LOADER_UWSGI, up.wsgi_lite, uwsgi.wsgi_req, up.main_thread, PYTHON_APP_TYPE_WSGI_LITE);
	}

	if (uwsgi.profiler) {
#ifndef UWSGI_PYPY
		if (!strcmp(uwsgi.profiler, "pycall")) {
			PyEval_SetProfile(uwsgi_python_profiler_call, NULL);
		}
#endif
	}

	PyObject *uwsgi_dict = get_uwsgi_pydict("uwsgi");
        if (uwsgi_dict) {
                up.after_req_hook = PyDict_GetItemString(uwsgi_dict, "after_req_hook");
                if (up.after_req_hook) {
			Py_INCREF(up.after_req_hook);
			up.after_req_hook_args = PyTuple_New(0);
			Py_INCREF(up.after_req_hook_args);
		}
	}

}

void uwsgi_python_master_fixup(int step) {

	static int master_fixed = 0;
	static int worker_fixed = 0;

	if (!uwsgi.master_process) return;

	if (uwsgi.has_threads) {
		if (step == 0) {
			if (!master_fixed) {
				UWSGI_RELEASE_GIL;
				master_fixed = 1;
			}
		}	
		else {
			if (!worker_fixed) {
				UWSGI_GET_GIL;
				worker_fixed = 1;
			}
		}
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

	up.swap_ts = simple_threaded_swap_ts;
	up.reset_ts = simple_threaded_reset_ts;

	if (uwsgi.threads > 1) {
		up.swap_ts = threaded_swap_ts;
		up.reset_ts = threaded_reset_ts;
	}

	uwsgi_log("threads support enabled\n");
	

}

void uwsgi_python_init_thread(int core_id) {

	// set a new ThreadState for each thread
	PyThreadState *pts;
	pts = PyThreadState_New(up.main_thread->interp);
	pthread_setspecific(up.upt_save_key, (void *) pts);
	pthread_setspecific(up.upt_gil_key, (void *) pts);
#ifdef UWSGI_DEBUG
	uwsgi_log("python ThreadState %d = %p\n", core_id, pts);
#endif
	UWSGI_GET_GIL;
	// call threading.currentThread (taken from mod_wsgi, but removes DECREFs as thread in uWSGI are fixed)
	PyObject *threading_module = PyImport_ImportModule("threading");
        if (threading_module) {
        	PyObject *threading_module_dict = PyModule_GetDict(threading_module);
                if (threading_module_dict) {
#ifdef PYTHREE
			PyObject *threading_current = PyDict_GetItemString(threading_module_dict, "current_thread");
#else
			PyObject *threading_current = PyDict_GetItemString(threading_module_dict, "currentThread");
#endif
                        if (threading_current) {
                                PyObject *current_thread = PyEval_CallObject(threading_current, (PyObject *)NULL);
                                if (!current_thread) {
					// ignore the error
                                        PyErr_Clear();
                                }
				else {
					PyObject_SetAttrString(current_thread, "name", PyString_FromFormat("uWSGIWorker%dCore%d", uwsgi.mywid, core_id));
					Py_INCREF(current_thread);
				}
                        }
                }
        }
	UWSGI_RELEASE_GIL;
	

}

#ifndef UWSGI_PYPY
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
#endif

char *uwsgi_python_code_string(char *id, char *code, char *function, char *key, uint16_t keylen) {

	PyObject *cs_module = NULL;
	PyObject *cs_dict = NULL;

	UWSGI_GET_GIL;

	cs_module = PyImport_ImportModule(id);
	if (!cs_module) {
		PyErr_Clear();
		cs_module = uwsgi_pyimport_by_filename(id, code);
	}

	if (!cs_module) {
		UWSGI_RELEASE_GIL;
		return NULL;
	}

	cs_dict = PyModule_GetDict(cs_module);
	if (!cs_dict) {
		PyErr_Print();
		UWSGI_RELEASE_GIL;
		return NULL;
	}
	
	PyObject *func = PyDict_GetItemString(cs_dict, function);
	if (!func) {
		uwsgi_log("function %s not available in %s\n", function, code);
		PyErr_Print();
		UWSGI_RELEASE_GIL;
		return NULL;
	}

	PyObject *args = PyTuple_New(1);

	PyTuple_SetItem(args, 0, PyString_FromStringAndSize(key, keylen));

	PyObject *ret = python_call(func, args, 0, NULL);
	Py_DECREF(args);
	if (ret && PyString_Check(ret)) {
		char *val = PyString_AsString(ret);
		UWSGI_RELEASE_GIL;
		return val;
	}

	UWSGI_RELEASE_GIL;
	return NULL;
	
}

int uwsgi_python_signal_handler(uint8_t sig, void *handler) {

	UWSGI_GET_GIL;

	PyObject *args = PyTuple_New(1);
	PyObject *ret;

	if (!args)
		goto clear;

	if (!handler) goto clear;


	PyTuple_SetItem(args, 0, PyInt_FromLong(sig));

	ret = python_call(handler, args, 0, NULL);
	Py_DECREF(args);
	if (ret) {
		Py_DECREF(ret);
		UWSGI_RELEASE_GIL;
		return 0;
	}

clear:
	UWSGI_RELEASE_GIL;
	return -1;
}

uint16_t uwsgi_python_rpc(void *func, uint8_t argc, char **argv, uint16_t argvs[], char *buffer) {

	UWSGI_GET_GIL;

	uint8_t i;
	char *rv;
	size_t rl;

	PyObject *pyargs = PyTuple_New(argc);
	PyObject *ret;

	if (!pyargs)
		return 0;

	for (i = 0; i < argc; i++) {
		PyTuple_SetItem(pyargs, i, PyString_FromStringAndSize(argv[i], argvs[i]));
	}

	ret = python_call((PyObject *) func, pyargs, 0, NULL);
	Py_DECREF(pyargs);
	if (ret) {
		if (PyString_Check(ret)) {
			rv = PyString_AsString(ret);
			rl = PyString_Size(ret);
			if (rl <= 65536) {
				memcpy(buffer, rv, rl);
				Py_DECREF(ret);
				UWSGI_RELEASE_GIL;
				return rl;
			}
		}
		Py_DECREF(ret);
	}

	if (PyErr_Occurred())
		PyErr_Print();

	UWSGI_RELEASE_GIL;

	return 0;

}

void uwsgi_python_add_item(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	PyObject *pydict = (PyObject *) data;

	PyDict_SetItem(pydict, PyString_FromStringAndSize(key, keylen), PyString_FromStringAndSize(val, vallen));
}

int uwsgi_python_spooler(char *filename, char *buf, uint16_t len, char *body, size_t body_len) {

	static int random_seed_reset = 0;

	UWSGI_GET_GIL;

	PyObject *spool_dict = PyDict_New();
	PyObject *spool_func, *pyargs, *ret;

	if (!random_seed_reset) {
		uwsgi_python_reset_random_seed();
		random_seed_reset = 1;	
	}

	if (!up.embedded_dict) {
		// ignore
		UWSGI_RELEASE_GIL;
		return 0;
	}

	spool_func = PyDict_GetItemString(up.embedded_dict, "spooler");
	if (!spool_func) {
		// ignore
		UWSGI_RELEASE_GIL;
		return 0;
	}

	if (uwsgi_hooked_parse(buf, len, uwsgi_python_add_item, spool_dict)) {
		// malformed packet, destroy it
		UWSGI_RELEASE_GIL;
		return -2;
	}

	pyargs = PyTuple_New(1);

	PyDict_SetItemString(spool_dict, "spooler_task_name", PyString_FromString(filename));

	if (body && body_len > 0) {
		PyDict_SetItemString(spool_dict, "body", PyString_FromStringAndSize(body, body_len));
	}
	PyTuple_SetItem(pyargs, 0, spool_dict);

	ret = python_call(spool_func, pyargs, 0, NULL);

	if (ret) {
		if (!PyInt_Check(ret)) {
			// error, retry
			UWSGI_RELEASE_GIL;
			return -1;
		}	

		int retval = (int) PyInt_AsLong(ret);
		UWSGI_RELEASE_GIL;
		return retval;
		
	}
	
	if (PyErr_Occurred())
		PyErr_Print();

	// error, retry
	UWSGI_RELEASE_GIL;
	return -1;
}

#ifndef UWSGI_PYPY
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
#endif

void uwsgi_python_fixup() {
	// set hacky modifier 30
	uwsgi.p[30] = uwsgi_malloc( sizeof(struct uwsgi_plugin) );
	memcpy(uwsgi.p[30], uwsgi.p[0], sizeof(struct uwsgi_plugin) );
	uwsgi.p[30]->init_thread = NULL;
	uwsgi.p[30]->atexit = NULL;
}

void uwsgi_python_hijack(void) {

	// the pyshell will be execute only in the first worker

	FILE *pyfile;
	if (up.pyrun) {
		uwsgi.workers[uwsgi.mywid].hijacked = 1;
		UWSGI_GET_GIL;
		pyfile = fopen(up.pyrun, "r");
		if (!pyfile) {
			uwsgi_error_open(up.pyrun);
			exit(1);
		}
		PyRun_SimpleFile(pyfile, up.pyrun);	
		// could be never executed
		exit(0);
	}

#ifndef UWSGI_PYPY
	if (up.pyshell_oneshot && uwsgi.workers[uwsgi.mywid].hijacked_count > 0) {
		uwsgi.workers[uwsgi.mywid].hijacked = 0;
		return;
	}
	if (up.pyshell && uwsgi.mywid == 1) {
		uwsgi.workers[uwsgi.mywid].hijacked = 1;
		uwsgi.workers[uwsgi.mywid].hijacked_count++;
		// re-map stdin to stdout and stderr if we are logging to a file
		if (uwsgi.logfile) {
			if (dup2(0, 1) < 0) {
				uwsgi_error("dup2()");
			}
			if (dup2(0, 2) < 0) {
				uwsgi_error("dup2()");
			}
		}
		UWSGI_GET_GIL;
		PyImport_ImportModule("readline");
		int ret = PyRun_InteractiveLoop(stdin, "uwsgi");

		if (up.pyshell_oneshot) {
			exit(UWSGI_DE_HIJACKED_CODE);
		}

		if (ret == 0) {
			exit(UWSGI_QUIET_CODE);
		}
		exit(0);
	}
#endif
}

int uwsgi_python_mule(char *opt) {

	if (uwsgi_endswith(opt, ".py")) {
		UWSGI_GET_GIL;
		if (uwsgi_pyimport_by_filename("__main__", opt) == NULL) {
			return 0;
		}
		UWSGI_RELEASE_GIL;
		return 1;
	}
	
	return 0;
	
}

int uwsgi_python_mule_msg(char *message, size_t len) {

	UWSGI_GET_GIL;

	PyObject *mule_msg_hook = PyDict_GetItemString(up.embedded_dict, "mule_msg_hook");
        if (!mule_msg_hook) {
                // ignore
                UWSGI_RELEASE_GIL;
                return 0;
        }

	PyObject *pyargs = PyTuple_New(1);
        PyTuple_SetItem(pyargs, 0, PyString_FromStringAndSize(message, len));

        PyObject *ret = python_call(mule_msg_hook, pyargs, 0, NULL);
	Py_DECREF(pyargs);
	if (ret) {
		Py_DECREF(ret);
	}

	if (PyErr_Occurred())
                PyErr_Print();

	UWSGI_RELEASE_GIL;
	return 1;
}

struct uwsgi_plugin python_plugin = {

	.name = "python",
	.alias = "python",
	.modifier1 = 0,
	.init = uwsgi_python_init,
	.post_fork = uwsgi_python_post_fork,
	.options = uwsgi_python_options,
	.request = uwsgi_request_wsgi,
	.after_request = uwsgi_after_request_wsgi,

	.preinit_apps = uwsgi_python_preinit_apps,
	.init_apps = uwsgi_python_init_apps,

	.fixup = uwsgi_python_fixup,
	.master_fixup = uwsgi_python_master_fixup,

	.mount_app = uwsgi_python_mount_app,

	.enable_threads = uwsgi_python_enable_threads,
	.init_thread = uwsgi_python_init_thread,

	.magic = uwsgi_python_magic,

#ifndef UWSGI_PYPY
	.suspend = uwsgi_python_suspend,
	.resume = uwsgi_python_resume,
#endif

	.hijack_worker = uwsgi_python_hijack,
	.spooler_init = uwsgi_python_spooler_init,

	.signal_handler = uwsgi_python_signal_handler,
	.rpc = uwsgi_python_rpc,

	.mule = uwsgi_python_mule,
	.mule_msg = uwsgi_python_mule_msg,

	.spooler = uwsgi_python_spooler,

	.atexit = uwsgi_python_atexit,

	.code_string = uwsgi_python_code_string,


};
