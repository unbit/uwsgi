/*******************************************************************

 This is the C part of the PyPy plugin (with the main logic being in
 Python, see pypy_setup.py).

 Idea and initial implementation by Maciej Fijalkowski

 *******************************************************************/

#include <uwsgi.h>

struct uwsgi_pypy {
	void *handler;
	char *lib;
	char *setup;
	char *home;
	char *wsgi;
	char *wsgi_file;
	char *paste;
	struct uwsgi_string_list *eval;
	struct uwsgi_string_list *eval_post_fork;
	struct uwsgi_string_list *exec;
	struct uwsgi_string_list *exec_post_fork;

	struct uwsgi_string_list *pp;

	pthread_mutex_t attach_thread_lock;
} upypy;

// the functions exposed by libpypy-c
char *(*u_rpython_startup_code)(void);
int (*u_pypy_setup_home)(char *, int);
int (*u_pypy_execute_source)(char *);
void (*u_pypy_thread_attach)(void);
void (*u_pypy_init_threads)(void);

// the hooks you can override with pypy
void (*uwsgi_pypy_hook_execute_source)(char *);
void (*uwsgi_pypy_hook_loader)(char *);
void (*uwsgi_pypy_hook_file_loader)(char *);
void (*uwsgi_pypy_hook_paste_loader)(char *);
void (*uwsgi_pypy_hook_pythonpath)(char *);
void (*uwsgi_pypy_hook_request)(void *, int);
void (*uwsgi_pypy_post_fork_hook)(void);

extern struct uwsgi_server uwsgi;
struct uwsgi_plugin pypy_plugin;

static int uwsgi_pypy_init() {

	size_t rlen = 0;
	char *buffer = NULL;

	void *is_cpython_loaded = dlsym(RTLD_DEFAULT, "Py_Initialize");
	if (is_cpython_loaded) {
		uwsgi_log("!!! Loading both PyPy and CPython in the same process IS PURE EVIL AND IT IS NOT SUPPORTED !!!\n");
		exit(1);
	}

	if (dlsym(RTLD_DEFAULT, "rpython_startup_code")) {
		uwsgi_log("PyPy runtime detected, skipping libpypy-c loading\n");
		goto ready;
	}
	else if (upypy.lib) {
		upypy.handler = dlopen(upypy.lib, RTLD_NOW | RTLD_GLOBAL);
	}
	else {
		if (upypy.home) {
			// first try with /bin way:
#ifdef __CYGWIN__
                        char *libpath = uwsgi_concat2(upypy.home, "/bin/libpypy-c.dll");
#elif defined(__APPLE__)
                        char *libpath = uwsgi_concat2(upypy.home, "/bin/libpypy-c.dylib");
#else
                        char *libpath = uwsgi_concat2(upypy.home, "/bin/libpypy-c.so");
#endif
			if (uwsgi_file_exists(libpath)) {
                                upypy.handler = dlopen(libpath, RTLD_NOW | RTLD_GLOBAL);
                        }
                        free(libpath);

			// fallback to old-style way
			if (!upypy.handler) {
			
#ifdef __CYGWIN__
                        	char *libpath = uwsgi_concat2(upypy.home, "/libpypy-c.dll");
#elif defined(__APPLE__)
                        	char *libpath = uwsgi_concat2(upypy.home, "/libpypy-c.dylib");
#else
                        	char *libpath = uwsgi_concat2(upypy.home, "/libpypy-c.so");
#endif
				if (uwsgi_file_exists(libpath)) {
					upypy.handler = dlopen(libpath, RTLD_NOW | RTLD_GLOBAL);
				}
				free(libpath);
			}
		}
		// fallback to standard library search path
		if (!upypy.handler) {
#ifdef __CYGWIN__
			upypy.handler = dlopen("libpypy-c.dll", RTLD_NOW | RTLD_GLOBAL);
#elif defined(__APPLE__)
			upypy.handler = dlopen("libpypy-c.dylib", RTLD_NOW | RTLD_GLOBAL);
#else
			upypy.handler = dlopen("libpypy-c.so", RTLD_NOW | RTLD_GLOBAL);
#endif
		}
	}

	if (!upypy.handler) {
		uwsgi_log("unable to load pypy library: %s\n", dlerror());
		exit(1);
	}

	u_rpython_startup_code = dlsym(upypy.handler, "rpython_startup_code");
	if (!u_rpython_startup_code) {
		uwsgi_log("unable to find rpython_startup_code() symbol\n");
		exit(1);
	}

	u_pypy_setup_home = dlsym(upypy.handler, "pypy_setup_home");
	if (!u_pypy_setup_home) {
		uwsgi_log("unable to find pypy_setup_home() symbol\n");
		exit(1);
	}

	u_pypy_init_threads = dlsym(upypy.handler, "pypy_init_threads");
        if (!u_pypy_init_threads) {
                uwsgi_log("!!! WARNING your libpypy-c does not export pypy_init_threads, multithreading will not work !!!\n");
        }
	
	u_rpython_startup_code();

	if (!upypy.home) {
		upypy.home = getenv("PYPY_HOME");
		if (!upypy.home) {
			uwsgi_log("you have to specify a pypy home with --pypy-home\n");
			exit(1);
		}
	}

	if (u_pypy_setup_home(upypy.home, 0)) {
		char *retry = uwsgi_concat2(upypy.home, "/lib_pypy");
		if (uwsgi_is_dir(retry)) {
			// this time we use debug
			if (!u_pypy_setup_home(retry, 1)) {
				free(retry);
				goto ready;
			}
		}
                uwsgi_log("unable to set pypy home to \"%s\"\n", upypy.home);
		exit(1);
        }

ready:
	u_pypy_execute_source = dlsym(upypy.handler, "pypy_execute_source");
	if (!u_pypy_execute_source) {
		uwsgi_log("unable to find pypy_execute_source() symbol\n");
		exit(1);
	}

	u_pypy_thread_attach = dlsym(upypy.handler, "pypy_thread_attach");
        if (!u_pypy_thread_attach) {
                uwsgi_log("!!! WARNING your libpypy-c does not export pypy_thread_attach, multithreading will not work !!!\n");
        }

	if (upypy.setup) {
		buffer = uwsgi_open_and_read(upypy.setup, &rlen, 1, NULL);
	}
	else {
		char *start = dlsym(RTLD_DEFAULT, "uwsgi_pypy_setup_start");
		if (!start) {
			start = dlsym(RTLD_DEFAULT, "_uwsgi_pypy_setup_start");
		}
		char *end = dlsym(RTLD_DEFAULT, "uwsgi_pypy_setup_end");
		if (!end) {
			end = dlsym(RTLD_DEFAULT, "_uwsgi_pypy_setup_end");
		}
		if (start && end) {
			buffer = uwsgi_concat2n(start, end-start, "", 0);
		}
	}

	if (!buffer) {
		uwsgi_log("you have to load a pypy setup file with --pypy-setup\n");
		exit(1);
	}
	if (u_pypy_execute_source(buffer)) {
		exit(1);
	}
	free(buffer);

	// add items to the pythonpath
	struct uwsgi_string_list *usl = upypy.pp;
	while(usl) {
		if (uwsgi_pypy_hook_pythonpath) {
			uwsgi_pypy_hook_pythonpath(usl->value);
		}
		usl = usl->next;
	}

	return 0;
}

static void uwsgi_pypy_preinit_apps() {

	if (!uwsgi_pypy_hook_execute_source) {
		uwsgi_log("*** WARNING your pypy setup code does not expose a callback for \"execute_source\" ***\n");
		return;
	}

	struct uwsgi_string_list *usl = NULL;
	uwsgi_foreach(usl, upypy.eval) {
		uwsgi_pypy_hook_execute_source(usl->value);
	}

	uwsgi_foreach(usl, upypy.exec) {
		size_t rlen = 0;
		char *buffer = uwsgi_open_and_read(usl->value, &rlen, 1, NULL);
		uwsgi_pypy_hook_execute_source(buffer);
		free(buffer);
	}
}

static int uwsgi_pypy_request(struct wsgi_request *wsgi_req) {
	/* Standard WSGI request */
        if (!wsgi_req->uh->pktsize) {
                uwsgi_log( "Empty pypy request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }

	if (uwsgi_pypy_hook_request) {
		uwsgi_pypy_hook_request(wsgi_req, wsgi_req->async_id);
	}
	return UWSGI_OK;
}

static void uwsgi_pypy_after_request(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

static void uwsgi_pypy_init_apps() {
	if (uwsgi_pypy_hook_loader && upypy.wsgi) {
		uwsgi_pypy_hook_loader(upypy.wsgi);
	}

	if (uwsgi_pypy_hook_file_loader && upypy.wsgi_file) {
		uwsgi_pypy_hook_file_loader(upypy.wsgi_file);
	}

	if (uwsgi_pypy_hook_paste_loader && upypy.paste) {
		uwsgi_pypy_hook_paste_loader(upypy.paste);
	}
}

/*
static void uwsgi_pypy_atexit() {
	if (pypy_debug_file)
		fflush(pypy_debug_file);
}
*/

static void uwsgi_opt_pypy_ini_paste(char *opt, char *value, void *foobar) {
        uwsgi_opt_load_ini(opt, value, NULL);
        upypy.paste = value;
}


static struct uwsgi_option uwsgi_pypy_options[] = {
	{"pypy-lib", required_argument, 0, "set the path/name of the pypy library", uwsgi_opt_set_str, &upypy.lib, 0},
	{"pypy-setup", required_argument, 0, "set the path of the python setup script", uwsgi_opt_set_str, &upypy.setup, 0},
	{"pypy-home", required_argument, 0, "set the home of pypy library", uwsgi_opt_set_str, &upypy.home, 0},
	{"pypy-wsgi", required_argument, 0, "load a WSGI module", uwsgi_opt_set_str, &upypy.wsgi, 0},
	{"pypy-wsgi-file", required_argument, 0, "load a WSGI/mod_wsgi file", uwsgi_opt_set_str, &upypy.wsgi_file, 0},
	{"pypy-ini-paste", required_argument, 0, "load a paste.deploy config file containing uwsgi section", uwsgi_opt_pypy_ini_paste, NULL, UWSGI_OPT_IMMEDIATE},
	{"pypy-paste", required_argument, 0, "load a paste.deploy config file", uwsgi_opt_set_str, &upypy.paste, 0},
	{"pypy-eval", required_argument, 0, "evaluate pypy code before fork()", uwsgi_opt_add_string_list, &upypy.eval, 0},
	{"pypy-eval-post-fork", required_argument, 0, "evaluate pypy code soon after fork()", uwsgi_opt_add_string_list, &upypy.eval_post_fork, 0},
	{"pypy-exec", required_argument, 0, "execute pypy code from file before fork()", uwsgi_opt_add_string_list, &upypy.exec, 0},
	{"pypy-exec-post-fork", required_argument, 0, "execute pypy code from file soon after fork()", uwsgi_opt_add_string_list, &upypy.exec_post_fork, 0},
	{"pypy-pp", required_argument, 0, "add an item to the pythonpath", uwsgi_opt_add_string_list, &upypy.pp, 0},
	{"pypy-python-path", required_argument, 0, "add an item to the pythonpath", uwsgi_opt_add_string_list, &upypy.pp, 0},
	{"pypy-pythonpath", required_argument, 0, "add an item to the pythonpath", uwsgi_opt_add_string_list, &upypy.pp, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

static void uwsgi_pypy_enable_threads() {
	if (u_pypy_init_threads) {
		u_pypy_init_threads();
	}
}

static void uwsgi_pypy_init_thread(int sig) {
	if (u_pypy_thread_attach) {
		pthread_mutex_lock(&upypy.attach_thread_lock);
		u_pypy_thread_attach();
		pthread_mutex_unlock(&upypy.attach_thread_lock);
	}
}

static int uwsgi_pypy_signal_handler(uint8_t sig, void *handler) {
	void (*pypy_func)(int) = (void(*)(int)) handler;
	pypy_func(sig);
	return 0;
}

static uint64_t uwsgi_pypy_rpc(void *func, uint8_t argc, char **argv, uint16_t argvs[], char **buffer) {
	int iargvs[UMAX8];
	int i;
	int (*pypy_func)(int, char **, int*, char **) = (int (*)(int, char **, int*, char **)) func;
	// we convert 16bit to int
	for(i=0;i<argc;i++) {
		iargvs[i] = (int) argvs[i]; 
	}
	return pypy_func(argc, argv, iargvs, buffer);
}

static void uwsgi_pypy_post_fork() {
	pthread_mutex_init(&upypy.attach_thread_lock, NULL);
	struct uwsgi_string_list *usl = NULL;
	uwsgi_foreach(usl, upypy.eval_post_fork) {
                uwsgi_pypy_hook_execute_source(usl->value);
        }
	uwsgi_foreach(usl, upypy.exec_post_fork) {
                size_t rlen = 0;
                char *buffer = uwsgi_open_and_read(usl->value, &rlen, 1, NULL);
                uwsgi_pypy_hook_execute_source(buffer);
                free(buffer);
        }

	if (uwsgi_pypy_post_fork_hook) {
		uwsgi_pypy_post_fork_hook();
	}
}

static void uwsgi_pypy_onload() {
#ifdef UWSGI_PYPY_HOME
	upypy.home = UWSGI_PYPY_HOME;
#endif
	uwsgi.has_threads = 1;
}

static int uwsgi_pypy_mule(char *opt) {

	if (!uwsgi_pypy_hook_execute_source) {
		uwsgi_log("!!! no \"execute_source\" callback in your pypy setup code !!!\n");
		exit(1);
	}

        if (uwsgi_endswith(opt, ".py")) {
                size_t rlen = 0;
                char *buffer = uwsgi_open_and_read(opt, &rlen, 1, NULL);
                uwsgi_pypy_hook_execute_source(buffer);
		free(buffer);
                return 1;
        }
        return 0;

}


struct uwsgi_plugin pypy_plugin = {
	.name = "pypy",
	.modifier1 = 0,
	.on_load = uwsgi_pypy_onload,
	.init = uwsgi_pypy_init,
	.request = uwsgi_pypy_request,
	.after_request = uwsgi_pypy_after_request,
	.options = uwsgi_pypy_options,
	.preinit_apps = uwsgi_pypy_preinit_apps,
	.init_apps = uwsgi_pypy_init_apps,
	.init_thread = uwsgi_pypy_init_thread,
	.signal_handler = uwsgi_pypy_signal_handler,
	.enable_threads = uwsgi_pypy_enable_threads,
	.rpc = uwsgi_pypy_rpc,
	.post_fork = uwsgi_pypy_post_fork,
	.mule = uwsgi_pypy_mule,
};
