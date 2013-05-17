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
} upypy;

// the functions exposed by libpypy-c
char *(*rpython_startup_code)(void);
int (*pypy_setup_home)(char *, int);
int (*pypy_execute_source)(char *);
void (*pypy_thread_attach)(void);

// the hooks you can override with pypy
void (*uwsgi_pypy_hook_loader)(char *);
void (*uwsgi_pypy_hook_request)(void *);

extern struct uwsgi_server uwsgi;

int uwsgi_pypy_helper_vars(void *r) {
	struct wsgi_request *wsgi_req = (struct wsgi_request *) r;
	return wsgi_req->var_cnt;
}

char *uwsgi_pypy_helper_key(void *r, int pos) {
	struct wsgi_request *wsgi_req = (struct wsgi_request *) r;
	return wsgi_req->hvec[pos].iov_base;
}

int uwsgi_pypy_helper_keylen(void *r, int pos) {
	struct wsgi_request *wsgi_req = (struct wsgi_request *) r;
	return wsgi_req->hvec[pos].iov_len;
}

char *uwsgi_pypy_helper_val(void *r, int pos) {
	struct wsgi_request *wsgi_req = (struct wsgi_request *) r;
	return wsgi_req->hvec[pos+1].iov_base;
}

int uwsgi_pypy_helper_vallen(void *r, int pos) {
	struct wsgi_request *wsgi_req = (struct wsgi_request *) r;
	return wsgi_req->hvec[pos+1].iov_len;
}

void uwsgi_pypy_helper_status(void *r, char *status, int status_len) {
	struct wsgi_request *wsgi_req = (struct wsgi_request *) r;
	uwsgi_response_prepare_headers(wsgi_req, status, status_len);
}

void uwsgi_pypy_helper_header(void *r, char *k, int kl, char *v, int vl) {
	struct wsgi_request *wsgi_req = (struct wsgi_request *) r;
	uwsgi_response_add_header(wsgi_req, k, kl, v, vl);
}

void uwsgi_pypy_helper_write(void *r, char *body, int len) {
	struct wsgi_request *wsgi_req = (struct wsgi_request *) r;
	uwsgi_response_write_body_do(wsgi_req, body, len);
}

static int uwsgi_pypy_init() {

	if (upypy.lib) {
		upypy.handler = dlopen(upypy.lib, RTLD_NOW | RTLD_GLOBAL);
	}
	else {
		upypy.handler = dlopen("libpypy-c.so", RTLD_NOW | RTLD_GLOBAL);
	}

	if (!upypy.handler) {
		uwsgi_log("unable to load pypy library: %s\n", dlerror());
		exit(1);
	}

	rpython_startup_code = dlsym(upypy.handler, "rpython_startup_code");
	if (!rpython_startup_code) {
		uwsgi_log("unable to find rpython_startup_code() symbol\n");
		exit(1);
	}

	pypy_setup_home = dlsym(upypy.handler, "pypy_setup_home");
	if (!pypy_setup_home) {
		uwsgi_log("unable to find pypy_setup_home() symbol\n");
		exit(1);
	}

	pypy_execute_source = dlsym(upypy.handler, "pypy_execute_source");
	if (!pypy_execute_source) {
		uwsgi_log("unable to find pypy_execute_source() symbol\n");
		exit(1);
	}

	pypy_thread_attach = dlsym(upypy.handler, "pypy_thread_attach");
        if (!pypy_thread_attach) {
                uwsgi_log("!!! WARNING your libpypy-c does not export pypy_thread_attach, multithreading will not work !!!\n");
        }
	
	rpython_startup_code();

	if (!upypy.home) {
		upypy.home = getenv("PYPY_HOME");
		if (!upypy.home) {
			uwsgi_log("you have to specify a pypy home with --pypy-home\n");
			exit(1);
		}
	}
	if (pypy_setup_home(upypy.home, 1)) {
                uwsgi_log("unable to set pypy home to \"%s\"\n", upypy.home);
		exit(1);
        }

	size_t rlen = 0;
	char *buffer = NULL;
	if (upypy.setup) {
		buffer = uwsgi_open_and_read(upypy.setup, &rlen, 1, NULL);
	}
	else {
		char *start = dlsym(RTLD_DEFAULT, "uwsgi_pypy_setup_start");
		char *end = dlsym(RTLD_DEFAULT, "uwsgi_pypy_setup_end");
		if (start && end) {
			buffer = uwsgi_concat2n(start, end-start, "", 0);
		}
	}

	if (!buffer) {
		uwsgi_log("you have to load a pypy setup file with --pypy-setup\n");
		exit(1);
	}
	pypy_execute_source(buffer);
	return 0;
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
		uwsgi_pypy_hook_request(wsgi_req);
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
}

/*
static void uwsgi_pypy_atexit() {
	if (pypy_debug_file)
		fflush(pypy_debug_file);
}
*/

static struct uwsgi_option uwsgi_pypy_options[] = {
	{"pypy-lib", required_argument, 0, "set the path/name of the pypy library", uwsgi_opt_set_str, &upypy.lib, 0},
	{"pypy-setup", required_argument, 0, "set the path of the python setup script", uwsgi_opt_set_str, &upypy.setup, 0},
	{"pypy-home", required_argument, 0, "set the home of pypy library", uwsgi_opt_set_str, &upypy.home, 0},
	{"pypy-wsgi", required_argument, 'w', "load a WSGI module", uwsgi_opt_set_str, &upypy.wsgi, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

static void uwsgi_pypy_init_thread() {
	if (pypy_thread_attach) {
		pypy_thread_attach();
	}
}

struct uwsgi_plugin pypy_plugin = {
	.name = "pypy",
	.modifier1 = 0,
	.init = uwsgi_pypy_init,
	.request = uwsgi_pypy_request,
	.after_request = uwsgi_pypy_after_request,
	.options = uwsgi_pypy_options,
	.init_apps = uwsgi_pypy_init_apps,
	.init_thread = uwsgi_pypy_init_thread,
};
