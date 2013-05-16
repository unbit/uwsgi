
/*******************************************************************

 This is the C part of the PyPy plugin (with the main logic being in
 Python, see plugin_setup.py), written by Maciej Fijalkowski,
 heavily based on python_plugin.c

 *******************************************************************/

#include <uwsgi.h>

struct uwsgi_pypy {
	void *handler;
	char *lib;
	char *home;
	char *wsgi;
} upypy;

// the functions exposed by libpypy-c
char *(*rpython_startup_code)(void);
int (*pypy_setup_home)(char *, int);
int (*pypy_execute_source)(char *);

// the hooks you can override with pypy
void (*uwsgi_pypy_hook_loader)(char *);
void (*uwsgi_pypy_hook_request)(void *);

extern struct uwsgi_server uwsgi;

int uwsgi_pypy_helper_vars(void *r) {
	struct wsgi_request *wsgi_req = (struct wsgi_request *) r;
	return wsgi_req->var_cnt/2;
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
	
	rpython_startup_code();
	if (pypy_setup_home(upypy.home, 1)) {
                uwsgi_error("unable to set pypy home\n");
		exit(1);
        }

	size_t rlen = 0;
	char *buffer = uwsgi_open_and_read("pypy_setup.py", &rlen, 1, NULL);
	pypy_execute_source(buffer);
/*
	if (!uwsgi_pypy_settings.homedir) {
		uwsgi_pypy_settings.homedir = getenv("PYPY_HOME");
	}
	if (!uwsgi_pypy_settings.homedir) {
		uwsgi_error("PYPY_HOME environment variable not set and pypy-home option not provided");
		return 1;
	}
	rpython_startup_code();
	buffer = (char *) malloc(strlen(uwsgi_pypy_settings.homedir) + strlen("pypy") + 2);
	sprintf(buffer, "%s%s", uwsgi_pypy_settings.homedir, "pypy");
	if (pypy_setup_home(buffer, 1)) {
		uwsgi_error("Failed to set up pypyhome\n");
	}
	free(buffer);
	buffer = (char *) malloc(strlen(initial_source_format) + strlen(uwsgi.binary_path) + 2);
	sprintf(buffer, initial_source_format, uwsgi.binary_path);
	pypy_execute_source(buffer);
	free(buffer);
	return 0;
*/
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
	{"pypy-home", required_argument, 0, "set the home of pypy library", uwsgi_opt_set_str, &upypy.home, 0},
	{"pypy-wsgi", required_argument, 'w', "load a WSGI module", uwsgi_opt_set_str, &upypy.wsgi, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

struct uwsgi_plugin pypy_plugin = {
	.name = "pypy",
	.modifier1 = 0,
	.init = uwsgi_pypy_init,
	.request = uwsgi_pypy_request,
	.after_request = uwsgi_pypy_after_request,
	.options = uwsgi_pypy_options,
	.init_apps = uwsgi_pypy_init_apps,
};
