
#include <uwsgi.h>
#include <uwsgi_pypy.h>

// XXX the following should be auto-generated but it's small enough
// I don't quite care

struct uwsgi_pypy uwsgi_pypy_settings = {
  .homedir = NULL,  
};

char* rpython_startup_code();
int pypy_setup_home(char *homedir, int verbose);
int pypy_execute_source(char *source);

extern struct uwsgi_server uwsgi;

const char* initial_source_format = "import sys, os; sys.path.insert(0, os.path.join(os.path.join(os.path.dirname('%s'), 'plugins'), 'pypy')); import plugin_setup";

static int uwsgi_pypy_init(){
  char *buffer;

  if (!uwsgi_pypy_settings.homedir) {
	uwsgi_pypy_settings.homedir = getenv("PYPY_HOME");
  }
  if (!uwsgi_pypy_settings.homedir) {
	uwsgi_error("PYPY_HOME environment variable not set and pypy-home option not provided");
	return 1;
  }
  rpython_startup_code();
  buffer = (char*)malloc(strlen(uwsgi_pypy_settings.homedir) + strlen("pypy") + 2);
  sprintf(buffer, "%s%s", uwsgi_pypy_settings.homedir, "pypy");
  if (pypy_setup_home(buffer, 1)) {
	uwsgi_error("Failed to set up pypyhome\n");
  }
  free(buffer);
  buffer = (char*)malloc(strlen(initial_source_format) +
						 strlen(uwsgi.binary_path) + 2);
  sprintf(buffer, initial_source_format, uwsgi.binary_path);
  pypy_execute_source(buffer);
  free(buffer);
  return 0;
}

int uwsgi_dummy_request(struct wsgi_request *wsgi_req) {
  // this is a placeholder so function does not stay empty
  return 0;
}

void uwsgi_dummy_after_request(struct wsgi_request *wsgi_req)
{
  // this is a placeholder so function does not stay empty  
}

void uwsgi_dummy_init_apps()
{
  // this is a placeholder so function does not stay empty  
}

void uwsgi_dummy_preinit_apps()
{
  // this is a placeholder so function does not stay empty  
}

struct uwsgi_option uwsgi_pypy_options[] = {
  {"pypy-home", required_argument, 0, "set the home of pypy library (required)",
   uwsgi_opt_set_str, &uwsgi_pypy_settings.homedir, 0},
  {"wsgi", required_argument, 'w', "load a WSGI module", uwsgi_opt_set_str,
   &uwsgi_pypy_settings.wsgi_app, 0},
  {0, 0, 0, 0, 0, 0, 0},
};

struct uwsgi_plugin pypy_plugin = {

        .name = "pypy",
        .modifier1 = 0,
        .init = uwsgi_pypy_init,
        .request = uwsgi_dummy_request,
        .after_request = uwsgi_dummy_after_request,
		.options = uwsgi_pypy_options,
		.init_apps = uwsgi_dummy_init_apps,
		.preinit_apps = uwsgi_dummy_preinit_apps,
};
