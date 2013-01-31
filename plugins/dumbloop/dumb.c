#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

// global variables for configuration
static uint8_t dumbloop_modifier1 = 0;
static char *dumbloop_code = "";
static char *dumbloop_function = "dumbloop";

struct uwsgi_option dumbloop_options[] = {
        {"dumbloop-modifier1", required_argument, 0, "set the modifier1 for the code_string", uwsgi_opt_set_int, &dumbloop_modifier1, 0},
        {"dumbloop-code", required_argument, 0, "set the script to load for the code_string", uwsgi_opt_set_str, &dumbloop_code, 0},
        {"dumbloop-function", required_argument, 0, "set the function to run for the code_string", uwsgi_opt_set_str, &dumbloop_function, 0},
        {0, 0, 0, 0, 0, 0, 0},

};


// this function is executed for each thread
static void *dumb_loop_run(void *arg1) {

	// get the core id (pthreads take a void pointer as argument, so we need this ugly trick)
        long core_id = (long) arg1;

	// complete threads setup (this is required for fixing things like UNIX signal handling)
        if (uwsgi.threads > 1) {
		// wsgi_request mapped to the core
        	struct wsgi_request *wsgi_req = &uwsgi.workers[uwsgi.mywid].cores[core_id].req;
		// fix it
                uwsgi_setup_thread_req(core_id, wsgi_req);
        }

	// this strign will be passed to the code_string function
	char *str_core = uwsgi_num2str(core_id);
        // ok we are ready, let's run custom code
        while (uwsgi.workers[uwsgi.mywid].manage_next_request) {
        	if (uwsgi.p[dumbloop_modifier1]->code_string) {
			// "uwsgi_dumbloop" is the name of the module (will be used while importing the file, if needed)
                	uwsgi.p[dumbloop_modifier1]->code_string("uwsgi_dumbloop", dumbloop_code, dumbloop_function, str_core, strlen(str_core));
                }
		else {
			uwsgi_log("the requested plugin does not support code_string hook\n");
			exit(1);
		}
	}

	return NULL;
}

static void dumb_loop() {
	// this run the dumb_loop_run in each thread (core)
	uwsgi_loop_cores_run(dumb_loop_run);
}



// register the new loop engine
static void dumbloop_register() {
	uwsgi_register_loop( (char *) "dumb", dumb_loop);
}


struct uwsgi_plugin dumbloop_plugin = {
	.name = "dumbloop",
	.on_load = dumbloop_register,
	.options = dumbloop_options,
};
