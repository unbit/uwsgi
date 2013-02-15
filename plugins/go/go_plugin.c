#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

void (*uwsgi_go_helper_post_fork_c)();
void (*uwsgi_go_helper_post_init_c)();
void * (*uwsgi_go_helper_env_new_c)(struct wsgi_request *);
void (*uwsgi_go_helper_env_add_c)(void *, char *, int, char *, int);
void (*uwsgi_go_helper_request_c)(void *, struct wsgi_request *);
int (*uwsgi_go_helper_signal_handler_c)(int, void *);
void (*uwsgi_go_helper_run_core_c)(int);
char *(*uwsgi_go_helper_version_c)();

void uwsgi_go_post_fork() {
	uwsgi_go_helper_post_fork_c();
}

void uwsgi_opt_setup_goroutines(char *opt, char *value, void *foobar) {
	// set async mode
        uwsgi_opt_set_int(opt, value, &uwsgi.async);
        // set loop engine
        uwsgi.loop = "goroutines";
}

struct uwsgi_option uwsgi_go_options[] = {
        {"goroutines", required_argument, 0, "a shortcut setting optimal options for goroutine-based apps, takes the number of goroutines to spawn as argument", uwsgi_opt_setup_goroutines, NULL, UWSGI_OPT_THREADS},
        {0, 0, 0, 0, 0, 0, 0},

};

#define uwsgi_go_get_symbol(x)	x ## _c = dlsym(RTLD_DEFAULT, #x);\
				if (!x ## _c) {\
					uwsgi_log("[uwsgi-go] unable to load " #x " function\n"); exit(1);\
				}

static int uwsgi_go_init() {

	// build the functions table

	uwsgi_go_get_symbol(uwsgi_go_helper_post_fork)
	uwsgi_go_get_symbol(uwsgi_go_helper_post_init)
	uwsgi_go_get_symbol(uwsgi_go_helper_env_new)
	uwsgi_go_get_symbol(uwsgi_go_helper_env_add)
	uwsgi_go_get_symbol(uwsgi_go_helper_request)
	uwsgi_go_get_symbol(uwsgi_go_helper_signal_handler)
	uwsgi_go_get_symbol(uwsgi_go_helper_run_core)
	uwsgi_go_get_symbol(uwsgi_go_helper_version)

	uwsgi_log("Go version \"%s\" initialized\n", uwsgi_go_helper_version_c());

	// call PostInit()
	uwsgi_go_helper_post_init_c();

	return 0;
}

static int uwsgi_go_request(struct wsgi_request *wsgi_req) {
	/* Standard GO request */
        if (!wsgi_req->uh->pktsize) {
                uwsgi_log("Empty GO request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }

	wsgi_req->async_environ = uwsgi_go_helper_env_new_c(wsgi_req);
	int i;
	for(i=0;i<wsgi_req->var_cnt;i++) {
        	uwsgi_go_helper_env_add_c(wsgi_req->async_environ, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, 
					wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len);
		i++;
	}


	uwsgi_go_helper_request_c(wsgi_req->async_environ, wsgi_req);

	return UWSGI_OK;
}

static void uwsgi_go_after_request(struct wsgi_request *wsgi_req) {

        log_request(wsgi_req);

}

static int uwsgi_go_signal_handler(uint8_t signum, void *handler) {
	return uwsgi_go_helper_signal_handler_c((int)signum, handler);
}

static void goroutines_loop() {
	int i;
	for (i = 1; i < uwsgi.async; i++) {
		uwsgi_go_helper_run_core_c(i);
	}
	simple_loop_run_int(0);
}

static void uwsgi_go_on_load() {
	uwsgi_register_loop("goroutines", goroutines_loop);
}

struct uwsgi_plugin go_plugin = {
	.name = "go",
	.modifier1 = 11,
	.request = uwsgi_go_request,
	.after_request = uwsgi_go_after_request,
	.post_fork = uwsgi_go_post_fork,
	.init = uwsgi_go_init,
	.signal_handler = uwsgi_go_signal_handler,
	.on_load = uwsgi_go_on_load,
	.options = uwsgi_go_options,
};
