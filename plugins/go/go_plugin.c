#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

void (*uwsgi_go_helper_post_fork_c)();
void (*uwsgi_go_helper_post_init_c)();
void * (*uwsgi_go_helper_env_new_c)();
void (*uwsgi_go_helper_env_add_c)(void *, char *, int, char *, int);
void (*uwsgi_go_helper_request_c)(void *, struct wsgi_request *);
int (*uwsgi_go_helper_signal_handler_c)(int, void *);
void (*uwsgi_go_helper_run_core_c)(int);

void uwsgi_go_post_fork() {
	uwsgi_go_helper_post_fork_c();
}

int uwsgi_go_init() {
	// build the functions table
	uwsgi_go_helper_post_fork_c = dlsym(RTLD_DEFAULT, "uwsgi_go_helper_post_fork");
	if (!uwsgi_go_helper_post_fork_c) { uwsgi_log("[uwsgi-go] unable to load uwsgi_go_helper_post_fork function\n"); exit(1); }

	uwsgi_go_helper_post_init_c = dlsym(RTLD_DEFAULT, "uwsgi_go_helper_post_init");
	if (!uwsgi_go_helper_post_init_c) { uwsgi_log("[uwsgi-go] unable to load uwsgi_go_helper_post_init function\n"); exit(1); }

	uwsgi_go_helper_env_new_c = dlsym(RTLD_DEFAULT, "uwsgi_go_helper_env_new");
	if (!uwsgi_go_helper_env_new_c) { uwsgi_log("[uwsgi-go] unable to load uwsgi_go_helper_env_new function\n"); exit(1); }

	uwsgi_go_helper_env_add_c = dlsym(RTLD_DEFAULT, "uwsgi_go_helper_env_add");
	if (!uwsgi_go_helper_env_add_c) { uwsgi_log("[uwsgi-go] unable to load uwsgi_go_helper_env_add function\n"); exit(1); }

	uwsgi_go_helper_request_c = dlsym(RTLD_DEFAULT, "uwsgi_go_helper_request");
	if (!uwsgi_go_helper_request_c) { uwsgi_log("[uwsgi-go] unable to load uwsgi_go_helper_request function\n"); exit(1); }

	uwsgi_go_helper_signal_handler_c = dlsym(RTLD_DEFAULT, "uwsgi_go_helper_signal_handler");
	if (!uwsgi_go_helper_signal_handler_c) { uwsgi_log("[uwsgi-go] unable to load uwsgi_go_helper_signal_handler function\n"); exit(1); }

	uwsgi_go_helper_run_core_c = dlsym(RTLD_DEFAULT, "uwsgi_go_helper_run_core");
	if (!uwsgi_go_helper_run_core_c) { uwsgi_log("[uwsgi-go] unable to load uwsgi_go_helper_run_core function\n"); exit(1); }

	// call PostInit()
	uwsgi_go_helper_post_init_c();

	return 0;
}

int uwsgi_go_request(struct wsgi_request *wsgi_req) {
	/* Standard GO request */
        if (!wsgi_req->uh.pktsize) {
                uwsgi_log("Invalid GO request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }

	void *env = uwsgi_go_helper_env_new_c();
	int i;
	for(i=0;i<wsgi_req->var_cnt;i++) {
        	uwsgi_go_helper_env_add_c(env, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, 
					wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len);
		i++;
	}

	uwsgi_go_helper_request_c(env, wsgi_req);

	return UWSGI_OK;
}

void uwsgi_go_after_request(struct wsgi_request *wsgi_req) {

        log_request(wsgi_req);

}

int uwsgi_go_signal_handler(uint8_t signum, void *handler) {
	return uwsgi_go_helper_signal_handler_c((int)signum, handler);
}

void goroutines_loop() {
	int i;
	for (i = 1; i < uwsgi.async; i++) {
		uwsgi_go_helper_run_core_c(i);
	}
	long y = 0;
        simple_loop_run((void *) y);
}

void uwsgi_go_on_load() {
	uwsgi_register_loop("goroutines", goroutines_loop);
}

struct uwsgi_plugin go_plugin = {
	.name = "go",
	.modifier1 = 17,
	.request = uwsgi_go_request,
	.after_request = uwsgi_go_after_request,
	.post_fork = uwsgi_go_post_fork,
	.init = uwsgi_go_init,
	.signal_handler = uwsgi_go_signal_handler,
	.on_load = uwsgi_go_on_load,
};
