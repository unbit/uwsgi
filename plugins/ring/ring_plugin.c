#include <jvm.h>

struct uwsgi_ring {
	char *app;
} uring;

static struct uwsgi_option uwsgi_ring_options[] = {
        {"ring-app", required_argument, 0, "load the specified clojure/ring application", uwsgi_opt_set_str, &uring.app, 0},
        {0, 0, 0, 0},
};

static int uwsgi_ring_request(struct wsgi_request *wsgi_req) {
	uwsgi_log("managing ring request\n");
	return UWSGI_OK;
}

static int uwsgi_ring_setup() {
	uwsgi_log("loading clojure environment...\n");
	return 0;
}

static int uwsgi_ring_init() {
	
	if (uring.app) {
		if (uwsgi_jvm_register_request_handler(1, uwsgi_ring_setup, uwsgi_ring_request)) {
			exit(1);
		}
	}
	return 0;
}

struct uwsgi_plugin ring_plugin = {
	.name = "ring",
	.options = uwsgi_ring_options,
	.init = uwsgi_ring_init,
};
