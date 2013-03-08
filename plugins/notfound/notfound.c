#include <uwsgi.h>

static int uwsgi_notfound_log_enabled = 0;

struct uwsgi_option uwsgi_notfound_options[] = {
	{"notfound-log", no_argument, 0, "log requests to the notfound plugin", uwsgi_opt_true, &uwsgi_notfound_log_enabled, 0},
	{NULL, 0, 0, NULL, NULL, NULL, 0},
};

static int uwsgi_request_notfound(struct wsgi_request *wsgi_req) {
	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}
	uwsgi_404(wsgi_req);
	return UWSGI_OK;
}

static void uwsgi_notfound_log(struct wsgi_request *wsgi_req) {
	if (uwsgi_notfound_log_enabled) {
		log_request(wsgi_req);
	}
}

struct uwsgi_plugin notfound_plugin = {
	.name = "notfound",
	.options = uwsgi_notfound_options,
	.request = uwsgi_request_notfound,
	.after_request = uwsgi_notfound_log,
};
