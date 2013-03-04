#include <uwsgi.h>

static int dummy_request(struct wsgi_request *wsgi_req) {

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}

	return UWSGI_OK;
}

struct uwsgi_plugin dummy_plugin = {
	.name = "dummy",
	.modifier1 = 0,
	.request = dummy_request,
};
