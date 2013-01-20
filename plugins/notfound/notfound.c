#include <uwsgi.h>

static int uwsgi_request_notfound(struct wsgi_request *wsgi_req) {

	uwsgi_404(wsgi_req);
	return UWSGI_OK;
}


struct uwsgi_plugin notfound_plugin = {

	.name = "notfound",
	.request = uwsgi_request_notfound,
};
