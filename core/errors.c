#include <uwsgi.h>

// generate internal server error message
void uwsgi_500(struct wsgi_request *wsgi_req) {
	if (uwsgi_response_prepare_headers(wsgi_req, "500 Internal Server Error", 25)) return;
	if (uwsgi_response_add_header(wsgi_req, "Content-Type", 12, "text/plain", 10)) return;
	uwsgi_response_write_body_do(wsgi_req, "Internal Server Error", 21);
}

