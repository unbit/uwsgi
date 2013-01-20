#include "../../uwsgi.h"

int uwsgi_request_notfound(struct wsgi_request *wsgi_req) {

	if (uwsgi_response_prepare_headers(wsgi_req, "404 Not Found", 13)) goto end;	
	if (uwsgi_response_add_header(wsgi_req, "Content-Type", 12, "text/plain", 10)) goto end;
	return uwsgi_response_write_body_do(wsgi_req, "Not Found", 9);
end:
	return UWSGI_OK;
}


struct uwsgi_plugin notfound_plugin = {

	.name = "notfound",
	.request = uwsgi_request_notfound,
};
