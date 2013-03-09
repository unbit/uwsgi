#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

static int uwsgi_echo_request(struct wsgi_request *wsgi_req) {

	return uwsgi_response_write_body_do(wsgi_req, wsgi_req->buffer, wsgi_req->uh->pktsize);
}

struct uwsgi_plugin echo_plugin = {

	.name = "echo",
	.modifier1 = 101,
	
	.request = uwsgi_echo_request,
};
