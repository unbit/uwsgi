#include "../../uwsgi.h"

#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

int uwsgi_routing_func_redirect(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

        struct iovec iov[4];

        if (wsgi_req->protocol_len > 0) {
        	iov[0].iov_base = wsgi_req->protocol;
        	iov[0].iov_len = wsgi_req->protocol_len;
	}
	else {
        	iov[0].iov_base = "HTTP/1.0";
        	iov[0].iov_len = 8;
	}

        iov[1].iov_base = " 302 Found\r\nLocation: ";
        iov[1].iov_len = 22;

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

	iov[2].iov_base = uwsgi_regexp_apply_ovec(*subject, *subject_len, ur->data, ur->data_len, ur->ovector, ur->ovn);
	iov[2].iov_len = strlen(iov[2].iov_base);

	iov[3].iov_base = "\r\n\r\n";
	iov[3].iov_len = 4;

        wsgi_req->headers_size = wsgi_req->socket->proto_writev_header(wsgi_req, iov, 4);

	wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, "Moved", 5);
	wsgi_req->status = 302;

	free(iov[2].iov_base);
	return UWSGI_ROUTE_BREAK;
}


int uwsgi_router_redirect(struct uwsgi_route *ur, char *args) {

	ur->func = uwsgi_routing_func_redirect;
	ur->data = args;
	ur->data_len = strlen(args);
	return 0;
}


void router_redirect_register(void) {

	uwsgi_register_router("redirect", uwsgi_router_redirect);
}

struct uwsgi_plugin router_redirect_plugin = {

	.name = "router_redirect",
	.on_load = router_redirect_register,
};
#else
struct uwsgi_plugin router_redirect_plugin = {
	.name = "router_redirect",
};
#endif
