#include "../../uwsgi.h"

int uwsgi_request_notfound(struct wsgi_request *wsgi_req) {

        struct iovec iov[3];

        if (wsgi_req->protocol_len > 0) {
        	iov[0].iov_base = wsgi_req->protocol;
        	iov[0].iov_len = wsgi_req->protocol_len;
	}
	else {
        	iov[0].iov_base = "HTTP/1.0";
        	iov[0].iov_len = 8;
	}

        iov[1].iov_base = " 404 Not Found\r\n";
        iov[1].iov_len = 16;

        iov[2].iov_base = "Content-Type: text/plain\r\n\r\n";
        iov[2].iov_len = 28;

        wsgi_req->headers_size = wsgi_req->socket->proto_writev_header(wsgi_req, iov, 3);

	wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, "Not Found", 9);
	wsgi_req->status = 404;

	return UWSGI_OK;
}


struct uwsgi_plugin notfound_plugin = {

	.name = "notfound",
	.request = uwsgi_request_notfound,
};
