#include "../../uwsgi.h"

int uwsgi_init(struct uwsgi_server *uwsgi, char *args){
	uwsgi_log("i am the example plugin initialization function with arg: %s\n", args);
	return 0;
}

int uwsgi_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	char *http = "HTTP/1.1 200 Ok\r\nContent-type: text/html\r\n\r\n<h1>Hello World</h1>" ;

	wsgi_req->response_size += write(wsgi_req->poll.fd, http, strlen(http));

	return 0;
}


void uwsgi_after_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	uwsgi_log("i am the example plugin after request function\n");
}
