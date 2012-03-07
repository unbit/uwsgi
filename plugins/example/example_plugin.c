#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_example_init(){
	uwsgi_log("i am the example plugin initialization function\n");
	return 0;
}

int uwsgi_example_request(struct wsgi_request *wsgi_req) {

	char *http = "HTTP/1.1 200 Ok\r\nContent-type: text/html\r\n\r\n<h1>Hello World</h1>";

	wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, http, strlen(http));

	return 0;
}


void uwsgi_example_after_request(struct wsgi_request *wsgi_req) {
	uwsgi_log("i am the example plugin after request function\n");
}


struct uwsgi_plugin example_plugin = {

        .name = "example",
        .modifier1 = 250,
        .init = uwsgi_example_init,
        .request = uwsgi_example_request,
        .after_request = uwsgi_example_after_request,

};

