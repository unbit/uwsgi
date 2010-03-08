#include "../../uwsgi.h"

/* gcc `python-config --cflags` `python ../../uwsgiconfig.py --cflags` -o example_plugin.so -fPIC -shared example_plugin.c  */

int uwsgi_init(struct uwsgi_server *uwsgi, char *args){
	fprintf(stderr,"i am the example plugin initialization function with arg: %s\n", args);
	return 0;
}

int uwsgi_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	char *http = "HTTP/1.1 200 Ok\r\nContent-type: text/html\r\n\r\n<h1>Hello World</h1>" ;
	wsgi_req->response_size += write(uwsgi->poll.fd, http, strlen(http));

	fprintf(stderr,"UWSGI POLL: %p\n", &uwsgi->poll);

	return 0;
}


void uwsgi_after_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	fprintf(stderr,"i am the example plugin after request function\n");
}
