#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

static int uwsgi_example_init(){
	uwsgi_log("i am the example plugin initialization function\n");
	return 0;
}

static int uwsgi_example_request(struct wsgi_request *wsgi_req) {

	uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6);
	uwsgi_response_add_header(wsgi_req, "Content-type", 12, "text/html", 9);
	uwsgi_response_write_body_do(wsgi_req, "<h1>Hello World</h1>", 20);

	return UWSGI_OK;
}


static void uwsgi_example_after_request(struct wsgi_request *wsgi_req) {
	uwsgi_log("i am the example plugin after request function\n");
}


struct uwsgi_plugin example_plugin = {

        .name = "example",
        .modifier1 = 250,
        .init = uwsgi_example_init,
        .request = uwsgi_example_request,
        .after_request = uwsgi_example_after_request,

};

