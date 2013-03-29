#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

class FakeClass {

	public:
		char *foobar;
		uint16_t foobar_len;
		void hello_world(struct wsgi_request *);

};

void FakeClass::hello_world(struct wsgi_request *wsgi_req) {

	uwsgi_response_prepare_headers(wsgi_req, (char *)"200 OK", 6);
	uwsgi_response_add_content_type(wsgi_req, (char *)"text/html", 9);
	uwsgi_response_write_body_do(wsgi_req, foobar, foobar_len);
}

extern "C" int uwsgi_cplusplus_init(){
        uwsgi_log("Initializing example c++ plugin\n");
        return 0;
}

extern "C" int uwsgi_cplusplus_request(struct wsgi_request *wsgi_req) {

	FakeClass *fc;

	// empty request ?
	if (!wsgi_req->uh->pktsize) {
                uwsgi_log( "Invalid request. skip.\n");
		goto clear;
        }

	// get uwsgi variables
        if (uwsgi_parse_vars(wsgi_req)) {
                uwsgi_log("Invalid request. skip.\n");
                goto clear;
        }

	fc = new FakeClass();
	// get PATH_INFO
        fc->foobar = uwsgi_get_var(wsgi_req, (char *) "PATH_INFO", 9, &fc->foobar_len);

	if (fc->foobar) {
		// send output
		fc->hello_world(wsgi_req);
	}

	delete fc;

clear:
        return UWSGI_OK;
}


extern "C" void uwsgi_cplusplus_after_request(struct wsgi_request *wsgi_req) {
	// call log_request(wsgi_req) if you want a standard logline
        uwsgi_log("logging c++ request\n");
}




