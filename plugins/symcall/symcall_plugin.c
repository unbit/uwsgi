#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;
int (*symcall_function)(struct wsgi_request *);

int uwsgi_symcall_init(){
	symcall_function = dlsym(RTLD_DEFAULT, "pypy_uwsgi_request");
	uwsgi_log("symcall function ptr: %p\n", symcall_function);
	return 0;
}

int uwsgi_symcall_request(struct wsgi_request *wsgi_req) {

	return symcall_function(wsgi_req);

}


void uwsgi_symcall_after_request(struct wsgi_request *wsgi_req) {
	// TODO
}


struct uwsgi_plugin symcall_plugin = {

        .name = "symcall",
        .modifier1 = 18,
        .init = uwsgi_symcall_init,
        .request = uwsgi_symcall_request,
        .after_request = uwsgi_symcall_after_request,

};

