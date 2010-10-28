#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include <ruby.h>

VALUE fiber_list[200];


VALUE fiber_request(VALUE core_id) {

	int async_id = NUM2INT(core_id);	
	struct wsgi_request *wsgi_req  = uwsgi.wsgi_requests[async_id];


	uwsgi_log("INSIDE FIBER\n");

        for(;;) {
                uwsgi_log("accept()\n");
                wsgi_req_setup(wsgi_req, async_id);

                wsgi_req->async_status = UWSGI_ACCEPTING;

		rb_fiber_yield(0, NULL);

                if (wsgi_req_accept(wsgi_req)) {
                        continue;
                }
                wsgi_req->async_status = UWSGI_OK;

                if (wsgi_req_recv(wsgi_req)) {
                        continue;
                }

                while(wsgi_req->async_status == UWSGI_AGAIN) {
			rb_fiber_yield(0, NULL);
                        wsgi_req->async_status = uwsgi.shared->hook_request[wsgi_req->uh.modifier1](wsgi_req);
                }


		rb_fiber_yield(0, NULL);

                uwsgi_close_request(wsgi_req);

        }

	return Qnil;
}


VALUE fiber_create(VALUE core_id) {

	return rb_fiber_new( fiber_request, core_id );
}

VALUE fiber_resume(VALUE core_id) {
	
	rb_fiber_resume( fiber_list[NUM2INT(core_id)], 0, NULL );
	uwsgi_log("fiber yielded\n");
	return Qnil;
}

void fiber_loop() {


	int i;
	int current = 0;
	// create a ruby fiber for each async core
	
	uwsgi_log("create a fiber for each async core...\n");
	for(i=0;i<uwsgi.async;i++) {
		uwsgi_log("creating fiber %d\n", i);
		fiber_list[i] = rb_protect(fiber_create, INT2NUM(i), 0);
		uwsgi_log("fiber %d ready\n", i);
	}


	// wait for io or resume if there are fiber in no-accepting state

	for(;;) {
		uwsgi_log("resuming fiber %d %p\n", current, fiber_list[current]);
		rb_funcall(fiber_list[current], rb_intern("resume"), 0);
		current++;
		if (current >= uwsgi.async) current = 0;
	}
	


}
