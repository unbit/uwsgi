#include "uwsgi_rack.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_rack ur;

VALUE fiber_list[200];

void uwsgi_ruby_exception(void);

VALUE fiber_request(VALUE core_id) {

	uwsgi_log("i am the fiber\n");

	int async_id = NUM2INT(core_id);	

	uwsgi_log("i am the fiber %d\n", async_id);

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

		uwsgi_log("request on fiber %d accepted\n", async_id);
                wsgi_req->async_status = UWSGI_OK;

		// reinitialize switches counter

		wsgi_req->switches = 0;
                if (wsgi_req_recv(wsgi_req)) {
                        continue;
                }

		uwsgi_log("FIBER %d HAS DONE\n", async_id);
                while(wsgi_req->async_status == UWSGI_AGAIN) {
			uwsgi_log("ASYNC APP DETECTED\n");
			rb_fiber_yield(0, NULL);
                        wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);
                }



		uwsgi_log("A LAST YIELD FOR %d\n", async_id);
		rb_fiber_yield(0, NULL);

		uwsgi_log("CLOSING REQUEST\n");
                uwsgi_close_request(wsgi_req);

        }

	return Qnil;
}


VALUE protected_fiber_loop() {

	int i, current = 0;
	VALUE core_id;

	// create a ruby fiber for each async core

	uwsgi_log("create a fiber for each async core...\n");
	for(i=0;i<uwsgi.async;i++) {
		uwsgi_log("creating fiber %d\n", i);
		fiber_list[i] = rb_fiber_new(fiber_request, INT2NUM(i));
		uwsgi_log("fiber %d ready\n", i);
	}


	for(;;) {
		uwsgi_log("resuming fiber %d %p\n", current, fiber_list[current]);
		core_id = INT2NUM(current);
		uwsgi_log("go resume %p!!\n", core_id);
		uwsgi.wsgi_req = uwsgi.wsgi_requests[current];
		uwsgi.wsgi_req->switches++;
		rb_fiber_resume(fiber_list[current], 1, &core_id);
		current++;
		if (current >= uwsgi.async) current = 0;
	}
	
	
	return Qnil;
}

void fiber_loop() {

	int error;

	// must run all the rack/ruby plugins without protection
	ur.unprotected = 1;

	rb_protect(protected_fiber_loop, 0, &error);

	if (error) {
        	uwsgi_ruby_exception();
                exit(1);
	}

	// never here

}
