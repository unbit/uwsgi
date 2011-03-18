#include "uwsgi_rack.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_rack ur;

VALUE fiber_list[200];

void uwsgi_ruby_exception(void);

VALUE fiber_request() {

	struct wsgi_request *wsgi_req  = uwsgi.wsgi_req;
	int async_id = wsgi_req->async_id;


        for(;;) {
                wsgi_req_setup(wsgi_req, async_id);

                wsgi_req->async_status = UWSGI_ACCEPTING;

		rb_fiber_yield(0, NULL);

                if (wsgi_req_simple_accept(wsgi_req, uwsgi.sockets_poll[0].fd)) {
                        continue;
                }

                wsgi_req->async_status = UWSGI_OK;

		rb_fiber_yield(0, NULL);

		// reinitialize switches counter

		wsgi_req->switches = 0;
                if (wsgi_req_recv(wsgi_req)) {
                        continue;
                }

                while(wsgi_req->async_status == UWSGI_AGAIN) {
			rb_fiber_yield(0, NULL);
                        wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);
                }



		rb_fiber_yield(0, NULL);

                uwsgi_close_request(wsgi_req);

        }

	return Qnil;
}


VALUE protected_fiber_loop() {

	int i, current = 0;

	struct wsgi_request *wsgi_req;

	// create a ruby fiber for each async core

	uwsgi_log("create a fiber for each async core...\n");
	for(i=0;i<uwsgi.async;i++) {
		fiber_list[i] = rb_fiber_new(fiber_request, Qnil);
		rb_gc_register_address(&fiber_list[i]);
		uwsgi.wsgi_requests[i]->async_status = UWSGI_ACCEPTING;
		uwsgi.wsgi_requests[i]->async_id = i;
		uwsgi.wsgi_req = uwsgi.wsgi_requests[i];
		rb_fiber_resume(fiber_list[i], 0, NULL);
		uwsgi_log("fiber %d ready\n", i);
	}


	for(;;) {

		//uwsgi.async_running = u_green_blocking();
		uwsgi.async_running = 0;
                //timeout = u_green_get_timeout();
		int timeout = 0;
                uwsgi.async_nevents = async_wait(uwsgi.async_queue, uwsgi.async_events, uwsgi.async, uwsgi.async_running, timeout);
                //u_green_expire_timeouts();

                if (uwsgi.async_nevents < 0) {
                        continue;
                }


                for(i=0; i<uwsgi.async_nevents;i++) {

                        uwsgi_log("received I/O event on fd %d\n", (int) uwsgi.async_events[i].ASYNC_FD);
                        if ( (int) uwsgi.async_events[i].ASYNC_FD == uwsgi.sockets[0].fd) {
                                wsgi_req = find_first_accepting_wsgi_req();
                                if (!wsgi_req) goto cycle;
                                uwsgi_log("request passed to fiber core %d\n", wsgi_req->async_id);
				uwsgi.wsgi_req = wsgi_req;
                        	rb_fiber_resume(fiber_list[wsgi_req->async_id], 0, NULL);
                        }
                        else {
                                wsgi_req = find_wsgi_req_by_fd((int)uwsgi.async_events[i].ASYNC_FD, -1);
                                if (wsgi_req) {
					uwsgi.wsgi_req = wsgi_req;
                        		rb_fiber_resume(fiber_list[wsgi_req->async_id], 0, NULL);
                                }
                                else {
                                        async_del(uwsgi.async_queue, (int)  uwsgi.async_events[i].ASYNC_FD, uwsgi.async_events[i].ASYNC_EV);
                                }
                        }

                }


cycle:

		//uwsgi_log("resuming fiber %d %p\n", current, fiber_list[current]);
		uwsgi.wsgi_req = uwsgi.wsgi_requests[current];
		if (uwsgi.wsgi_req->async_status != UWSGI_ACCEPTING) {
			uwsgi_log("passing control to fiber %d\n", current);
			rb_fiber_resume(fiber_list[current], 0, NULL);
			uwsgi_log("returned to main fiber\n");
		}
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
