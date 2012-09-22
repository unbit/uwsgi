#include "../rack/uwsgi_rack.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_rack ur;

struct ufib {
	VALUE *fib;
} ufiber;

VALUE uwsgi_fiber_request() {

	uwsgi.wsgi_req->async_status = uwsgi.p[uwsgi.wsgi_req->uh.modifier1]->request(uwsgi.wsgi_req);
	uwsgi.wsgi_req->suspended = 0;

	return Qnil;
}

static inline void fiber_schedule_to_req() {

	int id = uwsgi.wsgi_req->async_id;

	if (!uwsgi.wsgi_req->suspended) {
		ufiber.fib[id] = rb_fiber_new(uwsgi_fiber_request, Qnil);
		rb_gc_register_address(&ufiber.fib[id]);
		uwsgi.wsgi_req->suspended = 1;
	}

	rb_fiber_resume(ufiber.fib[id], 0, NULL);

	if (uwsgi.wsgi_req->suspended) {
		uwsgi.wsgi_req->async_status = UWSGI_AGAIN;
	}

}

static inline void fiber_schedule_to_main(struct wsgi_request *wsgi_req) {

	rb_fiber_yield(0, NULL);
	uwsgi.wsgi_req = wsgi_req;
}

VALUE protected_async_loop() {

	async_loop(NULL);
	return Qnil;
}

void fiber_loop() {

        int error = 0;

	ufiber.fib = uwsgi_malloc( sizeof(VALUE) * uwsgi.async );

        uwsgi.schedule_to_main = fiber_schedule_to_main;
        uwsgi.schedule_to_req = fiber_schedule_to_req;

	ur.unprotected = 1;

        rb_protect(protected_async_loop, 0, &error);

        if (error) {
                uwsgi_ruby_exception();
		exit(1);
        }

        // never here
}

int fiber_init() {
	uwsgi_register_loop( (char *) "fiber", fiber_loop);
	return 0;
}


struct uwsgi_plugin fiber_plugin = {

	.name = "fiber",
	.init = fiber_init,
};
