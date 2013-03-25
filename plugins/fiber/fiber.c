#include "../rack/uwsgi_rack.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_rack ur;
extern struct uwsgi_plugin rack_plugin;

struct ufib {
	int enabled;
	VALUE *fib;
} ufiber;

struct uwsgi_option fiber_options[] = {
        {"fiber", no_argument, 0, "enable ruby fiber as suspend engine", uwsgi_opt_true, &ufiber.enabled, 0},
        { 0, 0, 0, 0, 0, 0, 0 }
};


VALUE uwsgi_fiber_request() {
	uwsgi.wsgi_req->async_status = uwsgi.p[uwsgi.wsgi_req->uh->modifier1]->request(uwsgi.wsgi_req);
	uwsgi.wsgi_req->suspended = 0;
	return Qnil;
}

VALUE rb_fiber_schedule_to_req() {
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

	return Qnil;
}

static void fiber_schedule_to_req() {

	int id = uwsgi.wsgi_req->async_id;

	int error = 0;
	rb_protect(rb_fiber_schedule_to_req, 0, &error);
	if (error) {
		rack_plugin.exception_log(NULL);
		rb_gc_unregister_address(&ufiber.fib[id]);
		uwsgi.wsgi_req->async_status = UWSGI_OK;
	}

}

static void fiber_schedule_to_main(struct wsgi_request *wsgi_req) {

	rb_fiber_yield(0, NULL);
	uwsgi.wsgi_req = wsgi_req;
}

static int fiber_init() {
	return 0;
}

static void fiber_init_apps(void) {

        if (!ufiber.enabled) return;
	if (uwsgi.async <= 1) {
		uwsgi_log("the fiber loop engine requires async mode\n");
		exit(1);
	}

	ufiber.fib = uwsgi_malloc( sizeof(VALUE) * uwsgi.async );

        uwsgi.schedule_to_main = fiber_schedule_to_main;
        uwsgi.schedule_to_req = fiber_schedule_to_req;

	ur.unprotected = 1;
	uwsgi_log("*** fiber suspend engine enabled ***\n");

}



struct uwsgi_plugin fiber_plugin = {

	.name = "fiber",
	.init = fiber_init,
	.init_apps = fiber_init_apps,
	.options = fiber_options, 
};
