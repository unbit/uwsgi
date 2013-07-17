#include "../rack/uwsgi_rack.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_rack ur;
static struct uwsgi_plugin *rack_plugin;

struct ufib {
	int enabled;
	VALUE *fib;
} ufiber;

struct uwsgi_option fiber_options[] = {
        {"fiber", no_argument, 0, "enable ruby fiber as suspend engine", uwsgi_opt_true, &ufiber.enabled, 0},
        { 0, 0, 0, 0, 0, 0, 0 }
};


VALUE uwsgi_fiber_request() {
	async_schedule_to_req_green();
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

	return Qnil;
}

static void fiber_schedule_to_req() {

	int id = uwsgi.wsgi_req->async_id;
	uint8_t modifier1 = uwsgi.wsgi_req->uh->modifier1;

	// call it in the main core
        if (uwsgi.p[modifier1]->suspend) {
                uwsgi.p[modifier1]->suspend(NULL);
        }

	int error = 0;
	rb_protect(rb_fiber_schedule_to_req, 0, &error);

	// call it in the main core
        if (uwsgi.p[modifier1]->resume) {
                uwsgi.p[modifier1]->resume(NULL);
        }

	if (error) {
		rack_plugin->exception_log(NULL);
		rb_gc_unregister_address(&ufiber.fib[id]);
	}

}

static void fiber_schedule_to_main(struct wsgi_request *wsgi_req) {

	if (uwsgi.p[wsgi_req->uh->modifier1]->suspend) {
                uwsgi.p[wsgi_req->uh->modifier1]->suspend(wsgi_req);
        }
	rb_fiber_yield(0, NULL);
	if (uwsgi.p[wsgi_req->uh->modifier1]->resume) {
                uwsgi.p[wsgi_req->uh->modifier1]->resume(wsgi_req);
        }
	uwsgi.wsgi_req = wsgi_req;
}

static int fiber_init() {
	rack_plugin = uwsgi_plugin_get("rack");
	if (!rack_plugin) {
		uwsgi_log("[ruby-fiber] rack plugin is not loaded !!!\n");
		exit(1);
	}
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
