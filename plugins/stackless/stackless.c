#include "../python/uwsgi_python.h"
#include <stackless_api.h>

extern struct uwsgi_server uwsgi;

struct ustackless {
	int enabled;
	PyObject *callable;
	PyTaskletObject **sl;
} usl;

struct uwsgi_option stackless_options[] = {
	{"stackless", no_argument, 0, "use stackless as suspend engine", uwsgi_opt_true, &usl.enabled, 0},
	{ 0, 0, 0, 0 }
};

PyObject *py_uwsgi_stackless_request(PyObject * self, PyObject *args) {

	uwsgi.wsgi_req->async_status = uwsgi.p[uwsgi.wsgi_req->uh.modifier1]->request(uwsgi.wsgi_req);
	uwsgi.wsgi_req->suspended = 0;

	Py_DECREF(usl.sl[uwsgi.wsgi_req->async_id]);

	Py_INCREF(Py_None);
	return Py_None;
}

PyMethodDef uwsgi_stackless_request_method[] = {{"uwsgi_stackless_request", py_uwsgi_stackless_request, METH_VARARGS, ""}};

static inline static void stackless_schedule_to_req() {

	int id = uwsgi.wsgi_req->async_id;

	if (!uwsgi.wsgi_req->suspended) {
		usl.sl[id] = PyTasklet_New(NULL, usl.callable);
		PyObject *args = PyTuple_New(0);
		PyTasklet_Setup(usl.sl[id], args, NULL);
		Py_DECREF(args);
		uwsgi.wsgi_req->suspended = 1;
	}

	PyTasklet_Run(usl.sl[id]);

	if (uwsgi.wsgi_req->suspended) {
		uwsgi.wsgi_req->async_status = UWSGI_AGAIN;
	}

}

static inline static void stackless_schedule_to_main(struct wsgi_request *wsgi_req) {

	PyStackless_Schedule(Py_None, 1);
	uwsgi.wsgi_req = wsgi_req;
}


int stackless_init() {
	return 0;
}

void stackless_init_apps(void) {

	if (!usl.enabled) {
		return;
	}


	usl.sl = uwsgi_malloc( sizeof(PyTaskletObject *) * uwsgi.async );
	usl.callable = PyCFunction_New(uwsgi_stackless_request_method, NULL);
	uwsgi_log("enabled stackless engine\n");
	uwsgi.schedule_to_main = stackless_schedule_to_main;
	uwsgi.schedule_to_req = stackless_schedule_to_req;

	return;

}

struct uwsgi_plugin stackless_plugin = {

	.name = "stackless",
	.init = stackless_init,
	.init_apps = stackless_init_apps,
	.options = stackless_options,
};
