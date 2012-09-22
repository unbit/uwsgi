#include "../python/uwsgi_python.h"
#include <greenlet/greenlet.h>

extern struct uwsgi_server uwsgi;

struct ugreenlet {
	int enabled;
	PyObject *callable;
	PyGreenlet *main;
	PyGreenlet **gl;
} ugl;

struct uwsgi_option greenlet_options[] = {
	{"greenlet", no_argument, 0, "enable greenlet as suspend engine", uwsgi_opt_true, &ugl.enabled, 0},
	{ 0, 0, 0, 0, 0, 0, 0 }
};

PyObject *py_uwsgi_greenlet_request(PyObject * self, PyObject *args) {

	uwsgi.wsgi_req->async_status = uwsgi.p[uwsgi.wsgi_req->uh.modifier1]->request(uwsgi.wsgi_req);
	uwsgi.wsgi_req->suspended = 0;

	Py_DECREF(ugl.gl[uwsgi.wsgi_req->async_id]);

	Py_INCREF(Py_None);
	return Py_None;
}

PyMethodDef uwsgi_greenlet_request_method[] = {{"uwsgi_greenlet_request", py_uwsgi_greenlet_request, METH_VARARGS, ""}};

static inline void greenlet_schedule_to_req() {

	int id = uwsgi.wsgi_req->async_id;

	if (!uwsgi.wsgi_req->suspended) {
		ugl.gl[id] = PyGreenlet_New(ugl.callable, NULL);
		uwsgi.wsgi_req->suspended = 1;
	}

	PyGreenlet_Switch(ugl.gl[id], NULL, NULL);

	if (uwsgi.wsgi_req->suspended) {
		uwsgi.wsgi_req->async_status = UWSGI_AGAIN;
	}

}

static inline void greenlet_schedule_to_main(struct wsgi_request *wsgi_req) {

	PyGreenlet_Switch(ugl.main, NULL, NULL);
	uwsgi.wsgi_req = wsgi_req;
}


int greenlet_init() {
	return 0;
}

void greenlet_init_apps(void) {

	if (!ugl.enabled) {
		return;
	}


	PyGreenlet_Import();

	ugl.gl = uwsgi_malloc( sizeof(PyGreenlet *) * uwsgi.async );
	ugl.main = PyGreenlet_GetCurrent();
	ugl.callable = PyCFunction_New(uwsgi_greenlet_request_method, NULL);
	uwsgi_log("enabled greenlet engine\n");

	uwsgi.schedule_to_main = greenlet_schedule_to_main;
	uwsgi.schedule_to_req = greenlet_schedule_to_req;

	return;

}

struct uwsgi_plugin greenlet_plugin = {

	.name = "greenlet",
	.init = greenlet_init,
	.init_apps = greenlet_init_apps,
	.options = greenlet_options,
};
