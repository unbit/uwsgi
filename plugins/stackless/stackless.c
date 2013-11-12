#include "../python/uwsgi_python.h"
#include <stackless_api.h>

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

struct ustackless {
	int enabled;
	PyObject *callable;
	PyTaskletObject **sl;
} usl;

static void gil_stackless_get() {
        pthread_setspecific(up.upt_gil_key, (void *) PyGILState_Ensure());
}

static void gil_stackless_release() {
        PyGILState_Release((PyGILState_STATE) pthread_getspecific(up.upt_gil_key));
}

static struct uwsgi_option stackless_options[] = {
	{"stackless", no_argument, 0, "use stackless as suspend engine", uwsgi_opt_true, &usl.enabled, 0},
	{ 0, 0, 0, 0, 0, 0, 0 }
};

static PyObject *py_uwsgi_stackless_request(PyObject * self, PyObject *args) {

	async_schedule_to_req_green();
	Py_DECREF(usl.sl[uwsgi.wsgi_req->async_id]);

	Py_INCREF(Py_None);
	return Py_None;
}

PyMethodDef uwsgi_stackless_request_method[] = {{"uwsgi_stackless_request", py_uwsgi_stackless_request, METH_VARARGS, ""}};

static void stackless_schedule_to_req() {

	int id = uwsgi.wsgi_req->async_id;
	uint8_t modifier1 = uwsgi.wsgi_req->uh->modifier1;

	// ensure gil
	UWSGI_GET_GIL

	if (!uwsgi.wsgi_req->suspended) {
		usl.sl[id] = PyTasklet_New(NULL, usl.callable);
		PyObject *args = PyTuple_New(0);
		PyTasklet_Setup(usl.sl[id], args, NULL);
		Py_DECREF(args);
		uwsgi.wsgi_req->suspended = 1;
	}

	// call it in the main core
        if (uwsgi.p[modifier1]->suspend) {
                uwsgi.p[modifier1]->suspend(NULL);
        }

	PyTasklet_Run(usl.sl[id]);

	// call it in the main core
        if (uwsgi.p[modifier1]->resume) {
                uwsgi.p[modifier1]->resume(NULL);
        }

}

static void stackless_schedule_to_main(struct wsgi_request *wsgi_req) {

	// ensure gil
	UWSGI_GET_GIL

	if (uwsgi.p[wsgi_req->uh->modifier1]->suspend) {
                uwsgi.p[wsgi_req->uh->modifier1]->suspend(wsgi_req);
        }
	PyStackless_Schedule(Py_None, 1);
	if (uwsgi.p[wsgi_req->uh->modifier1]->resume) {
                uwsgi.p[wsgi_req->uh->modifier1]->resume(wsgi_req);
        }
	uwsgi.wsgi_req = wsgi_req;
}


static void stackless_init_apps(void) {

	if (!usl.enabled) return;

	if (uwsgi.async <= 1) {
                uwsgi_log("the stackless suspend engine requires async mode\n");
                exit(1);
        }

	if (uwsgi.has_threads) {
		up.gil_get = gil_stackless_get;
        	up.gil_release = gil_stackless_release;
	}

	// blindly call it as the stackless gil engine is already set
	UWSGI_GET_GIL

	usl.sl = uwsgi_malloc( sizeof(PyTaskletObject *) * uwsgi.async );
	usl.callable = PyCFunction_New(uwsgi_stackless_request_method, NULL);
	Py_INCREF(usl.callable);
	uwsgi_log("enabled stackless engine\n");
	uwsgi.schedule_to_main = stackless_schedule_to_main;
	uwsgi.schedule_to_req = stackless_schedule_to_req;

}

struct uwsgi_plugin stackless_plugin = {

	.name = "stackless",
	.init_apps = stackless_init_apps,
	.options = stackless_options,
};
