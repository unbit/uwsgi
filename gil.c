#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void gil_real_get() {
	PyEval_AcquireLock();
	PyThreadState_Swap((PyThreadState *) pthread_getspecific(uwsgi.ut_save_key));
}

void gil_real_release() {
	pthread_setspecific(uwsgi.ut_save_key, (void *) PyThreadState_Swap(NULL));
	PyEval_ReleaseLock();
}

struct wsgi_request* threaded_current_wsgi_req() { return pthread_getspecific(uwsgi.ut_key); }
struct wsgi_request* simple_current_wsgi_req() { return uwsgi.wsgi_req ; }


void gil_fake_get() {}
void gil_fake_release() {}
