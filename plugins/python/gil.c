#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

void gil_real_get() {
	PyEval_AcquireLock();
	PyThreadState_Swap((PyThreadState *) pthread_getspecific(up.upt_gil_key));
}

void gil_real_release() {
	pthread_setspecific(up.upt_gil_key, (void *) PyThreadState_Swap(NULL));
	PyEval_ReleaseLock();
}

void gil_fake_get() {}
void gil_fake_release() {}
