#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

void gil_real_get() {
#ifndef PYTHREE
	PyEval_AcquireLock();
	PyThreadState_Swap((PyThreadState *) pthread_getspecific(up.upt_gil_key));
#else
	PyEval_RestoreThread((PyThreadState *) pthread_getspecific(up.upt_gil_key));
#endif
}

void gil_real_release() {
#ifndef PYTHREE
	pthread_setspecific(up.upt_gil_key, (void *) PyThreadState_Swap(NULL));
	PyEval_ReleaseLock();	
#else
	pthread_setspecific(up.upt_gil_key, (void *) PyThreadState_Get());
	PyEval_SaveThread();
#endif
}

void gil_fake_get() {}
void gil_fake_release() {}
