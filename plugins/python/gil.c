#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

void gil_real_get() {
	//uwsgi_log("LOCK %d\n", uwsgi.mywid);
	PyEval_RestoreThread((PyThreadState *) pthread_getspecific(up.upt_gil_key));
	//uwsgi_log("LOCKED !!! %d\n", uwsgi.mywid);
}

void gil_real_release() {
	//uwsgi_log("UNLOCK %d\n", uwsgi.mywid);
	pthread_setspecific(up.upt_gil_key, (void *) PyThreadState_Get());
	PyEval_SaveThread();
}


void gil_fake_get() {}
void gil_fake_release() {}
