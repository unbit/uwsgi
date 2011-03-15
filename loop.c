#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

struct wsgi_request* threaded_current_wsgi_req() { return pthread_getspecific(uwsgi.tur_key); }
struct wsgi_request* simple_current_wsgi_req() { return uwsgi.wsgi_req; }


void uwsgi_register_loop(char *name, void *loop) {
	
	if (uwsgi.loops_cnt >= MAX_LOOPS) {
		uwsgi_log("you can define %d loops at max\n", MAX_LOOPS);
		exit(1);
	}

	uwsgi.loops[uwsgi.loops_cnt].name = name;
	uwsgi.loops[uwsgi.loops_cnt].loop = loop;
	uwsgi.loops_cnt++;
}

void *uwsgi_get_loop(char *name) {

	int i;
	
	for(i=0;i<uwsgi.loops_cnt;i++) {
		if (!strcmp(name, uwsgi.loops[i].name)) {
			return uwsgi.loops[i].loop;
		}
	}

	return NULL;
}

void *simple_loop(void *arg1) {

	long core_id = (long) arg1;

	struct wsgi_request *wsgi_req = uwsgi.wsgi_requests[core_id];
	int i;

#ifdef UWSGI_THREADING
	//PyThreadState *pts;
	sigset_t smask;

	if (uwsgi.threads > 1) {

		pthread_setspecific(uwsgi.tur_key, (void *) wsgi_req);

		if (core_id > 0) {
			// block all signals on new threads
			sigfillset(&smask);
			pthread_sigmask(SIG_BLOCK, &smask, NULL);
			for(i=0;i<0xFF;i++) {
				if (uwsgi.p[i]->init_thread) {
					uwsgi.p[i]->init_thread(core_id);
				}
			}
			/*
			   pts = PyThreadState_New(uwsgi.main_thread->interp);
			   pthread_setspecific(uwsgi.ut_save_key, (void *) pts);
			   */
		}
	}
#endif

	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {


		UWSGI_CLEAR_STATUS;


		wsgi_req_setup(wsgi_req, core_id);

		if (wsgi_req_accept(wsgi_req)) {
			continue;
		}

		if (wsgi_req_recv(wsgi_req)) {
			continue;
		}

		uwsgi_close_request(wsgi_req);
	}

	pthread_exit(NULL);
	
	//never here
	return NULL;
}
