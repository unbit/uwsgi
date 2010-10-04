#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void *simple_loop(void *arg1) {

	long core_id = (long) arg1;
	PyThreadState *pts;

	struct wsgi_request *wsgi_req = uwsgi.wsgi_requests[core_id];

	pthread_setspecific(uwsgi.ut_key, (void *) wsgi_req);

	uwsgi_log("started core %d\n", core_id);

	if (core_id > 0) {
		pts = PyThreadState_New(uwsgi.main_thread->interp);
		pthread_setspecific(uwsgi.ut_save_key, (void *) pts);
	}
	
	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {


                wsgi_req_setup(wsgi_req, core_id);

                if (wsgi_req_accept(wsgi_req)) {
                        continue;
                }

		uwsgi_get_gil();

                if (wsgi_req_recv(wsgi_req)) {
			uwsgi_release_gil();
                        continue;
                }

                uwsgi_close_request(wsgi_req);
		uwsgi_release_gil();
        }

	pthread_exit(NULL);

}
