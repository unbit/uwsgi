#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void *simple_loop(void *arg1) {

	int *core_ptr = (int *) arg1;
	int core_id = *core_ptr;

	struct wsgi_request *wsgi_req = uwsgi.wsgi_requests[core_id];

	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {


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

}
