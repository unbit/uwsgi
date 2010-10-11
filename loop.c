#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void *simple_loop(void *arg1) {

	long core_id = (long) arg1;

	struct wsgi_request *wsgi_req = uwsgi.wsgi_requests[core_id];

#ifdef UWSGI_THREADING
	PyThreadState *pts;
	sigset_t smask;

	if (uwsgi.threads > 1) {
	
		pthread_setspecific(uwsgi.ut_key, (void *) wsgi_req);

		if (core_id > 0) {
			// block all signals on new threads
			sigfillset(&smask);
			pthread_sigmask(SIG_BLOCK, &smask, NULL);
			pts = PyThreadState_New(uwsgi.main_thread->interp);
			pthread_setspecific(uwsgi.ut_save_key, (void *) pts);
		}
	}
#endif
	
	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {

#ifndef __linux__
                if (uwsgi.no_orphans && uwsgi.master_process) {
                        // am i a son of init ? 
                        if (getppid() == 1) {
                                uwsgi_log("UAAAAAAH my parent died :( i will follow him...\n");
                                exit(1);
                        }
                }
#endif

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

}

void complex_loop() {

	int current_async_timeout = 0;
	int i;

	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {

		current_async_timeout = async_get_timeout() ;
                uwsgi.async_nevents = async_wait(uwsgi.async_queue, uwsgi.async_events, uwsgi.async, uwsgi.async_running, current_async_timeout);
                async_expire_timeouts();

                if (uwsgi.async_nevents < 0) {
                        continue;
                }

                for(i=0; i<uwsgi.async_nevents;i++) {

                        if ( (int) uwsgi.async_events[i].ASYNC_FD == uwsgi.sockets[0].fd) {

                                uwsgi.wsgi_req = find_first_available_wsgi_req();
                                if (uwsgi.wsgi_req == NULL) {
                                        // async system is full !!!
                                        goto cycle;
                                }

                                wsgi_req_setup(uwsgi.wsgi_req, ( (uint8_t *)uwsgi.wsgi_req - (uint8_t *)uwsgi.wsgi_requests)/sizeof(struct wsgi_request) );

                                if (wsgi_req_accept(uwsgi.wsgi_req)) {
                                        continue;
                                }

                                if (wsgi_req_recv(uwsgi.wsgi_req)) {
                                        continue;
                                }

                                if (uwsgi.wsgi_req->async_status == UWSGI_OK) {
                                        goto reqclear;
                                }

                        }
                        else {
                                uwsgi.wsgi_req = find_wsgi_req_by_fd(uwsgi.async_events[i].ASYNC_FD, uwsgi.async_events[i].ASYNC_EV);
                                if (uwsgi.wsgi_req) {
                                        uwsgi.wsgi_req->async_status = UWSGI_AGAIN ;
                                        uwsgi.wsgi_req->async_waiting_fd = -1 ;
                                        uwsgi.wsgi_req->async_waiting_fd_monitored = 0 ;
                                }

                                async_del(uwsgi.async_queue, uwsgi.async_events[i].ASYNC_FD, uwsgi.async_events[i].ASYNC_EV);
                        }
                }

cycle:
                uwsgi.wsgi_req = async_loop();

                if (uwsgi.wsgi_req == NULL)
                        continue ;
                uwsgi.wsgi_req->async_status = UWSGI_OK ;

reqclear:
                uwsgi_close_request(uwsgi.wsgi_req);

	}
}
