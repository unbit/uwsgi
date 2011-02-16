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

#ifdef UWSGI_ASYNC
void complex_loop() {
	int current_async_timeout = 0;
	int i, j;
	int interesting_fd;

	struct wsgi_request *wsgi_req;

	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {

		current_async_timeout = async_get_timeout();

		uwsgi_log("waiting multi %d\n", current_async_timeout);
		uwsgi.async_nevents = event_queue_wait_multi(uwsgi.async_queue, current_async_timeout, uwsgi.async_events, 64);
		uwsgi_log("waiting done\n");
		async_expire_timeouts();

		if (uwsgi.async_nevents < 0) {
			continue;
		}


		
		for(i=0; i<uwsgi.async_nevents;i++) {

			interesting_fd = event_queue_interesting_fd(uwsgi.async_events, i);

			uwsgi_log("interesting_fd: %d\n", interesting_fd);

			if ( interesting_fd == uwsgi.sockets[0].fd) {

				uwsgi.wsgi_req = find_first_available_wsgi_req();
				if (uwsgi.wsgi_req == NULL) {
					// async system is full !!!
					goto cycle;
				}

				wsgi_req_setup(uwsgi.wsgi_req, uwsgi.wsgi_req->async_id );

                                if (wsgi_req_simple_accept(uwsgi.wsgi_req, interesting_fd)) {
                                        continue;
                                }

// on linux we do not need to reset the socket to blocking state
#ifndef __linux__
                                if (uwsgi.numproc > 1) {
                                        /* re-set blocking socket */
                                        if (fcntl(uwsgi.wsgi_req->poll.fd, F_SETFL, uwsgi.sockets[0].arg) < 0) {
                                                uwsgi_error("fcntl()");
						continue;
                                        }
                                }
#endif

				if (wsgi_req_recv(uwsgi.wsgi_req)) {
					continue;
				}

				if (uwsgi.wsgi_req->async_status == UWSGI_OK) {
					goto reqclear;
				}

			}
			else if (  interesting_fd == uwsgi.sockets_poll[uwsgi.sockets_cnt].fd) {
				// wake up cores waiting for signal
				char byte;
				uwsgi_log("*** READING SIGNAL ***\n");
				if (read(uwsgi.sockets_poll[uwsgi.sockets_cnt].fd, &byte, 1) == 1) {
					uwsgi_log("signal %d received\n", byte);
				}
				else {
					uwsgi_error("read()");
				}
				for(j=0;j<uwsgi.async_current_max;j++) {
                			wsgi_req = uwsgi.wsgi_requests[j] ;
                			if (wsgi_req->sigwait) {
						wsgi_req->signal_received = byte;
						wsgi_req->sigwait = 0;
					}
				}
			}
			else {
				uwsgi.wsgi_req = find_wsgi_req_by_fd(interesting_fd);
				if (uwsgi.wsgi_req) {
					uwsgi.wsgi_req->async_status = UWSGI_AGAIN;
					uwsgi.wsgi_req->async_waiting_fd = -1;
					uwsgi.wsgi_req->async_waiting_fd_monitored = 0;
					uwsgi.wsgi_req->async_timeout = 0;
				}

				event_queue_del_fd(uwsgi.async_queue, interesting_fd);
			}
		}

cycle:

		uwsgi_log("async_loop\n");
		uwsgi.wsgi_req = async_loop();

		if (uwsgi.wsgi_req == NULL)
			continue;
		uwsgi.wsgi_req->async_status = UWSGI_OK;

reqclear:
		uwsgi_close_request(uwsgi.wsgi_req);

	}
}
#endif
