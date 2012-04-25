#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

struct wsgi_request *threaded_current_wsgi_req() {
	return pthread_getspecific(uwsgi.tur_key);
}
struct wsgi_request *simple_current_wsgi_req() {
	return uwsgi.wsgi_req;
}


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

	for (i = 0; i < uwsgi.loops_cnt; i++) {
		if (!strcmp(name, uwsgi.loops[i].name)) {
			return uwsgi.loops[i].loop;
		}
	}

	return NULL;
}

void *simple_loop(void *arg1) {

	long core_id = (long) arg1;

	struct wsgi_request *wsgi_req = uwsgi.wsgi_requests[core_id];

#ifdef UWSGI_THREADING
	int i;
	//PyThreadState *pts;
	sigset_t smask;

	if (uwsgi.threads > 1) {

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &i);
		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &i);
		pthread_setspecific(uwsgi.tur_key, (void *) wsgi_req);

		if (core_id > 0) {
			// block all signals on new threads
			sigfillset(&smask);
#ifdef UWSGI_DEBUG
			sigdelset(&smask, SIGSEGV);
#endif
			pthread_sigmask(SIG_BLOCK, &smask, NULL);
			for (i = 0; i < 256; i++) {
				if (uwsgi.p[i]->init_thread) {
					uwsgi.p[i]->init_thread(core_id);
				}
			}
		}
	}
#endif

	// initialize the main event queue to monitor sockets
	int main_queue = event_queue_init();

	uwsgi_add_sockets_to_queue(main_queue);

	if (uwsgi.signal_socket > -1) {
		event_queue_add_fd_read(main_queue, uwsgi.signal_socket);
		event_queue_add_fd_read(main_queue, uwsgi.my_signal_socket);
	}

	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {

		wsgi_req_setup(wsgi_req, core_id, NULL);

		if (wsgi_req_accept(main_queue, wsgi_req)) {
			continue;
		}

		if (wsgi_req_recv(wsgi_req)) {
			uwsgi_destroy_request(wsgi_req);
			continue;
		}

		uwsgi_close_request(wsgi_req);
	}

	// end of the loop
	if (uwsgi.workers[uwsgi.mywid].destroy && uwsgi.workers[0].pid > 0) {
#ifdef __APPLE__
		kill(uwsgi.workers[0].pid, SIGTERM);
#else
		if (uwsgi.propagate_touch) {
			kill(uwsgi.workers[0].pid, SIGHUP);
		}
		else {
			gracefully_kill(0);
		}
#endif
	}
	return NULL;
}

#ifdef UWSGI_ZEROMQ
void *zeromq_loop(void *arg1) {
	sigset_t smask;
	int i;

	long core_id = (long) arg1;

	struct wsgi_request *wsgi_req = uwsgi.wsgi_requests[core_id];
	uwsgi.zeromq_recv_flag = 0;
	zmq_pollitem_t zmq_poll_items[3];

	if (uwsgi.threads > 1) {

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &i);
		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &i);
		pthread_setspecific(uwsgi.tur_key, (void *) wsgi_req);

		if (core_id > 0) {
			// block all signals on new threads
			sigfillset(&smask);
#ifdef UWSGI_DEBUG
			sigdelset(&smask, SIGSEGV);
#endif
			pthread_sigmask(SIG_BLOCK, &smask, NULL);
			for (i = 0; i < 256; i++) {
				if (uwsgi.p[i]->init_thread) {
					uwsgi.p[i]->init_thread(core_id);
				}
			}


			void *tmp_zmq_pull = zmq_socket(uwsgi.zmq_context, ZMQ_PULL);
			if (tmp_zmq_pull == NULL) {
				uwsgi_error("zmq_socket()");
				exit(1);
			}
			if (zmq_connect(tmp_zmq_pull, uwsgi.zmq_receiver) < 0) {
				uwsgi_error("zmq_connect()");
				exit(1);
			}

			pthread_setspecific(uwsgi.zmq_pull, tmp_zmq_pull);
		}

	}


	if (uwsgi.signal_socket > -1) {
		zmq_poll_items[0].socket = pthread_getspecific(uwsgi.zmq_pull);
		zmq_poll_items[0].fd = -1;
		zmq_poll_items[0].events = ZMQ_POLLIN;

		zmq_poll_items[1].socket = NULL;
		zmq_poll_items[1].fd = uwsgi.signal_socket;
		zmq_poll_items[1].events = ZMQ_POLLIN;

		zmq_poll_items[2].socket = NULL;
		zmq_poll_items[2].fd = uwsgi.my_signal_socket;
		zmq_poll_items[2].events = ZMQ_POLLIN;
	}


	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {

		wsgi_req_setup(wsgi_req, core_id, NULL);

		uwsgi.edge_triggered = 1;
		wsgi_req->socket = uwsgi.zmq_socket;


		if (uwsgi.signal_socket > -1) {
			if (zmq_poll(zmq_poll_items, 3, -1) < 0) {
				uwsgi_error("zmq_poll()");
				continue;
			}

			if (zmq_poll_items[1].revents & ZMQ_POLLIN) {
				uwsgi_receive_signal(uwsgi.signal_socket, "worker", uwsgi.mywid);
				continue;
			}

			if (zmq_poll_items[2].revents & ZMQ_POLLIN) {
				uwsgi_receive_signal(uwsgi.my_signal_socket, "worker", uwsgi.mywid);
                                continue;
                        }

			

			if (zmq_poll_items[0].revents & ZMQ_POLLIN) {
				wsgi_req->poll.fd = wsgi_req->socket->proto_accept(wsgi_req, uwsgi.zmq_socket->fd);
			}
		}
		else {
			wsgi_req->poll.fd = wsgi_req->socket->proto_accept(wsgi_req, uwsgi.zmq_socket->fd);
		}

		if (wsgi_req->poll.fd >= 0) {
			wsgi_req_recv(wsgi_req);
		}

		uwsgi_close_request(wsgi_req);
	}


        // end of the loop
        return NULL;
}
#endif
