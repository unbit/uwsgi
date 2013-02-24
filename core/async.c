#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

void uwsgi_async_queue_is_full(time_t now) {
	if (now > uwsgi.async_queue_is_full) {
		uwsgi_log_verbose("[DANGER] async queue is full !!!\n");
		uwsgi.async_queue_is_full = now;
	}
}

void uwsgi_async_init() {
	int i;

	uwsgi.async_queue = event_queue_init();

	if (uwsgi.async_queue < 0) {
		exit(1);
	}

	uwsgi_add_sockets_to_queue(uwsgi.async_queue, -1);

	uwsgi.rb_async_timeouts = uwsgi_init_rb_timer();

	uwsgi.async_queue_unused = uwsgi_malloc(sizeof(struct wsgi_request *) * uwsgi.async);

	for (i = 0; i < uwsgi.async; i++) {
		uwsgi.async_queue_unused[i] = &uwsgi.workers[uwsgi.mywid].cores[i].req;
	}

	uwsgi.async_queue_unused_ptr = uwsgi.async - 1;

}

struct wsgi_request *find_wsgi_req_proto_by_fd(int fd) {
	return uwsgi.async_proto_fd_table[fd];
}

struct wsgi_request *find_wsgi_req_by_fd(int fd) {
	return uwsgi.async_waiting_fd_table[fd];
}

static void runqueue_remove(struct uwsgi_async_request *u_request) {

	struct uwsgi_async_request *parent = u_request->prev;
	struct uwsgi_async_request *child = u_request->next;

	if (parent) {
		parent->next = child;
	}
	if (child) {
		child->prev = parent;
	}

	if (parent == NULL) {
		uwsgi.async_runqueue = child;
	}

	if (u_request == uwsgi.async_runqueue_last) {
		uwsgi.async_runqueue_last = parent;
	}

	free(u_request);

	uwsgi.async_runqueue_cnt--;
}

static void runqueue_push(struct wsgi_request *wsgi_req) {

	struct uwsgi_async_request *uar;

	if (uwsgi.async_runqueue == NULL) {
		// empty runqueue, create a new one
		uwsgi.async_runqueue = uwsgi_malloc(sizeof(struct uwsgi_async_request));
		uwsgi.async_runqueue->next = NULL;
		uwsgi.async_runqueue->prev = NULL;
		uwsgi.async_runqueue->wsgi_req = wsgi_req;
		uwsgi.async_runqueue_last = uwsgi.async_runqueue;
	}
	else {
		uar = uwsgi_malloc(sizeof(struct uwsgi_async_request));
		uar->prev = uwsgi.async_runqueue_last;
		uar->next = NULL;
		uar->wsgi_req = wsgi_req;
		uwsgi.async_runqueue_last->next = uar;
		uwsgi.async_runqueue_last = uar;
	}

	uwsgi.async_runqueue_cnt++;

}

struct wsgi_request *find_first_available_wsgi_req() {

	struct wsgi_request *wsgi_req;

	if (uwsgi.async_queue_unused_ptr < 0) {
		return NULL;
	}

	wsgi_req = uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr];
	uwsgi.async_queue_unused_ptr--;
	return wsgi_req;
}

static void async_expire_timeouts(uint64_t now) {

	struct wsgi_request *wsgi_req;
	struct uwsgi_async_fd *uaf = NULL, *current_uaf;

	struct uwsgi_rb_timer *urbt;

	for (;;) {

		urbt = uwsgi_min_rb_timer(uwsgi.rb_async_timeouts, NULL);

		if (urbt == NULL)
			return;

		if (urbt->value <= now) {
			wsgi_req = (struct wsgi_request *) urbt->data;
			// timeout expired
			wsgi_req->async_timed_out = 1;
			uwsgi_del_rb_timer(uwsgi.rb_async_timeouts, wsgi_req->async_timeout);
			free(wsgi_req->async_timeout);
			wsgi_req->async_timeout = NULL;
			uaf = wsgi_req->waiting_fds;
			// remove fds from monitoring (no problem modifying the queue here, as the function is executed only when there are no fd ready)
			while (uaf) {
				event_queue_del_fd(uwsgi.async_queue, uaf->fd, uaf->event);
				uwsgi.async_waiting_fd_table[uaf->fd] = NULL;
				current_uaf = uaf;
				uaf = current_uaf->next;
				free(current_uaf);
			}
			wsgi_req->waiting_fds = NULL;
			// put th request in the runqueue
			runqueue_push(wsgi_req);
			continue;
		}

		break;
	}

}

int async_add_fd_read(struct wsgi_request *wsgi_req, int fd, int timeout) {

	struct uwsgi_async_fd *last_uad = NULL, *uad = wsgi_req->waiting_fds;

	if (fd < 0)
		return -1;

	// find first slot
	while (uad) {
		last_uad = uad;
		uad = uad->next;
	}

	uad = uwsgi_malloc(sizeof(struct uwsgi_async_fd));
	uad->fd = fd;
	uad->event = event_queue_read();
	uad->prev = last_uad;
	uad->next = NULL;

	if (last_uad) {
		last_uad->next = uad;
	}
	else {
		wsgi_req->waiting_fds = uad;
	}

	if (timeout > 0) {
		async_add_timeout(wsgi_req, timeout);
	}
	uwsgi.async_waiting_fd_table[fd] = wsgi_req;
	wsgi_req->async_force_again = 1;
	return event_queue_add_fd_read(uwsgi.async_queue, fd);
}

static int async_wait_fd_read(int fd, int timeout) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	if (async_add_fd_read(wsgi_req, fd, timeout)) {
		return -1;
	}
	if (uwsgi.schedule_to_main) {
		uwsgi.schedule_to_main(wsgi_req);
	}
	if (wsgi_req->async_timed_out) {
		wsgi_req->async_timed_out = 0;
		return 0;
	}
	return 1;
}

void async_add_timeout(struct wsgi_request *wsgi_req, int timeout) {

	if (timeout > 0 && wsgi_req->async_timeout == NULL) {
		wsgi_req->async_timeout = uwsgi_add_rb_timer(uwsgi.rb_async_timeouts, uwsgi_now() + timeout, wsgi_req);
	}

}

int async_add_fd_write(struct wsgi_request *wsgi_req, int fd, int timeout) {

	struct uwsgi_async_fd *last_uad = NULL, *uad = wsgi_req->waiting_fds;

	if (fd < 0)
		return -1;

	// find first slot
	while (uad) {
		last_uad = uad;
		uad = uad->next;
	}

	uad = uwsgi_malloc(sizeof(struct uwsgi_async_fd));
	uad->fd = fd;
	uad->event = event_queue_write();
	uad->prev = last_uad;
	uad->next = NULL;

	if (last_uad) {
		last_uad->next = uad;
	}
	else {
		wsgi_req->waiting_fds = uad;
	}

	if (timeout > 0) {
		async_add_timeout(wsgi_req, timeout);
	}

	uwsgi.async_waiting_fd_table[fd] = wsgi_req;
	wsgi_req->async_force_again = 1;
	return event_queue_add_fd_write(uwsgi.async_queue, fd);
}

static int async_wait_fd_write(int fd, int timeout) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	if (async_add_fd_write(wsgi_req, fd, timeout)) {
		return -1;
	}
	if (uwsgi.schedule_to_main) {
		uwsgi.schedule_to_main(wsgi_req);
	}
	if (wsgi_req->async_timed_out) {
		wsgi_req->async_timed_out = 0;
		return 0;
	}
	return 1;
}

void async_schedule_to_req(void) {
	uwsgi.wsgi_req->async_status = uwsgi.p[uwsgi.wsgi_req->uh->modifier1]->request(uwsgi.wsgi_req);
}

void async_loop() {

	if (uwsgi.async < 2) {
		uwsgi_log("the async loop engine requires async mode (--async <n>)\n");
		exit(1);
	}

	struct uwsgi_async_fd *tmp_uaf;
	int interesting_fd, i;
	struct uwsgi_rb_timer *min_timeout;
	int timeout;
	int is_a_new_connection;
	int proto_parser_status;

	uint64_t now;

	static struct uwsgi_async_request *current_request = NULL, *next_async_request = NULL;

	void *events = event_queue_alloc(64);
	struct uwsgi_socket *uwsgi_sock;

	uwsgi.async_runqueue = NULL;
	uwsgi.async_runqueue_cnt = 0;

	uwsgi.wait_write_hook = async_wait_fd_write;
        uwsgi.wait_read_hook = async_wait_fd_read;

	if (uwsgi.signal_socket > -1) {
		event_queue_add_fd_read(uwsgi.async_queue, uwsgi.signal_socket);
		event_queue_add_fd_read(uwsgi.async_queue, uwsgi.my_signal_socket);
	}

	// set a default request manager
	if (!uwsgi.schedule_to_req)
		uwsgi.schedule_to_req = async_schedule_to_req;

	if (!uwsgi.schedule_to_main) {
		uwsgi_log("*** WARNING *** async mode without coroutine/greenthread engine loaded !!!\n");
	}

	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {

		now = (uint64_t) uwsgi_now();
		if (uwsgi.async_runqueue_cnt) {
			timeout = 0;
		}
		else {
			min_timeout = uwsgi_min_rb_timer(uwsgi.rb_async_timeouts, NULL);
			if (min_timeout) {
				timeout = min_timeout->value - now;
				if (timeout <= 0) {
					async_expire_timeouts(now);
					timeout = 0;
				}
			}
			else {
				timeout = -1;
			}
		}

		uwsgi.async_nevents = event_queue_wait_multi(uwsgi.async_queue, timeout, events, 64);

		now = (uint64_t) uwsgi_now();
		// timeout ???
		if (uwsgi.async_nevents == 0) {
			async_expire_timeouts(now);
		}


		for (i = 0; i < uwsgi.async_nevents; i++) {
			// manage events
			interesting_fd = event_queue_interesting_fd(events, i);

			if (uwsgi.signal_socket > -1 && (interesting_fd == uwsgi.signal_socket || interesting_fd == uwsgi.my_signal_socket)) {
				uwsgi_receive_signal(interesting_fd, "worker", uwsgi.mywid);
				continue;
			}


			is_a_new_connection = 0;

			// new request coming in ?

			uwsgi_sock = uwsgi.sockets;
			while (uwsgi_sock) {

				if (interesting_fd == uwsgi_sock->fd) {

					is_a_new_connection = 1;

					uwsgi.wsgi_req = find_first_available_wsgi_req();
					if (uwsgi.wsgi_req == NULL) {
						uwsgi_async_queue_is_full((time_t)now);
						break;
					}

					wsgi_req_setup(uwsgi.wsgi_req, uwsgi.wsgi_req->async_id, uwsgi_sock);
					if (wsgi_req_simple_accept(uwsgi.wsgi_req, interesting_fd)) {
						uwsgi.async_queue_unused_ptr++;
						uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = uwsgi.wsgi_req;
						break;
					}

					if (wsgi_req_async_recv(uwsgi.wsgi_req)) {
						uwsgi.async_queue_unused_ptr++;
						uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = uwsgi.wsgi_req;
						break;
					}

					if (uwsgi.wsgi_req->do_not_add_to_async_queue) {
						runqueue_push(uwsgi.wsgi_req);
					}

					break;
				}

				uwsgi_sock = uwsgi_sock->next;
			}

			if (!is_a_new_connection) {
				// proto event
				uwsgi.wsgi_req = find_wsgi_req_proto_by_fd(interesting_fd);
				if (uwsgi.wsgi_req) {
					proto_parser_status = uwsgi.wsgi_req->socket->proto(uwsgi.wsgi_req);
					// reset timeout
					uwsgi_del_rb_timer(uwsgi.rb_async_timeouts, uwsgi.wsgi_req->async_timeout);
					free(uwsgi.wsgi_req->async_timeout);
					uwsgi.wsgi_req->async_timeout = NULL;
					// parsing complete
					if (!proto_parser_status) {
						// remove fd from event poll and fd proto table 
						uwsgi.async_proto_fd_table[interesting_fd] = NULL;
						event_queue_del_fd(uwsgi.async_queue, interesting_fd, event_queue_read());
						// put request in the runqueue
						runqueue_push(uwsgi.wsgi_req);
						continue;
					}
					else if (proto_parser_status < 0) {
						if (proto_parser_status == -1)
							uwsgi_log("error parsing request\n");
						uwsgi.async_proto_fd_table[interesting_fd] = NULL;
						close(interesting_fd);
						continue;
					}
					// re-add timer
					async_add_timeout(uwsgi.wsgi_req, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
					continue;
				}

				// app event
				uwsgi.wsgi_req = find_wsgi_req_by_fd(interesting_fd);
				// unknown fd, remove it (for safety)
				if (uwsgi.wsgi_req == NULL) {
					close(interesting_fd);
					continue;
				}

				// remove all the fd monitors and timeout
				while (uwsgi.wsgi_req->waiting_fds) {
					tmp_uaf = uwsgi.wsgi_req->waiting_fds;
					uwsgi.async_waiting_fd_table[tmp_uaf->fd] = NULL;
					event_queue_del_fd(uwsgi.async_queue, tmp_uaf->fd, tmp_uaf->event);
					uwsgi.wsgi_req->waiting_fds = tmp_uaf->next;
					free(tmp_uaf);
				}
				uwsgi.wsgi_req->waiting_fds = NULL;
				if (uwsgi.wsgi_req->async_timeout) {
					uwsgi_del_rb_timer(uwsgi.rb_async_timeouts, uwsgi.wsgi_req->async_timeout);
					free(uwsgi.wsgi_req->async_timeout);
					uwsgi.wsgi_req->async_timeout = NULL;
				}

				uwsgi.wsgi_req->async_ready_fd = 1;
				uwsgi.wsgi_req->async_last_ready_fd = interesting_fd;

				// put the request in the runqueue again
				runqueue_push(uwsgi.wsgi_req);
				// avoid managing other enqueued events...
				break;
			}
		}

		// event queue managed, give cpu to runqueue
		if (!current_request)
			current_request = uwsgi.async_runqueue;

		if (uwsgi.async_runqueue_cnt) {

			uwsgi.wsgi_req = current_request->wsgi_req;

			uwsgi.schedule_to_req();
			uwsgi.wsgi_req->switches++;

			next_async_request = current_request->next;
			// request ended ?
			if (uwsgi.wsgi_req->async_status <= UWSGI_OK) {
				// remove all the monitored fds and timeout
				while (uwsgi.wsgi_req->waiting_fds) {
					tmp_uaf = uwsgi.wsgi_req->waiting_fds;
					uwsgi.async_waiting_fd_table[tmp_uaf->fd] = NULL;
					event_queue_del_fd(uwsgi.async_queue, tmp_uaf->fd, tmp_uaf->event);
					uwsgi.wsgi_req->waiting_fds = tmp_uaf->next;
					free(tmp_uaf);
				}
				uwsgi.wsgi_req->waiting_fds = NULL;
				if (uwsgi.wsgi_req->async_timeout) {
					uwsgi_del_rb_timer(uwsgi.rb_async_timeouts, uwsgi.wsgi_req->async_timeout);
					free(uwsgi.wsgi_req->async_timeout);
					uwsgi.wsgi_req->async_timeout = NULL;
				}

				// remove from the list
				runqueue_remove(current_request);

				uwsgi_close_request(uwsgi.wsgi_req);

				// push wsgi_request in the unused stack
				uwsgi.async_queue_unused_ptr++;
				uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = uwsgi.wsgi_req;

			}
			else if (uwsgi.wsgi_req->waiting_fds || uwsgi.wsgi_req->async_timeout) {
				// remove this request from suspended list      
				runqueue_remove(current_request);
			}

			current_request = next_async_request;

		}


	}

}
