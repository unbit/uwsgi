#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

struct wsgi_request *find_wsgi_req_by_fd(int fd) {
	return uwsgi.async_waiting_fd_table[fd];
}

void runqueue_remove(struct uwsgi_async_request *u_request) {

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

void runqueue_push(struct wsgi_request *wsgi_req) {

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

void async_expire_timeouts() {

	struct wsgi_request *wsgi_req;
	time_t current_time = time(NULL);
	struct uwsgi_async_fd *uaf = NULL, *current_uaf;

	struct uwsgi_rb_timer *urbt;

        for(;;) {

                urbt = uwsgi_min_rb_timer(uwsgi.rb_async_timeouts);

                if (urbt == NULL) return;

                if (urbt->key <= current_time) {
                        wsgi_req = (struct wsgi_request *) urbt->data;
			// timeout expired
			wsgi_req->async_timed_out = 1;
			rb_erase(&wsgi_req->async_timeout->rbt, uwsgi.rb_async_timeouts);
			free(wsgi_req->async_timeout);
			wsgi_req->async_timeout = NULL;
			uaf = wsgi_req->waiting_fds;
			// remove fds from monitoring (no problem modifying the queue here, as the function is executed only when there are no fd ready)
			while(uaf) {
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

void async_add_fd_read(struct wsgi_request *wsgi_req, int fd, int timeout) {

	struct uwsgi_async_fd *last_uad = NULL, *uad = wsgi_req->waiting_fds;

	if (fd < 0) return ;

	// find first slot
	while(uad) {
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
	event_queue_add_fd_read(uwsgi.async_queue, fd);
	
}

void async_add_timeout(struct wsgi_request *wsgi_req, int timeout) {

	if (timeout > 0 && wsgi_req->async_timeout == NULL) {
        	wsgi_req->async_timeout = uwsgi_add_rb_timer(uwsgi.rb_async_timeouts, time(NULL)+timeout, wsgi_req);
        }

}

void async_add_fd_write(struct wsgi_request *wsgi_req, int fd, int timeout) {

        struct uwsgi_async_fd *last_uad = NULL, *uad = wsgi_req->waiting_fds;

	if (fd < 0) return ;

        // find first slot
        while(uad) {
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
        event_queue_add_fd_write(uwsgi.async_queue, fd);

}

void async_schedule_to_req(void) {
	uwsgi.wsgi_req->async_status = uwsgi.p[uwsgi.wsgi_req->uh.modifier1]->request(uwsgi.wsgi_req);
}

void *async_loop(void *arg1) {

	struct uwsgi_async_fd *tmp_uaf;
	int interesting_fd, i;
	struct uwsgi_rb_timer *min_timeout;
	int timeout;

	static struct uwsgi_async_request *current_request = NULL, *next_async_request = NULL;

	void *events = event_queue_alloc(64);

	uwsgi.async_runqueue = NULL;
	uwsgi.async_runqueue_cnt = 0;

	// set a default request manager
        if (!uwsgi.schedule_to_req) uwsgi.schedule_to_req = async_schedule_to_req;

	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {

		if (uwsgi.async_runqueue_cnt) {
			timeout = 0;
		}
		else {
			min_timeout = uwsgi_min_rb_timer(uwsgi.rb_async_timeouts);
			if (uwsgi.async_runqueue_cnt) {
                        	timeout = 0;
			}
                	if (min_timeout) {
                        	timeout = min_timeout->key - time(NULL);
                        	if (timeout <= 0) {
                                	async_expire_timeouts();
                                	timeout = 0;
                        	}
			}
			else {
				timeout = -1;
			}
                }

		uwsgi.async_nevents = event_queue_wait_multi(uwsgi.async_queue, timeout, events, 64);

		// timeout ???
		if (uwsgi.async_nevents == 0) {
                	async_expire_timeouts();
		}

		for(i=0;i<uwsgi.async_nevents;i++) {
			// manage events
			interesting_fd = event_queue_interesting_fd(events, i);

			// new request coming in
			if (interesting_fd == uwsgi.sockets[0].fd) {
				uwsgi.wsgi_req = find_first_available_wsgi_req();
				if (uwsgi.wsgi_req == NULL) {
					uwsgi_log("async queue is full !!!\n");
					continue;
				}

				wsgi_req_setup(uwsgi.wsgi_req, uwsgi.wsgi_req->async_id );
				if (wsgi_req_simple_accept(uwsgi.wsgi_req, interesting_fd)) {
#ifdef UWSGI_EVENT_USE_PORT
                                	event_queue_add_fd_read(uwsgi.async_queue, interesting_fd);
#endif
					continue;
				}
#ifdef UWSGI_EVENT_USE_PORT
                                event_queue_add_fd_read(uwsgi.async_queue, interesting_fd);
#endif

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


				if (wsgi_req_simple_recv(uwsgi.wsgi_req)) {
					continue;
				}

				// put request in the runqueue
				runqueue_push(uwsgi.wsgi_req);
			}
			else {
				// app event
				uwsgi.wsgi_req = find_wsgi_req_by_fd(interesting_fd);
				// unknown fd, remove it (for safety)
				if (uwsgi.wsgi_req == NULL) {
					close(interesting_fd);
					continue;
				}

				// remove all the fd monitors and timeout
				while(uwsgi.wsgi_req->waiting_fds) {
#ifndef UWSGI_EVENT_USE_PORT
                                        event_queue_del_fd(uwsgi.async_queue, uwsgi.wsgi_req->waiting_fds->fd, uwsgi.wsgi_req->waiting_fds->event);
#endif
                                        tmp_uaf = uwsgi.wsgi_req->waiting_fds;
                                        uwsgi.async_waiting_fd_table[tmp_uaf->fd] = NULL;
                                        uwsgi.wsgi_req->waiting_fds = tmp_uaf->next;
                                        free(tmp_uaf);
                                }
				uwsgi.wsgi_req->waiting_fds = NULL;
                                if (uwsgi.wsgi_req->async_timeout) {
                                        rb_erase(&uwsgi.wsgi_req->async_timeout->rbt, uwsgi.rb_async_timeouts);
                                        free(uwsgi.wsgi_req->async_timeout);
                                        uwsgi.wsgi_req->async_timeout = NULL;
                                }	

				uwsgi.wsgi_req->async_ready_fd = 1;
				uwsgi.wsgi_req->async_last_ready_fd = interesting_fd;

				// put the request in the runqueue again
				runqueue_push(uwsgi.wsgi_req);
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
			if (uwsgi.wsgi_req->async_status == UWSGI_OK) {
				// remove all the monitored fds and timeout
				while(uwsgi.wsgi_req->waiting_fds) {
#ifndef UWSGI_EVENT_USE_PORT
					event_queue_del_fd(uwsgi.async_queue, uwsgi.wsgi_req->waiting_fds->fd, uwsgi.wsgi_req->waiting_fds->event);
#endif
					tmp_uaf = uwsgi.wsgi_req->waiting_fds;
					uwsgi.async_waiting_fd_table[tmp_uaf->fd] = NULL;
					uwsgi.wsgi_req->waiting_fds = tmp_uaf->next;
					free(tmp_uaf);
				}
				uwsgi.wsgi_req->waiting_fds = NULL;
				if (uwsgi.wsgi_req->async_timeout) {
					rb_erase(&uwsgi.wsgi_req->async_timeout->rbt, uwsgi.rb_async_timeouts);
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

	return NULL;

}
