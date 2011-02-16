#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int async_get_timeout() {

        struct wsgi_request* wsgi_req ;
        int i ;
	time_t curtime, tdelta = 0 ;
	int ret = 0 ;

	// do not wait if there are cores running
	if (!uwsgi.async_running) return 0;

        for(i=0;i<uwsgi.async_current_max;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
                if (wsgi_req->async_status == UWSGI_AGAIN) {
			if (wsgi_req->async_timeout_expired) {
				// do not wait if there are timeout expired
				return 0;
			}
			if (wsgi_req->async_timeout > 0) {
				if (tdelta <= 0 || tdelta > wsgi_req->async_timeout) {
					tdelta = wsgi_req->async_timeout ;
				}
			}
                }
        }

	curtime = time(NULL);

	ret = tdelta - curtime ;
	if (ret > 0) {
		return ret;
	}
	
	return -1;
}

void async_expire_timeouts() {

        struct wsgi_request* wsgi_req ;
        int i ;
	time_t deadline = time(NULL);


        for(i=0;i<uwsgi.async_current_max;i++) {
                wsgi_req = uwsgi.wsgi_requests[i] ;

                if (wsgi_req->async_status == UWSGI_AGAIN && wsgi_req->async_timeout > 0) {
			if (wsgi_req->async_timeout <= deadline) {
				wsgi_req->async_timeout = 0 ;
				wsgi_req->async_timeout_expired = 1 ;
				if (wsgi_req->async_waiting_fd != -1) {
                                        event_queue_del_fd(uwsgi.async_queue, wsgi_req->async_waiting_fd);
					uwsgi.async_waiting_fd_table[wsgi_req->async_waiting_fd] = -1;
                                        wsgi_req->async_waiting_fd = -1;
                                        wsgi_req->async_waiting_fd_monitored = 0;
                                }
			}	
                }
        }
}

struct wsgi_request *find_first_available_wsgi_req() {

        struct wsgi_request* wsgi_req;
        int i ;

	// optimization
	if (uwsgi.async_current_max > 1) {
		if (uwsgi.wsgi_requests[uwsgi.async_current_max-1]->async_status == UWSGI_OK) {
			//uwsgi_log("decreasing current max cores\n");
			uwsgi.async_current_max--;
		}
	}

        for(i=0;i<uwsgi.async;i++) {
                wsgi_req = uwsgi.wsgi_requests[i] ;
                if (wsgi_req->async_status == UWSGI_OK) {
			// optimization
			if (i > uwsgi.async_current_max-1) uwsgi.async_current_max = i+1;
			wsgi_req->async_id = i;
                        return wsgi_req ;
                }
        }

        return NULL ;
}

struct wsgi_request *find_wsgi_req_by_fd(int fd) {

        struct wsgi_request* wsgi_req = NULL ;
	int core_id = uwsgi.async_waiting_fd_table[fd];

	if (core_id == -1) return NULL;

	wsgi_req = uwsgi.wsgi_requests[core_id];
        //if (wsgi_req->async_waiting_fd_type == etype) return wsgi_req ;
	return wsgi_req;

        return NULL ;

}

void async_set_timeout(struct wsgi_request *wsgi_req, time_t timeout) {

	wsgi_req->async_timeout = time(NULL);
	wsgi_req->async_timeout += timeout;
	wsgi_req->async_timeout_expired = 0 ;
	
}

void async_write_all(char *data, size_t len) {
	
	struct wsgi_request *wsgi_req;
	int i;
	ssize_t rlen ;

	for(i=0;i<uwsgi.async_current_max;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
                if (wsgi_req->async_status == UWSGI_PAUSED) {
			rlen = write(wsgi_req->poll.fd, data, len);
			if (rlen < 0) {
				uwsgi_error("write()");
			}
			else {
				wsgi_req->response_size += rlen ;
			}
		}
	}
}

void async_unpause_all() {
	
	struct wsgi_request *wsgi_req ;
	int i;

	for(i=0;i<uwsgi.async_current_max;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
                if (wsgi_req->async_status == UWSGI_PAUSED) {
			wsgi_req->async_status = UWSGI_AGAIN;
		}
	}
}

struct wsgi_request * async_loop() {

	struct wsgi_request *wsgi_req ;
	int i ;
	int ret;

	uwsgi.async_running = -1 ;

	for(i=0;i<uwsgi.async_current_max;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
        	if (wsgi_req->async_status == UWSGI_AGAIN) {
			if (wsgi_req->sigwait) {
				uwsgi_log("waiting for signal\n");
				continue;
			}
                	else if (wsgi_req->async_waiting_fd != -1 && !wsgi_req->async_waiting_fd_monitored) {
				// add fd to monitoring
				ret = -1;
				if (wsgi_req->async_waiting_fd_type == ASYNC_IN) {
					ret = event_queue_add_fd_read(uwsgi.async_queue, wsgi_req->async_waiting_fd);
				}
				else if (wsgi_req->async_waiting_fd_type == ASYNC_OUT) {
					ret = event_queue_add_fd_write(uwsgi.async_queue, wsgi_req->async_waiting_fd);
				}

				if (ret < 0) {
					// error adding fd to the async queue, better to close it...
					close(wsgi_req->async_waiting_fd);
					wsgi_req->async_status = UWSGI_OK ;
					return wsgi_req;
				}
				uwsgi.async_waiting_fd_table[wsgi_req->async_waiting_fd] = wsgi_req->async_id;
				wsgi_req->async_waiting_fd_monitored = 1;
				wsgi_req->async_status = UWSGI_AGAIN;
			}
			else if (wsgi_req->async_waiting_fd == -1 && wsgi_req->async_timeout <= 0) {
                		uwsgi.async_running = 0 ;
				// st global wsgi_req
				uwsgi.wsgi_req = wsgi_req ;

				uwsgi_log("!!! getting new part\n");
				wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);;

				wsgi_req->switches++;

				if (wsgi_req->async_status < UWSGI_AGAIN) {
					return wsgi_req;
				}
			}
		}
	}

	return NULL;

}
