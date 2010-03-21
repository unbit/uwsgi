#ifdef UWSGI_ASYNC

#include "uwsgi.h"


#ifdef __linux__

#include <sys/epoll.h>

int async_queue_init(int serverfd) {
	int epfd ;
	struct epoll_event ee;

	epfd = epoll_create(256);	

	if (epfd < 0) {
		perror("epoll_create()");
		return -1 ;
	}

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.events = EPOLLIN;
        ee.data.fd = serverfd;

        if (epoll_ctl(epfd, EPOLL_CTL_ADD, serverfd, &ee)) {
                perror("epoll_ctl()");
		close(epfd);
		return -1;
        }

	return epfd;
}

int async_wait(int queuefd, void *events, int nevents, int block, int timeout) {

	int ret ;

	if (timeout <= 0) {
		timeout = block;
	}
	else {
		timeout = timeout*1000;
	}

	//fprintf(stderr,"waiting with timeout %d nevents %d\n", timeout, nevents);
	ret = epoll_wait(queuefd, (struct epoll_event *) events, nevents, timeout);
	if (ret < 0) {
		perror("epoll_wait()");
	}
	return ret ;
}

int async_add(int queuefd, int fd, int etype) {
	struct epoll_event ee;

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.events = etype;
        ee.data.fd = fd;

        if (epoll_ctl(queuefd, EPOLL_CTL_ADD, fd, &ee)) {
                perror("epoll_ctl()");
		return -1;
        }

	return 0;
}

int async_del(int queuefd, int fd, int etype) {
	struct epoll_event ee;

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.events = etype;
        ee.data.fd = fd;

        if (epoll_ctl(queuefd, EPOLL_CTL_DEL, fd, &ee)) {
                perror("epoll_ctl()");
		return -1;
        }

	return 0;
}

#elif defined(__sun__)
#else
int async_queue_init(int serverfd) {
	int kfd ;
	struct kevent kev;

	kfd = kqueue();	

	if (kfd < 0) {
		perror("kqueue()");
		return -1 ;
	}

	EV_SET(&kev, serverfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
        if (kevent(kfd, &kev, 1, NULL, 0, NULL) < 0) {
                perror("kevent()");
                return -1;
        }

	return kfd;
}

int async_wait() {
	uwsgi.async_nevents = kevent(uwsgi.async_queue, NULL, 0, uwsgi.async_events, uwsgi.async, &uwsgi.async_timeout);
}

int async_add(int queuefd, int fd, int etype) {
	struct kevent kev;


	EV_SET(&kev, fd, etype, EV_ADD, 0, 0, NULL);
        if (kevent(queuefd, &kev, 1, NULL, 0, NULL) < 0) {
                perror("kevent()");
                return -1;
        }
	return 0;
}

int async_del(int queuefd, int fd, int etype) {
	struct kevent kev;

	EV_SET(&kev, fd, etype, EV_DELETE, 0, 0, NULL);
        if (kevent(queuefd, &kev, 1, NULL, 0, NULL) < 0) {
                perror("kevent()");
                return -1;
        }

	return 0;
}

#endif

struct wsgi_request *next_wsgi_req(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

        uint8_t *ptr = (uint8_t *) wsgi_req ;

        ptr += sizeof(struct wsgi_request)+(uwsgi->buffer_size-1) ;

        return (struct wsgi_request *) ptr ;
}

int async_get_timeout(struct uwsgi_server *uwsgi) {


        struct wsgi_request* wsgi_req = uwsgi->wsgi_requests ;
        int i ;
	time_t curtime, tdelta = 0 ;
	int ret = 0 ;

	if (!uwsgi->async_running) return 0;

        for(i=0;i<uwsgi->async;i++) {
                if (wsgi_req->async_status == UWSGI_AGAIN) {
			if (wsgi_req->async_timeout_expired) {
				return 0;
			}
			if (wsgi_req->async_timeout > 0) {
				if (tdelta <= 0 || tdelta > wsgi_req->async_timeout) {
					tdelta = wsgi_req->async_timeout ;
				}
			}
                }
                wsgi_req = next_wsgi_req(uwsgi, wsgi_req) ;
        }

	curtime = time(NULL);

	ret = tdelta - curtime ;
	if (ret > 0) {
		return ret;
	}
	
	return 0;
}

void async_expire_timeouts(struct uwsgi_server *uwsgi) {

        struct wsgi_request* wsgi_req = uwsgi->wsgi_requests ;
        int i ;
	time_t deadline = time(NULL);


        for(i=0;i<uwsgi->async;i++) {
                if (wsgi_req->async_status == UWSGI_AGAIN && wsgi_req->async_timeout > 0) {
			if (wsgi_req->async_timeout <= deadline) {
				wsgi_req->async_timeout = 0 ;
				wsgi_req->async_timeout_expired = 1 ;
			}	
                }
                wsgi_req = next_wsgi_req(uwsgi, wsgi_req) ;
        }
}

struct wsgi_request *find_first_available_wsgi_req(struct uwsgi_server *uwsgi) {

        struct wsgi_request* wsgi_req = uwsgi->wsgi_requests ;
        int i ;

        for(i=0;i<uwsgi->async;i++) {
                if (wsgi_req->async_status == UWSGI_OK) {
                        return wsgi_req ;
                }
                wsgi_req = next_wsgi_req(uwsgi, wsgi_req) ;
        }

        return NULL ;
}

struct wsgi_request *find_wsgi_req_by_fd(struct uwsgi_server *uwsgi, int fd, int etype) {

        struct wsgi_request* wsgi_req = uwsgi->wsgi_requests ;
        int i ;

        for(i=0;i<uwsgi->async;i++) {
                if (wsgi_req->async_waiting_fd == fd && wsgi_req->async_waiting_fd_type & etype) {
                        return wsgi_req ;
                }
                wsgi_req = next_wsgi_req(uwsgi, wsgi_req) ;
        }

        return NULL ;

}

void async_set_timeout(struct wsgi_request *wsgi_req, time_t timeout) {

	wsgi_req->async_timeout = time(NULL);
	wsgi_req->async_timeout += timeout;
	wsgi_req->async_timeout_expired = 0 ;
	
}

struct wsgi_request * async_loop(struct uwsgi_server *uwsgi) {

	struct wsgi_request *wsgi_req ;
	int i ;

	uwsgi->async_running = -1 ;
        wsgi_req = uwsgi->wsgi_requests ;


	for(i=0;i<uwsgi->async;i++) {
        	if (wsgi_req->async_status == UWSGI_AGAIN) {
			//fprintf(stderr,"REQUEST MONITORED %d %d\n",wsgi_req->async_waiting_fd, wsgi_req->async_waiting_fd_monitored);
                	if (wsgi_req->async_waiting_fd != -1 && !wsgi_req->async_waiting_fd_monitored) {
				// add fd to monitoring
				if (async_add(uwsgi->async_queue, wsgi_req->async_waiting_fd, wsgi_req->async_waiting_fd_type)) {
					// error adding fd to the async queue, better to close it...
					close(wsgi_req->async_waiting_fd);
					wsgi_req->async_status = UWSGI_OK ;
					return wsgi_req;
				}
				wsgi_req->async_waiting_fd_monitored = 1;
				wsgi_req->async_status = UWSGI_AGAIN;
			}
			else if (wsgi_req->async_waiting_fd == -1 && wsgi_req->async_timeout <= 0) {
                		uwsgi->async_running = 0 ;
				// st global wsgi_req for python functions
				uwsgi->wsgi_req = wsgi_req ;
				wsgi_req->async_status = (*uwsgi->shared->hooks[wsgi_req->modifier]) (uwsgi, wsgi_req);

				wsgi_req->async_switches++;

				if (wsgi_req->async_status < UWSGI_AGAIN) {
					return wsgi_req;
				}
			}
		}
		wsgi_req = next_wsgi_req(uwsgi, wsgi_req) ;
	}

	return NULL;

}
#endif
