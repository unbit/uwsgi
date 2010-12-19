#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

#ifdef UWSGI_EVENT_USE_EPOLL

#include <sys/epoll.h>

int event_queue_init() {

        int epfd;

        epfd = epoll_create(256);

        if (epfd < 0) {
                uwsgi_error("epoll_create()");
                return -1;
        }

        return epfd;
}


int event_queue_add_fd_read(int eq, int fd) {

        struct epoll_event ee;

        memset(&ee, 0, sizeof(struct epoll_event));
        ee.events = EPOLLIN;
        ee.data.fd = fd;

        if (epoll_ctl(eq, EPOLL_CTL_ADD, fd, &ee)) {
                uwsgi_error("epoll_ctl()");
                return -1;
        }

        return fd;
}

int event_queue_wait(int eq, int timeout, int *interesting_fd) {

        int ret;
	struct epoll_event ee;

        if (timeout > 0) {
                timeout = timeout*1000;
        }

        ret = epoll_wait(eq, &ee, 1, timeout);
        if (ret < 0) {
                uwsgi_error("epoll_wait()");
        }

	if (ret > 0) {
                *interesting_fd = ee.data.fd;
        }

        return ret;
}

#endif

#ifdef UWSGI_EVENT_USE_KQUEUE
int event_queue_init() {

	int kfd = kqueue();

        if (kfd < 0) {
                uwsgi_error("kqueue()");
                return -1;
        }

	return kfd;
}

int event_queue_add_fd_read(int eq, int fd) {

	struct kevent kev;

        EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, 0);
        if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
                uwsgi_error("kevent()");
                return -1;
        }
	
	return fd;
}

int event_queue_add_fd_write(int eq, int fd) {

	struct kevent kev;

        EV_SET(&kev, fd, EVFILT_WRITE, EV_ADD, 0, 0, 0);
        if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
                uwsgi_error("kevent()");
                return -1;
        }
	
	return 0;
}

int event_queue_wait(int eq, int timeout, int *interesting_fd) {

	int ret;
	struct timespec ts;
	struct kevent ev;

	if (timeout <= 0) {
        	ret = kevent(eq, NULL, 0, &ev, 1, NULL);
        }
        else {
                memset(&ts, 0, sizeof(struct timespec));
                ts.tv_sec = timeout;
                ret = kevent(eq, NULL, 0, &ev, 1, &ts);
        }

        if (ret < 0) {
                uwsgi_error("kevent()");
        }

	if (ret > 0) {
		*interesting_fd = ev.ident;
	}

	return ret;

}
#endif

#ifdef UWSGI_EVENT_FILEMONITOR_USE_KQUEUE
int event_queue_add_file_monitor(int eq, char *filename, int *id) {

	struct kevent kev;

	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_error("open()");
		return -1;
	}
	
        EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD|EV_CLEAR, NOTE_WRITE|NOTE_DELETE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_RENAME|NOTE_REVOKE, 0, 0);
        if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
                uwsgi_error("kevent()");
                return -1;
        }

	*id = fd;
	
	return fd;
}

struct uwsgi_fmon *event_queue_ack_file_monitor(int id, void hook(char *, uint32_t, char *)) {

	int i;
	struct uwsgi_fmon *uf = NULL;

        for(i=0;i<uwsgi.files_monitored_cnt;i++) {
        	if (uwsgi.files_monitored[i].registered) {
                	if (uwsgi.files_monitored[i].fd == id) {
                        	if (hook) {
                                	hook(uwsgi.files_monitored[i].filename, 0, NULL);
                                }
                                else {
                                	uf = &uwsgi.files_monitored[i];
                                }
			}
		}
        }

        return uf;

}

#endif

#ifdef UWSGI_EVENT_FILEMONITOR_USE_INOTIFY
#include <sys/inotify.h>

int event_queue_add_file_monitor(int eq, char *filename, int *id) {

	int ifd = -1;
	int i;
	int add_to_queue = 0;

	for (i=0;i<uwsgi.files_monitored_cnt;i++) {
		if (uwsgi.files_monitored[i].registered) {
			ifd = uwsgi.files_monitored[0].fd;
			break;
		}
	}

	if (ifd == -1) {
		ifd = inotify_init();
		if (ifd < 0) {
			uwsgi_error("inotify_init()");
			return -1;
		}		
		add_to_queue = 1;
	}

	*id = inotify_add_watch(ifd, filename, IN_ATTRIB|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MODIFY|IN_MOVE_SELF|IN_MOVED_FROM|IN_MOVED_TO);
		
	uwsgi_log("added watch %d for filename %s\n", *id, filename);

	if (add_to_queue) {
		return event_queue_add_fd_read(eq, ifd);
	}
	else {
		return ifd;
	}
}

struct uwsgi_fmon *event_queue_ack_file_monitor(int id, void hook(char *, uint32_t, char *)) {

	ssize_t rlen = 0;
	struct inotify_event ie, *bie, *iie;
	int i,j;
	int items = 0;

	unsigned int isize = sizeof(struct inotify_event);
	struct uwsgi_fmon *uf = NULL;

	if (ioctl(id, FIONREAD, &isize) < 0) {
		uwsgi_error("ioctl()");
		return NULL;
	}

	if (isize > sizeof(struct inotify_event)) {
		bie = uwsgi_malloc(isize);
		rlen = read(id, bie, isize);
	}
	else {
		rlen = read(id, &ie, sizeof(struct inotify_event));
		bie = &ie;
	}

	if (rlen < 0) {
		uwsgi_error("read()");
	}
	else {
		items = isize/(sizeof(struct inotify_event));
		uwsgi_log("inotify returned %d items\n", items);
		for(j=0;j<items;j++) {	
			iie = &bie[j];
			for(i=0;i<uwsgi.files_monitored_cnt;i++) {
				if (uwsgi.files_monitored[i].registered) {
					if (uwsgi.files_monitored[i].fd == id && uwsgi.files_monitored[i].id == iie->wd) {
						if (hook) {
							hook(uwsgi.files_monitored[i].filename, iie->mask, iie->name);
						}
						else {
							uf = &uwsgi.files_monitored[i];
						}
					}
				}
			}

		}	

		if (items > 1) {
			free(bie);
		}

		return uf;
	}
	
	return NULL;
	
}
#endif

#ifdef UWSGI_EVENT_TIMER_USE_TIMERFD

#include <sys/timerfd.h>

int event_queue_add_timer(int eq, int *id, int sec) {

	struct itimerspec it;
	int tfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);

	if (tfd < 0) {
		uwsgi_error("timerfd_create()");
		return -1;
	}

	it.it_value.tv_sec = sec;
	it.it_value.tv_nsec = 0;

	it.it_interval.tv_sec = sec;
	it.it_interval.tv_nsec = 0;

	if (timerfd_settime(tfd, 0, &it, NULL)) {
		uwsgi_error("timerfd_settime()");
		close(tfd);
		return -1;
	}
	
	*id = tfd;
	return event_queue_add_fd_read(eq, tfd);
}

struct uwsgi_timer *event_queue_ack_timer(int id, void hook(int, int)) {
	
	int i;
	ssize_t rlen;
	uint64_t counter;
	struct uwsgi_timer *ut = NULL;

	for(i=0;i<uwsgi.timers_cnt;i++) {
		if (uwsgi.timers[i].registered) {
			if (uwsgi.timers[i].id == id) {
				ut = &uwsgi.timers[i];
			}
		}
	}

	rlen = read(id, &counter, sizeof(uint64_t));

	if (rlen < 0) {
		uwsgi_error("read()");
	}
	else {
		if (hook && ut) {
			hook(ut->value, ut->id);
		}
	}
	
	return ut;
}
#endif

#ifdef UWSGI_EVENT_TIMER_USE_NONE
int event_queue_add_timer(int eq, int *id, int sec) { return -1; }
struct uwsgi_timer *event_queue_ack_timer(int id, void hook(int ,int)) { return NULL;}
#endif

#ifdef UWSGI_EVENT_TIMER_USE_KQUEUE
int event_queue_add_timer(int eq, int *id, int sec) {

	static int timer_id = 0xffffff00;
	struct kevent kev;

	*id = timer_id ;
	timer_id++;	

	uwsgi_log("registering timer %d\n", sec);
	
        EV_SET(&kev, *id, EVFILT_TIMER, EV_ADD, 0, sec*1000, 0);
        if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
                uwsgi_error("kevent()");
                return -1;
        }
	
	return *id;
}

struct uwsgi_timer *event_queue_ack_timer(int id, void hook(int ,int)) {

	int i;
	struct uwsgi_timer *ut = NULL;

	for(i=0;i<uwsgi.timers_cnt;i++) {
		if (uwsgi.timers[i].registered) {
			if (uwsgi.timers[i].id == id) {
				ut = &uwsgi.timers[i];
			}
		}
	}

	if (hook) {
		hook(ut->value, ut->id);
	}

	return ut;

}
#endif
