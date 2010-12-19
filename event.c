#include "uwsgi.h"

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

        return 0;
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
	
	return 0;
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
int event_queue_add_file_monitor(int eq, int fd) {

	struct kevent kev;
	
        EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD|EV_CLEAR, NOTE_WRITE|NOTE_DELETE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_RENAME|NOTE_REVOKE, 0, 0);
        if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
                uwsgi_error("kevent()");
                return -1;
        }
	
	return 0;
}
#endif

#ifdef UWSGI_EVENT_FILEMONITOR_USE_INOTIFY
#include <sys/inotify.h>

int event_queue_add_file_monitor(int eq, char *filename, int *id) {

	int ifd = inotify_init();
	if (ifd < 0) {
		uwsgi_error("inotify_init()");
		return -1;
	}	

	*id = ifd;
		
	uwsgi_log("added watch %d for filename %s\n", inotify_add_watch(ifd, filename, IN_ATTRIB|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MODIFY|IN_MOVE_SELF|IN_MOVED_FROM|IN_MOVED_TO), filename);

	
	return event_queue_add_fd_read(eq, ifd);
}

void event_queue_ack_file_monitor(int id) {

	ssize_t rlen = 0;
	struct inotify_event ie;

	rlen = read(id, &ie, sizeof(struct inotify_event));

	if (rlen < 0) {
		uwsgi_error("read()");
	}
	
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

void event_queue_ack_timer(int id) {
	
	ssize_t rlen;
	uint64_t counter;

	rlen = read(id, &counter, sizeof(uint64_t));

	if (rlen < 0) {
		uwsgi_error("read()");
	}
	
}
#endif

#ifdef UWSGI_EVENT_TIMER_USE_NONE
int event_queue_add_timer(int eq, int *id, int sec) { return -1; }
void event_queue_ack_timer(int id) {}
#endif

#ifdef UWSGI_EVENT_TIMER_USE_KQUEUE
int event_queue_add_timer(int eq, int *id, int sec) {

	struct kevent kev;
	
        EV_SET(&kev, *id, EVFILT_TIMER, EV_ADD, 0, sec*1000, 0);
        if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
                uwsgi_error("kevent()");
                return -1;
        }
	
	return 0;
}

void event_queue_ack_timer(int id) {}
#endif
