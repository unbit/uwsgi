#include "uwsgi.h"

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
		uwsgi_log("FFLAGS: %d\n", ev.fflags);
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

#ifdef UWSGI_EVENT_TIMER_USE_KQUEUE
int event_queue_add_timer(int eq, int id, int sec) {

	struct kevent kev;
	
        EV_SET(&kev, id, EVFILT_TIMER, EV_ADD, 0, sec*1000, 0);
        if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
                uwsgi_error("kevent()");
                return -1;
        }
	
	return 0;
}
#endif
