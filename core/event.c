#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

#ifdef UWSGI_EVENT_USE_PORT

#include <port.h>

#define UWSGI_EVENT_IN POLLIN
#define UWSGI_EVENT_OUT POLLOUT

int event_queue_init() {

	int port = port_create();

	if (port < 0) {
		uwsgi_error("port_create()");
		return -1;
	}

	return port;
}

int event_queue_del_fd(int eq, int fd, int event) {

	if (port_dissociate(eq, PORT_SOURCE_FD, fd)) {
		uwsgi_error("port_disassociate");
		return -1;
	}

	return 0;
}

int event_queue_fd_write_to_read(int eq, int fd) {

	if (port_associate(eq, PORT_SOURCE_FD, fd, POLLIN, NULL)) {
		uwsgi_error("port_associate");
		return -1;
	}

	return 0;

}

int event_queue_fd_read_to_write(int eq, int fd) {

	if (port_associate(eq, PORT_SOURCE_FD, fd, POLLOUT, NULL)) {
		uwsgi_error("port_associate");
		return -1;
	}

	return 0;

}

int event_queue_fd_readwrite_to_read(int eq, int fd) {

	if (port_associate(eq, PORT_SOURCE_FD, fd, POLLIN, NULL)) {
		uwsgi_error("port_associate");
		return -1;
	}

	return 0;

}

int event_queue_fd_readwrite_to_write(int eq, int fd) {

	if (port_associate(eq, PORT_SOURCE_FD, fd, POLLOUT, NULL)) {
		uwsgi_error("port_associate");
		return -1;
	}

	return 0;

}

int event_queue_fd_write_to_readwrite(int eq, int fd) {

	if (port_associate(eq, PORT_SOURCE_FD, fd, POLLIN | POLLOUT, NULL)) {
		uwsgi_error("port_associate");
		return -1;
	}

	return 0;

}

int event_queue_fd_read_to_readwrite(int eq, int fd) {

	if (port_associate(eq, PORT_SOURCE_FD, fd, POLLIN | POLLOUT, NULL)) {
		uwsgi_error("port_associate");
		return -1;
	}

	return 0;

}


int event_queue_interesting_fd_has_error(void *events, int id) {
	port_event_t *pe = (port_event_t *) events;
	if (pe[id].portev_events == POLLHUP || pe[id].portev_events == POLLERR) {
		return 1;
	}
	return 0;
}

int event_queue_interesting_fd_is_read(void *events, int id) {
	port_event_t *pe = (port_event_t *) events;
	if (pe[id].portev_events = POLLIN) {
		return 1;
	}
	return 0;
}

int event_queue_interesting_fd_is_write(void *events, int id) {
	port_event_t *pe = (port_event_t *) events;
	if (pe[id].portev_events == POLLOUT) {
		return 1;
	}
	return 0;
}

int event_queue_add_fd_read(int eq, int fd) {

	if (port_associate(eq, PORT_SOURCE_FD, fd, POLLIN, (void *) eq)) {
		uwsgi_error("port_associate");
		return -1;
	}

	return 0;
}

int event_queue_add_fd_write(int eq, int fd) {

	if (port_associate(eq, PORT_SOURCE_FD, fd, POLLOUT, NULL)) {
		uwsgi_error("port_associate");
		return -1;
	}

	return 0;
}

void *event_queue_alloc(int nevents) {

	return uwsgi_malloc(sizeof(port_event_t) * nevents);
}

int event_queue_interesting_fd(void *events, int id) {
	port_event_t *pe = (port_event_t *) events;
	if (pe[id].portev_source == PORT_SOURCE_FILE || pe[id].portev_source == PORT_SOURCE_TIMER) {
		return (long) pe[id].portev_user;
	}

	int fd = (int) pe[id].portev_object;
	int eq = (int) pe[id].portev_user;

	if (pe[id].portev_events == POLLOUT) {
		event_queue_add_fd_write(eq, fd);
	}
	if (pe[id].portev_events == POLLIN) {
		event_queue_add_fd_read(eq, fd);
	}

	return fd;
}

int event_queue_wait_multi(int eq, int timeout, void *events, int nevents) {

	int ret;
	uint_t nget = 1;
	timespec_t ts;

	if (timeout >= 0) {
		ts.tv_sec = timeout;
		ts.tv_nsec = 0;
		ret = port_getn(eq, events, nevents, &nget, &ts);
	}
	else {
		ret = port_getn(eq, events, nevents, &nget, NULL);
	}

	if (ret < 0) {
		if (errno != ETIME) {
			uwsgi_error("port_getn()");
			return -1;
		}
		return 0;
	}

	return nget;
}



int event_queue_wait(int eq, int timeout, int *interesting_fd) {

	int ret;
	port_event_t pe;
	timespec_t ts;

	if (timeout > 0) {
		ts.tv_sec = timeout;
		ts.tv_nsec = 0;
		ret = port_get(eq, &pe, &ts);
	}
	else {
		ret = port_get(eq, &pe, NULL);
	}
	if (ret < 0) {
		if (errno != ETIME) {
			uwsgi_error("port_get()");
			return -1;
		}
		return 0;
	}

	if (pe.portev_source == PORT_SOURCE_FD) {
		// event must be readded (damn Oracle/Sun why the fu*k you made such a horrible choice ???? why not adding a ONESHOT flag ???)
		if (port_associate(eq, pe.portev_source, pe.portev_object, pe.portev_events, NULL)) {
			uwsgi_error("port_associate");
		}
	}


	if (pe.portev_source == PORT_SOURCE_FILE || pe.portev_source == PORT_SOURCE_TIMER) {
		*interesting_fd = (long) pe.portev_user;
	}
	else {
		*interesting_fd = (int) pe.portev_object;
	}

	return 1;
}

#endif


#ifdef UWSGI_EVENT_USE_EPOLL

#include <sys/epoll.h>

#define UWSGI_EVENT_IN EPOLLIN
#define UWSGI_EVENT_OUT EPOLLOUT

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

int event_queue_fd_write_to_read(int eq, int fd) {

	struct epoll_event ee;

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.events = EPOLLIN;
	ee.data.fd = fd;

	if (epoll_ctl(eq, EPOLL_CTL_MOD, fd, &ee)) {
		uwsgi_error("epoll_ctl()");
		return -1;
	}

	return 0;
}

int event_queue_fd_read_to_write(int eq, int fd) {

	struct epoll_event ee;

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.events = EPOLLOUT;
	ee.data.fd = fd;

	if (epoll_ctl(eq, EPOLL_CTL_MOD, fd, &ee)) {
		uwsgi_error("epoll_ctl()");
		return -1;
	}

	return 0;
}

int event_queue_fd_readwrite_to_read(int eq, int fd) {

	struct epoll_event ee;

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.events = EPOLLIN;
	ee.data.fd = fd;

	if (epoll_ctl(eq, EPOLL_CTL_MOD, fd, &ee)) {
		uwsgi_error("epoll_ctl()");
		return -1;
	}

	return 0;
}

int event_queue_fd_readwrite_to_write(int eq, int fd) {

	struct epoll_event ee;

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.events = EPOLLOUT;
	ee.data.fd = fd;

	if (epoll_ctl(eq, EPOLL_CTL_MOD, fd, &ee)) {
		uwsgi_error("epoll_ctl()");
		return -1;
	}

	return 0;
}


int event_queue_fd_read_to_readwrite(int eq, int fd) {

	struct epoll_event ee;

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.events = EPOLLIN | EPOLLOUT;
	ee.data.fd = fd;

	if (epoll_ctl(eq, EPOLL_CTL_MOD, fd, &ee)) {
		uwsgi_error("epoll_ctl()");
		return -1;
	}

	return 0;
}

int event_queue_fd_write_to_readwrite(int eq, int fd) {

	struct epoll_event ee;

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.events = EPOLLIN | EPOLLOUT;
	ee.data.fd = fd;

	if (epoll_ctl(eq, EPOLL_CTL_MOD, fd, &ee)) {
		uwsgi_error("epoll_ctl()");
		return -1;
	}

	return 0;
}



int event_queue_del_fd(int eq, int fd, int event) {

	struct epoll_event ee;

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.data.fd = fd;
	ee.events = event;

	if (epoll_ctl(eq, EPOLL_CTL_DEL, fd, &ee)) {
		uwsgi_error("epoll_ctl()");
		return -1;
	}

	return 0;
}

int event_queue_add_fd_write(int eq, int fd) {

	struct epoll_event ee;

	memset(&ee, 0, sizeof(struct epoll_event));
	ee.events = EPOLLOUT;
	ee.data.fd = fd;

	if (epoll_ctl(eq, EPOLL_CTL_ADD, fd, &ee)) {
		uwsgi_error("epoll_ctl()");
		return -1;
	}

	return 0;
}

void *event_queue_alloc(int nevents) {

	return uwsgi_malloc(sizeof(struct epoll_event) * nevents);
}

int event_queue_interesting_fd(void *events, int id) {
	struct epoll_event *ee = (struct epoll_event *) events;
	return ee[id].data.fd;
}

int event_queue_interesting_fd_has_error(void *events, int id) {
	struct epoll_event *ee = (struct epoll_event *) events;
	if (ee[id].events == EPOLLHUP || ee[id].events == EPOLLERR || (ee[id].events == (EPOLLERR | EPOLLHUP))) {
		return 1;
	}
	return 0;
}

int event_queue_interesting_fd_is_read(void *events, int id) {
	struct epoll_event *ee = (struct epoll_event *) events;
	if (ee[id].events & EPOLLIN) {
		return 1;
	}
	return 0;
}

int event_queue_interesting_fd_is_write(void *events, int id) {
	struct epoll_event *ee = (struct epoll_event *) events;
	if (ee[id].events & EPOLLOUT) {
		return 1;
	}
	return 0;
}


int event_queue_wait_multi(int eq, int timeout, void *events, int nevents) {

	int ret;

	if (timeout > 0) {
		timeout = timeout * 1000;
	}

	ret = epoll_wait(eq, (struct epoll_event *) events, nevents, timeout);
	if (ret < 0) {
		if (errno != EINTR)
			uwsgi_error("epoll_wait()");
	}

	return ret;
}

int event_queue_wait(int eq, int timeout, int *interesting_fd) {

	int ret;
	struct epoll_event ee;

	if (timeout > 0) {
		timeout = timeout * 1000;
	}

	ret = epoll_wait(eq, &ee, 1, timeout);
	if (ret < 0) {
		if (errno != EINTR)
			uwsgi_error("epoll_wait()");
	}

	if (ret > 0) {
		*interesting_fd = ee.data.fd;
	}

	return ret;
}

#endif

#ifdef UWSGI_EVENT_USE_KQUEUE

#define UWSGI_EVENT_IN EVFILT_READ
#define UWSGI_EVENT_OUT EVFILT_WRITE

int event_queue_init() {

	int kfd = kqueue();

	if (kfd < 0) {
		uwsgi_error("kqueue()");
		return -1;
	}

	return kfd;
}

int event_queue_fd_write_to_read(int eq, int fd) {

	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	return 0;
}

int event_queue_fd_read_to_write(int eq, int fd) {

	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_READ, EV_DELETE, 0, 0, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	EV_SET(&kev, fd, EVFILT_WRITE, EV_ADD, 0, 0, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	return 0;
}

int event_queue_fd_readwrite_to_read(int eq, int fd) {

	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	return 0;
}

int event_queue_fd_readwrite_to_write(int eq, int fd) {

	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_READ, EV_DELETE, 0, 0, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	return 0;
}

int event_queue_fd_read_to_readwrite(int eq, int fd) {

	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_WRITE, EV_ADD, 0, 0, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	return 0;
}


int event_queue_fd_write_to_readwrite(int eq, int fd) {

	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	return 0;
}



int event_queue_del_fd(int eq, int fd, int event) {

	struct kevent kev;

	EV_SET(&kev, fd, event, EV_DELETE, 0, 0, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	return 0;
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

void *event_queue_alloc(int nevents) {

	return uwsgi_malloc(sizeof(struct kevent) * nevents);
}

int event_queue_wait_multi(int eq, int timeout, void *events, int nevents) {

	int ret;
	struct timespec ts;

	if (timeout < 0) {
		ret = kevent(eq, NULL, 0, events, nevents, NULL);
	}
	else {
		memset(&ts, 0, sizeof(struct timespec));
		ts.tv_sec = timeout;
		ret = kevent(eq, NULL, 0, (struct kevent *) events, nevents, &ts);
	}

	if (ret < 0) {
		if (errno != EINTR)
			uwsgi_error("kevent()");
	}

	return ret;

}

int event_queue_interesting_fd(void *events, int id) {

	struct kevent *ev = (struct kevent *) events;
	return ev[id].ident;
}

int event_queue_interesting_fd_has_error(void *events, int id) {
	struct kevent *ev = (struct kevent *) events;

	// DO NOT CHECK FOR EOF !!!
	if (ev[id].flags & EV_ERROR) {
		return 1;
	}
	return 0;
}

int event_queue_interesting_fd_is_read(void *events, int id) {
	struct kevent *ev = (struct kevent *) events;
	if (ev[id].filter == EVFILT_READ) {
		return 1;
	}
	return 0;
}


int event_queue_interesting_fd_is_write(void *events, int id) {
	struct kevent *ev = (struct kevent *) events;
	if (ev[id].filter == EVFILT_WRITE) {
		return 1;
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
		if (errno != EINTR)
			uwsgi_error("kevent()");
	}

	if (ret > 0) {
		*interesting_fd = ev.ident;
	}

	return ret;

}
#endif

#ifdef UWSGI_EVENT_FILEMONITOR_USE_NONE
int event_queue_add_file_monitor(int eq, char *filename, int *id) {
	return -1;
}
struct uwsgi_fmon *event_queue_ack_file_monitor(int eq, int id) {
	return NULL;
}
#endif

#ifdef UWSGI_EVENT_FILEMONITOR_USE_PORT
int event_queue_add_file_monitor(int eq, char *filename, int *id) {

	struct file_obj fo;
	struct stat st;
	static int fmon_id = 0xffffee00;

	if (stat(filename, &st)) {
		uwsgi_error("stat()");
		return -1;
	}

	fo.fo_name = filename;
	fo.fo_atime = st.st_atim;
	fo.fo_mtime = st.st_mtim;
	fo.fo_ctime = st.st_ctim;

	fmon_id++;
	if (port_associate(eq, PORT_SOURCE_FILE, (uintptr_t) & fo, FILE_MODIFIED | FILE_ATTRIB, (void *) (long) fmon_id)) {
		uwsgi_error("port_associate()");
		return -1;
	}


	*id = fmon_id;

	uwsgi_log("added new file to monitor %s [%d]\n", filename, *id);

	return *id;
}

struct uwsgi_fmon *event_queue_ack_file_monitor(int eq, int id) {

	int i;
	struct file_obj fo;
	struct stat st;

	for (i = 0; i < ushared->files_monitored_cnt; i++) {
		if (ushared->files_monitored[i].registered) {
			if (ushared->files_monitored[i].fd == id) {
				if (stat(ushared->files_monitored[i].filename, &st)) {
					uwsgi_error("stat()");
					return NULL;
				}
				fo.fo_name = ushared->files_monitored[i].filename;
				fo.fo_atime = st.st_atim;
				fo.fo_mtime = st.st_mtim;
				fo.fo_ctime = st.st_ctim;
				if (port_associate(eq, PORT_SOURCE_FILE, (uintptr_t) & fo, FILE_MODIFIED | FILE_ATTRIB, (void *) (long) id)) {
					uwsgi_error("port_associate()");
					return NULL;
				}
				return &ushared->files_monitored[i];
			}
		}
	}

	return NULL;

}

#endif


#ifdef UWSGI_EVENT_FILEMONITOR_USE_KQUEUE
int event_queue_add_file_monitor(int eq, char *filename, int *id) {

	struct kevent kev;

	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_error_open(filename);
		return -1;
	}

	EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE | NOTE_DELETE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_RENAME | NOTE_REVOKE, 0, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	*id = fd;

	uwsgi_log("added new file to monitor %s\n", filename);

	return fd;
}

struct uwsgi_fmon *event_queue_ack_file_monitor(int eq, int id) {

	int i;

	for (i = 0; i < ushared->files_monitored_cnt; i++) {
		if (ushared->files_monitored[i].registered) {
			if (ushared->files_monitored[i].fd == id) {
				return &ushared->files_monitored[i];
			}
		}
	}

	return NULL;

}

#endif

#ifdef UWSGI_EVENT_FILEMONITOR_USE_INOTIFY


#ifdef OBSOLETE_LINUX_KERNEL
int event_queue_add_file_monitor(int eq, char *filename, int *id) {
	return -1;
}
struct uwsgi_fmon *event_queue_ack_file_monitor(int eq, int id) {
	return NULL;
}
#else
#include <sys/inotify.h>

int event_queue_add_file_monitor(int eq, char *filename, int *id) {

	int ifd = -1;
	int i;
	int add_to_queue = 0;

	for (i = 0; i < ushared->files_monitored_cnt; i++) {
		if (ushared->files_monitored[i].registered) {
			ifd = ushared->files_monitored[0].fd;
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

	*id = inotify_add_watch(ifd, filename, IN_ATTRIB | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO);

#ifdef UWSGI_DEBUG
	uwsgi_log("added watch %d for filename %s\n", *id, filename);
#endif

	if (add_to_queue) {
		if (event_queue_add_fd_read(eq, ifd)) {
			return -1;
		}
	}
	return ifd;
}

struct uwsgi_fmon *event_queue_ack_file_monitor(int eq, int id) {

	ssize_t rlen = 0;
	struct inotify_event ie, *bie, *iie;
	int i, j;
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
		items = isize / (sizeof(struct inotify_event));
#ifdef UWSGI_DEBUG
		uwsgi_log("inotify returned %d items\n", items);
#endif
		for (j = 0; j < items; j++) {
			iie = &bie[j];
			for (i = 0; i < ushared->files_monitored_cnt; i++) {
				if (ushared->files_monitored[i].registered) {
					if (ushared->files_monitored[i].fd == id && ushared->files_monitored[i].id == iie->wd) {
						uf = &ushared->files_monitored[i];
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
#endif

#ifdef UWSGI_EVENT_TIMER_USE_TIMERFD

#ifndef UWSGI_EVENT_TIMER_USE_TIMERFD_NOINC
#include <sys/timerfd.h>
#endif

#ifndef TFD_CLOEXEC

// timerfd support

enum {
	TFD_CLOEXEC = 02000000,
#define TFD_CLOEXEC TFD_CLOEXEC
	TFD_NONBLOCK = 04000
#define TFD_NONBLOCK TFD_NONBLOCK
};


/* Bits to be set in the FLAGS parameter of `timerfd_settime'.  */
enum {
	TFD_TIMER_ABSTIME = 1 << 0
#define TFD_TIMER_ABSTIME TFD_TIMER_ABSTIME
};


static int timerfd_create(clockid_t __clock_id, int __flags) {
#ifdef __amd64__
	return syscall(283, __clock_id, __flags);
#elif defined(__i386__)
	return syscall(322, __clock_id, __flags);
#else
	return -1;
#endif
}

static int timerfd_settime(int __ufd, int __flags, __const struct itimerspec *__utmr, struct itimerspec *__otmr) {
#ifdef __amd64__
	return syscall(286, __ufd, __flags, __utmr, __otmr);
#elif defined(__i386__)
	return syscall(325, __ufd, __flags, __utmr, __otmr);
#endif
}
#endif

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
	if (event_queue_add_fd_read(eq, tfd)) {
		return -1;
	}
	return tfd;
}

struct uwsgi_timer *event_queue_ack_timer(int id) {

	int i;
	ssize_t rlen;
	uint64_t counter;
	struct uwsgi_timer *ut = NULL;

	for (i = 0; i < ushared->timers_cnt; i++) {
		if (ushared->timers[i].registered) {
			if (ushared->timers[i].id == id) {
				ut = &ushared->timers[i];
			}
		}
	}

	rlen = read(id, &counter, sizeof(uint64_t));

	if (rlen < 0) {
		uwsgi_error("read()");
	}

	return ut;
}
#endif

#ifdef UWSGI_EVENT_TIMER_USE_NONE
int event_queue_add_timer(int eq, int *id, int sec) {
	return -1;
}
struct uwsgi_timer *event_queue_ack_timer(int id) {
	return NULL;
}
#endif

#ifdef UWSGI_EVENT_TIMER_USE_PORT
int event_queue_add_timer(int eq, int *id, int sec) {

	static int timer_id = 0xffffff00;
	port_notify_t pnotif;
	struct sigevent sigev;
	itimerspec_t it;
	timer_t tid;

	timer_id++;

	pnotif.portnfy_port = eq;
	pnotif.portnfy_user = (void *) (long) timer_id;

	sigev.sigev_notify = SIGEV_PORT;
	sigev.sigev_value.sival_ptr = &pnotif;

	if (timer_create(CLOCK_REALTIME, &sigev, &tid) < 0) {
		uwsgi_error("timer_create()");
		return -1;
	}


	it.it_value.tv_sec = sec;
	it.it_value.tv_nsec = 0;

	it.it_interval.tv_sec = sec;
	it.it_interval.tv_nsec = 0;

	if (timer_settime(tid, 0, &it, NULL) < 0) {
		uwsgi_error("timer_settime()");
		return -1;
	}

	*id = timer_id;

	return *id;

}

struct uwsgi_timer *event_queue_ack_timer(int id) {

	int i;
	struct uwsgi_timer *ut = NULL;

	for (i = 0; i < uwsgi.shared->timers_cnt; i++) {
		if (uwsgi.shared->timers[i].registered) {
			if (uwsgi.shared->timers[i].id == id) {
				ut = &uwsgi.shared->timers[i];
			}
		}
	}

	return ut;
}
#endif


#ifdef UWSGI_EVENT_TIMER_USE_KQUEUE
int event_queue_add_timer(int eq, int *id, int sec) {

	static int timer_id = 0xffffff00;
	struct kevent kev;

	*id = timer_id;
	timer_id++;

	EV_SET(&kev, *id, EVFILT_TIMER, EV_ADD, 0, sec * 1000, 0);
	if (kevent(eq, &kev, 1, NULL, 0, NULL) < 0) {
		uwsgi_error("kevent()");
		return -1;
	}

	return *id;
}

struct uwsgi_timer *event_queue_ack_timer(int id) {

	int i;
	struct uwsgi_timer *ut = NULL;

	for (i = 0; i < uwsgi.shared->timers_cnt; i++) {
		if (uwsgi.shared->timers[i].registered) {
			if (uwsgi.shared->timers[i].id == id) {
				ut = &uwsgi.shared->timers[i];
			}
		}
	}

	return ut;

}
#endif

int event_queue_read() {
	return UWSGI_EVENT_IN;
}

int event_queue_write() {
	return UWSGI_EVENT_OUT;
}
