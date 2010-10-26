#ifdef __linux__

#include <sys/inotify.h>

int uwsgi_file_monitor_new() {

	int inotify_fd;


	inotify_fd = inotify_init();

	if (inotify_fd < 0) {
		uwsgi_error("inotify_init()");
		return -1;
	}

	return inotify_fd;
}

int uwsgi_file_monitor_add(int fd, char *what) {

	int inotify_watch_fd;

	inotify_watch_fd = inotify_add_watch(fd, what, IN_ALL_EVENTS);

	if (inotify_watch_fd < 0) {
		uwsgi_error("inotify_add_watch()");
		return -1;
	}

	return inotify_watch_fd;
}

#endif
