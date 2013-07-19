#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

void uwsgi_register_fsmon(struct uwsgi_string_list *usl) {
#ifdef UWSGI_EVENT_FILEMONITOR_USE_INOTIFY
#ifdef OBSOLETE_LINUX_KERNEL
	return -1;
#else
	static int inotify_fd = -1;
	if (inotify_fd == -1) {
		inotify_fd = inotify_init();
		if (inotify_fd < 0) {
			uwsgi_error("uwsgi_register_fsmon()/inotify_init()");
			exit(1);
		}
		if (event_queue_add_fd_read(uwsgi.master_queue, inotify_fd)) {
			uwsgi_error("uwsgi_register_fsmon()/event_queue_add_fd_read()");
			exit(1);
		}
	}
	int wd = inotify_add_watch(inotify_fd, usl->value, IN_ATTRIB | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO);
	if (wd < 0) {
		uwsgi_error("uwsgi_register_fsmon()/inotify_add_watch()");
		exit(1);
	}
	usl->custom = inotify_fd;
	usl->custom64 = wd;
	return 0;
#endif
#else
	return -1;
#endif
}

static void uwsgi_fsmon_ack(struct uwsgi_string_list *ul, struct uwsgi_string_list *usl) {
#ifdef UWSGI_EVENT_FILEMONITOR_USE_INOTIFY
#ifdef OBSOLETE_LINUX_KERNEL
	return;
#else
	// allocate the exact amoutn of needed memory
	// read from the inotify descriptor
	// search for the wd and print it
#endif
#else
	return;
#endif
}

int uwsgi_fsmon_event(struct uwsgi_string_list *ul, int interesting_fd) {

	struct uwsgi_string_list *usl = ul;
	while(usl) {
		if (usl->custom == interesting_fd) {
			uwsgi_fsmon_ack(ul, usl);
			return 1;
		}
		usl = usl->next;
	}
	
	return 0;
}

