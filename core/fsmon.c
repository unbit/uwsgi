#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

#ifdef UWSGI_EVENT_FILEMONITOR_USE_INOTIFY
#ifndef OBSOLETE_LINUX_KERNEL
#include <sys/inotify.h>
#endif
#endif


void uwsgi_fsmon_setup() {
	struct uwsgi_string_list *usl = uwsgi.fs_reload;
        while(usl) {
                if (uwsgi_register_fsmon(usl)) {
                        uwsgi_log("[uwsgi-fsmon] unable to register monitor for \"%s\"\n", usl->value);
                }
                else {
                        uwsgi_log("[uwsgi-fsmon] registered monitor for \"%s\"\n", usl->value);
                }
                usl = usl->next;
        }

	usl = uwsgi.fs_brutal_reload;
        while(usl) {
                if (uwsgi_register_fsmon(usl)) {
                        uwsgi_log("[uwsgi-fsmon] unable to register monitor for \"%s\"\n", usl->value);
                }
                else {
                        uwsgi_log("[uwsgi-fsmon] registered monitor for \"%s\"\n", usl->value);
                }
                usl = usl->next;
        }

	usl = uwsgi.fs_signal;
        while(usl) {
		char *copy = uwsgi_str(usl->value);
		char *space = strchr(copy, ' ');
		if (!space) {
			uwsgi_log("[uwsgi-fsmon] invalid syntax: \"%s\"\n", usl->value);
			free(copy);
			goto next;			
		}
		*space = 0;
		usl->value = copy;
		usl->len = strlen(copy);
		usl->custom_ptr = space+1;	
                if (uwsgi_register_fsmon(usl)) {
                        uwsgi_log("[uwsgi-fsmon] unable to register monitor for \"%s\"\n", usl->value);
                }
                else {
                        uwsgi_log("[uwsgi-fsmon] registered monitor for \"%s\"\n", usl->value);
                }
next:
                usl = usl->next;
        }
}


int uwsgi_register_fsmon(struct uwsgi_string_list *usl) {
#ifdef UWSGI_EVENT_FILEMONITOR_USE_INOTIFY
#ifndef OBSOLETE_LINUX_KERNEL
	static int inotify_fd = -1;
	if (inotify_fd == -1) {
		inotify_fd = inotify_init();
		if (inotify_fd < 0) {
			uwsgi_error("uwsgi_register_fsmon()/inotify_init()");
			return -1;
		}
		if (event_queue_add_fd_read(uwsgi.master_queue, inotify_fd)) {
			uwsgi_error("uwsgi_register_fsmon()/event_queue_add_fd_read()");
			return -1;
		}
	}
	int wd = inotify_add_watch(inotify_fd, usl->value, IN_ATTRIB | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO);
	if (wd < 0) {
		uwsgi_error("uwsgi_register_fsmon()/inotify_add_watch()");
		return -1;
	}
	usl->custom = inotify_fd;
	usl->custom2 = wd;
	return 0;
#endif
#endif
#ifdef UWSGI_EVENT_FILEMONITOR_USE_KQUEUE
        struct kevent kev;
        int fd = open(usl->value, O_RDONLY);
        if (fd < 0) {
                uwsgi_error_open(usl->value);
		uwsgi_error("uwsgi_register_fsmon()/open()");	
                return -1;
        }

        EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE | NOTE_DELETE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_RENAME | NOTE_REVOKE, 0, 0);
        if (kevent(uwsgi.master_queue, &kev, 1, NULL, 0, NULL) < 0) {
                uwsgi_error("uwsgi_register_fsmon()/kevent()");
                return -1;
        }
	usl->custom = fd;
	usl->custom2 = fd;
	return 0;
#endif

	uwsgi_log("[uwsgi-fsmon] filesystem monitoring interface not available in this platform !!!\n");
	return 1;
}

static struct uwsgi_string_list *uwsgi_fsmon_ack(int interesting_fd) {
	int found_fd = -1;
	struct uwsgi_string_list *usl = uwsgi.fs_reload;
	while(usl) {
		if ((int)usl->custom == interesting_fd) {
			found_fd = usl->custom;
			goto found;
		}
		usl = usl->next;
	}
	usl = uwsgi.fs_brutal_reload;
	while(usl) {
                if ((int)usl->custom == interesting_fd) {
                        found_fd = usl->custom;
                        goto found;
                }
                usl = usl->next;
        }
	usl = uwsgi.fs_signal;
        while(usl) {
                if ((int)usl->custom == interesting_fd) {
                        found_fd = usl->custom;
                        goto found;
                }
                usl = usl->next;
        }
found:
	if (found_fd == -1) return NULL;
#ifdef UWSGI_EVENT_FILEMONITOR_USE_INOTIFY
#ifndef OBSOLETE_LINUX_KERNEL
	unsigned int isize = 0;
	if (ioctl(found_fd, FIONREAD, &isize) < 0) {
                uwsgi_error("uwsgi_fsmon_ack()/ioctl()");
                return 0;
        }
	if (isize == 0) return NULL;
	struct inotify_event *ie = uwsgi_malloc(isize);
	// read from the inotify descriptor
	ssize_t len = read(found_fd, ie, isize);
	if (len < 0) { free(ie); uwsgi_error("uwsgi_fsmon_ack()/read()"); return NULL;}
	found_fd = ie->wd;
	free(ie);
#endif
#endif
	// search for the item id and print it
	usl = uwsgi.fs_reload;	
        while(usl) {
                if ((int)usl->custom2 == found_fd) {
                        uwsgi_log("[uwsgi-fsmon] \"%s\" has been modified\n", usl->value);
                        return uwsgi.fs_reload;
                }
                usl = usl->next;
        }

	usl = uwsgi.fs_brutal_reload;
        while(usl) {
                if ((int)usl->custom2 == found_fd) {
                        uwsgi_log("[uwsgi-fsmon] \"%s\" has been modified\n", usl->value);
                        return uwsgi.fs_brutal_reload;
                } 
                usl = usl->next;
        }

	usl = uwsgi.fs_signal;
        while(usl) {
                if ((int)usl->custom2 == found_fd) {
                        uwsgi_log("[uwsgi-fsmon] \"%s\" has been modified\n", usl->value);
                        return usl;
                } 
                usl = usl->next;
        }

	return NULL;
}

int uwsgi_fsmon_event(int interesting_fd) {

	struct uwsgi_string_list *usl = uwsgi_fsmon_ack(interesting_fd);

	if (!usl) return 0;

	if (usl == uwsgi.fs_reload) {
		uwsgi_block_signal(SIGHUP);
                grace_them_all(0);
                uwsgi_unblock_signal(SIGHUP);
                return 1;
        }

	if (usl == uwsgi.fs_brutal_reload) {
                if (uwsgi.die_on_term) {
                        uwsgi_block_signal(SIGQUIT);
                        reap_them_all(0);
                        uwsgi_unblock_signal(SIGQUIT);
                }
                else {
                        uwsgi_block_signal(SIGTERM);
                        reap_them_all(0);
                        uwsgi_unblock_signal(SIGTERM);
                }
                return 1;
        }

	// fallback to signal
        uwsgi_route_signal(atoi(usl->custom_ptr));
	return 1;
}

