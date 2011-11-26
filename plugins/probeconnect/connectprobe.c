#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

int connect_prober_callback(int interesting_fd, struct uwsgi_signal_probe *up) {

	// is this a timeout event ?
	if (interesting_fd == -1) {
		// am i wating for something ?
		if (up->fd != -1) {
			if (up->cycles > (uint64_t) up->timeout) {
				// reset the cycle
				up->cycles = 0;
				close(up->fd);
				up->fd = -1;
				// state = NOOP
				up->state = 0;
				// avoid duplicated events
				if (!up->bad) {
					up->bad = 1;
					return 1;
				}
			}
		}
		// ok register a new event
		else {
			if ((up->cycles % up->freq) == 0) {
				up->fd = uwsgi_connect(up->args, -1, 1);
				if (up->fd != -1) {
					// status = CONNECTING
					up->state = 1;
					event_queue_add_fd_write(uwsgi.master_queue, up->fd);
					return 0;
				}
				// signal the bad event (if not already bad)
				if (!up->bad) {
					up->bad = 1;
					return 1;
				}

			}
		}
	}
	else if (up->fd != -1) {
		// is this event for me ?
		if (interesting_fd == up->fd) {
			// uselsess here (we have only one state), only to show a good practice
			// check the state
			if (up->state == 1) {
				if (uwsgi_is_bad_connection(up->fd)) {
					// signal the bad connection (if needed)
					up->cycles = 0;
					close(up->fd);
					up->fd = -1;
					// state = NOOP
					up->state = 0;
					if (!up->bad) {
						up->bad = 1;
						return 1;
					}
					return 0;
				}
				// this is a good connection
				up->cycles = 0;
				close(up->fd);
				up->fd = -1;
				// state = NOOP
				up->state = 0;
				if (up->bad) {
					up->bad = 0;
					return 1;
				}
			}
		}
	}

	// default action
	return 0;
}

int probeconnect_init() {

	uwsgi_probe_register(&uwsgi.probes, "connect", connect_prober_callback);
	return 0;
}

struct uwsgi_plugin probeconnect_plugin = {

	.init = probeconnect_init,
};
