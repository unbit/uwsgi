#include "../../uwsgi.h"
#include <libpq-fe.h>

extern struct uwsgi_server uwsgi;
int pg_prober_callback(int, struct uwsgi_signal_probe *);
int probepg_init(void);

int pg_prober_callback(int interesting_fd, struct uwsgi_signal_probe *up) {

	// is this a timeout event ?
	if (interesting_fd == -1) {
		// am i wating for something ?
		if (up->fd != -1) {
			if (up->cycles > (uint64_t) up->timeout) {
				// reset the cycle
				up->cycles = 0;
				PQfinish((PGconn *) up->data);
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
				up->last_event = event_queue_write();
				up->data = (void *) PQconnectStart(up->args);
				if (up->data) {
					// status = CONNECTING
					up->state = PQstatus((PGconn *) up->data);
					if (up->state == CONNECTION_BAD)
						goto bad;
					up->fd = PQsocket((PGconn *) up->data);
					event_queue_add_fd_write(uwsgi.master_queue, up->fd);
					return 0;
				}
			      bad:
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
			// check the state
			up->state = PQstatus((PGconn *) up->data);
			if (up->state == CONNECTION_BAD) {
				// signal the bad connection (if needed)
				up->cycles = 0;
				PQfinish((PGconn *) up->data);
				up->fd = -1;
				up->state = 0;
				if (!up->bad) {
					up->bad = 1;
					return 1;
				}
				return 0;
			}
			else if (up->state == CONNECTION_OK) {
				up->cycles = 0;
				PQfinish((PGconn *) up->data);
				up->fd = -1;
				// state = NOOP
				up->state = 0;
				if (up->bad) {
					up->bad = 0;
					return 1;
				}
			}
			// still wait...
			else {
				PostgresPollingStatusType wait_type = PQconnectPoll((PGconn *) up->data);
				// the connection is good
				if (wait_type == PGRES_POLLING_ACTIVE || wait_type == PGRES_POLLING_FAILED || wait_type == PGRES_POLLING_OK) {
					if (wait_type == PGRES_POLLING_ACTIVE)
						wait_type = PQconnectPoll((PGconn *) up->data);
					up->cycles = 0;
					up->fd = -1;
					// state = NOOP
					up->state = 0;
					PQfinish((PGconn *) up->data);
					if (wait_type == PGRES_POLLING_FAILED) {
						if (!up->bad) {
							up->bad = 1;
							return 1;
						}
					}
					else {
						if (up->bad) {
							up->bad = 0;
							return 1;
						}
					}
				}
				else if (wait_type == PGRES_POLLING_READING) {
					event_queue_del_fd(uwsgi.master_queue, up->fd, up->last_event);
					event_queue_add_fd_read(uwsgi.master_queue, up->fd);
					up->last_event = event_queue_read();
				}
				else if (wait_type == PGRES_POLLING_WRITING) {
					event_queue_del_fd(uwsgi.master_queue, up->fd, up->last_event);
					event_queue_add_fd_write(uwsgi.master_queue, up->fd);
					up->last_event = event_queue_write();
				}
			}
		}
	}

	// default action
	return 0;
}

int probepg_init() {

	uwsgi_probe_register(&uwsgi.probes, "pg", pg_prober_callback);
	return 0;
}

struct uwsgi_plugin probepg_plugin = {

	.init = probepg_init,
};
