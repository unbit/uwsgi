#include "../../uwsgi.h"

#include "rr.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_rawrouter urr;

void uwsgi_rawrouter_switch_events(struct uwsgi_corerouter *ucr, struct corerouter_session *cs, int interesting_fd) {

	socklen_t solen = sizeof(int);
	ssize_t len;
	char buf[8192];

	switch (cs->status) {

		case COREROUTER_STATUS_RECV_HDR:
#ifdef UWSGI_EVENT_USE_PORT
			event_queue_add_fd_read(ucr->queue, cs->fd);
#endif
			// use the address as hostname
			cs->hostname = cs->ugs->name;
			cs->hostname_len = cs->ugs->name_len;

			// the mapper hook
			if (ucr->mapper(ucr, cs))
				break;

			// no address found
			if (!cs->instance_address_len) {
				// if fallback nodes are configured, trigger them
				if (ucr->fallback) {
					cs->instance_failed = 1;
				}
				corerouter_close_session(ucr, cs);
				break;
			}

			cs->instance_fd = uwsgi_connectn(cs->instance_address, cs->instance_address_len, 0, 1);

			if (cs->instance_fd < 0) {
				cs->instance_failed = 1;
				cs->soopt = errno;
				corerouter_close_session(ucr, cs);
				break;
			}


			cs->status = COREROUTER_STATUS_CONNECTING;
			ucr->cr_table[cs->instance_fd] = cs;
			event_queue_add_fd_write(ucr->queue, cs->instance_fd);
			break;



	case COREROUTER_STATUS_CONNECTING:

		if (interesting_fd == cs->instance_fd) {

			if (getsockopt(cs->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&cs->soopt), &solen) < 0) {
				uwsgi_error("getsockopt()");
				cs->instance_failed = 1;
				corerouter_close_session(ucr, cs);
				break;
			}

			if (cs->soopt) {
				cs->instance_failed = 1;
				corerouter_close_session(ucr, cs);
				break;
			}

			// increment node requests counter
			if (cs->un) {
				cs->un->requests++;

				// update node rpm
				time_t now = uwsgi_now();
				time_t target_ts = now / 60;

				// first check for clock jumps
				if (cs->un->rpm_timecheck == 0 || cs->un->rpm_timecheck > target_ts || (target_ts - cs->un->rpm_timecheck) > 1) {
					// if clock go back or jumps to the future than just reset everything
					cs->un->rpm_timecheck = target_ts;
					cs->un->last_minute_requests = 1;
				} else if (cs->un->rpm_timecheck != target_ts) {
					// clock did not jumped, this is next minute
					cs->un->requests_per_minute = cs->un->last_minute_requests;
					cs->un->rpm_timecheck = target_ts;
					cs->un->last_minute_requests = 1;
				} else {
					cs->un->last_minute_requests++;
				}

			}

			event_queue_fd_write_to_read(ucr->queue, cs->instance_fd);
			cs->status = COREROUTER_STATUS_RESPONSE;
		}

		break;

	case COREROUTER_STATUS_RESPONSE:

		// data from instance
		if (interesting_fd == cs->instance_fd) {
			len = recv(cs->instance_fd, buf, 8192, 0);
#ifdef UWSGI_EVENT_USE_PORT
                        event_queue_add_fd_read(ucr->queue, cs->instance_fd);
#endif
			if (len <= 0) {
				if (len < 0)
					uwsgi_error("recv()");
				corerouter_close_session(ucr, cs);
				break;
			}

			len = send(cs->fd, buf, len, 0);

			if (len <= 0) {
				if (len < 0)
					uwsgi_error("send()");
				corerouter_close_session(ucr, cs);
				break;
			}

			// update transfer statistics
			if (cs->un)
				cs->un->transferred += len;

		}

		// body from client
		else if (interesting_fd == cs->fd) {

			//uwsgi_log("receiving body...\n");
			len = recv(cs->fd, buf, 8192, 0);
#ifdef UWSGI_EVENT_USE_PORT
                        event_queue_add_fd_read(ucr->queue, cs->fd);
#endif
			if (len <= 0) {
				if (len < 0)
					uwsgi_error("recv()");
				corerouter_close_session(ucr, cs);
				break;
			}


			len = send(cs->instance_fd, buf, len, 0);

			if (len <= 0) {
				if (len < 0)
					uwsgi_error("send()");
				corerouter_close_session(ucr, cs);
				break;
			}
		}

		break;

		// fallback to destroy !!!
	default:
		uwsgi_log("unknown event: closing session\n");
		corerouter_close_session(ucr, cs);
		break;

	}
}
