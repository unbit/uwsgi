#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

int uwsgi_master_manage_events(int interesting_fd) {

	// is a logline ?
	if (uwsgi.log_master && !uwsgi.threaded_logger) {
		// stderr log ?
		if (interesting_fd == uwsgi.shared->worker_log_pipe[0]) {
			uwsgi_master_log();
			return 0;
		}
		// req log ?
		if (uwsgi.req_log_master && interesting_fd == uwsgi.shared->worker_req_log_pipe[0]) {
			uwsgi_master_req_log();
			return 0;
		}
	}

	// stats server ?
	if (uwsgi.stats && uwsgi.stats_fd > -1) {
		if (interesting_fd == uwsgi.stats_fd) {
			uwsgi_send_stats(uwsgi.stats_fd, uwsgi_master_generate_stats);
			return 0;
		}
	}

	// a zerg connection ?
	if (uwsgi.zerg_server) {
		if (interesting_fd == uwsgi.zerg_server_fd) {
			uwsgi_manage_zerg(uwsgi.zerg_server_fd, 0, NULL);
			return 0;
		}
	}

	// emperor event ?
	if (uwsgi.has_emperor) {
		if (interesting_fd == uwsgi.emperor_fd) {
			uwsgi_master_manage_emperor();
			return 0;
		}
	}


	// wakeup from cheap mode ?
	if (uwsgi.status.is_cheap) {
		struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
		while (uwsgi_sock) {
			if (interesting_fd == uwsgi_sock->fd) {
				uwsgi.status.is_cheap = 0;
				uwsgi_del_sockets_from_queue(uwsgi.master_queue);
				// how many worker we need to respawn ?
				int needed = uwsgi.numproc;
				// if in cheaper mode, just respawn the minimal amount
				if (uwsgi.cheaper) {
					needed = uwsgi.cheaper_count;
				}
				int i;
				for (i = 1; i <= needed; i++) {
					if (uwsgi_respawn_worker(i))
						return -1;
				}
				// here we continue instead of returning
				break;
			}
			uwsgi_sock = uwsgi_sock->next;
		}
	}


	// an SNMP request ?
	if (uwsgi.snmp_addr && interesting_fd == uwsgi.snmp_fd) {
		uwsgi_master_manage_snmp(uwsgi.snmp_fd);
		return 0;
	}

	// a UDP request ?
	if (uwsgi.udp_socket && interesting_fd == uwsgi.udp_fd) {
		uwsgi_master_manage_udp(uwsgi.udp_fd);
		return 0;
	}


	// check if some file monitor is ready
	// no need to lock as we are only getting registered items (and only the master can register them)
	int i;
	for (i = 0; i < ushared->files_monitored_cnt; i++) {
		if (ushared->files_monitored[i].registered) {
			if (interesting_fd == ushared->files_monitored[i].fd) {
				struct uwsgi_fmon *uf = event_queue_ack_file_monitor(uwsgi.master_queue, interesting_fd);
				// now call the file_monitor handler
				if (uf)
					uwsgi_route_signal(uf->sig);
				return 0;
			}
		}
	}

	// check if some timer elapsed
	// no need to lock again
	for (i = 0; i < ushared->timers_cnt; i++) {
		if (ushared->timers[i].registered) {
			if (interesting_fd == ushared->timers[i].fd) {
				struct uwsgi_timer *ut = event_queue_ack_timer(interesting_fd);
				// now call the timer handler
				if (ut)
					uwsgi_route_signal(ut->sig);
				return 0;
			}
		}
	}

	uint8_t uwsgi_signal;
	// check for worker signal
	if (interesting_fd == uwsgi.shared->worker_signal_pipe[0]) {
		ssize_t rlen = read(interesting_fd, &uwsgi_signal, 1);
		if (rlen < 0) {
			uwsgi_error("uwsgi_master_manage_events()/read()");
		}
		else if (rlen > 0) {
			uwsgi_route_signal(uwsgi_signal);
		}
		else {
			// TODO restart workers here
			uwsgi_log_verbose("lost connection with workers !!!\n");
			close(interesting_fd);
		}
		return 0;
	}

	// check for spooler signal
	if (uwsgi.spoolers) {
		if (interesting_fd == uwsgi.shared->spooler_signal_pipe[0]) {
			ssize_t rlen = read(interesting_fd, &uwsgi_signal, 1);
			if (rlen < 0) {
				uwsgi_error("uwsgi_master_manage_events()/read()");
			}
			else if (rlen > 0) {
				uwsgi_route_signal(uwsgi_signal);
			}
			else {
				// TODO restart spoolers here
				uwsgi_log_verbose("lost connection with spoolers\n");
				close(interesting_fd);
			}
			return 0;
		}

	}

	// check for mules signal
	if (uwsgi.mules_cnt > 0) {
		if (interesting_fd == uwsgi.shared->mule_signal_pipe[0]) {
			ssize_t rlen = read(interesting_fd, &uwsgi_signal, 1);
			if (rlen < 0) {
				uwsgi_error("uwsgi_master_manage_events()/read()");
			}
			else if (rlen > 0) {
				uwsgi_route_signal(uwsgi_signal);
			}
			else {
				// TODO respawn mules here
				uwsgi_log_verbose("lost connection with mules\n");
				close(interesting_fd);
			}
			// return 0;
		}

	}

	return 0;

}
