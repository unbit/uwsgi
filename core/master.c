#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void uwsgi_restore_auto_snapshot(int signum) {

	if (uwsgi.workers[1].snapshot > 0) {
		uwsgi.restore_snapshot = 1;
	}
	else {
		uwsgi_log("[WARNING] no snapshot available\n");
	}

}

void uwsgi_block_signal(int signum) {
	sigset_t smask;
	sigemptyset(&smask);
	sigaddset(&smask, signum);
	if (sigprocmask(SIG_BLOCK, &smask, NULL)) {
		uwsgi_error("sigprocmask()");
	}
}

void uwsgi_unblock_signal(int signum) {
	sigset_t smask;
	sigemptyset(&smask);
	sigaddset(&smask, signum);
	if (sigprocmask(SIG_UNBLOCK, &smask, NULL)) {
		uwsgi_error("sigprocmask()");
	}
}

void uwsgi_master_manage_udp(int udp_fd) {
	struct sockaddr_in udp_client;
	char udp_client_addr[16];
	int i;

	socklen_t udp_len = sizeof(udp_client);
	ssize_t rlen = recvfrom(udp_fd, uwsgi.wsgi_req->buffer, uwsgi.buffer_size, 0, (struct sockaddr *) &udp_client, &udp_len);

	if (rlen < 0) {
		uwsgi_error("recvfrom()");
	}
	else if (rlen > 0) {

		memset(udp_client_addr, 0, 16);
		if (inet_ntop(AF_INET, &udp_client.sin_addr.s_addr, udp_client_addr, 16)) {
			if (uwsgi.wsgi_req->buffer[0] == UWSGI_MODIFIER_MULTICAST_ANNOUNCE) {
			}
			else if (uwsgi.wsgi_req->buffer[0] == 0x30 && uwsgi.snmp) {
				manage_snmp(udp_fd, (uint8_t *) uwsgi.wsgi_req->buffer, rlen, &udp_client);
			}
			else {

				// loop the various udp manager until one returns true
				int udp_managed = 0;
				for (i = 0; i < 256; i++) {
					if (uwsgi.p[i]->manage_udp) {
						if (uwsgi.p[i]->manage_udp(udp_client_addr, udp_client.sin_port, uwsgi.wsgi_req->buffer, rlen)) {
							udp_managed = 1;
							break;
						}
					}
				}

				// else a simple udp logger
				if (!udp_managed) {
					uwsgi_log("[udp:%s:%d] %.*s", udp_client_addr, ntohs(udp_client.sin_port), (int) rlen, uwsgi.wsgi_req->buffer);
				}
			}
		}
		else {
			uwsgi_error("inet_ntop()");
		}

	}
}

void uwsgi_master_manage_emperor() {
	char byte;
	ssize_t rlen = read(uwsgi.emperor_fd, &byte, 1);
	if (rlen > 0) {
		uwsgi_log_verbose("received message %d from emperor\n", byte);
		// remove me
		if (byte == 0) {
			close(uwsgi.emperor_fd);
			if (!uwsgi.status.brutally_reloading)
				kill_them_all(0);
		}
		// reload me
		else if (byte == 1) {
			// un-lazy the stack to trigger a real reload
			uwsgi.lazy = 0;
			uwsgi_block_signal(SIGHUP);
			grace_them_all(0);
			uwsgi_unblock_signal(SIGHUP);
		}
	}
	else {
		uwsgi_log("lost connection with my emperor !!!\n");
		close(uwsgi.emperor_fd);
		if (!uwsgi.status.brutally_reloading)
			kill_them_all(0);
		sleep(2);
		exit(1);
	}

}


void uwsgi_master_restore_snapshot() {
	int i, waitpid_status;
	uwsgi_log("[snapshot] restoring workers...\n");
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].pid == 0)
			continue;
		kill(uwsgi.workers[i].pid, SIGKILL);
		if (waitpid(uwsgi.workers[i].pid, &waitpid_status, 0) < 0) {
			uwsgi_error("waitpid()");
		}
		if (uwsgi.auto_snapshot > 0 && i > uwsgi.auto_snapshot) {
			uwsgi.workers[i].pid = 0;
			uwsgi.workers[i].snapshot = 0;
		}
		else {
			uwsgi.workers[i].pid = uwsgi.workers[i].snapshot;
			uwsgi.workers[i].snapshot = 0;
			kill(uwsgi.workers[i].pid, SIGURG);
			uwsgi_log("Restored uWSGI worker %d (pid: %d)\n", i, (int) uwsgi.workers[i].pid);
		}
	}

	uwsgi.restore_snapshot = 0;
}

void suspend_resume_them_all(int signum) {

	int i;
	int suspend = 0;

	if (uwsgi.workers[0].suspended == 1) {
		uwsgi_log_verbose("*** (SIGTSTP received) resuming workers ***\n");
		uwsgi.workers[0].suspended = 0;
	}
	else {
		uwsgi_log_verbose("*** PAUSE (press start to resume, if you do not have a joypad send SIGTSTP) ***\n");
		suspend = 1;
		uwsgi.workers[0].suspended = 1;
	}

	// subscribe/unsubscribe if needed
	uwsgi_subscribe_all(suspend, 1);

	for (i = 1; i <= uwsgi.numproc; i++) {
		uwsgi.workers[i].suspended = suspend;
		if (uwsgi.workers[i].pid > 0) {
			if (kill(uwsgi.workers[i].pid, SIGTSTP)) {
				uwsgi_error("kill()");
			}
		}
	}
}


void uwsgi_master_check_mercy() {

	int i;

	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].pid > 0 && uwsgi.workers[i].cursed_at) {
			if (uwsgi_now() > uwsgi.workers[i].no_mercy_at) {
				uwsgi_log_verbose("worker %d (pid: %d) is taking too much time to die...NO MERCY !!!\n", i, uwsgi.workers[i].pid);
				// yes that look strangem but we avoid callign it again if we skip waitpid() call below
				uwsgi_curse(i, SIGKILL);
			}
		}
	}
}


void expire_rb_timeouts(struct uwsgi_rbtree *tree) {

	uint64_t current = (uint64_t) uwsgi_now();
	struct uwsgi_rb_timer *urbt;
	struct uwsgi_signal_rb_timer *usrbt;

	for (;;) {

		urbt = uwsgi_min_rb_timer(tree, NULL);

		if (urbt == NULL)
			return;

		if (urbt->value <= current) {
			// remove the timeout and add another
			usrbt = (struct uwsgi_signal_rb_timer *) urbt->data;
			uwsgi_del_rb_timer(tree, urbt);
			free(urbt);
			usrbt->iterations_done++;
			uwsgi_route_signal(usrbt->sig);
			if (!usrbt->iterations || usrbt->iterations_done < usrbt->iterations) {
				usrbt->uwsgi_rb_timer = uwsgi_add_rb_timer(tree, uwsgi_now() + usrbt->value, usrbt);
			}
			continue;
		}

		break;
	}
}

int uwsgi_get_tcp_info(int fd) {

#if defined(__linux__) || defined(__FreeBSD__)
	socklen_t tis = sizeof(struct tcp_info);

	if (!getsockopt(fd, IPPROTO_TCP, TCP_INFO, &uwsgi.shared->ti, &tis)) {

		// checks for older kernels
#if defined(__linux__)
		if (!uwsgi.shared->ti.tcpi_sacked) {
#elif defined(__FreeBSD__)
		if (!uwsgi.shared->ti.__tcpi_sacked) {
#endif
                        return 0;
                }

#if defined(__linux__)
		uwsgi.shared->load = (uint64_t) uwsgi.shared->ti.tcpi_unacked;
		uwsgi.shared->max_load = (uint64_t) uwsgi.shared->ti.tcpi_sacked;
#elif defined(__FreeBSD__)
		uwsgi.shared->load = (uint64_t) uwsgi.shared->ti.__tcpi_unacked;
		uwsgi.shared->max_load = (uint64_t) uwsgi.shared->ti.__tcpi_sacked;
#endif

		uwsgi.shared->options[UWSGI_OPTION_BACKLOG_STATUS] = uwsgi.shared->load;
		if (uwsgi.vassal_sos_backlog > 0 && uwsgi.has_emperor) {
			if (uwsgi.shared->load >= (uint64_t) uwsgi.vassal_sos_backlog) {
				// ask emperor for help
				char byte = 30;
				if (write(uwsgi.emperor_fd, &byte, 1) != 1) {
					uwsgi_error("write()");
				}
				else {
					uwsgi_log("asking emperor for reinforcements (backlog: %llu)...\n", (unsigned long long ) uwsgi.shared->load);
				}
			}
		}
		if (uwsgi.shared->load >= uwsgi.shared->max_load) {
			uwsgi_log_verbose("*** uWSGI listen queue of socket %d full !!! (%llu/%llu) ***\n", fd, (unsigned long long ) uwsgi.shared->load, (unsigned long long ) uwsgi.shared->max_load);
			uwsgi.shared->options[UWSGI_OPTION_BACKLOG_ERRORS]++;
		}

		return uwsgi.shared->load;
	}
#endif

	return 0;
}


#ifdef __linux__
#include <linux/sockios.h>

#ifdef UNBIT
#define SIOBKLGQ 0x8908
#endif

#ifdef SIOBKLGQ

int get_linux_unbit_SIOBKLGQ(int fd) {

	int queue = 0;
	if (ioctl(fd, SIOBKLGQ, &queue) >= 0) {
		uwsgi.shared->load = queue;
		uwsgi.shared->options[UWSGI_OPTION_BACKLOG_STATUS] = queue;
		if (queue >= uwsgi.listen_queue) {
			uwsgi_log_verbose("*** uWSGI listen queue of socket %d full !!! (%d/%d) ***\n", fd, queue, uwsgi.listen_queue);
			uwsgi.shared->options[UWSGI_OPTION_BACKLOG_ERRORS]++;
		}
		return queue;
	}

	return 0;

}
#endif
#endif


int master_loop(char **argv, char **environ) {

	struct timeval last_respawn;
	int last_respawn_rate = 0;

	pid_t diedpid;
	int waitpid_status;

	time_t now = 0;

	int i = 0;
	int rlen;

	int check_interval = 1;

	struct uwsgi_rb_timer *min_timeout;
	struct uwsgi_rbtree *rb_timers = uwsgi_init_rb_timer();


	if (uwsgi.procname_master) {
		uwsgi_set_processname(uwsgi.procname_master);
	}
	else if (uwsgi.procname) {
		uwsgi_set_processname(uwsgi.procname);
	}
	else if (uwsgi.auto_procname) {
		uwsgi_set_processname("uWSGI master");
	}


	uwsgi.current_time = uwsgi_now();

	uwsgi_unix_signal(SIGTSTP, suspend_resume_them_all);
	uwsgi_unix_signal(SIGHUP, grace_them_all);
	if (uwsgi.die_on_term) {
		uwsgi_unix_signal(SIGTERM, kill_them_all);
		uwsgi_unix_signal(SIGQUIT, reap_them_all);
	}
	else {
		uwsgi_unix_signal(SIGTERM, reap_them_all);
		uwsgi_unix_signal(SIGQUIT, kill_them_all);
	}
	uwsgi_unix_signal(SIGINT, kill_them_all);
	uwsgi_unix_signal(SIGUSR1, stats);
	if (uwsgi.auto_snapshot) {
		uwsgi_unix_signal(SIGURG, uwsgi_restore_auto_snapshot);
	}

	atexit(uwsgi_master_cleanup_hooks);

	uwsgi.master_queue = event_queue_init();

	/* route signals to workers... */
#ifdef UWSGI_DEBUG
	uwsgi_log("adding %d to signal poll\n", uwsgi.shared->worker_signal_pipe[0]);
#endif
	event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->worker_signal_pipe[0]);

	if (uwsgi.spoolers) {
		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->spooler_signal_pipe[0]);
	}

	if (uwsgi.mules_cnt > 0) {
		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->mule_signal_pipe[0]);
	}

	if (uwsgi.log_master) {
		uwsgi.log_master_buf = uwsgi_malloc(uwsgi.log_master_bufsize);
		if (!uwsgi.threaded_logger) {
#ifdef UWSGI_DEBUG
			uwsgi_log("adding %d to master logging\n", uwsgi.shared->worker_log_pipe[0]);
#endif
			event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->worker_log_pipe[0]);
			if (uwsgi.req_log_master) {
				event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->worker_req_log_pipe[0]);
			}
		}
		else {
			uwsgi_threaded_logger_spawn();
		}

	}

#ifdef UWSGI_SSL
	uwsgi_start_legions();
#endif

	uwsgi_cache_start_sweepers();
	uwsgi_cache_start_sync_servers();

	uwsgi.wsgi_req->buffer = uwsgi.workers[0].cores[0].buffer;

	if (uwsgi.has_emperor) {
		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.emperor_fd);
	}

	if (uwsgi.zerg_server) {
		uwsgi.zerg_server_fd = bind_to_unix(uwsgi.zerg_server, uwsgi.listen_queue, 0, 0);
		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.zerg_server_fd);
		uwsgi_log("*** Zerg server enabled on %s ***\n", uwsgi.zerg_server);
	}

	if (uwsgi.stats) {
		char *tcp_port = strchr(uwsgi.stats, ':');
		if (tcp_port) {
			// disable deferred accept for this socket
			int current_defer_accept = uwsgi.no_defer_accept;
			uwsgi.no_defer_accept = 1;
			uwsgi.stats_fd = bind_to_tcp(uwsgi.stats, uwsgi.listen_queue, tcp_port);
			uwsgi.no_defer_accept = current_defer_accept;
		}
		else {
			uwsgi.stats_fd = bind_to_unix(uwsgi.stats, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
		}

		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.stats_fd);
		uwsgi_log("*** Stats server enabled on %s fd: %d ***\n", uwsgi.stats, uwsgi.stats_fd);
	}


	if (uwsgi.stats_pusher_instances) {
		if (!uwsgi_thread_new(uwsgi_stats_pusher_loop)) {
			uwsgi_log("!!! unable to spawn stats pusher thread !!!\n");
			exit(1);
		}
	}

	if (uwsgi.udp_socket) {
		uwsgi.udp_fd = bind_to_udp(uwsgi.udp_socket, 0, 0);
		if (uwsgi.udp_fd < 0) {
			uwsgi_log("unable to bind to udp socket. SNMP services will be disabled.\n");
		}
		else {
			uwsgi_log("UDP server enabled.\n");
			event_queue_add_fd_read(uwsgi.master_queue, uwsgi.udp_fd);
		}
	}

	uwsgi.snmp_fd = uwsgi_setup_snmp();

	if (uwsgi.status.is_cheap) {
		uwsgi_add_sockets_to_queue(uwsgi.master_queue, -1);
		for (i = 1; i <= uwsgi.numproc; i++) {
			uwsgi.workers[i].cheaped = 1;
		}
		uwsgi_log("cheap mode enabled: waiting for socket connection...\n");
	}


	// spawn mules
	for (i = 0; i < uwsgi.mules_cnt; i++) {
		size_t mule_patch_size = 0;
		uwsgi.mules[i].patch = uwsgi_string_get_list(&uwsgi.mules_patches, i, &mule_patch_size);
		uwsgi_mule(i + 1);
	}

	// spawn gateways
	for (i = 0; i < ushared->gateways_cnt; i++) {
		if (ushared->gateways[i].pid == 0) {
			gateway_respawn(i);
		}
	}

	// spawn daemons
	uwsgi_daemons_spawn_all();

	// first subscription
	uwsgi_subscribe_all(0, 1);

	// sync the cache store if needed
	uwsgi_cache_sync_all();

	if (uwsgi.queue_store && uwsgi.queue_filesize) {
		if (msync(uwsgi.queue_header, uwsgi.queue_filesize, MS_ASYNC)) {
			uwsgi_error("msync()");
		}
	}

	// update touches timestamps
	uwsgi_check_touches(uwsgi.touch_reload);
	uwsgi_check_touches(uwsgi.touch_logrotate);
	uwsgi_check_touches(uwsgi.touch_logreopen);
	uwsgi_check_touches(uwsgi.touch_chain_reload);
	uwsgi_check_touches(uwsgi.touch_workers_reload);
	uwsgi_check_touches(uwsgi.touch_gracefully_stop);

	// setup cheaper algos (can be stacked)
	uwsgi.cheaper_algo = uwsgi_cheaper_algo_spare;
	if (uwsgi.requested_cheaper_algo) {
		uwsgi.cheaper_algo = NULL;
		struct uwsgi_cheaper_algo *uca = uwsgi.cheaper_algos;
		while (uca) {
			if (!strcmp(uca->name, uwsgi.requested_cheaper_algo)) {
				uwsgi.cheaper_algo = uca->func;
				break;
			}
			uca = uca->next;
		}

		if (!uwsgi.cheaper_algo) {
			uwsgi_log("unable to find requested cheaper algorithm, falling back to spare\n");
			uwsgi.cheaper_algo = uwsgi_cheaper_algo_spare;
		}

	}

	// here really starts the master loop

	for (;;) {
		//uwsgi_log("uwsgi.ready_to_reload %d %d\n", uwsgi.ready_to_reload, uwsgi.numproc);

		// run master_cycle hook for every plugin
		for (i = 0; i < uwsgi.gp_cnt; i++) {
			if (uwsgi.gp[i]->master_cycle) {
				uwsgi.gp[i]->master_cycle();
			}
		}
		for (i = 0; i < 256; i++) {
			if (uwsgi.p[i]->master_cycle) {
				uwsgi.p[i]->master_cycle();
			}
		}

		// check for death (before reload !!!)
		uwsgi_master_check_death();
		// check for realod
		if (uwsgi_master_check_reload(argv)) {
			return -1;
		}

		// check chain reload
		uwsgi_master_check_chain();

		// check if some worker is taking too much to die...
		uwsgi_master_check_mercy();

		// check for daemons (smart and dumb)
		uwsgi_daemons_smart_check();


		if (uwsgi.respawn_snapshots) {
			for (i = 1; i <= uwsgi.respawn_snapshots; i++) {
				if (uwsgi_respawn_worker(i))
					return 0;
			}

			uwsgi.respawn_snapshots = 0;
		}

		if (uwsgi.restore_snapshot) {
			uwsgi_master_restore_snapshot();
			continue;
		}

		// cheaper management
		if (uwsgi.cheaper && !uwsgi.status.is_cheap && !uwsgi_instance_is_reloading && !uwsgi_instance_is_dying && !uwsgi.workers[0].suspended) {
			if (!uwsgi_calc_cheaper())
				return 0;
		}


		// check if someone is dead
		diedpid = waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
		if (diedpid == -1) {
			if (errno == ECHILD) {
				// something did not work as expected, just assume all has been cleared
				uwsgi_master_commit_status();
				diedpid = 0;
			}
			else {
				uwsgi_error("waitpid()");
				/* here is better to reload all the uWSGI stack */
				uwsgi_log("something horrible happened...\n");
				reap_them_all(0);
				exit(1);
			}
		}

		// no one died just run all of the standard master tasks
		if (diedpid == 0) {

			/* all processes ok, doing status scan after N seconds */
			check_interval = uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL];
			if (!check_interval)
				check_interval = 1;


			// add unregistered file monitors
			// locking is not needed as monitors can only increase
			for (i = 0; i < ushared->files_monitored_cnt; i++) {
				if (!ushared->files_monitored[i].registered) {
					ushared->files_monitored[i].fd = event_queue_add_file_monitor(uwsgi.master_queue, ushared->files_monitored[i].filename, &ushared->files_monitored[i].id);
					ushared->files_monitored[i].registered = 1;
				}
			}


			// add unregistered timers
			// locking is not needed as timers can only increase
			for (i = 0; i < ushared->timers_cnt; i++) {
				if (!ushared->timers[i].registered) {
					ushared->timers[i].fd = event_queue_add_timer(uwsgi.master_queue, &ushared->timers[i].id, ushared->timers[i].value);
					ushared->timers[i].registered = 1;
				}
			}

			// add unregistered rb_timers
			// locking is not needed as rb_timers can only increase
			for (i = 0; i < ushared->rb_timers_cnt; i++) {
				if (!ushared->rb_timers[i].registered) {
					ushared->rb_timers[i].uwsgi_rb_timer = uwsgi_add_rb_timer(rb_timers, uwsgi_now() + ushared->rb_timers[i].value, &ushared->rb_timers[i]);
					ushared->rb_timers[i].registered = 1;
				}
			}

			int interesting_fd = -1;

			if (ushared->rb_timers_cnt > 0) {
				min_timeout = uwsgi_min_rb_timer(rb_timers, NULL);
				if (min_timeout == NULL) {
					check_interval = uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL];
				}
				else {
					check_interval = min_timeout->value - uwsgi_now();
					if (check_interval <= 0) {
						expire_rb_timeouts(rb_timers);
						check_interval = 0;
					}
				}
			}

			// wait for event
			rlen = event_queue_wait(uwsgi.master_queue, check_interval, &interesting_fd);

			if (rlen == 0) {
				if (ushared->rb_timers_cnt > 0) {
					expire_rb_timeouts(rb_timers);
				}
			}


			// check uwsgi-cron table
			if (ushared->cron_cnt) {
				uwsgi_manage_signal_cron(uwsgi_now());
			}

			if (uwsgi.crons) {
				uwsgi_manage_command_cron(uwsgi_now());
			}


			// check for probes
			if (ushared->probes_cnt > 0) {
				uwsgi_lock(uwsgi.probe_table_lock);
				for (i = 0; i < ushared->probes_cnt; i++) {
					if (interesting_fd == -1) {
						// increment cycles
						ushared->probes[i].cycles++;
					}
					if (ushared->probes[i].func(interesting_fd, &ushared->probes[i])) {
						uwsgi_route_signal(ushared->probes[i].sig);
					}
				}
				uwsgi_unlock(uwsgi.probe_table_lock);
			}

			// some event returned
			if (rlen > 0) {
				// if the following function returns -1, a new worker has just spawned
				if (uwsgi_master_manage_events(interesting_fd)) {
					return 0;
				}
			}

			now = uwsgi_now();
			if (now - uwsgi.current_time < 1) {
				continue;
			}
			uwsgi.current_time = now;

			// checking logsize
			if (uwsgi.logfile) {
				uwsgi_check_logrotate();
			}

			// this will be incremented at (more or less) regular intervals
			uwsgi.master_cycles++;

			// recalculate requests counter on race conditions risky configurations
			// a bit of inaccuracy is better than locking;)
			uwsgi_master_fix_request_counters();

			// check for idle
			uwsgi_master_check_idle();

			check_interval = uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL];
			if (!check_interval)
				check_interval = 1;


			// get listen_queue status
			struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
			while (uwsgi_sock) {
				if (uwsgi_sock->family == AF_INET) {
					uwsgi_sock->queue = uwsgi_get_tcp_info(uwsgi_sock->fd);
				}
#ifdef __linux__
#ifdef SIOBKLGQ
				else if (uwsgi_sock->family == AF_UNIX) {
					uwsgi_sock->queue = get_linux_unbit_SIOBKLGQ(uwsgi_sock->fd);
				}
#endif
#endif
				uwsgi_sock = uwsgi_sock->next;
			}

			// check if some worker has to die (harakiri, evil checks...)
			uwsgi_master_check_workers_deadline();

			uwsgi_master_check_gateways_deadline();
			uwsgi_master_check_mules_deadline();
			uwsgi_master_check_spoolers_deadline();

#ifdef __linux__
#ifdef MADV_MERGEABLE
			if (uwsgi.linux_ksm > 0 && (uwsgi.master_cycles % uwsgi.linux_ksm) == 0) {
				uwsgi_linux_ksm_map();
			}
#endif
#endif

			// resubscribe every 10 cycles by default
			if (( (uwsgi.subscriptions || uwsgi.subscriptions2) && ((uwsgi.master_cycles % uwsgi.subscribe_freq) == 0 || uwsgi.master_cycles == 1)) && !uwsgi_instance_is_reloading && !uwsgi_instance_is_dying && !uwsgi.workers[0].suspended) {
				uwsgi_subscribe_all(0, 0);
			}

			uwsgi_cache_sync_all();

			if (uwsgi.queue_store && uwsgi.queue_filesize && uwsgi.queue_store_sync && ((uwsgi.master_cycles % uwsgi.queue_store_sync) == 0)) {
				if (msync(uwsgi.queue_header, uwsgi.queue_filesize, MS_ASYNC)) {
					uwsgi_error("msync()");
				}
			}

			// check touch_reload
			if (!uwsgi_instance_is_reloading && !uwsgi_instance_is_dying) {
				char *touched = uwsgi_check_touches(uwsgi.touch_reload);
				if (touched) {
					uwsgi_log_verbose("*** %s has been touched... grace them all !!! ***\n", touched);
					uwsgi_block_signal(SIGHUP);
					grace_them_all(0);
					uwsgi_unblock_signal(SIGHUP);
					continue;
				}
				touched = uwsgi_check_touches(uwsgi.touch_workers_reload);
				if (touched) {
                                        uwsgi_log_verbose("*** %s has been touched... workers reload !!! ***\n", touched);
					uwsgi_block_signal(SIGHUP);
					for(i=1;i<=uwsgi.numproc;i++) {
						if (uwsgi.workers[i].pid > 0) {
							uwsgi_curse(i, SIGHUP);
						}
					}
					uwsgi_unblock_signal(SIGHUP);
                                        continue;
                                }
				touched = uwsgi_check_touches(uwsgi.touch_chain_reload);
				if (touched) {
					if (uwsgi.status.chain_reloading == 0) {
                                        	uwsgi_log_verbose("*** %s has been touched... chain reload !!! ***\n", touched);
						uwsgi.status.chain_reloading = 1;
					}
					else {
                                        	uwsgi_log_verbose("*** %s has been touched... but chain reload is already running ***\n", touched);
					}
				}
			}

			continue;

		}

		// no one died
		if (diedpid <= 0)
			continue;

		// check for deadlocks first
		uwsgi_deadlock_check(diedpid);

		// reload gateways and daemons only on normal workflow (+outworld status)
		if (!uwsgi_instance_is_reloading && !uwsgi_instance_is_dying) {

			if (uwsgi_master_check_emperor_death(diedpid)) continue;
			if (uwsgi_master_check_spoolers_death(diedpid)) continue;
			if (uwsgi_master_check_mules_death(diedpid)) continue;
			if (uwsgi_master_check_gateways_death(diedpid)) continue;
			if (uwsgi_master_check_daemons_death(diedpid)) continue;
		}


		/* What happens here ?

		   case 1) the diedpid is not a worker, report it and continue
		   case 2) the diedpid is a worker and we are not in a reload procedure -> reload it
		   case 3) the diedpid is a worker and we are in graceful reload -> uwsgi.ready_to_reload++ and continue
		   case 3) the diedpid is a worker and we are in brutal reload -> uwsgi.ready_to_die++ and continue


		 */

		int thewid = find_worker_id(diedpid);
		if (thewid <= 0) {
			// check spooler, mules, gateways and daemons
			struct uwsgi_spooler *uspool = uwsgi.spoolers;
			while (uspool) {
				if (uspool->pid > 0 && diedpid == uspool->pid) {
					uwsgi_log("spooler (pid: %d) annihilated\n", (int) diedpid);
					goto next;
				}
				uspool = uspool->next;
			}

			for (i = 0; i < uwsgi.mules_cnt; i++) {
				if (uwsgi.mules[i].pid == diedpid) {
					uwsgi_log("mule %d (pid: %d) annihilated\n", i + 1, (int) diedpid);
					goto next;
				}
			}

			for (i = 0; i < ushared->gateways_cnt; i++) {
				if (ushared->gateways[i].pid == diedpid) {
					uwsgi_log("gateway %d (%s, pid: %d) annihilated\n", i + 1, ushared->gateways[i].fullname, (int) diedpid);
					goto next;
				}
			}

			if (uwsgi_daemon_check_pid_death(diedpid))
				goto next;

			if (WIFEXITED(waitpid_status)) {
				uwsgi_log("subprocess %d exited with code %d\n", (int) diedpid, WEXITSTATUS(waitpid_status));
			}
			else if (WIFSIGNALED(waitpid_status)) {
				uwsgi_log("subprocess %d exited by signal %d\n", (int) diedpid, WTERMSIG(waitpid_status));
			}
			else if (WIFSTOPPED(waitpid_status)) {
				uwsgi_log("subprocess %d stopped\n", (int) diedpid);
			}
next:
			continue;
		}


		// ok a worker died...
		uwsgi.workers[thewid].pid = 0;
		// only to be safe :P
		uwsgi.workers[thewid].harakiri = 0;

		// ok, if we are reloading or dying, just continue the master loop
		// as soon as all of the workers have pid == 0, the action (exit, or reload) is triggered
		if (uwsgi_instance_is_reloading || uwsgi_instance_is_dying) {
			uwsgi_log("worker %d buried after %d seconds\n", thewid, (int) (uwsgi_now()-uwsgi.workers[thewid].cursed_at));
			uwsgi.workers[thewid].cursed_at = 0;
			continue;
		}

		// if we are stopping workers, just end here

		if (WIFEXITED(waitpid_status) && WEXITSTATUS(waitpid_status) == UWSGI_FAILED_APP_CODE) {
			uwsgi_log("OOPS ! failed loading app in worker %d (pid %d) :( trying again...\n", thewid, (int) diedpid);
		}
		else if (WIFEXITED(waitpid_status) && WEXITSTATUS(waitpid_status) == UWSGI_DE_HIJACKED_CODE) {
			uwsgi_log("...restoring worker %d (pid: %d)...\n", thewid, (int) diedpid);
		}
		else if (WIFEXITED(waitpid_status) && WEXITSTATUS(waitpid_status) == UWSGI_EXCEPTION_CODE) {
			uwsgi_log("... monitored exception detected, respawning worker %d (pid: %d)...\n", thewid, (int) diedpid);
		}
		else if (WIFEXITED(waitpid_status) && WEXITSTATUS(waitpid_status) == UWSGI_QUIET_CODE) {
			// noop
		}
		else if (uwsgi.workers[thewid].manage_next_request) {
			if (WIFSIGNALED(waitpid_status)) {
				uwsgi_log("DAMN ! worker %d (pid: %d) died, killed by signal %d :( trying respawn ...\n", thewid, (int) diedpid, (int) WTERMSIG(waitpid_status));
			}
			else {
				uwsgi_log("DAMN ! worker %d (pid: %d) died :( trying respawn ...\n", thewid, (int) diedpid);
			}
		}
		else if (uwsgi.workers[thewid].cursed_at > 0) {
			uwsgi_log("worker %d killed successfully (pid: %d)\n", thewid, (int) diedpid);
		}
		// manage_next_request is zero, but killed by signal...
		else if (WIFSIGNALED(waitpid_status)) {
			uwsgi_log("DAMN ! worker %d (pid: %d) MISTERIOUSLY killed by signal %d :( trying respawn ...\n", thewid, (int) diedpid, (int) WTERMSIG(waitpid_status));
		}

		if (uwsgi.workers[thewid].cheaped == 1) {
			uwsgi_log("uWSGI worker %d cheaped.\n", thewid);
			continue;
		}

		// avoid fork bombing
		gettimeofday(&last_respawn, NULL);
		if (last_respawn.tv_sec <= uwsgi.respawn_delta + check_interval) {
			last_respawn_rate++;
			if (last_respawn_rate > uwsgi.numproc) {
				if (uwsgi.forkbomb_delay > 0) {
					uwsgi_log("worker respawning too fast !!! i have to sleep a bit (%d seconds)...\n", uwsgi.forkbomb_delay);
					/* use --forkbomb-delay 0 to disable sleeping */
					sleep(uwsgi.forkbomb_delay);
				}
				last_respawn_rate = 0;
			}
		}
		else {
			last_respawn_rate = 0;
		}
		gettimeofday(&last_respawn, NULL);
		uwsgi.respawn_delta = last_respawn.tv_sec;

		// are we chain reloading it ?
		if (uwsgi.status.chain_reloading == thewid) {
			uwsgi.status.chain_reloading++;
		}

		// respawn the worker (if needed)
		if (uwsgi_respawn_worker(thewid))
			return 0;

		// end of the loop
	}

	// never here
}
