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

	for (i = 1; i <= uwsgi.numproc; i++) {
		uwsgi.workers[i].suspended = suspend;
		if (uwsgi.workers[i].pid > 0) {
			if (kill(uwsgi.workers[i].pid, SIGTSTP)) {
				uwsgi_error("kill()");
			}
		}
	}
}

void expire_rb_timeouts(struct rb_root *root) {

	time_t current = time(NULL);
	struct uwsgi_rb_timer *urbt;
	struct uwsgi_signal_rb_timer *usrbt;

	for (;;) {

		urbt = uwsgi_min_rb_timer(root);

		if (urbt == NULL)
			return;

		if (urbt->key <= current) {
			// remove the timeout and add another
			usrbt = (struct uwsgi_signal_rb_timer *) urbt->data;
			rb_erase(&usrbt->uwsgi_rb_timer->rbt, root);
			free(usrbt->uwsgi_rb_timer);
			usrbt->iterations_done++;
			uwsgi_route_signal(usrbt->sig);
			if (!usrbt->iterations || usrbt->iterations_done < usrbt->iterations) {
				usrbt->uwsgi_rb_timer = uwsgi_add_rb_timer(root, time(NULL) + usrbt->value, usrbt);
			}
			continue;
		}

		break;
	}
}

int uwsgi_master_log(void) {

	char log_buf[4096];

	ssize_t rlen = read(uwsgi.shared->worker_log_pipe[0], log_buf, 4096);
	if (rlen > 0) {
		if (uwsgi.choosen_logger) {
			uwsgi.choosen_logger->func(uwsgi.choosen_logger, log_buf, rlen);
		}
		else {
			rlen = write(uwsgi.original_log_fd, log_buf, rlen);
		}
		// TODO allow uwsgi.logger = func
		return 0;
	}

	return -1;
}

void *logger_thread_loop(void *noarg) {
	struct pollfd logpoll;

	// block all signals
	sigset_t smask;
        sigfillset(&smask);
        pthread_sigmask(SIG_BLOCK, &smask, NULL);

	logpoll.events = POLLIN;
	logpoll.fd = uwsgi.shared->worker_log_pipe[0];

	for(;;) {
		int ret = poll(&logpoll, 1, -1);
		if (ret > 0 && logpoll.revents & POLLIN) {
			pthread_mutex_lock(&uwsgi.threaded_logger_lock);
			uwsgi_master_log();
			pthread_mutex_unlock(&uwsgi.threaded_logger_lock);
		}
	}

	return NULL;
}

void uwsgi_subscribe(char *subscription, uint8_t cmd) {

	int subfile_size;
	int i;
	char *key = NULL;
	int keysize = 0;
	char *modifier1 = NULL;
	int modifier1_len = 0;

	char *udp_address = strchr(subscription, ':');
	if (!udp_address)
		return;

	char *subscription_key = strchr(udp_address + 1, ':');
	if (!subscription_key)
		return;

	udp_address = uwsgi_concat2n(subscription, subscription_key - subscription, "", 0);

	if (subscription_key[1] == '@') {
		if (!uwsgi_file_exists(subscription_key + 2))
			goto clear;
		char *lines = uwsgi_open_and_read(subscription_key + 2, &subfile_size, 1, NULL);
		if (subfile_size > 0) {
			key = lines;
			for (i = 0; i < subfile_size; i++) {
				if (lines[i] == 0) {
					if (keysize > 0) {
						if (key[0] != '#' && key[0] != '\n') {
							modifier1 = strchr(key, ',');
							if (modifier1) {
								modifier1[0] = 0;
								modifier1++;
								modifier1_len = strlen(modifier1);
								keysize = strlen(key);
							}
							uwsgi_send_subscription(udp_address, key, keysize, uwsgi_str_num(modifier1, modifier1_len), 0, cmd);
							modifier1 = NULL;
							modifier1_len = 0;
						}
					}
					break;
				}
				else if (lines[i] == '\n') {
					if (keysize > 0) {
						if (key[0] != '#' && key[0] != '\n') {
							lines[i] = 0;
							modifier1 = strchr(key, ',');
							if (modifier1) {
								modifier1[0] = 0;
								modifier1++;
								modifier1_len = strlen(modifier1);
								keysize = strlen(key);
							}
							uwsgi_send_subscription(udp_address, key, keysize, uwsgi_str_num(modifier1, modifier1_len), 0, cmd);
							modifier1 = NULL;
							modifier1_len = 0;
							lines[i] = '\n';
						}
					}
					key = lines + i + 1;
					keysize = 0;
					continue;
				}
				keysize++;
			}

			free(lines);
		}
	}
	else {
		modifier1 = strchr(subscription_key + 1, ',');
		if (modifier1) {
			modifier1[0] = 0;
			modifier1++;
			modifier1_len = strlen(modifier1);
		}

		uwsgi_send_subscription(udp_address, subscription_key + 1, strlen(subscription_key + 1), uwsgi_str_num(modifier1, modifier1_len), 0, cmd);
		if (modifier1)
			modifier1[-1] = ',';
	}

      clear:

	free(udp_address);

}

#ifdef __linux__
void get_linux_tcp_info(int fd) {
	socklen_t tis = sizeof(struct tcp_info);

	if (!getsockopt(fd, IPPROTO_TCP, TCP_INFO, &uwsgi.shared->ti, &tis)) {
		// a check for older linux kernels
		if (!uwsgi.shared->ti.tcpi_sacked) {
			return;
		}

		uwsgi.shared->load = uwsgi.shared->ti.tcpi_unacked;

		uwsgi.shared->options[UWSGI_OPTION_BACKLOG_STATUS] = uwsgi.shared->ti.tcpi_unacked;
		if (uwsgi.vassal_sos_backlog > 0 && uwsgi.has_emperor) {
			if ((int) uwsgi.shared->ti.tcpi_unacked >= uwsgi.vassal_sos_backlog) {
				// ask emperor for help
				char byte = 30;
				if (write(uwsgi.emperor_fd, &byte, 1) != 1) {
					uwsgi_error("write()");
				}
				else {
					uwsgi_log("asking emperor for reinforcements (backlog: %d)...\n", (int) uwsgi.shared->ti.tcpi_unacked);
				}
			}
		}
		if (uwsgi.shared->ti.tcpi_unacked >= uwsgi.shared->ti.tcpi_sacked) {
			uwsgi_log_verbose("*** uWSGI listen queue of socket %d full !!! (%d/%d) ***\n", fd, uwsgi.shared->ti.tcpi_unacked, uwsgi.shared->ti.tcpi_sacked);
			uwsgi.shared->options[UWSGI_OPTION_BACKLOG_ERRORS]++;
		}
	}
}

#include <linux/sockios.h>

#ifdef UNBIT
#define SIOBKLGQ 0x8908
#endif

#ifdef SIOBKLGQ

void get_linux_unbit_SIOBKLGQ(int fd) {

	int queue = 0;
	if (ioctl(fd, SIOBKLGQ, &queue) >= 0) {
		uwsgi.shared->load = queue;
		uwsgi.shared->options[UWSGI_OPTION_BACKLOG_STATUS] = queue;
		if (queue >= uwsgi.listen_queue) {
			uwsgi_log_verbose("*** uWSGI listen queue of socket %d full !!! (%d/%d) ***\n", fd, queue, uwsgi.listen_queue);
			uwsgi.shared->options[UWSGI_OPTION_BACKLOG_ERRORS]++;
		}
	}

}
#endif
#endif


int master_loop(char **argv, char **environ) {

	uint64_t tmp_counter;

	struct timeval last_respawn;
	int last_respawn_rate = 0;

	int pid_found = 0;

	pid_t diedpid;
	int waitpid_status;

	int ready_to_reload = 0;
	int ready_to_die = 0;

	int master_has_children = 0;

	uint8_t uwsgi_signal;

	time_t last_request_timecheck = 0, now = 0;
	uint64_t last_request_count = 0;

	pthread_t logger_thread;

#ifdef UWSGI_UDP
	struct sockaddr_in udp_client;
	socklen_t udp_len;
	char udp_client_addr[16];
	int udp_managed = 0;
	int udp_fd = -1;

#ifdef UWSGI_MULTICAST
	char *cluster_opt_buf = NULL;
	int cluster_opt_size = 4;

	char *cptrbuf;
	uint16_t ustrlen;
	struct uwsgi_header *uh;
	struct uwsgi_cluster_node nucn;
#endif
#endif

#ifdef UWSGI_SNMP
	int snmp_fd = -1;
#endif
	int i = 0;
	int rlen;

	int check_interval = 1;

	struct uwsgi_rb_timer *min_timeout;
	struct rb_root *rb_timers = uwsgi_init_rb_timer();


	if (uwsgi.procname_master) {
		uwsgi_set_processname(uwsgi.procname_master);
	}
	else if (uwsgi.procname) {
		uwsgi_set_processname(uwsgi.procname);
	}
	else if (uwsgi.auto_procname) {
		uwsgi_set_processname("uWSGI master");
	}


	uwsgi.current_time = time(NULL);

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

	uwsgi.master_queue = event_queue_init();

	/* route signals to workers... */
#ifdef UWSGI_DEBUG
	uwsgi_log("adding %d to signal poll\n", uwsgi.shared->worker_signal_pipe[0]);
#endif
	event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->worker_signal_pipe[0]);

#ifdef UWSGI_SPOOLER
	if (uwsgi.spoolers) {
		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->spooler_signal_pipe[0]);
	}
#endif

	if (uwsgi.mules_cnt > 0) {
		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->mule_signal_pipe[0]);
	}

	if (uwsgi.log_master) {
		if (!uwsgi.threaded_logger) {
#ifdef UWSGI_DEBUG
			uwsgi_log("adding %d to master logging\n", uwsgi.shared->worker_log_pipe[0]);
#endif
			event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->worker_log_pipe[0]);
		}
		else {
			if (pthread_create(&logger_thread, NULL, logger_thread_loop, NULL)) {
				uwsgi_error("pthread_create()");
				uwsgi_log("falling back to non-threaded logger...\n");
				event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->worker_log_pipe[0]);
				uwsgi.threaded_logger = 0;
			}
		}
	}


	uwsgi.wsgi_req->buffer = uwsgi.async_buf[0];

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
#ifdef UWSGI_UDP
	if (uwsgi.udp_socket) {
		udp_fd = bind_to_udp(uwsgi.udp_socket, 0, 0);
		if (udp_fd < 0) {
			uwsgi_log("unable to bind to udp socket. SNMP and cluster management services will be disabled.\n");
		}
		else {
			uwsgi_log("UDP server enabled.\n");
			event_queue_add_fd_read(uwsgi.master_queue, udp_fd);
		}
	}

	if (uwsgi.cheap) {
		uwsgi_add_sockets_to_queue(uwsgi.master_queue);
		for (i = 1; i <= uwsgi.numproc; i++) {
			uwsgi.workers[i].cheaped = 1;
		}
		uwsgi_log("cheap mode enabled: waiting for socket connection...\n");
	}

#ifdef UWSGI_MULTICAST
	if (uwsgi.cluster) {

		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.cluster_fd);

		for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
			//uwsgi_log("%s\n", uwsgi.exported_opts[i]->key);
			cluster_opt_size += 2 + strlen(uwsgi.exported_opts[i]->key);
			if (uwsgi.exported_opts[i]->value) {
				cluster_opt_size += 2 + strlen(uwsgi.exported_opts[i]->value);
			}
			else {
				cluster_opt_size += 2 + 1;
			}
		}

		//uwsgi_log("cluster opts size: %d\n", cluster_opt_size);
		cluster_opt_buf = uwsgi_malloc(cluster_opt_size);

		uh = (struct uwsgi_header *) cluster_opt_buf;

		uh->modifier1 = 99;
		uh->pktsize = cluster_opt_size - 4;
		uh->modifier2 = 1;

#ifdef __BIG_ENDIAN__
		uh->pktsize = uwsgi_swap16(uh->pktsize);
#endif

		cptrbuf = cluster_opt_buf + 4;

		for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
			//uwsgi_log("%s\n", uwsgi.exported_opts[i]->key);
			ustrlen = strlen(uwsgi.exported_opts[i]->key);
			*cptrbuf++ = (uint8_t) (ustrlen & 0xff);
			*cptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
			memcpy(cptrbuf, uwsgi.exported_opts[i]->key, ustrlen);
			cptrbuf += ustrlen;

			if (uwsgi.exported_opts[i]->value) {
				ustrlen = strlen(uwsgi.exported_opts[i]->value);
				*cptrbuf++ = (uint8_t) (ustrlen & 0xff);
				*cptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
				memcpy(cptrbuf, uwsgi.exported_opts[i]->value, ustrlen);
			}
			else {
				ustrlen = 1;
				*cptrbuf++ = (uint8_t) (ustrlen & 0xff);
				*cptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
				*cptrbuf = '1';
			}
			cptrbuf += ustrlen;
		}

	}
#endif
#endif

#ifdef UWSGI_SNMP
	if (uwsgi.snmp) {
		if (uwsgi.snmp_community) {
			if (strlen(uwsgi.snmp_community) > 72) {
				uwsgi_log("*** warning the supplied SNMP community string will be truncated to 72 chars ***\n");
				memcpy(uwsgi.shared->snmp_community, uwsgi.snmp_community, 72);
			}
			else {
				memcpy(uwsgi.shared->snmp_community, uwsgi.snmp_community, strlen(uwsgi.snmp_community) + 1);
			}
		}

		uwsgi.shared->snmp_gvalue[0].type = SNMP_COUNTER64;
		uwsgi.shared->snmp_gvalue[0].val = &uwsgi.workers[0].requests;

		for (i = 0; i < uwsgi.numproc; i++) {
			uwsgi.shared->snmp_gvalue[30 + i].type = SNMP_COUNTER64;
			uwsgi.shared->snmp_gvalue[30 + i].val = &uwsgi.workers[i + 1].requests;
		}

		if (uwsgi.snmp_addr) {
			snmp_fd = bind_to_udp(uwsgi.snmp_addr, 0, 0);
			if (snmp_fd < 0) {
				uwsgi_log("unable to bind to udp socket. SNMP service will be disabled.\n");
			}
			else {
				uwsgi_log("SNMP server enabled on %s\n", uwsgi.snmp_addr);
				event_queue_add_fd_read(uwsgi.master_queue, snmp_fd);
			}
		}
		else {
			uwsgi_log("SNMP agent enabled.\n");
		}

	}
#endif


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
	struct uwsgi_daemon *ud = uwsgi.daemons;
	while (ud) {
		if (!ud->registered) {
			spawn_daemon(ud);
			ud->registered = 1;
		}
		ud = ud->next;
	}


	// first subscription
	struct uwsgi_string_list *subscriptions = uwsgi.subscriptions;
	while (subscriptions) {
		uwsgi_subscribe(subscriptions->value, 0);
		subscriptions = subscriptions->next;
	}

	// sync the cache store if needed
	if (uwsgi.cache_store && uwsgi.cache_filesize) {
		if (msync(uwsgi.cache_items, uwsgi.cache_filesize, MS_ASYNC)) {
			uwsgi_error("msync()");
		}
	}

	if (uwsgi.queue_store && uwsgi.queue_filesize) {
		if (msync(uwsgi.queue_header, uwsgi.queue_filesize, MS_ASYNC)) {
			uwsgi_error("msync()");
		}
	}

	// update touches timestamps
	uwsgi_check_touches(uwsgi.touch_reload);
	uwsgi_check_touches(uwsgi.touch_logrotate);
	uwsgi_check_touches(uwsgi.touch_logreopen);

	// setup cheaper algos
	uwsgi_register_cheaper_algo("spare", uwsgi_cheaper_algo_spare);
	uwsgi_register_cheaper_algo("backlog", uwsgi_cheaper_algo_backlog);

	uwsgi.cheaper_algo = uwsgi_cheaper_algo_spare;
	if (uwsgi.requested_cheaper_algo) {
		uwsgi.cheaper_algo = NULL;
		struct uwsgi_cheaper_algo *uca = uwsgi.cheaper_algos;
		while(uca) {
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
		//uwsgi_log("ready_to_reload %d %d\n", ready_to_reload, uwsgi.numproc);

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

		if (uwsgi.to_outworld) {
			//uwsgi_log("%d/%d\n", uwsgi.lazy_respawned, uwsgi.numproc);
			if (uwsgi.lazy_respawned >= uwsgi.numproc) {
				uwsgi.to_outworld = 0;
				uwsgi.master_mercy = 0;
				uwsgi.lazy_respawned = 0;
			}
		}

		if (uwsgi.master_mercy) {
			if (uwsgi.master_mercy < time(NULL)) {
				for (i = 1; i <= uwsgi.numproc; i++) {
					if (uwsgi.workers[i].pid > 0) {
						if (uwsgi.lazy && uwsgi.workers[i].destroy == 0)
							continue;
						uwsgi_log("worker %d (pid: %d) is taking too much time to die...NO MERCY !!!\n", i, uwsgi.workers[i].pid);
						if (!kill(uwsgi.workers[i].pid, SIGKILL)) {
							if (waitpid(uwsgi.workers[i].pid, &waitpid_status, 0) < 0) {
								uwsgi_error("waitpid()");
							}
							uwsgi.workers[i].pid = 0;
							if (uwsgi.to_hell) {
								ready_to_die++;
							}
							else if (uwsgi.to_heaven) {
								ready_to_reload++;
							}
							else if (uwsgi.to_outworld) {
								uwsgi.lazy_respawned++;
								if (uwsgi_respawn_worker(i))
									return 0;
							}
						}
						else {
							uwsgi_error("kill()");
						}
					}
				}
				uwsgi.master_mercy = 0;
			}
		}
		if (uwsgi.respawn_workers) {
			for (i = 1; i <= uwsgi.numproc; i++) {
				if (uwsgi_respawn_worker(i))
					return 0;
			}

			uwsgi.respawn_workers = 0;
		}
		if (uwsgi.restore_snapshot) {
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
			continue;
		}

		// cheaper management
		if (uwsgi.cheaper && !uwsgi.cheap && !uwsgi.to_heaven && !uwsgi.to_hell) {
			if (!uwsgi_calc_cheaper()) return 0;
		}


		if ((uwsgi.cheap || ready_to_die >= uwsgi.numproc) && uwsgi.to_hell) {
			// call a series of waitpid to ensure all processes (gateways, mules and daemons) are dead
			for (i = 0; i < (ushared->gateways_cnt + uwsgi.daemons_cnt + uwsgi.mules_cnt); i++) {
				diedpid = waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
			}

			uwsgi_log("goodbye to uWSGI.\n");
			exit(0);
		}
		if ((uwsgi.cheap || ready_to_reload >= uwsgi.numproc) && uwsgi.to_heaven) {
			uwsgi_reload(argv);
			// never here (unless in shared library mode)
			return -1;
		}

		if (!uwsgi.cheap) {

			if (uwsgi.numproc > 0 || ushared->gateways_cnt > 0 || uwsgi.daemons_cnt > 0) {
				master_has_children = 1;
			}
#ifdef UWSGI_SPOOLER
			if (uwsgi.spoolers) {
				master_has_children = 1;
			}
#endif
		}

		if (!master_has_children) {
			diedpid = 0;
		}
		else {
			diedpid = waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
			if (diedpid == -1) {
				if (errno == ECHILD && uwsgi.cheaper) {
					if (uwsgi.to_heaven) {
						ready_to_reload = uwsgi.numproc;
						continue;
					}
					else if (uwsgi.to_hell) {
						ready_to_die = uwsgi.numproc;
						continue;
					}
				}
				uwsgi_error("waitpid()");
				/* here is better to reload all the uWSGI stack */
				uwsgi_log("something horrible happened...\n");
				reap_them_all(0);
				exit(1);
			}
		}

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
					ushared->rb_timers[i].uwsgi_rb_timer = uwsgi_add_rb_timer(rb_timers, time(NULL) + ushared->rb_timers[i].value, &ushared->rb_timers[i]);
					ushared->rb_timers[i].registered = 1;
				}
			}

			int interesting_fd = -1;

			if (ushared->rb_timers_cnt > 0) {
				min_timeout = uwsgi_min_rb_timer(rb_timers);
				if (min_timeout == NULL) {
					check_interval = uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL];
				}
				else {
					check_interval = min_timeout->key - time(NULL);
					if (check_interval <= 0) {
						expire_rb_timeouts(rb_timers);
						check_interval = 0;
					}
				}
			}
			rlen = event_queue_wait(uwsgi.master_queue, check_interval, &interesting_fd);

			if (rlen == 0) {
				if (ushared->rb_timers_cnt > 0) {
					expire_rb_timeouts(rb_timers);
				}
			}


			// check uwsgi-cron table
			if (ushared->cron_cnt) {
				uwsgi_manage_signal_cron(time(NULL));
			}

			if (uwsgi.crons) {
				uwsgi_manage_command_cron(time(NULL));
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

			if (rlen > 0) {

				if (uwsgi.log_master && !uwsgi.threaded_logger) {
					if (interesting_fd == uwsgi.shared->worker_log_pipe[0]) {
						uwsgi_master_log();
						goto health_cycle;
					}
				}

				if (uwsgi.stats && uwsgi.stats_fd > -1) {
					if (interesting_fd == uwsgi.stats_fd) {
						uwsgi_send_stats(uwsgi.stats_fd);
						goto health_cycle;
					}
				}

				if (uwsgi.zerg_server) {
					if (interesting_fd == uwsgi.zerg_server_fd) {
						uwsgi_manage_zerg(uwsgi.zerg_server_fd, 0, NULL);
						goto health_cycle;
					}
				}

				if (uwsgi.has_emperor) {
					if (interesting_fd == uwsgi.emperor_fd) {
						char byte;
						rlen = read(uwsgi.emperor_fd, &byte, 1);
						if (rlen > 0) {
							uwsgi_log_verbose("received message %d from emperor\n", byte);
							// remove me
							if (byte == 0) {
								close(uwsgi.emperor_fd);
								if (!uwsgi.to_hell)
									kill_them_all(0);
							}
							// reload me
							else if (byte == 1) {
								// un-lazy the stack to trigger a real reload
								uwsgi.lazy = 0;
								grace_them_all(0);
							}
						}
						else {
							uwsgi_log("lost connection with my emperor !!!\n");
							close(uwsgi.emperor_fd);
							if (!uwsgi.to_hell)
								kill_them_all(0);
							sleep(2);
							exit(1);
						}
						goto health_cycle;
					}
				}


				if (uwsgi.cheap) {
					int found = 0;
					struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
					while (uwsgi_sock) {
						if (interesting_fd == uwsgi_sock->fd) {
							found = 1;
							uwsgi.cheap = 0;
							uwsgi_del_sockets_from_queue(uwsgi.master_queue);
							int needed = uwsgi.numproc;
							if (uwsgi.cheaper) {
								needed = uwsgi.cheaper_count;
							}
							for (i = 1; i <= needed; i++) {
								if (uwsgi_respawn_worker(i))
									return 0;
							}
							break;
						}
						uwsgi_sock = uwsgi_sock->next;
					}
					// here is better to continue instead going to health_cycle
					if (found)
						continue;
				}
#ifdef UWSGI_SNMP
				if (uwsgi.snmp_addr && interesting_fd == snmp_fd) {
					udp_len = sizeof(udp_client);
					rlen = recvfrom(snmp_fd, uwsgi.wsgi_req->buffer, uwsgi.buffer_size, 0, (struct sockaddr *) &udp_client, &udp_len);

					if (rlen < 0) {
						uwsgi_error("recvfrom()");
					}
					else if (rlen > 0) {
						manage_snmp(snmp_fd, (uint8_t *) uwsgi.wsgi_req->buffer, rlen, &udp_client);
					}
					goto health_cycle;
				}
#endif

#ifdef UWSGI_UDP
				if (uwsgi.udp_socket && interesting_fd == udp_fd) {
					udp_len = sizeof(udp_client);
					rlen = recvfrom(udp_fd, uwsgi.wsgi_req->buffer, uwsgi.buffer_size, 0, (struct sockaddr *) &udp_client, &udp_len);

					if (rlen < 0) {
						uwsgi_error("recvfrom()");
					}
					else if (rlen > 0) {

						memset(udp_client_addr, 0, 16);
						if (inet_ntop(AF_INET, &udp_client.sin_addr.s_addr, udp_client_addr, 16)) {
							if (uwsgi.wsgi_req->buffer[0] == UWSGI_MODIFIER_MULTICAST_ANNOUNCE) {
							}
#ifdef UWSGI_SNMP
							else if (uwsgi.wsgi_req->buffer[0] == 0x30 && uwsgi.snmp) {
								manage_snmp(udp_fd, (uint8_t *) uwsgi.wsgi_req->buffer, rlen, &udp_client);
							}
#endif
							else {

								// loop the various udp manager until one returns true
								udp_managed = 0;
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
									uwsgi_log("[udp:%s:%d] %.*s", udp_client_addr, ntohs(udp_client.sin_port), rlen, uwsgi.wsgi_req->buffer);
								}
							}
						}
						else {
							uwsgi_error("inet_ntop()");
						}
					}

					goto health_cycle;
				}

#ifdef UWSGI_MULTICAST
				if (interesting_fd == uwsgi.cluster_fd) {

					if (uwsgi_get_dgram(uwsgi.cluster_fd, uwsgi.wsgi_requests[0])) {
						goto health_cycle;
					}

					switch (uwsgi.wsgi_requests[0]->uh.modifier1) {
					case 95:
						memset(&nucn, 0, sizeof(struct uwsgi_cluster_node));

#ifdef __BIG_ENDIAN__
						uwsgi.wsgi_requests[0]->uh.pktsize = uwsgi_swap16(uwsgi.wsgi_requests[0]->uh.pktsize);
#endif
						uwsgi_hooked_parse(uwsgi.wsgi_requests[0]->buffer, uwsgi.wsgi_requests[0]->uh.pktsize, manage_cluster_announce, &nucn);
						if (nucn.name[0] != 0) {
							uwsgi_cluster_add_node(&nucn, CLUSTER_NODE_DYNAMIC);
						}
						break;
					case 96:
#ifdef __BIG_ENDIAN__
						uwsgi.wsgi_requests[0]->uh.pktsize = uwsgi_swap16(uwsgi.wsgi_requests[0]->uh.pktsize);
#endif
						uwsgi_log_verbose("%.*s\n", uwsgi.wsgi_requests[0]->uh.pktsize, uwsgi.wsgi_requests[0]->buffer);
						break;
					case 98:
						if (kill(getpid(), SIGHUP)) {
							uwsgi_error("kill()");
						}
						break;
					case 99:
						if (uwsgi.cluster_nodes)
							break;
						if (uwsgi.wsgi_requests[0]->uh.modifier2 == 0) {
							uwsgi_log("requested configuration data, sending %d bytes\n", cluster_opt_size);
							sendto(uwsgi.cluster_fd, cluster_opt_buf, cluster_opt_size, 0, (struct sockaddr *) &uwsgi.mc_cluster_addr, sizeof(uwsgi.mc_cluster_addr));
						}
						break;
					case 73:
#ifdef __BIG_ENDIAN__
						uwsgi.wsgi_requests[0]->uh.pktsize = uwsgi_swap16(uwsgi.wsgi_requests[0]->uh.pktsize);
#endif
						uwsgi_log_verbose("[uWSGI cluster %s] new node available: %.*s\n", uwsgi.cluster, uwsgi.wsgi_requests[0]->uh.pktsize, uwsgi.wsgi_requests[0]->buffer);
						break;
					}
					goto health_cycle;
				}
#endif

#endif


				int next_iteration = 0;

				uwsgi_lock(uwsgi.fmon_table_lock);
				for (i = 0; i < ushared->files_monitored_cnt; i++) {
					if (ushared->files_monitored[i].registered) {
						if (interesting_fd == ushared->files_monitored[i].fd) {
							struct uwsgi_fmon *uf = event_queue_ack_file_monitor(uwsgi.master_queue, interesting_fd);
							// now call the file_monitor handler
							if (uf)
								uwsgi_route_signal(uf->sig);
							break;
						}
					}
				}

				uwsgi_unlock(uwsgi.fmon_table_lock);
				if (next_iteration)
					goto health_cycle;;

				next_iteration = 0;

				uwsgi_lock(uwsgi.timer_table_lock);
				for (i = 0; i < ushared->timers_cnt; i++) {
					if (ushared->timers[i].registered) {
						if (interesting_fd == ushared->timers[i].fd) {
							struct uwsgi_timer *ut = event_queue_ack_timer(interesting_fd);
							// now call the file_monitor handler
							if (ut)
								uwsgi_route_signal(ut->sig);
							break;
						}
					}
				}
				uwsgi_unlock(uwsgi.timer_table_lock);
				if (next_iteration)
					goto health_cycle;;


				// check for worker signal
				if (interesting_fd == uwsgi.shared->worker_signal_pipe[0]) {
					rlen = read(interesting_fd, &uwsgi_signal, 1);
					if (rlen < 0) {
						uwsgi_error("read()");
					}
					else if (rlen > 0) {
#ifdef UWSGI_DEBUG
						uwsgi_log_verbose("received uwsgi signal %d from a worker\n", uwsgi_signal);
#endif
						uwsgi_route_signal(uwsgi_signal);
					}
					else {
						uwsgi_log_verbose("lost connection with worker %d\n", i);
						close(interesting_fd);
					}
					goto health_cycle;
				}

#ifdef UWSGI_SPOOLER
				// check for spooler signal
				if (uwsgi.spoolers) {
					if (interesting_fd == uwsgi.shared->spooler_signal_pipe[0]) {
						rlen = read(interesting_fd, &uwsgi_signal, 1);
						if (rlen < 0) {
							uwsgi_error("read()");
						}
						else if (rlen > 0) {
#ifdef UWSGI_DEBUG
							uwsgi_log_verbose("received uwsgi signal %d from a spooler\n", uwsgi_signal);
#endif
							uwsgi_route_signal(uwsgi_signal);
						}
						else {
							uwsgi_log_verbose("lost connection with the spooler\n");
							close(interesting_fd);
						}
						goto health_cycle;
					}

				}
#endif

				// check for mules signal
				if (uwsgi.mules_cnt > 0) {
					if (interesting_fd == uwsgi.shared->mule_signal_pipe[0]) {
						rlen = read(interesting_fd, &uwsgi_signal, 1);
						if (rlen < 0) {
							uwsgi_error("read()");
						}
						else if (rlen > 0) {
#ifdef UWSGI_DEBUG
							uwsgi_log_verbose("received uwsgi signal %d from a mule\n", uwsgi_signal);
#endif
							uwsgi_route_signal(uwsgi_signal);
						}
						else {
							uwsgi_log_verbose("lost connection with a mule\n");
							close(interesting_fd);
						}
						goto health_cycle;
					}

				}


			}

		      health_cycle:
			now = time(NULL);
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

			if (uwsgi.numproc > 1) {
				tmp_counter = 0;
				for (i = 1; i < uwsgi.numproc + 1; i++)
					tmp_counter += uwsgi.workers[i].requests;
				uwsgi.workers[0].requests = tmp_counter;
			}

			if (uwsgi.idle > 0 && !uwsgi.cheap) {
				uwsgi.current_time = time(NULL);
				if (!last_request_timecheck)
					last_request_timecheck = uwsgi.current_time;
				if (last_request_count != uwsgi.workers[0].requests) {
					last_request_timecheck = uwsgi.current_time;
					last_request_count = uwsgi.workers[0].requests;
				}
				// a bit of over-engeneering to avoid clock skews
				else if (last_request_timecheck < uwsgi.current_time && (uwsgi.current_time - last_request_timecheck > uwsgi.idle)) {
					uwsgi_log("workers have been inactive for more than %d seconds (%llu-%llu)\n", uwsgi.idle, (unsigned long long) uwsgi.current_time, (unsigned long long) last_request_timecheck);
					uwsgi.cheap = 1;
					master_has_children = 0;
					if (uwsgi.die_on_idle) {
						if (uwsgi.has_emperor) {
							char byte = 22;
							if (write(uwsgi.emperor_fd, &byte, 1) != 1) {
								uwsgi_error("write()");
								kill_them_all(0);
							}
						}
						else {
							kill_them_all(0);
						}
						continue;
					}
					for (i = 1; i <= uwsgi.numproc; i++) {
						uwsgi.workers[i].cheaped = 1;
						if (uwsgi.workers[i].pid == 0)
							continue;
						kill(uwsgi.workers[i].pid, SIGKILL);
						if (waitpid(uwsgi.workers[i].pid, &waitpid_status, 0) < 0) {
							uwsgi_error("waitpid()");
						}
					}
					uwsgi_add_sockets_to_queue(uwsgi.master_queue);
					uwsgi_log("cheap mode enabled: waiting for socket connection...\n");
					last_request_timecheck = 0;
					continue;
				}
			}

			// remove expired cache items TODO use rb_tree timeouts
			if (uwsgi.cache_max_items > 0) {
				for (i = 0; i < (int) uwsgi.cache_max_items; i++) {
					uwsgi_wlock(uwsgi.cache_lock);
					if (uwsgi.cache_items[i].expires) {
						if (uwsgi.cache_items[i].expires < (uint64_t) uwsgi.current_time) {
							uwsgi_cache_del(uwsgi.cache_items[i].key, uwsgi.cache_items[i].keysize);
						}
					}
					uwsgi_rwunlock(uwsgi.cache_lock);
				}
			}

			check_interval = uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL];
			if (!check_interval)
				check_interval = 1;


#ifdef __linux__
			// get listen_queue status
			struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
			while (uwsgi_sock) {
				if (uwsgi_sock->family == AF_INET) {
					get_linux_tcp_info(uwsgi_sock->fd);
				}
#ifdef SIOBKLGQ
				else if (uwsgi_sock->family == AF_UNIX) {
					get_linux_unbit_SIOBKLGQ(uwsgi_sock->fd);
				}
#endif
				uwsgi_sock = uwsgi_sock->next;
			}
#endif

			for (i = 1; i <= uwsgi.numproc; i++) {
				/* first check for harakiri */
				if (uwsgi.workers[i].harakiri > 0) {
					if (uwsgi.workers[i].harakiri < (time_t) uwsgi.current_time) {
						/* first try to invoke the harakiri() custom handler */
						/* TODO */
						/* then brutally kill the worker */
						uwsgi_log("*** HARAKIRI ON WORKER %d (pid: %d) ***\n", i, uwsgi.workers[i].pid);
						if (uwsgi.harakiri_verbose) {
#ifdef __linux__
							int proc_file;
							char proc_buf[4096];
							char proc_name[64];
							ssize_t proc_len;

							if (snprintf(proc_name, 64, "/proc/%d/syscall", uwsgi.workers[i].pid) > 0) {
								memset(proc_buf, 0, 4096);
								proc_file = open(proc_name, O_RDONLY);
								if (proc_file >= 0) {
									proc_len = read(proc_file, proc_buf, 4096);
									if (proc_len > 0) {
										uwsgi_log("HARAKIRI: -- syscall> %s", proc_buf);
									}
									close(proc_file);
								}
							}

							if (snprintf(proc_name, 64, "/proc/%d/wchan", uwsgi.workers[i].pid) > 0) {
								memset(proc_buf, 0, 4096);

								proc_file = open(proc_name, O_RDONLY);
								if (proc_file >= 0) {
									proc_len = read(proc_file, proc_buf, 4096);
									if (proc_len > 0) {
										uwsgi_log("HARAKIRI: -- wchan> %s\n", proc_buf);
									}
									close(proc_file);
								}
							}

#endif
						}

						if (uwsgi.workers[i].pid > 0) {
							kill(uwsgi.workers[i].pid, SIGUSR2);
							// allow SIGUSR2 to be delivered
							sleep(1);
							kill(uwsgi.workers[i].pid, SIGKILL);
						}
						// to avoid races
						uwsgi.workers[i].harakiri = 0;
					}
				}
				// then for evil memory checkers
				if (uwsgi.evil_reload_on_as) {
					if ((rlim_t) uwsgi.workers[i].vsz_size >= uwsgi.evil_reload_on_as) {
						uwsgi_log("*** EVIL RELOAD ON WORKER %d ADDRESS SPACE: %lld (pid: %d) ***\n", i, (long long) uwsgi.workers[i].vsz_size, uwsgi.workers[i].pid);
						kill(uwsgi.workers[i].pid, SIGKILL);
						uwsgi.workers[i].vsz_size = 0;
					}
				}
				if (uwsgi.evil_reload_on_rss) {
					if ((rlim_t) uwsgi.workers[i].rss_size >= uwsgi.evil_reload_on_rss) {
						uwsgi_log("*** EVIL RELOAD ON WORKER %d RSS: %lld (pid: %d) ***\n", i, (long long) uwsgi.workers[i].rss_size, uwsgi.workers[i].pid);
						kill(uwsgi.workers[i].pid, SIGKILL);
						uwsgi.workers[i].rss_size = 0;
					}
				}

				// need to find a better way
				//uwsgi.workers[i].last_running_time = uwsgi.workers[i].running_time;
			}

			for (i = 0; i < ushared->gateways_cnt; i++) {
				if (ushared->gateways_harakiri[i] > 0) {
					if (ushared->gateways_harakiri[i] < (time_t) uwsgi.current_time) {
						if (ushared->gateways[i].pid > 0) {
							kill(ushared->gateways[i].pid, SIGKILL);
						}
						ushared->gateways_harakiri[i] = 0;
					}
				}
			}

			for (i = 0; i < uwsgi.mules_cnt; i++) {
				if (uwsgi.mules[i].harakiri > 0) {
					if (uwsgi.mules[i].harakiri < (time_t) uwsgi.current_time) {
						uwsgi_log("*** HARAKIRI ON MULE %d HANDLING SIGNAL %d (pid: %d) ***\n", i + 1, uwsgi.mules[i].signum, uwsgi.mules[i].pid);
						kill(uwsgi.mules[i].pid, SIGKILL);
						uwsgi.mules[i].harakiri = 0;
					}
				}
			}
#ifdef UWSGI_SPOOLER
			struct uwsgi_spooler *uspool = uwsgi.spoolers;
			while(uspool) {
				if (uspool->harakiri > 0 && uspool->harakiri < (time_t) uwsgi.current_time) {
					uwsgi_log("*** HARAKIRI ON THE SPOOLER (pid: %d) ***\n", uspool->pid);
					kill(uspool->pid, SIGKILL);
					uspool->harakiri = 0;
				}
				uspool = uspool->next;
			}
#endif

#ifdef __linux__
#ifdef MADV_MERGEABLE
			if (uwsgi.linux_ksm > 0 && (uwsgi.master_cycles % uwsgi.linux_ksm) == 0) {
				uwsgi_linux_ksm_map();
			}
#endif
#endif

#ifdef UWSGI_UDP
			// check for cluster nodes
			master_check_cluster_nodes();

			// reannounce myself every 10 cycles
			if (uwsgi.cluster && uwsgi.cluster_fd >= 0 && !uwsgi.cluster_nodes && (uwsgi.master_cycles % 10) == 0) {
				uwsgi_cluster_add_me();
			}

			// resubscribe every 10 cycles by default
			if ((uwsgi.subscriptions && ((uwsgi.master_cycles % uwsgi.subscribe_freq) == 0 || uwsgi.master_cycles == 1)) && !uwsgi.to_heaven && !uwsgi.to_hell) {
				struct uwsgi_string_list *subscriptions = uwsgi.subscriptions;
				while (subscriptions) {
					uwsgi_subscribe(subscriptions->value, 0);
					subscriptions = subscriptions->next;
				}
			}

#endif

			if (uwsgi.cache_store && uwsgi.cache_filesize && uwsgi.cache_store_sync && ((uwsgi.master_cycles % uwsgi.cache_store_sync) == 0)) {
				if (msync(uwsgi.cache_items, uwsgi.cache_filesize, MS_ASYNC)) {
					uwsgi_error("msync()");
				}
			}

			if (uwsgi.queue_store && uwsgi.queue_filesize && uwsgi.queue_store_sync && ((uwsgi.master_cycles % uwsgi.queue_store_sync) == 0)) {
				if (msync(uwsgi.queue_header, uwsgi.queue_filesize, MS_ASYNC)) {
					uwsgi_error("msync()");
				}
			}

			// check touch_reload
			if (!uwsgi.to_heaven && !uwsgi.to_hell) {
				char *touched = uwsgi_check_touches(uwsgi.touch_reload);
				if (touched) {
					uwsgi_log("*** %s has been touched... grace them all !!! ***\n", touched);
					grace_them_all(0);
				}
			}

			continue;

		}

		if (diedpid > 0) {
			// check for deadlocks first
			struct uwsgi_lock_item *uli = uwsgi.registered_locks;
			while(uli) {
				if (!uli->can_deadlock) goto nextlock;
				pid_t locked_pid = 0;
				if (uli->rw) {
					locked_pid = uwsgi_rwlock_check(uli);
				}
				else {
					locked_pid = uwsgi_lock_check(uli);
				}
				if (locked_pid == diedpid) {
					uwsgi_log("[deadlock-detector] pid %d was holding lock %s (%p)\n", (int) diedpid, uli->id, uli->lock_ptr);
					if (uli->rw) {
						uwsgi_rwunlock(uli);
					}
					else {
						uwsgi_unlock(uli);
					}
				}
nextlock:
				uli = uli->next;
			}
		}
		// reload gateways and daemons only on normal workflow
		if (!uwsgi.to_heaven && !uwsgi.to_hell) {

#ifdef UWSGI_SPOOLER
			/* reload the spooler */
			struct uwsgi_spooler *uspool = uwsgi.spoolers;
			pid_found = 0;
			while(uspool) {
				if (uspool->pid > 0 && diedpid == uspool->pid) {
					uwsgi_log("OOOPS the spooler is no more...trying respawn...\n");
					uspool->respawned++;
					uspool->pid = spooler_start(uspool);
					pid_found = 1;
					break;
				}
				uspool = uspool->next;
			}

			if (pid_found)
				continue;
#endif

			pid_found = 0;
			for (i = 0; i < uwsgi.mules_cnt; i++) {
				if (uwsgi.mules[i].pid == diedpid) {
					uwsgi_log("OOOPS mule %d crippled...trying respawn...\n", i + 1);
					uwsgi_mule(i + 1);
					pid_found = 1;
					break;
				}
			}

			if (pid_found)
				continue;


			/* reload the gateways */
			pid_found = 0;
			for (i = 0; i < ushared->gateways_cnt; i++) {
				if (ushared->gateways[i].pid == diedpid) {
					gateway_respawn(i);
					pid_found = 1;
					break;
				}
			}

			if (pid_found)
				continue;

			/* reload the daemons */
			// TODO reload_daemons(diedpid);
			pid_found = 0;
			struct uwsgi_daemon *ud = uwsgi.daemons;
			while (ud) {
				if (ud->pid == diedpid) {
					spawn_daemon(ud);
					pid_found = 1;
					break;
				}
				ud = ud->next;
			}

			if (pid_found)
				continue;

		}

		/* What happens here ?

		   case 1) the diedpid is not a worker, report it and continue
		   case 2) the diedpid is a worker and we are not in a reload procedure -> reload it
		   case 3) the diedpid is a worker and we are in graceful reload -> ready_to_reload++ and continue
		   case 3) the diedpid is a worker and we are in brutal reload -> ready_to_die++ and continue


		 */

		uwsgi.mywid = find_worker_id(diedpid);
		if (uwsgi.mywid <= 0) {
			// check spooler, mules, gateways and daemons
#ifdef UWSGI_SPOOLER
			struct uwsgi_spooler *uspool = uwsgi.spoolers;
			while(uspool) {
				if (uspool->pid > 0 && diedpid == uspool->pid) {
					uwsgi_log("spooler (pid: %d) annihilated\n", (int) diedpid);
					goto next;
				}
				uspool = uspool->next;
			}
#endif

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

			struct uwsgi_daemon *ud = uwsgi.daemons;
			while (ud) {
				if (ud->pid == diedpid) {
					uwsgi_log("daemon \"%s\" (pid: %d) annihilated\n", ud->command, (int) diedpid);
					goto next;
				}
				ud = ud->next;
			}

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
		else {


			if (uwsgi.to_heaven) {
				ready_to_reload++;
				uwsgi.workers[uwsgi.mywid].pid = 0;
				// only to be safe :P
				uwsgi.workers[uwsgi.mywid].harakiri = 0;
				continue;
			}
			else if (uwsgi.to_hell) {
				ready_to_die++;
				uwsgi.workers[uwsgi.mywid].pid = 0;
				// only to be safe :P
				uwsgi.workers[uwsgi.mywid].harakiri = 0;
				continue;
			}
			else if (uwsgi.to_outworld) {
				uwsgi.lazy_respawned++;
				uwsgi.workers[uwsgi.mywid].destroy = 0;
				uwsgi.workers[uwsgi.mywid].pid = 0;
				// only to be safe :P
				uwsgi.workers[uwsgi.mywid].harakiri = 0;
			}

			if (WIFEXITED(waitpid_status) && WEXITSTATUS(waitpid_status) == UWSGI_FAILED_APP_CODE) {
				uwsgi_log("OOPS ! failed loading app in worker %d (pid %d) :( trying again...\n", uwsgi.mywid, (int) diedpid);
			}
			else if (WIFEXITED(waitpid_status) && WEXITSTATUS(waitpid_status) == UWSGI_DE_HIJACKED_CODE) {
				uwsgi_log("...restoring worker %d (pid: %d)...\n", uwsgi.mywid, (int) diedpid);
			}
			else if (WIFEXITED(waitpid_status) && WEXITSTATUS(waitpid_status) == UWSGI_QUIET_CODE) {
				// noop
			}
			else if (uwsgi.workers[uwsgi.mywid].manage_next_request) {
				uwsgi_log("DAMN ! worker %d (pid: %d) died :( trying respawn ...\n", uwsgi.mywid, (int) diedpid);
			}

			if (uwsgi.workers[uwsgi.mywid].cheaped == 1) {
				uwsgi.workers[uwsgi.mywid].pid = 0;
				uwsgi_log("uWSGI worker %d cheaped.\n", uwsgi.mywid);
				uwsgi.workers[uwsgi.mywid].harakiri = 0;
				continue;
			}
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

			if (uwsgi_respawn_worker(uwsgi.mywid))
				return 0;

		}
	}

	// never here
}
