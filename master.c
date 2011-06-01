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

void expire_rb_timeouts(struct rb_root *root) {

        time_t current = time(NULL);
        struct uwsgi_rb_timer *urbt;
        struct uwsgi_signal_rb_timer *usrbt;

        for(;;) {

                urbt = uwsgi_min_rb_timer(root);

                if (urbt == NULL) return;

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


void uwsgi_subscribe(char *subscription) {

	char *ssb;
	char subscrbuf[4096];
	uint16_t ustrlen;

	char *udp_address = strchr(subscription,':');
        if (!udp_address) return;

        char *subscription_key = strchr(udp_address+1, ':');
	if (!subscription_key) return;
        udp_address = uwsgi_concat2n(subscription, subscription_key-subscription, "", 0);

        ssb = subscrbuf;

	ustrlen = 3;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, "key", ustrlen);
        ssb+=ustrlen;

        ustrlen = strlen(subscription_key+1);
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, subscription_key+1, ustrlen);
        ssb+=ustrlen;

        ustrlen = 7;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, "address", ustrlen);
        ssb+=ustrlen;

        ustrlen = strlen(uwsgi.sockets->name);
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, uwsgi.sockets->name, ustrlen);
        ssb+=ustrlen;

        send_udp_message(224, udp_address, subscrbuf, ssb-subscrbuf);
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

		uwsgi.shared->options[UWSGI_OPTION_BACKLOG_STATUS] = uwsgi.shared->ti.tcpi_unacked;
		if (uwsgi.shared->ti.tcpi_unacked >= uwsgi.shared->ti.tcpi_sacked) {
			uwsgi_log_verbose("*** uWSGI listen queue of socket %d full !!! (%d/%d) ***\n", fd, uwsgi.shared->ti.tcpi_unacked, uwsgi.shared->ti.tcpi_sacked);
			uwsgi.shared->options[UWSGI_OPTION_BACKLOG_ERRORS]++;
		}
	}
}
#endif

void manage_cluster_announce(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	char *tmpstr;
	struct uwsgi_cluster_node *ucn = (struct uwsgi_cluster_node *) data;
	uwsgi_log("%.*s = %.*s\n", keylen, key, vallen, val);

	if (!uwsgi_strncmp("hostname", 8, key, keylen)) {
		strncpy(ucn->nodename, val, UMIN(vallen, 255));
	}

	if (!uwsgi_strncmp("address", 7, key, keylen)) {
		strncpy(ucn->name, val, UMIN(vallen, 100));
	}

	if (!uwsgi_strncmp("workers", 7, key, keylen)) {
		tmpstr = uwsgi_concat2n(val, vallen, "", 0);
		ucn->workers = atoi(tmpstr);
		free(tmpstr);
	}

	if (!uwsgi_strncmp("requests", 8, key, keylen)) {
		tmpstr = uwsgi_concat2n(val, vallen, "", 0);
		ucn->requests = strtoul(tmpstr, NULL, 0);
		free(tmpstr);
	}
}

void master_loop(char **argv, char **environ) {

	uint64_t tmp_counter;

	char log_buf[4096];


	struct timeval last_respawn;
	int last_respawn_rate = 0;

	int pid_found = 0;

	pid_t diedpid;
	int waitpid_status;

	int ready_to_reload = 0;
	int ready_to_die = 0;

	int master_has_children = 0;

	uint8_t uwsgi_signal;

	time_t last_request_timecheck = 0;
	uint64_t last_request_count = 0;

#ifdef UWSGI_UDP
	struct sockaddr_in udp_client;
	socklen_t udp_len;
	char udp_client_addr[16];
	int udp_managed = 0;
	int udp_fd = -1 ;

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

	int i=0;
	int rlen;

	int check_interval = 1;

	struct uwsgi_rb_timer *min_timeout;
	struct rb_root *rb_timers = uwsgi_init_rb_timer();
	struct tm *uwsgi_cron_delta;

	uwsgi.current_time = time(NULL);

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

	if (uwsgi.log_master) {
#ifdef UWSGI_DEBUG
		uwsgi_log("adding %d to master logging\n", uwsgi.shared->worker_log_pipe[0]);
#endif
		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.shared->worker_log_pipe[0]);
	}
	

	uwsgi.wsgi_req->buffer = uwsgi.async_buf[0];

	if (uwsgi.has_emperor) {
		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.emperor_fd);
	}
#ifdef UWSGI_UDP
	if (uwsgi.udp_socket) {
		udp_fd = bind_to_udp(uwsgi.udp_socket, 0, 0);
		if (udp_fd < 0) {
			uwsgi_log( "unable to bind to udp socket. SNMP and cluster management services will be disabled.\n");
		}
		else {
			uwsgi_log( "UDP server enabled.\n");
			event_queue_add_fd_read(uwsgi.master_queue, udp_fd);
		}
	}

	if (uwsgi.cheap) {
		uwsgi_add_sockets_to_queue(uwsgi.master_queue);
		uwsgi_log("cheap mode enabled: waiting for socket connection...\n");
	}

#ifdef UWSGI_MULTICAST
	if (uwsgi.cluster) {

		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.cluster_fd);

		for(i=0;i<uwsgi.exported_opts_cnt;i++) {
			//uwsgi_log("%s\n", uwsgi.exported_opts[i]->key);
                	cluster_opt_size += 2+strlen(uwsgi.exported_opts[i]->key);
			if (uwsgi.exported_opts[i]->value) {
                        	cluster_opt_size += 2+strlen(uwsgi.exported_opts[i]->value);
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
	
		cptrbuf = cluster_opt_buf+4;

		for(i=0;i<uwsgi.exported_opts_cnt;i++) {
			//uwsgi_log("%s\n", uwsgi.exported_opts[i]->key);
			ustrlen = strlen(uwsgi.exported_opts[i]->key);
			*cptrbuf++ = (uint8_t) (ustrlen	 & 0xff);
			*cptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
			memcpy(cptrbuf, uwsgi.exported_opts[i]->key, ustrlen);
			cptrbuf+=ustrlen;

			if (uwsgi.exported_opts[i]->value) {
				ustrlen = strlen(uwsgi.exported_opts[i]->value);
				*cptrbuf++ = (uint8_t) (ustrlen	 & 0xff);
				*cptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
				memcpy(cptrbuf, uwsgi.exported_opts[i]->value, ustrlen);
			}
			else {
				ustrlen = 1;
				*cptrbuf++ = (uint8_t) (ustrlen	 & 0xff);
				*cptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
				*cptrbuf = '1' ;
			}
			cptrbuf+=ustrlen;
		}

	}
#endif
#endif

#ifdef UWSGI_SNMP
	if (uwsgi.snmp) {
		if (uwsgi.snmp_community) {
			if (strlen(uwsgi.snmp_community) > 72) {
				uwsgi_log( "*** warning the supplied SNMP community string will be truncated to 72 chars ***\n");
				memcpy(uwsgi.shared->snmp_community, uwsgi.snmp_community, 72);
			}
			else {
				memcpy(uwsgi.shared->snmp_community, uwsgi.snmp_community, strlen(uwsgi.snmp_community) + 1);
			}
		}

		uwsgi.shared->snmp_gvalue[0].type = SNMP_COUNTER64;
		uwsgi.shared->snmp_gvalue[0].val = &uwsgi.workers[0].requests;

		for(i=0;i<uwsgi.numproc;i++) {
			uwsgi.shared->snmp_gvalue[30+i].type = SNMP_COUNTER64;
			uwsgi.shared->snmp_gvalue[30+i].val = &uwsgi.workers[i+1].requests;
		}

		if (uwsgi.snmp_addr) {
			snmp_fd = bind_to_udp(uwsgi.snmp_addr, 0, 0);
                	if (snmp_fd < 0) {
                        	uwsgi_log( "unable to bind to udp socket. SNMP service will be disabled.\n");
                	}
                	else {
                        	uwsgi_log( "SNMP server enabled on %s\n", uwsgi.snmp_addr);
                        	event_queue_add_fd_read(uwsgi.master_queue, snmp_fd);
                	}
		}
		else {
			uwsgi_log( "SNMP agent enabled.\n");
		}

	}
#endif

	
/*


*/

	// spawn fat gateways
	for(i=0;i<uwsgi.gateways_cnt;i++) {
        	if (uwsgi.gateways[i].pid == 0) {
                	gateway_respawn(i);
                }
        }

	// first subscription
	for(i=0;i<uwsgi.subscriptions_cnt;i++) {
		uwsgi_log("requested subscription for %s\n", uwsgi.subscriptions[i]);
		uwsgi_subscribe(uwsgi.subscriptions[i]);
	}

	// sync the cache store if needed
	if (uwsgi.cache_store && uwsgi.cache_filesize) {
		if (msync(uwsgi.cache_items, uwsgi.cache_filesize, MS_ASYNC)) {
			uwsgi_error("msync()");
		}
	}

	if (uwsgi.queue_store && uwsgi.queue_filesize) {
		if (msync(uwsgi.queue, uwsgi.queue_filesize, MS_ASYNC)) {
			uwsgi_error("msync()");
		}
	}

	if (uwsgi.touch_reload) {
		struct stat tr_st;
		if (stat(uwsgi.touch_reload, &tr_st)) {
			uwsgi_error("stat()");
			uwsgi_log("unable to stat() %s, touch-reload will be disabled\n", uwsgi.touch_reload);
			uwsgi.touch_reload = NULL;
		}
		else {
			uwsgi.last_touch_reload_mtime = tr_st.st_mtime;
		}
	}

	for (;;) {
		//uwsgi_log("ready_to_reload %d %d\n", ready_to_reload, uwsgi.numproc);

		if (uwsgi.master_mercy) {
			if (uwsgi.master_mercy < time(NULL)) {
				for(i=1;i<=uwsgi.numproc;i++) {
					if (uwsgi.workers[i].pid > 0) {
						uwsgi_log("worker %d (pid: %d) is taking too much time to die...NO MERCY !!!\n", i, uwsgi.workers[i].pid);
						if (!kill(uwsgi.workers[i].pid, SIGKILL)) {
							if (waitpid(uwsgi.workers[i].pid, &waitpid_status, 0) < 0) {
								uwsgi_error("waitpid()");
							}
							uwsgi.workers[i].pid = 0;
							if (uwsgi.to_hell) { ready_to_die++;}
							else if (uwsgi.to_heaven) { ready_to_reload++;}
						}
						else {
							uwsgi_error("kill()");
						}
					}
				}
			}
		}
		if (uwsgi.respawn_workers) {
			for(i=1;i<=uwsgi.numproc;i++) {
				if (uwsgi_respawn_worker(i)) return;
			}

			uwsgi.respawn_workers = 0;
		}
		if (uwsgi.restore_snapshot) {
			uwsgi_log("[snapshot] restoring workers...\n");
			for(i=1;i<=uwsgi.numproc;i++) {
				if (uwsgi.workers[i].pid == 0) continue;
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
					uwsgi_log( "Restored uWSGI worker %d (pid: %d)\n", i, (int) uwsgi.workers[i].pid);
				}
			}

			uwsgi.restore_snapshot = 0;
			continue;
		}
		if ((uwsgi.cheap || ready_to_die >= uwsgi.numproc) && uwsgi.to_hell) {
			// call a series of waitpid to ensure all processes (gateways and daemons) are dead
			for(i=0;i<(uwsgi.gateways_cnt+ushared->daemons_cnt);i++) {
				diedpid = waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
			}

			uwsgi_log( "goodbye to uWSGI.\n");
			exit(0);
		}
		if ( (uwsgi.cheap || ready_to_reload >= uwsgi.numproc) && uwsgi.to_heaven) {
			// call a series of waitpid to ensure all processes (gateways and daemons) are dead
			for(i=0;i<(uwsgi.gateways_cnt+ushared->daemons_cnt);i++) {
				diedpid = waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
			}

			if (uwsgi.exit_on_reload) {
				uwsgi_log("uWSGI: GAME OVER (insert coin)\n");
				exit(0);
			}

			uwsgi_log( "binary reloading uWSGI...\n");
			if (chdir(uwsgi.cwd)) {
				uwsgi_error("chdir()");
				exit(1);
			}

			/* check fd table (a module can obviosly open some fd on initialization...) */
			uwsgi_log( "closing all non-uwsgi socket fds > 2 (_SC_OPEN_MAX = %ld)...\n", sysconf(_SC_OPEN_MAX));
			for (i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
				int found = 0;
				struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
                		while(uwsgi_sock) {
					if (i == uwsgi_sock->fd) {
						uwsgi_log("found fd %d mapped to socket %d (%s)\n", i, uwsgi_get_socket_num(uwsgi_sock), uwsgi_sock->name);
						found = 1;
						break;
					}
					uwsgi_sock = uwsgi_sock->next;
				}

				if (!found) {
					if (uwsgi.has_emperor) {
						if (i == uwsgi.emperor_fd) {
							found = 1;
						}
					}
				}
				if (!found) {
#ifdef __APPLE__
					fcntl(i, F_SETFD, FD_CLOEXEC);	
#else
					close(i);
#endif
				}
			}

			uwsgi_log( "running %s\n", uwsgi.binary_path);
			argv[0] = uwsgi.binary_path;
			//strcpy (argv[0], uwsgi.binary_path);
			execvp(uwsgi.binary_path, argv);
			uwsgi_error("execvp()");
			// never here
			exit(1);
		}

		if (!uwsgi.cheap) {

			if (uwsgi.numproc > 0 || uwsgi.gateways_cnt > 0 || ushared->daemons_cnt > 0) {
				master_has_children = 1;
			}
#ifdef UWSGI_SPOOLER
			if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
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
				uwsgi_error("waitpid()");
				/* here is better to reload all the uWSGI stack */
				uwsgi_log( "something horrible happened...\n");
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
			for(i=0;i<ushared->files_monitored_cnt;i++) {
				if (!ushared->files_monitored[i].registered) {
					ushared->files_monitored[i].fd = event_queue_add_file_monitor(uwsgi.master_queue, ushared->files_monitored[i].filename, &ushared->files_monitored[i].id);
					ushared->files_monitored[i].registered = 1;		
				}
			}

			// add unregistered daemons
			// locking is not needed as daemons can only increase (for now)
			for(i=0;i<ushared->daemons_cnt;i++) {
				if (!ushared->daemons[i].registered) {
					uwsgi_log("spawning daemon %s\n", ushared->daemons[i].command);
					spawn_daemon(&ushared->daemons[i]);
					ushared->daemons[i].registered = 1;		
				}
			}


			// add unregistered timers
			// locking is not needed as timers can only increase
			for(i=0;i<ushared->timers_cnt;i++) {
                                if (!ushared->timers[i].registered) {
					ushared->timers[i].fd = event_queue_add_timer(uwsgi.master_queue, &ushared->timers[i].id, ushared->timers[i].value);
					ushared->timers[i].registered = 1;
				}
			}

			// add unregistered rb_timers
			// locking is not needed as rb_timers can only increase
			for(i=0;i<ushared->rb_timers_cnt;i++) {
                                if (!ushared->rb_timers[i].registered) {
					ushared->rb_timers[i].uwsgi_rb_timer = uwsgi_add_rb_timer(rb_timers, time(NULL) + ushared->rb_timers[i].value, &ushared->rb_timers[i]);
					ushared->rb_timers[i].registered = 1;
				}
			}

				int interesting_fd = -1;

				if (ushared->rb_timers_cnt>0) {
					min_timeout = uwsgi_min_rb_timer(rb_timers);
                			if (min_timeout == NULL ) {
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
					if (ushared->rb_timers_cnt>0) {
						expire_rb_timeouts(rb_timers);
					}
				}

			
				// check uwsgi-cron table
				if (ushared->cron_cnt) {
					uwsgi.current_time = time(NULL);
					uwsgi_cron_delta = localtime( &uwsgi.current_time );

					if (uwsgi_cron_delta) {

						// fix month
						uwsgi_cron_delta->tm_mon++;

						uwsgi_lock(uwsgi.cron_table_lock);
						for(i=0;i<ushared->cron_cnt;i++) {
	
							struct uwsgi_cron *ucron = &ushared->cron[i];
							int uc_minute, uc_hour, uc_day, uc_month, uc_week;

							uc_minute = ucron->minute;
							uc_hour = ucron->hour;
							uc_day = ucron->day;
							uc_month = ucron->month;
							uc_week = ucron->week;
	
							if (ucron->minute == -1) uc_minute = uwsgi_cron_delta->tm_min;
							if (ucron->hour == -1) uc_hour = uwsgi_cron_delta->tm_hour;
							if (ucron->month == -1) uc_month = uwsgi_cron_delta->tm_mon;

							// mday and wday are ORed
							if (ucron->day == -1 && ucron->week == -1) {
								if (ucron->day == -1) uc_day = uwsgi_cron_delta->tm_mday;
								if (ucron->week == -1) uc_week = uwsgi_cron_delta->tm_wday;
							}
							else if (ucron->day == -1) {
								ucron->day = uwsgi_cron_delta->tm_mday;
							}
							else if (ucron->week == -1) {
								ucron->week = uwsgi_cron_delta->tm_wday;
							}
							else {
								if (ucron->day == uwsgi_cron_delta->tm_mday) {
									ucron->week = uwsgi_cron_delta->tm_wday;
								}
								else if (ucron->week == uwsgi_cron_delta->tm_wday) {
									ucron->day = uwsgi_cron_delta->tm_mday;
								}
							}
							
							if (uwsgi_cron_delta->tm_min == uc_minute &&
								uwsgi_cron_delta->tm_hour == uc_hour &&
								uwsgi_cron_delta->tm_mon == uc_month &&
								uwsgi_cron_delta->tm_mday == uc_day &&
								uwsgi_cron_delta->tm_wday == uc_week) {


								// date match, signal it ?
								if (uwsgi.current_time - ucron->last_job > 60) {
									uwsgi_route_signal(ucron->sig);
									ucron->last_job = uwsgi.current_time;
								}
							}
					
						}
						uwsgi_unlock(uwsgi.cron_table_lock);
					}
					else {
						uwsgi_error("localtime()");
					}
				}

				if (rlen > 0) {

					if (uwsgi.log_master) {
						if (interesting_fd == uwsgi.shared->worker_log_pipe[0]) {
							rlen = read(uwsgi.shared->worker_log_pipe[0], log_buf, 4096);
							if (rlen > 0) {
								if (uwsgi.log_syslog) {
									syslog(LOG_INFO, "%.*s", rlen, log_buf);
								}
#ifdef UWSGI_ZEROMQ
								else if (uwsgi.zmq_log_socket) {
                                                                        zmq_msg_t msg;
                                                                        if (zmq_msg_init_size (&msg, rlen) == 0) {
                                                                                memcpy(zmq_msg_data(&msg), log_buf, rlen);
                                                                                zmq_send(uwsgi.zmq_log_socket, &msg, 0);
                                                                                zmq_msg_close(&msg);
                                                                        }
                                                                }
#endif
								else if (uwsgi.log_socket) {
									sendto(uwsgi.log_socket_fd, log_buf, rlen, 0, &uwsgi.log_socket_addr->sa, uwsgi.log_socket_size);
								}
								// TODO allow uwsgi.logger = func
							}	
						}
					}

					if (uwsgi.has_emperor) {
						if (interesting_fd == uwsgi.emperor_fd) {
							char byte;
							rlen = read(uwsgi.emperor_fd, &byte, 1);
                                                        if (rlen > 0) {
								uwsgi_log("received message %d from emperor\n", byte);
								// remove me
								if (byte == 0) {
									close(uwsgi.emperor_fd);
									if (!uwsgi.to_hell) kill_them_all(0);
								}
								// reload me
								else if (byte == 1) {
									grace_them_all(0);
								}
                                                        }
							else {
								uwsgi_log("lost connection with my emperor !!!\n");
								close(uwsgi.emperor_fd);
								if (!uwsgi.to_hell) kill_them_all(0);
								sleep(2);
								exit(1);
							}
						}
					}


					if (uwsgi.cheap) {
						int found = 0 ;
						struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
						while(uwsgi_sock) {
							if (interesting_fd == uwsgi_sock->fd) {
								found = 1;
								uwsgi.cheap = 0;
								uwsgi_del_sockets_from_queue(uwsgi.master_queue);
								for(i=1;i<=uwsgi.numproc;i++) {
									if (uwsgi_respawn_worker(i)) return;		
								}
								break;
							}
							uwsgi_sock = uwsgi_sock->next;
						}
						if (found) continue;
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
						continue;
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
									for(i=0;i<0xFF;i++) {
										if (uwsgi.p[i]->manage_udp) {
											if (uwsgi.p[i]->manage_udp(udp_client_addr, udp_client.sin_port, uwsgi.wsgi_req->buffer, rlen)) {
												udp_managed = 1;
												break;
											}
										}
									}

									// else a simple udp logger
									if (!udp_managed) {
										uwsgi_log( "[udp:%s:%d] %.*s", udp_client_addr, ntohs(udp_client.sin_port), rlen, uwsgi.wsgi_req->buffer);
									}
								}
							}
							else {
								uwsgi_error("inet_ntop()");
							}
						}

						continue;
					}

#ifdef UWSGI_MULTICAST
					if (interesting_fd == uwsgi.cluster_fd) {
					
						if (uwsgi_get_dgram(uwsgi.cluster_fd, uwsgi.wsgi_requests[0])) {
							continue;
						}

						switch(uwsgi.wsgi_requests[0]->uh.modifier1) {
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
								if (uwsgi.cluster_nodes) break;
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
						continue;
					}
#endif

#endif

					
					int next_iteration = 0;

					uwsgi_lock(uwsgi.fmon_table_lock);
					for(i=0;i<ushared->files_monitored_cnt;i++) {
						if (ushared->files_monitored[i].registered) {
							if (interesting_fd == ushared->files_monitored[i].fd) {
								struct uwsgi_fmon *uf = event_queue_ack_file_monitor(uwsgi.master_queue, interesting_fd);
								// now call the file_monitor handler
								if (uf) uwsgi_route_signal(uf->sig);
								break;
							}
						}
					}

					uwsgi_unlock(uwsgi.fmon_table_lock);
					if (next_iteration) continue;

					next_iteration = 0;

					for(i=0;i<ushared->timers_cnt;i++) {
                                                if (ushared->timers[i].registered) {
                                                        if (interesting_fd == ushared->timers[i].fd) {
                                                                struct uwsgi_timer *ut = event_queue_ack_timer(interesting_fd);
                                                                // now call the file_monitor handler
                                                                if (ut) uwsgi_route_signal(ut->sig);
                                                                break;
                                                        }
                                                }
                                        }
                                        if (next_iteration) continue;


					// check for worker signal
					if (interesting_fd == uwsgi.shared->worker_signal_pipe[0]) {
						rlen = read(interesting_fd, &uwsgi_signal, 1);
						if (rlen < 0) {
							uwsgi_error("read()");
						}	
						else if (rlen > 0) {
							uwsgi_log("received uwsgi signal %d from workers\n", uwsgi_signal);
							uwsgi_route_signal(uwsgi_signal);
						}
						else {
							uwsgi_log_verbose("lost connection with worker %d\n", i);
							close(interesting_fd);
							//uwsgi.workers[i].pipe[0] = -1;
						}
					}
				}

			uwsgi.current_time = time(NULL);	
			// checking logsize
			if (uwsgi.logfile) {
				uwsgi.shared->logsize = lseek(2, 0, SEEK_CUR);
/*
				if (uwsgi.shared->logsize > 8192) {
					//uwsgi_log("logsize: %d\n", uwsgi.shared->logsize);
					char *new_logfile = uwsgi_malloc(strlen(uwsgi.logfile) + 14 + 1);
					memset(new_logfile, 0, strlen(uwsgi.logfile) + 14 + 1);    
					if (!rename(uwsgi.logfile, new_logfile)) {
						// close 2, reopen logfile dup'it and gracefully reload workers;
					}
					free(new_logfile);
				}	
*/
			}

				
			uwsgi.master_cycles++;

			// recalculate requests counter on race conditions risky configurations
			// a bit of inaccuracy is better than locking;)

			if (uwsgi.numproc > 1) {
				tmp_counter = 0;
				for(i=1;i<uwsgi.numproc+1;i++)
					tmp_counter += uwsgi.workers[i].requests;
				uwsgi.workers[0].requests = tmp_counter;
			}
		
			if (uwsgi.idle > 0 && !uwsgi.cheap) {
				uwsgi.current_time = time(NULL);
				if (!last_request_timecheck) last_request_timecheck = uwsgi.current_time;
				if (last_request_count != uwsgi.workers[0].requests) {
					last_request_timecheck = uwsgi.current_time;
					last_request_count = uwsgi.workers[0].requests;
				}
				else if (uwsgi.current_time - last_request_timecheck > uwsgi.idle) {
					uwsgi_log("workers have been inactive for more than %d seconds\n", uwsgi.idle);
					for(i=1;i<=uwsgi.numproc;i++) {
                               			if (uwsgi.workers[i].pid == 0) continue;
                               			kill(uwsgi.workers[i].pid, SIGKILL);
                               			if (waitpid(uwsgi.workers[i].pid, &waitpid_status, 0) < 0) {
                                       			uwsgi_error("waitpid()");
                               			}
					}
					master_has_children = 0;
					uwsgi.cheap = 1;
					uwsgi_add_sockets_to_queue(uwsgi.master_queue);
                			uwsgi_log("cheap mode enabled: waiting for socket connection...\n");
					last_request_timecheck = 0;
					continue;	
				}
			}

			// remove expired cache items TODO use rb_tree timeouts
			if (uwsgi.cache_max_items > 0) {
				for(i=0;i< (int)uwsgi.cache_max_items;i++) {
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
			struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
                	while(uwsgi_sock) {
				if (uwsgi_sock->family == AF_INET) {
					get_linux_tcp_info(uwsgi_sock->fd);
				}
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
						kill(uwsgi.workers[i].pid, SIGUSR2);
						// allow SIGUSR2 to be delivered
						sleep(1);
						kill(uwsgi.workers[i].pid, SIGKILL);
						// to avoid races
						uwsgi.workers[i].harakiri = 0;
					}
				}

				// need to find a better way
				//uwsgi.workers[i].last_running_time = uwsgi.workers[i].running_time;
			}

#ifdef UWSGI_UDP
			// check for cluster nodes
			master_check_cluster_nodes();

			// reannounce myself every 10 cycles
			if (uwsgi.cluster && uwsgi.cluster_fd >= 0 && !uwsgi.cluster_nodes && (uwsgi.master_cycles % 10) == 0) {
				uwsgi_cluster_add_me();
			}

			// resubscribe every 10 cycles
			if (uwsgi.subscriptions_cnt > 0 && ((uwsgi.master_cycles % 10) == 0 || uwsgi.master_cycles == 1)) {
				for(i=0;i<uwsgi.subscriptions_cnt;i++) {
					uwsgi_subscribe(uwsgi.subscriptions[i]);
				}
			}

#endif

			if (uwsgi.cache_store && uwsgi.cache_filesize && uwsgi.cache_store_sync && ((uwsgi.master_cycles % uwsgi.cache_store_sync) == 0)) {
				if (msync(uwsgi.cache_items, uwsgi.cache_filesize, MS_ASYNC)) {
                        		uwsgi_error("msync()");
                		}
			}

			if (uwsgi.queue_store && uwsgi.queue_filesize && uwsgi.queue_store_sync && ((uwsgi.master_cycles % uwsgi.queue_store_sync) == 0)) {
				if (msync(uwsgi.queue, uwsgi.queue_filesize, MS_ASYNC)) {
                        		uwsgi_error("msync()");
                		}
			}

			// check touch_reload
			if (uwsgi.touch_reload && !uwsgi.to_heaven && !uwsgi.to_hell) {
                		struct stat tr_st;
                		if (stat(uwsgi.touch_reload, &tr_st)) {
                        		uwsgi_error("stat()");
                        		uwsgi_log("unable to stat() %s, touch-reload will be disabled\n", uwsgi.touch_reload);
                        		uwsgi.touch_reload = NULL;
                		}
                		else {
					if (tr_st.st_mtime > uwsgi.last_touch_reload_mtime) {
						uwsgi_log("*** %s has been touched... grace them all !!! ***\n", uwsgi.touch_reload);
						grace_them_all(0);
					}
                		}
			}


			// now check for lb pool
			
			
			continue;

		}
		// reload gateways and daemons only on normal workflow
		if (!uwsgi.to_heaven && !uwsgi.to_hell) {

#ifdef UWSGI_SPOOLER
		/* reload the spooler */
		if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
			if (diedpid == uwsgi.shared->spooler_pid) {
				uwsgi_log( "OOOPS the spooler is no more...trying respawn...\n");
				uwsgi.shared->spooler_pid = spooler_start();
				continue;
			}
		}
#endif

		/* reload the gateways */
		// TODO reload_gateway(diedpid);
		pid_found = 0;
		for(i=0;i<uwsgi.gateways_cnt;i++) {
			if (uwsgi.gateways[i].pid == diedpid) {
				gateway_respawn(i);
				pid_found = 1;
				break;
			}
		}

		if (pid_found) continue;

		/* reload the daemons */
                // TODO reload_gateway(diedpid);
                pid_found = 0;
                for(i=0;i<uwsgi.shared->daemons_cnt;i++) {
                        if (uwsgi.shared->daemons[i].pid == diedpid) {
                                spawn_daemon(&uwsgi.shared->daemons[i]);
                                pid_found = 1;
                                break;
                        }
                }

		if (pid_found) continue;

		}

		/* What happens here ?

			case 1) the diedpid is not a worker, report it and continue
			case 2) the diedpid is a worker and we are not in a reload procedure -> reload it
			case 3) the diedpid is a worker and we are in graceful reload -> ready_to_reload++ and continue
			case 3) the diedpid is a worker and we are in brutal reload -> ready_to_die++ and continue
		

		*/

		uwsgi.mywid = find_worker_id(diedpid);
		if (uwsgi.mywid <= 0) {
			if (WIFEXITED(waitpid_status)) {
				uwsgi_log("subprocess %d exited with code %d\n", (int) diedpid, WEXITSTATUS(waitpid_status));
			}
			else if (WIFSIGNALED(waitpid_status)) {
				uwsgi_log("subprocess %d exited by signal %d\n", (int) diedpid, WTERMSIG(waitpid_status));
			}
			else if (WIFSTOPPED(waitpid_status)) {
				uwsgi_log("subprocess %d stopped\n", (int) diedpid);
			}
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


		if (uwsgi.workers[uwsgi.mywid].manage_next_request) {
			uwsgi_log( "DAMN ! worker %d (pid: %d) died :( trying respawn ...\n", uwsgi.mywid, (int)diedpid);
		}
		gettimeofday(&last_respawn, NULL);
		if (last_respawn.tv_sec == uwsgi.respawn_delta) {
			last_respawn_rate++;
			if (last_respawn_rate > uwsgi.numproc) {
				uwsgi_log( "worker respawning too fast !!! i have to sleep a bit...\n");
				/* TODO, user configurable fork throttler */
				sleep(2);
				last_respawn_rate = 0;
			}
		}
		else {
			last_respawn_rate = 0;
		}
		gettimeofday(&last_respawn, NULL);
		uwsgi.respawn_delta = last_respawn.tv_sec;
		// close the communication pipe
		/*
		close(uwsgi.workers[uwsgi.mywid].pipe[0]);
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, uwsgi.workers[uwsgi.mywid].pipe)) {
			uwsgi_error("socketpair()\n");
			continue;
		}
		*/
		if (uwsgi_respawn_worker(uwsgi.mywid)) return;

	}
}

}
