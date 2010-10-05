#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

#ifdef __linux__
void get_linux_tcp_info(int fd) {
        struct tcp_info ti;
        socklen_t tis = sizeof(struct tcp_info) ;

        if (!getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tis)) {
                if (ti.tcpi_unacked >= ti.tcpi_sacked) {
                        uwsgi_log_verbose("*** uWSGI listen queue of socket %d full !!! (%d/%d) ***\n", fd, ti.tcpi_unacked, ti.tcpi_sacked);
                }
        }
}
#endif


void master_loop(char **argv, char **environ) {

	uint64_t master_cycles = 0;

	struct timeval last_respawn;

	pid_t pid;

	pid_t diedpid;
	int waitpid_status;

	int working_workers = 0;
        int blocking_workers = 0;

        int ready_to_reload = 0;
        int ready_to_die = 0;

	int master_has_children = 0;

#ifdef UWSGI_UDP
        struct pollfd uwsgi_poll;
        struct sockaddr_in udp_client;
        socklen_t udp_len;
        char udp_client_addr[16];
        PyObject *udp_callable;
        PyObject *udp_callable_args = NULL;
        PyObject *udp_response;
#endif

	int i,j;
#ifdef UWSGI_UDP
	int rlen;
#endif

	struct timeval check_interval = {.tv_sec = 1,.tv_usec = 0 };

	// release the GIL
	UWSGI_RELEASE_GIL

	/* route signals to workers... */
	signal(SIGHUP, (void *) &grace_them_all);
	signal(SIGTERM, (void *) &reap_them_all);
	signal(SIGINT, (void *) &kill_them_all);
	signal(SIGQUIT, (void *) &kill_them_all);
	/* used only to avoid human-errors */

	signal(SIGUSR1, (void *) &stats);

	uwsgi.wsgi_req->buffer = uwsgi.async_buf[0];
#ifdef UWSGI_UDP
	if (uwsgi.udp_socket) {
		uwsgi_poll.fd = bind_to_udp(uwsgi.udp_socket);
		if (uwsgi_poll.fd < 0) {
			uwsgi_log( "unable to bind to udp socket. SNMP and cluster management services will be disabled.\n");
		}
		else {
			uwsgi_log( "UDP server enabled.\n");
			uwsgi_poll.events = POLLIN;
		}
	}
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
		uwsgi_log( "filling SNMP table...");

		uwsgi.shared->snmp_gvalue[0].type = SNMP_COUNTER64;
		uwsgi.shared->snmp_gvalue[0].val = &uwsgi.workers[0].requests;

		uwsgi_log( "done\n");

	}
#endif

#ifdef UWSGI_UDP
		UWSGI_GET_GIL	
		udp_callable = PyDict_GetItemString(uwsgi.embedded_dict, "udp_callable");
		if (udp_callable) {
			udp_callable_args = PyTuple_New(3);
		}
		UWSGI_RELEASE_GIL
#endif
		for (;;) {
			if (ready_to_die >= uwsgi.numproc && uwsgi.to_hell) {
#ifdef UWSGI_SPOOLER
				if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
					kill(uwsgi.shared->spooler_pid, SIGKILL);
					uwsgi_log( "killed the spooler with pid %d\n", uwsgi.shared->spooler_pid);
				}

#endif

#ifdef UWSGI_PROXY
				if (uwsgi.proxy_socket_name && uwsgi.shared->proxy_pid > 0) {
					kill(uwsgi.shared->proxy_pid, SIGKILL);
					uwsgi_log( "killed proxy with pid %d\n", uwsgi.shared->proxy_pid);
				}
#endif
				uwsgi_log( "goodbye to uWSGI.\n");
				exit(0);
			}
			if (ready_to_reload >= uwsgi.numproc && uwsgi.to_heaven) {
#ifdef UWSGI_SPOOLER
				if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
					kill(uwsgi.shared->spooler_pid, SIGKILL);
					uwsgi_log( "wait4() the spooler with pid %d...", uwsgi.shared->spooler_pid);
					diedpid = waitpid(uwsgi.shared->spooler_pid, &waitpid_status, 0);
					uwsgi_log( "done.");
				}
#endif

#ifdef UWSGI_PROXY
				if (uwsgi.proxy_socket_name && uwsgi.shared->proxy_pid > 0) {
					kill(uwsgi.shared->proxy_pid, SIGKILL);
					uwsgi_log( "wait4() the proxy with pid %d...", uwsgi.shared->proxy_pid);
					diedpid = waitpid(uwsgi.shared->proxy_pid, &waitpid_status, 0);
					uwsgi_log( "done.");
				}
#endif
				uwsgi_log( "binary reloading uWSGI...\n");
				if (chdir(uwsgi.cwd)) {
					uwsgi_error("chdir()");
					exit(1);
				}
				/* check fd table (a module can obviosly open some fd on initialization...) */
				uwsgi_log( "closing all non-uwsgi socket fds > 2 (_SC_OPEN_MAX = %ld)...\n", sysconf(_SC_OPEN_MAX));
				for (i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
					int found = 0;
					for(j=0;j<uwsgi.sockets_cnt;j++) {
						if (i == uwsgi.sockets[j].fd) {
							found = 1;
							break;
						}
					}
					if (!found) close(i);
				}

				uwsgi_log( "running %s\n", uwsgi.binary_path);
				argv[0] = uwsgi.binary_path;
				//strcpy (argv[0], uwsgi.binary_path);
				execve(uwsgi.binary_path, argv, environ);
				uwsgi_error("execve()");
				// never here
				exit(1);
			}

			

			if (uwsgi.numproc > 0 ) {
				master_has_children = 1;
			}
#ifdef UWSGI_SPOOLER
			if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
				master_has_children = 1;
			}
#endif
#ifdef UWSGI_PROXY
			if (uwsgi.proxy_socket_name && uwsgi.shared->proxy_pid > 0) {
				master_has_children = 1;
			}
#endif

			if (!master_has_children) {
				diedpid = 0;
			}
			else {
				diedpid = waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
				if (diedpid == -1) {
					uwsgi_error("waitpid()");
					/* here is better to reload all the uWSGI stack */
					uwsgi_log( "something horrible happened...\n");
					reap_them_all();
					exit(1);
				}
			}

			if (diedpid == 0) {

				/* all processes ok, doing status scan after N seconds */
				check_interval.tv_sec = uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL];
				if (!check_interval.tv_sec)
					check_interval.tv_sec = 1;

#ifdef UWSGI_UDP
				if (uwsgi.udp_socket && uwsgi_poll.fd >= 0) {
					rlen = poll(&uwsgi_poll, 1, check_interval.tv_sec * 1000);
					if (rlen < 0) {
						uwsgi_error("poll()");
					}
					else if (rlen > 0) {
						udp_len = sizeof(udp_client);
						rlen = recvfrom(uwsgi_poll.fd, uwsgi.wsgi_req->buffer, uwsgi.buffer_size, 0, (struct sockaddr *) &udp_client, &udp_len);
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
									manage_snmp(uwsgi_poll.fd, (uint8_t *) uwsgi.wsgi_req->buffer, rlen, &udp_client);
								}
#endif
								else {
									if (udp_callable && udp_callable_args) {
										UWSGI_GET_GIL
										PyTuple_SetItem(udp_callable_args, 0, PyString_FromString(udp_client_addr));
										PyTuple_SetItem(udp_callable_args, 1, PyInt_FromLong(ntohs(udp_client.sin_port)));
										PyTuple_SetItem(udp_callable_args, 2, PyString_FromStringAndSize(uwsgi.wsgi_req->buffer, rlen));
										udp_response = python_call(udp_callable, udp_callable_args, 0);
										if (udp_response) {
											Py_DECREF(udp_response);
										}
										if (PyErr_Occurred())
											PyErr_Print();

										UWSGI_RELEASE_GIL
									}
									else {
										// a simple udp logger
										uwsgi_log( "[udp:%s:%d] %.*s", udp_client_addr, ntohs(udp_client.sin_port), rlen, uwsgi.wsgi_req->buffer);
									}
								}
							}
							else {
								uwsgi_error("inet_ntop()");
							}
						}
					}
				}
				else {
#endif
					select(0, NULL, NULL, NULL, &check_interval);
#ifdef UWSGI_UDP
				}
#endif

				// checking logsize
				if (uwsgi.logfile) {
					uwsgi.shared->logsize = lseek(2, 0, SEEK_CUR);
				}
				
				master_cycles++;
				working_workers = 0;
				blocking_workers = 0;

				check_interval.tv_sec = uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL];
				if (!check_interval.tv_sec)
					check_interval.tv_sec = 1;

				
#ifdef __linux__
				for(i=0;i<uwsgi.sockets_cnt;i++) {
					if (uwsgi.sockets[i].family != AF_INET) continue;
					get_linux_tcp_info(uwsgi.sockets[i].fd);
				}
#endif

				for (i = 1; i <= uwsgi.numproc; i++) {
					/* first check for harakiri */
					if (uwsgi.workers[i].harakiri > 0) {
						if (uwsgi.workers[i].harakiri < time(NULL)) {
							/* first try to invoke the harakiri() custom handler */
							/* TODO */
							/* then brutally kill the worker */
							uwsgi_log("*** HARAKIRI ON WORKER %d (pid: %d) ***\n", i, uwsgi.workers[i].pid);
							kill(uwsgi.workers[i].pid, SIGUSR2);
							// allow SIGUSR2 to be delivered
							sleep(1);
							kill(uwsgi.workers[i].pid, SIGKILL);
							// to avoid races
							uwsgi.workers[i].harakiri = 0;
						}
					}
					/* load counters */
					if (uwsgi.workers[i].status & UWSGI_STATUS_IN_REQUEST)
						working_workers++;

					if (uwsgi.workers[i].status & UWSGI_STATUS_BLOCKING)
						blocking_workers++;

					uwsgi.workers[i].last_running_time = uwsgi.workers[i].running_time;
				}

				// check for cluster nodes
				for (i = 0; i < MAX_CLUSTER_NODES; i++) {
					struct uwsgi_cluster_node *ucn = &uwsgi.shared->nodes[i];

					if (ucn->name[0] != 0 && ucn->status == UWSGI_NODE_FAILED) {
						// should i retry ?
						if (master_cycles % ucn->errors == 0) {
							if (!uwsgi_ping_node(i, uwsgi.wsgi_req)) {
								ucn->status = UWSGI_NODE_OK;
								uwsgi_log( "re-enabled cluster node %d/%s\n", i, ucn->name);
							}
							else {
								ucn->errors++;
							}
						}
					}
				}

				continue;

			}
#ifdef UWSGI_SPOOLER
			/* reload the spooler */
			if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
				if (diedpid == uwsgi.shared->spooler_pid) {
					uwsgi_log( "OOOPS the spooler is no more...trying respawn...\n");
					uwsgi.shared->spooler_pid = spooler_start(uwsgi.embedded_dict);
					continue;
				}
			}
#endif

#ifdef UWSGI_PROXY
			/* reload the proxy (can be the only process running) */
			if (uwsgi.proxy_socket_name && uwsgi.shared->proxy_pid > 0) {
				if (diedpid == uwsgi.shared->proxy_pid) {
					if (WIFEXITED(waitpid_status)) {
						if (WEXITSTATUS(waitpid_status) != UWSGI_END_CODE) {
							uwsgi_log( "OOOPS the proxy is no more...trying respawn...\n");
							uwsgi.shared->spooler_pid = proxy_start(1);
							continue;
						}
					}
				}
			}
#endif
			// TODO rewrite without using exit code (targeted at 0.9.7)

#ifdef __sun__
                        /* horrible hack... what the FU*K is doing Solaris ??? */
                        if (WIFSIGNALED(waitpid_status)) {
                                if (uwsgi.to_heaven) {
                                        ready_to_reload++;
                                        continue;
                                }
                                else if (uwsgi.to_hell) {
                                        ready_to_die++;
                                        continue;
                                }
                        }
#endif
			/* check for reloading */
			if (WIFEXITED(waitpid_status)) {
				if (WEXITSTATUS(waitpid_status) == UWSGI_RELOAD_CODE && uwsgi.to_heaven) {
					ready_to_reload++;
					continue;
				}
				else if (WEXITSTATUS(waitpid_status) == UWSGI_END_CODE && uwsgi.to_hell) {
					ready_to_die++;
					continue;
				}
			}


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
			
			uwsgi_log( "DAMN ! process %d died :( trying respawn ...\n", diedpid);
			gettimeofday(&last_respawn, NULL);
			if (last_respawn.tv_sec == uwsgi.respawn_delta) {
				uwsgi_log( "worker respawning too fast !!! i have to sleep a bit...\n");
				/* TODO, user configurable fork throttler */
				sleep(2);
			}
			gettimeofday(&last_respawn, NULL);
			uwsgi.respawn_delta = last_respawn.tv_sec;
			pid = fork();
			if (pid == 0) {
				uwsgi.mypid = getpid();
				uwsgi.workers[uwsgi.mywid].pid = uwsgi.mypid;
				uwsgi.workers[uwsgi.mywid].harakiri = 0;
				uwsgi.workers[uwsgi.mywid].requests = 0;
				uwsgi.workers[uwsgi.mywid].failed_requests = 0;
				uwsgi.workers[uwsgi.mywid].respawn_count++;
				uwsgi.workers[uwsgi.mywid].last_spawn = time(NULL);
				uwsgi.workers[uwsgi.mywid].manage_next_request = 1;
				break;
			}
			else if (pid < 1) {
				uwsgi_error("fork()");
			}
			else {
				uwsgi_log( "Respawned uWSGI worker (new pid: %d)\n", pid);
#ifdef UWSGI_SPOOLER
				if (uwsgi.mywid <= 0 && diedpid != uwsgi.shared->spooler_pid) {
#else
				if (uwsgi.mywid <= 0) {
#endif

#ifdef UWSGI_PROXY
					if (diedpid != uwsgi.shared->proxy_pid) {
#endif
						uwsgi_log( "warning the died pid was not in the workers list. Probably you hit a BUG of uWSGI\n");
#ifdef UWSGI_PROXY
					}
#endif
				}
			}
		}

}
