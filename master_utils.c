#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void worker_wakeup() {}

void master_check_cluster_nodes() {

	int i;

	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
		struct uwsgi_cluster_node *ucn = &uwsgi.shared->nodes[i];

		if (ucn->name[0] != 0 && ucn->type == CLUSTER_NODE_STATIC && ucn->status == UWSGI_NODE_FAILED) {
			// should i retry ?
			if (uwsgi.master_cycles % ucn->errors == 0) {
				if (!uwsgi_ping_node(i, uwsgi.wsgi_req)) {
					ucn->status = UWSGI_NODE_OK;
					uwsgi_log("re-enabled cluster node %d/%s\n", i, ucn->name);
				}
				else {
					ucn->errors++;
				}
			}
		}
		else if (ucn->name[0] != 0 && ucn->type == CLUSTER_NODE_DYNAMIC) {
			// if the last_seen attr is higher than 30 secs ago, mark the node as dead
			if ((uwsgi.current_time - ucn->last_seen) > 30) {
				uwsgi_log_verbose("no presence announce in the last 30 seconds by node %s, i assume it is dead.\n", ucn->name);
				ucn->name[0] = 0;
			}
		}
	}
}

void uwsgi_fixup_fds(int wid, int muleid) {

	int i;

	// close the cache server
	if (uwsgi.cache_server_fd != -1) {
		close(uwsgi.cache_server_fd);
	}

	if (uwsgi.master_process) {
                        // fix the communication pipe
                        close(uwsgi.shared->worker_signal_pipe[0]);
                        for(i=1;i<=uwsgi.numproc;i++) {
                                if (uwsgi.workers[i].signal_pipe[0] != -1) close(uwsgi.workers[i].signal_pipe[0]);
                                if (i != wid) {
                                        if (uwsgi.workers[i].signal_pipe[1] != -1) close(uwsgi.workers[i].signal_pipe[1]);
                                }
                        }
#ifdef UWSGI_SPOOLER
			if (uwsgi.shared->spooler_pid != getpid()) {
                        	if (uwsgi.shared->spooler_signal_pipe[0] != -1) close (uwsgi.shared->spooler_signal_pipe[0]);
                        	if (uwsgi.shared->spooler_signal_pipe[1] != -1) close (uwsgi.shared->spooler_signal_pipe[1]);
			}
#endif

                        if (uwsgi.shared->mule_signal_pipe[0] != -1) close(uwsgi.shared->mule_signal_pipe[0]);

			if (muleid == 0) {
                        	if (uwsgi.shared->mule_signal_pipe[1] != -1) close(uwsgi.shared->mule_signal_pipe[1]);
                        	if (uwsgi.shared->mule_queue_pipe[1] != -1) close(uwsgi.shared->mule_queue_pipe[1]);
			}

                        for(i=0;i<uwsgi.mules_cnt;i++) {
                                if (uwsgi.mules[i].signal_pipe[0] != -1) close(uwsgi.mules[i].signal_pipe[0]);
				if (muleid != i+1) {
                                	if (uwsgi.mules[i].signal_pipe[1] != -1) close(uwsgi.mules[i].signal_pipe[1]);
                                	if (uwsgi.mules[i].queue_pipe[1] != -1) close(uwsgi.mules[i].queue_pipe[1]);
				}
                        }

			for(i=0;i<uwsgi.farms_cnt;i++) {
                                if (uwsgi.farms[i].signal_pipe[0] != -1) close(uwsgi.farms[i].signal_pipe[0]);

				if (muleid == 0) {
                                	if (uwsgi.farms[i].signal_pipe[1] != -1) close(uwsgi.farms[i].signal_pipe[1]);
                                	if (uwsgi.farms[i].queue_pipe[1] != -1) close(uwsgi.farms[i].queue_pipe[1]);
				}
			}

                }

	
}

int uwsgi_respawn_worker(int wid) {

	int respawns = uwsgi.workers[wid].respawn_count;
	int i;

	pid_t pid = uwsgi_fork(uwsgi.workers[wid].name);

	if (pid == 0) {
		signal(SIGWINCH, worker_wakeup);
		signal(SIGTSTP, worker_wakeup);
		uwsgi.mywid = wid;
		uwsgi.mypid = getpid();
		uwsgi.workers[uwsgi.mywid].pid = uwsgi.mypid;
		uwsgi.workers[uwsgi.mywid].id = uwsgi.mywid;
		uwsgi.workers[uwsgi.mywid].harakiri = 0;

		uwsgi.workers[uwsgi.mywid].rss_size = 0;
		uwsgi.workers[uwsgi.mywid].vsz_size = 0;
		// do not reset worker counters on reload !!!
		//uwsgi.workers[uwsgi.mywid].requests = 0;
		// ...but maintain a delta counter (yes this is racy in multithread)
		uwsgi.workers[uwsgi.mywid].delta_requests = 0;	
		//uwsgi.workers[uwsgi.mywid].failed_requests = 0;
		uwsgi.workers[uwsgi.mywid].respawn_count++;
		uwsgi.workers[uwsgi.mywid].last_spawn = uwsgi.current_time;
		uwsgi.workers[uwsgi.mywid].manage_next_request = 1;
		uwsgi.workers[uwsgi.mywid].cheaped = 0;
		uwsgi.workers[uwsgi.mywid].busy = 0;
		uwsgi.workers[uwsgi.mywid].suspended = 0;
		uwsgi.workers[uwsgi.mywid].sig = 0;

		// reset the apps count with a copy from the master 
		uwsgi.workers[uwsgi.mywid].apps_cnt = uwsgi.workers[0].apps_cnt;

		uwsgi_fixup_fds(wid, 0);

                uwsgi.my_signal_socket = uwsgi.workers[wid].signal_pipe[1];

		if (uwsgi.master_process) {
                        if ((uwsgi.workers[uwsgi.mywid].respawn_count || uwsgi.cheap)) {
                                for (i = 0; i < 0xFF; i++) {
                                        if (uwsgi.p[i]->master_fixup) {
                                                uwsgi.p[i]->master_fixup(1);
                                        }
                                }
                        }
		}

		return 1;
	}
	else if (pid < 1) {
		uwsgi_error("fork()");
	}
	else {
		if (respawns > 0) {
			uwsgi_log("Respawned uWSGI worker %d (new pid: %d)\n", wid, (int) pid);
		}
		else {
			uwsgi_log("spawned uWSGI worker %d (pid: %d, cores: %d)\n", wid, pid, uwsgi.cores);
		}
	}

	return 0;
}


void uwsgi_manage_signal_cron(time_t now) {

	struct tm *uwsgi_cron_delta;
	int i;

	uwsgi.current_time = now;
	uwsgi_cron_delta = localtime(&uwsgi.current_time);

	if (uwsgi_cron_delta) {

		// fix month
		uwsgi_cron_delta->tm_mon++;

		uwsgi_lock(uwsgi.cron_table_lock);
		for (i = 0; i < ushared->cron_cnt; i++) {

			struct uwsgi_cron *ucron = &ushared->cron[i];
			int uc_minute, uc_hour, uc_day, uc_month, uc_week;

			uc_minute = ucron->minute;
			uc_hour = ucron->hour;
			uc_day = ucron->day;
			uc_month = ucron->month;
			uc_week = ucron->week;

			if (ucron->minute == -1)
				uc_minute = uwsgi_cron_delta->tm_min;
			if (ucron->hour == -1)
				uc_hour = uwsgi_cron_delta->tm_hour;
			if (ucron->month == -1)
				uc_month = uwsgi_cron_delta->tm_mon;
			if (ucron->day == -1)
				uc_day = uwsgi_cron_delta->tm_mday;
			if (ucron->week == -1)
				uc_week = uwsgi_cron_delta->tm_wday;

			int run_task = 0;
			// mday and wday are ORed
			if (ucron->day != -1 && ucron->week != -1) {
				if (uwsgi_cron_delta->tm_min == uc_minute && uwsgi_cron_delta->tm_hour == uc_hour && uwsgi_cron_delta->tm_mon == uc_month && (uwsgi_cron_delta->tm_mday == uc_day || uwsgi_cron_delta->tm_wday == uc_week)) {
					run_task = 1;
				}
			}
			else {
				if (uwsgi_cron_delta->tm_min == uc_minute && uwsgi_cron_delta->tm_hour == uc_hour && uwsgi_cron_delta->tm_mon == uc_month && uwsgi_cron_delta->tm_mday == uc_day && uwsgi_cron_delta->tm_wday == uc_week) {
					run_task = 1;
				}
			}


			if (run_task == 1) {
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

void uwsgi_manage_command_cron(time_t now) {

	struct tm *uwsgi_cron_delta;

	struct uwsgi_cron *current_cron = uwsgi.crons;
	int uc_minute, uc_hour, uc_day, uc_month, uc_week;

	uwsgi.current_time = now;
	uwsgi_cron_delta = localtime(&uwsgi.current_time);


	if (!uwsgi_cron_delta) {
		uwsgi_error("localtime()");
		return;
	}

	while (current_cron) {


		uc_minute = current_cron->minute;
		uc_hour = current_cron->hour;
		uc_day = current_cron->day;
		uc_month = current_cron->month;
		uc_week = current_cron->week;

		if (current_cron->minute == -1)
			uc_minute = uwsgi_cron_delta->tm_min;
		if (current_cron->hour == -1)
			uc_hour = uwsgi_cron_delta->tm_hour;
		if (current_cron->month == -1)
			uc_month = uwsgi_cron_delta->tm_mon;
		if (current_cron->day == -1)
			uc_day = uwsgi_cron_delta->tm_mday;
		if (current_cron->week == -1)
			uc_week = uwsgi_cron_delta->tm_wday;

		int run_task = 0;
                        // mday and wday are ORed
                        if (current_cron->day != -1 && current_cron->week != -1) {
                                if (uwsgi_cron_delta->tm_min == uc_minute && uwsgi_cron_delta->tm_hour == uc_hour && uwsgi_cron_delta->tm_mon == uc_month && (uwsgi_cron_delta->tm_mday == uc_day || uwsgi_cron_delta->tm_wday == uc_week)) {
                                        run_task = 1;
                                }
                        }
                        else {
                                if (uwsgi_cron_delta->tm_min == uc_minute && uwsgi_cron_delta->tm_hour == uc_hour && uwsgi_cron_delta->tm_mon == uc_month && uwsgi_cron_delta->tm_mday == uc_day && uwsgi_cron_delta->tm_wday == uc_week) {
                                        run_task = 1;
                                }
                        }


                if (run_task == 1) {

			// date match, run command ?
			if (uwsgi.current_time - current_cron->last_job > 60) {
				//call command
				if (current_cron->command) {
					if (uwsgi_run_command(current_cron->command) >=0) {
						uwsgi_log_verbose("[uWSGI-cron] running %s\n", current_cron->command);
					}
				}
				current_cron->last_job = uwsgi.current_time;
			}
		}



		current_cron = current_cron->next;
	}


}

#define stats_send_llu(x, y) fprintf(output, x, (long long unsigned int) y)
#define stats_send(x, y) fprintf(output, x, y)

void uwsgi_send_stats(int fd) {

	int i,j;
	struct sockaddr_un client_src;
	struct uwsgi_app *ua;
	socklen_t client_src_len = 0;
	int client_fd = accept(fd, (struct sockaddr *) &client_src, &client_src_len);
	if (client_fd < 0) {
		uwsgi_error("accept()");
		return;
	}

	FILE *output = fdopen(client_fd, "w");
	if (!output) {
		uwsgi_error("fdopen()");
		close(client_fd);
		return;
	}

	stats_send("{ \"version\": \"%s\",\n", UWSGI_VERSION);

#ifdef __linux__
	stats_send_llu("\"listen_queue\": %llu,\n", uwsgi.shared->ti.tcpi_unacked);
#endif

	stats_send_llu("\"load\": %llu,\n", uwsgi.shared->load);

	fprintf(output,"\"pid\": %d,\n", (int)(getpid()));
	fprintf(output,"\"uid\": %d,\n", (int)(getuid()));
	fprintf(output,"\"gid\": %d,\n", (int)(getgid()));

	char *cwd = uwsgi_get_cwd();
	stats_send("\"cwd\": \"%s\",\n", cwd);
	free(cwd);

	if (uwsgi.daemons) {
		fprintf(output, "\"daemons\": [\n");
		struct uwsgi_daemon *ud = uwsgi.daemons;
        	while(ud) {
			fprintf(output, "\t{ \"cmd\": \"%s\", \"pid\": %d, \"respawns\": %llu }",
			ud->command, (int) ud->pid, (unsigned long long) ud->respawns-1);
			if (ud->next)
				fprintf(output, ",\n");
			else {
				fprintf(output, "\n");
			}
			ud = ud->next;
		}
		fprintf(output, "],\n");
	}

	fprintf(output, "\"workers\": [\n");

	for (i = 0; i < uwsgi.numproc; i++) {
		fprintf(output,"\t{");

		fprintf(output,"\"id\": %d, ", uwsgi.workers[i+1].id);
		fprintf(output,"\"pid\": %d, ", (int) uwsgi.workers[i+1].pid);
		stats_send_llu("\"requests\": %llu, ", uwsgi.workers[i+1].requests);
		stats_send_llu("\"delta_requests\": %llu, ", uwsgi.workers[i+1].delta_requests);
		stats_send_llu("\"exceptions\": %llu, ", uwsgi.workers[i+1].exceptions);
		stats_send_llu("\"signals\": %llu, ", uwsgi.workers[i+1].signals);

		if (uwsgi.workers[i + 1].cheaped) {
			fprintf(output,"\"status\": \"cheap\", ");
		}
                else if (uwsgi.workers[i + 1].suspended) {
			fprintf(output,"\"status\": \"pause\", ");
                }
		else {
			if (uwsgi.workers[i + 1].sig) {
				fprintf(output,"\"status\": \"sig%d\", ", uwsgi.workers[i + 1].signum);
			}
                	else if (uwsgi.workers[i + 1].busy) {
				fprintf(output,"\"status\": \"busy\", ");
                        }
                        else {
				fprintf(output,"\"status\": \"idle\", ");
                        }
                }

		stats_send_llu("\"rss\": %llu, ", uwsgi.workers[i+1].rss_size);
		stats_send_llu("\"vsz\": %llu, ", uwsgi.workers[i+1].vsz_size);

		stats_send_llu("\"running_time\": %llu, ", uwsgi.workers[i+1].running_time);
		stats_send_llu("\"last_spawn\": %llu, ", uwsgi.workers[i+1].last_spawn);
		stats_send_llu("\"respawn_count\": %llu, ", uwsgi.workers[i+1].respawn_count);
		stats_send_llu("\"tx\": %llu, ", uwsgi.workers[i+1].tx);
		stats_send_llu("\"avg_rt\": %llu, ", uwsgi.workers[i+1].avg_response_time);

		fprintf(output,"\"apps\": [\n");

		for(j=0;j<uwsgi.workers[i+1].apps_cnt;j++) {
			ua = &uwsgi.workers[i+1].apps[j];
			fprintf(output,"\t\t{ ");

			fprintf(output, "\"id\": %d, ", j);
			fprintf(output, "\"modifier1\": %d, ", ua->modifier1);
			fprintf(output, "\"mountpoint\": \"%.*s\", ", ua->mountpoint_len, ua->mountpoint);

			stats_send_llu( "\"requests\": %llu, ", ua->requests);
			stats_send_llu( "\"exceptions\": %llu, ", ua->exceptions);

			if (ua->chdir) {
				fprintf(output, "\"chdir\": \"%s\", ", ua->chdir);
			}
			else {
				fprintf(output, "\"chdir\": \"\" ");
			}
			
			if (j == uwsgi.workers[i+1].apps_cnt-1) {
				fprintf(output,"}\n");
			}
			else {
				fprintf(output,"},\n");
			}
		}

		fprintf(output,"\t\t]");

		if (i == uwsgi.numproc-1) {
			fprintf(output,"}\n");
		}
		else {
			fprintf(output,"},\n");
		}
	}

	fprintf(output,"]}\n");
	fclose(output);
}
