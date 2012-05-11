#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void worker_wakeup() {
}

int uwsgi_calc_cheaper(void) {

	int i;
	static time_t last_check = 0;
	int check_interval = uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL];

	if (!last_check) last_check = time(NULL);

	time_t now = time(NULL);
        if (!check_interval)
        	check_interval = 1;

	if ( (now - last_check) < check_interval) return 1;

	last_check = now;

	int needed_workers = uwsgi.cheaper_algo();

	if (needed_workers > 0) {
		for (i = 1; i <= uwsgi.numproc; i++) {
			if (uwsgi.workers[i].cheaped == 1 && uwsgi.workers[i].pid == 0) {
				if (uwsgi_respawn_worker(i))
					return 0;
				needed_workers--;
			}
			if (needed_workers == 0)
				break;
		}
	}
	else if (needed_workers < 0) {
		int oldest_worker = 0;
		time_t oldest_worker_spawn = INT_MAX;
		for (i = 1; i <= uwsgi.numproc; i++) {
			if (uwsgi.workers[i].cheaped == 0 && uwsgi.workers[i].pid > 0) {
				if (uwsgi.workers[i].last_spawn < oldest_worker_spawn) {
					oldest_worker_spawn = uwsgi.workers[i].last_spawn;
					oldest_worker = i;
				}
			}
		}
		if (oldest_worker > 0) {
#ifdef UWSGI_DEBUG
			uwsgi_log("worker %d should die...\n", oldest_worker);
#endif
			uwsgi.workers[oldest_worker].cheaped = 1;
			uwsgi.workers[oldest_worker].manage_next_request = 0;
			// wakeup task in case of wait
			(void) kill(uwsgi.workers[oldest_worker].pid, SIGWINCH);
		}
	}

	return 1;
}

/*

        -- Cheaper, spare algorithm, adapted from old-fashioned spare system --
        
        when all of the workers are busy, the overload_count is incremented.
        as soon as overload_count is higher than uwsgi.cheaper_overload (--cheaper-overload options)
        at most cheaper_step (default to 1) new workers are spawned.

        when at least one worker is free, the overload_count is decremented and the idle_count is incremented.
        If overload_count reaches 0, the system will count active workers (the ones uncheaped) and busy workers (the ones running a request)
	if there is exacly 1 free worker we are in "stable state" (1 spare worker available). no worker will be touched.
	if the number of active workers is higher than uwsgi.cheaper_count and at least uwsgi.cheaper_overload cycles are passed from the last
        "cheap it" procedure, then cheap a worker.

        Example:
            10 processes
            2 cheaper
            2 cheaper step
            3 cheaper_overload 
            1 second master cycle
    
            there are 7 workers running (triggered by some kind of spike activity).
	    Of this, 6 are busy, 1 is free. We are in stable state.
            After a bit the spike disappear and idle_count start to increase.

	    After 3 seconds (uwsgi.cheaper_overload cycles) the oldest worker will be cheaped. This will happens
	    every  seconds (uwsgi.cheaper_overload cycles) til the number of workers is == uwsgi.cheaper_count.

	    If during the "cheap them all" procedure, an overload condition come again (another spike) the "cheap them all"
            will be interrupted.


*/


int uwsgi_cheaper_algo_spare(void) {

	int i;
	static uint64_t overload_count = 0;
	static uint64_t idle_count = 0;

	// step 1 -> count the number of busy workers
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].cheaped == 0 && uwsgi.workers[i].pid > 0) {
			// if a non-busy worker is found, the overload_count is decremented and stop the cycle
			if (uwsgi.workers[i].busy == 0) {
				if (overload_count > 0)
					overload_count--;
				goto healthy;
			}
		}
	}

	overload_count++;
	idle_count = 0;

      healthy:

	// are we overloaded ?
	if (overload_count > uwsgi.cheaper_overload) {

#ifdef UWSGI_DEBUG
		uwsgi_log("overloaded !!!\n");
#endif

		// activate the first available worker (taking step into account)
		int decheaped = 0;
		// search for cheaped workers
		for (i = 1; i <= uwsgi.numproc; i++) {
			if (uwsgi.workers[i].cheaped == 1 && uwsgi.workers[i].pid == 0) {
				decheaped++;
				if (decheaped >= uwsgi.cheaper_step)
					break;
			}
		}
		// reset overload
		overload_count = 0;
		// return the maximum number of workers to spawn
		return decheaped;
	}
	// we are no more overloaded
	else if (overload_count == 0) {
		// how many active workers ?
		int active_workers = 0;
		int busy_workers = 0;
		for (i = 1; i <= uwsgi.numproc; i++) {
			if (uwsgi.workers[i].cheaped == 0 && uwsgi.workers[i].pid > 0) {
				active_workers++;
				if (uwsgi.workers[i].busy == 1)
					busy_workers++;
			}
		}

#ifdef UWSGI_DEBUG
		uwsgi_log("active workers %d busy_workers %d\n", active_workers, busy_workers);
#endif

		// special condition: uwsgi.cheaper running workers and 1 free
		if (active_workers > busy_workers && active_workers - busy_workers == 1) {
#ifdef UWSGI_DEBUG
			uwsgi_log("stable status: 1 spare worker\n");
#endif
			return 0;
		}

		idle_count++;

		if (active_workers > uwsgi.cheaper_count && idle_count % uwsgi.cheaper_overload == 0) {
			// we are in "cheap them all"
			return -1;
		}
	}

	return 0;

}


/*

	-- Cheaper,  backlog algorithm (supported only on Linux) --

        increse the number of workers when the listen queue is higher than uwsgi.cheaper_overload.
	Decrese when lower.

*/

int uwsgi_cheaper_algo_backlog(void) {

	int i;
#ifdef __linux__
	int backlog = uwsgi.shared->options[UWSGI_OPTION_BACKLOG_STATUS];
#else
	int backlog = 0;
#endif

	if (backlog > (int)uwsgi.cheaper_overload) {
		// activate the first available worker (taking step into account)
                int decheaped = 0;
                // search for cheaped workers
                for (i = 1; i <= uwsgi.numproc; i++) {
                        if (uwsgi.workers[i].cheaped == 1 && uwsgi.workers[i].pid == 0) {
                                decheaped++;
                                if (decheaped >= uwsgi.cheaper_step)
                                        break;
                        }
                }
                // return the maximum number of workers to spawn
                return decheaped;

	}
	else if (backlog < (int) uwsgi.cheaper_overload) {
		int active_workers = 0;
		for (i = 1; i <= uwsgi.numproc; i++) {
			if (uwsgi.workers[i].cheaped == 0 && uwsgi.workers[i].pid > 0) {
				active_workers++;
			}
		}

		if (active_workers > uwsgi.cheaper_count) {
			return -1;
		}
	}
	
	return 0;
}


// reload uWSGI, close unneded file descriptor, restore the original environment and re-exec the binary

void uwsgi_reload(char **argv) {
	int i;
	int waitpid_status;

	// call a series of waitpid to ensure all processes (gateways, mules and daemons) are dead
	for (i = 0; i < (ushared->gateways_cnt + uwsgi.daemons_cnt + uwsgi.mules_cnt); i++) {
		waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
	}

	// call atexit user exec
	uwsgi_exec_atexit();

	if (uwsgi.exit_on_reload) {
		uwsgi_log("uWSGI: GAME OVER (insert coin)\n");
		exit(0);
	}

	uwsgi_log("binary reloading uWSGI...\n");
	uwsgi_log("chdir() to %s\n", uwsgi.cwd);
	if (chdir(uwsgi.cwd)) {
		uwsgi_error("chdir()");
	}

	/* check fd table (a module can obviosly open some fd on initialization...) */
	uwsgi_log("closing all non-uwsgi socket fds > 2 (max_fd = %d)...\n", (int)uwsgi.max_fd);
	for (i = 3; i < (int)uwsgi.max_fd; i++) {
		int found = 0;

		struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
		while (uwsgi_sock) {
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

		if (uwsgi.log_master) {
			if (uwsgi.original_log_fd > -1) {
				if (i == uwsgi.original_log_fd) {
					found = 1;
				}
			}

			if (uwsgi.shared->worker_log_pipe[0] > -1) {
				if (i == uwsgi.shared->worker_log_pipe[0]) {
					found = 1;
				}
			}

			if (uwsgi.shared->worker_log_pipe[1] > -1) {
				if (i == uwsgi.shared->worker_log_pipe[1]) {
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

#ifdef UWSGI_AS_SHARED_LIBRARY
	return;
#else
	uwsgi_log("running %s\n", uwsgi.binary_path);
	uwsgi_flush_logs();
	argv[0] = uwsgi.binary_path;
	//strcpy (argv[0], uwsgi.binary_path);
	if (uwsgi.log_master) {
		if (uwsgi.original_log_fd > -1) {
			dup2(uwsgi.original_log_fd, 1);
			dup2(1, 2);
		}
		if (uwsgi.shared->worker_log_pipe[0] > -1) {
			close(uwsgi.shared->worker_log_pipe[0]);
		}
		if (uwsgi.shared->worker_log_pipe[1] > -1) {
			close(uwsgi.shared->worker_log_pipe[1]);
		}
	}
	execvp(uwsgi.binary_path, argv);
	uwsgi_error("execvp()");
	// never here
	exit(1);
#endif

}

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

void uwsgi_fixup_fds(int wid, int muleid, struct uwsgi_gateway *ug) {

	int i;

	// close the cache server
	if (uwsgi.cache_server_fd != -1) {
		close(uwsgi.cache_server_fd);
	}

	if (uwsgi.master_process) {
		if (uwsgi.master_queue > -1)
			close(uwsgi.master_queue);
		// close gateways
		if (!ug) {
			for (i = 0; i < ushared->gateways_cnt; i++) {
				close(ushared->gateways[i].internal_subscription_pipe[0]);
				close(ushared->gateways[i].internal_subscription_pipe[1]);
			}
		}
		struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
		while (ugs) {
			if (ug && !strcmp(ug->name, ugs->owner)) {
				ugs = ugs->next;
				continue;
			}
			// do not close shared sockets !!!
			if (!ugs->shared) {
				close(ugs->fd);
			}
			ugs = ugs->next;
		}
		// fix the communication pipe
		close(uwsgi.shared->worker_signal_pipe[0]);
		for (i = 1; i <= uwsgi.numproc; i++) {
			if (uwsgi.workers[i].signal_pipe[0] != -1)
				close(uwsgi.workers[i].signal_pipe[0]);
			if (i != wid) {
				if (uwsgi.workers[i].signal_pipe[1] != -1)
					close(uwsgi.workers[i].signal_pipe[1]);
			}
		}
#ifdef UWSGI_SPOOLER
		if (uwsgi.i_am_a_spooler && uwsgi.i_am_a_spooler->pid != getpid()) {
			if (uwsgi.shared->spooler_signal_pipe[0] != -1)
				close(uwsgi.shared->spooler_signal_pipe[0]);
			if (uwsgi.shared->spooler_signal_pipe[1] != -1)
				close(uwsgi.shared->spooler_signal_pipe[1]);
		}
#endif

		if (uwsgi.shared->mule_signal_pipe[0] != -1)
			close(uwsgi.shared->mule_signal_pipe[0]);

		if (muleid == 0) {
			if (uwsgi.shared->mule_signal_pipe[1] != -1)
				close(uwsgi.shared->mule_signal_pipe[1]);
			if (uwsgi.shared->mule_queue_pipe[1] != -1)
				close(uwsgi.shared->mule_queue_pipe[1]);
		}

		for (i = 0; i < uwsgi.mules_cnt; i++) {
			if (uwsgi.mules[i].signal_pipe[0] != -1)
				close(uwsgi.mules[i].signal_pipe[0]);
			if (muleid != i + 1) {
				if (uwsgi.mules[i].signal_pipe[1] != -1)
					close(uwsgi.mules[i].signal_pipe[1]);
				if (uwsgi.mules[i].queue_pipe[1] != -1)
					close(uwsgi.mules[i].queue_pipe[1]);
			}
		}

		for (i = 0; i < uwsgi.farms_cnt; i++) {
			if (uwsgi.farms[i].signal_pipe[0] != -1)
				close(uwsgi.farms[i].signal_pipe[0]);

			if (muleid == 0) {
				if (uwsgi.farms[i].signal_pipe[1] != -1)
					close(uwsgi.farms[i].signal_pipe[1]);
				if (uwsgi.farms[i].queue_pipe[1] != -1)
					close(uwsgi.farms[i].queue_pipe[1]);
			}
		}

	}


}

int uwsgi_respawn_worker(int wid) {

	int respawns = uwsgi.workers[wid].respawn_count;
	int i;

	if (uwsgi.threaded_logger) {
		pthread_mutex_lock(&uwsgi.threaded_logger_lock);
	}

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

		uwsgi_fixup_fds(wid, 0, NULL);

		uwsgi.my_signal_socket = uwsgi.workers[wid].signal_pipe[1];

		if (uwsgi.master_process) {
			if ((uwsgi.workers[uwsgi.mywid].respawn_count || uwsgi.cheap)) {
				for (i = 0; i < 256; i++) {
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

	if (uwsgi.threaded_logger) {
		pthread_mutex_unlock(&uwsgi.threaded_logger_lock);
	}


	return 0;
}


void uwsgi_manage_signal_cron(time_t now) {

	struct tm *uwsgi_cron_delta;
	int i;

	uwsgi_cron_delta = localtime(&now);

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

			// negative values as interval -1 = * , -5 = */5
			if (ucron->minute < 0) {
				if ((uwsgi_cron_delta->tm_min % abs(ucron->minute)) == 0) {
					uc_minute = uwsgi_cron_delta->tm_min;
				}
			}
			if (ucron->hour < 0) {
				if ((uwsgi_cron_delta->tm_hour % abs(ucron->hour)) == 0) {
					uc_hour = uwsgi_cron_delta->tm_hour;
				}
			}
			if (ucron->month < 0) {
				if ((uwsgi_cron_delta->tm_mon % abs(ucron->month)) == 0) {
					uc_month = uwsgi_cron_delta->tm_mon;
				}
			}
			if (ucron->day < 0) {
				if ((uwsgi_cron_delta->tm_mday % abs(ucron->day)) == 0) {
					uc_day = uwsgi_cron_delta->tm_mday;
				}
			}
			if (ucron->week < 0) {
				if ((uwsgi_cron_delta->tm_wday % abs(ucron->week)) == 0) {	
					uc_week = uwsgi_cron_delta->tm_wday;
				}
			}

			int run_task = 0;
			// mday and wday are ORed
			if (ucron->day >= 0 && ucron->week >= 0) {
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
				if (now - ucron->last_job > 60) {
					uwsgi_route_signal(ucron->sig);
					ucron->last_job = now;
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

	uwsgi_cron_delta = localtime(&now);


	if (!uwsgi_cron_delta) {
		uwsgi_error("localtime()");
		return;
	}

	// fix month
	uwsgi_cron_delta->tm_mon++;

	while (current_cron) {

		uc_minute = current_cron->minute;
		uc_hour = current_cron->hour;
		uc_day = current_cron->day;
		uc_month = current_cron->month;
		uc_week = current_cron->week;

		// negative values as interval -1 = * , -5 = */5
		if (current_cron->minute < 0) {
			if ((uwsgi_cron_delta->tm_min % abs(current_cron->minute)) == 0) {
				uc_minute = uwsgi_cron_delta->tm_min;
			}
		}
		if (current_cron->hour < 0) {
			if ((uwsgi_cron_delta->tm_hour % abs(current_cron->hour)) == 0) {
				uc_hour = uwsgi_cron_delta->tm_hour;
			}
		}
		if (current_cron->month < 0) {
			if ((uwsgi_cron_delta->tm_hour % abs(current_cron->month)) == 0) {
				uc_month = uwsgi_cron_delta->tm_mon;
			}
		}
		if (current_cron->day < 0) {
			if ((uwsgi_cron_delta->tm_mday % abs(current_cron->day)) == 0) {
				uc_day = uwsgi_cron_delta->tm_mday;
			}
		}
		if (current_cron->week < 0) {
			if ((uwsgi_cron_delta->tm_wday % abs(current_cron->week)) == 0) {
				uc_week = uwsgi_cron_delta->tm_wday;
			}
		}

		int run_task = 0;
		// mday and wday are ORed
		if (current_cron->day >= 0 && current_cron->week >= 0) {
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
			if (now - current_cron->last_job > 60) {
				//call command
				if (current_cron->command) {
					if (uwsgi_run_command(current_cron->command, NULL, -1) >= 0) {
						uwsgi_log_verbose("[uWSGI-cron] running %s\n", current_cron->command);
					}
				}
				current_cron->last_job = now;
			}
		}



		current_cron = current_cron->next;
	}


}

#define stats_send_llu(x, y) fprintf(output, x, (long long unsigned int) y)
#define stats_send(x, y) fprintf(output, x, y)

void uwsgi_send_stats(int fd) {

	int i, j;
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
	stats_send_llu("\"listen_queue\": %llu,\n", (unsigned long long) uwsgi.shared->options[UWSGI_OPTION_BACKLOG_STATUS]);
	stats_send_llu("\"listen_queue_errors\": %llu,\n", (unsigned long long) uwsgi.shared->options[UWSGI_OPTION_BACKLOG_ERRORS]);
#endif

	stats_send_llu("\"load\": %llu,\n", uwsgi.shared->load);

	fprintf(output, "\"pid\": %d,\n", (int) (getpid()));
	fprintf(output, "\"uid\": %d,\n", (int) (getuid()));
	fprintf(output, "\"gid\": %d,\n", (int) (getgid()));

	char *cwd = uwsgi_get_cwd();
	stats_send("\"cwd\": \"%s\",\n", cwd);
	free(cwd);

	if (uwsgi.daemons) {
		fprintf(output, "\"daemons\": [\n");
		struct uwsgi_daemon *ud = uwsgi.daemons;
		while (ud) {
			fprintf(output, "\t{ \"cmd\": \"%s\", \"pid\": %d, \"respawns\": %llu }", ud->command, (int) ud->pid, (unsigned long long) ud->respawns - 1);
			if (ud->next)
				fprintf(output, ",\n");
			else {
				fprintf(output, "\n");
			}
			ud = ud->next;
		}
		fprintf(output, "],\n");
	}

	fprintf(output, "\"locks\": [\n");

	struct uwsgi_lock_item *uli = uwsgi.registered_locks;
	while (uli) {
		if (uli->next) {
			fprintf(output, "\t{ \"%s\": %d },\n", uli->id, (int) uli->pid);
		}
		else {
			fprintf(output, "\t{ \"%s\": %d }\n", uli->id, (int) uli->pid);
		}
		uli = uli->next;
	}

	fprintf(output, "],\n");

	fprintf(output, "\"workers\": [\n");

	for (i = 0; i < uwsgi.numproc; i++) {
		fprintf(output, "\t{");

		fprintf(output, "\"id\": %d, ", uwsgi.workers[i + 1].id);
		fprintf(output, "\"pid\": %d, ", (int) uwsgi.workers[i + 1].pid);
		stats_send_llu("\"requests\": %llu, ", uwsgi.workers[i + 1].requests);
		stats_send_llu("\"delta_requests\": %llu, ", uwsgi.workers[i + 1].delta_requests);
		stats_send_llu("\"exceptions\": %llu, ", uwsgi.workers[i + 1].exceptions);
		stats_send_llu("\"signals\": %llu, ", uwsgi.workers[i + 1].signals);
		stats_send_llu("\"static_offload_threads\": %llu, ", uwsgi.workers[i + 1].static_offload_threads);

		if (uwsgi.workers[i + 1].cheaped) {
			fprintf(output, "\"status\": \"cheap\", ");
		}
		else if (uwsgi.workers[i + 1].suspended && !uwsgi.workers[i + 1].busy) {
			fprintf(output, "\"status\": \"pause\", ");
		}
		else {
			if (uwsgi.workers[i + 1].sig) {
				fprintf(output, "\"status\": \"sig%d\", ", uwsgi.workers[i + 1].signum);
			}
			else if (uwsgi.workers[i + 1].busy) {
				fprintf(output, "\"status\": \"busy\", ");
			}
			else {
				fprintf(output, "\"status\": \"idle\", ");
			}
		}

		stats_send_llu("\"rss\": %llu, ", uwsgi.workers[i + 1].rss_size);
		stats_send_llu("\"vsz\": %llu, ", uwsgi.workers[i + 1].vsz_size);

		stats_send_llu("\"running_time\": %llu, ", uwsgi.workers[i + 1].running_time);
		stats_send_llu("\"last_spawn\": %llu, ", uwsgi.workers[i + 1].last_spawn);
		stats_send_llu("\"respawn_count\": %llu, ", uwsgi.workers[i + 1].respawn_count);
		stats_send_llu("\"tx\": %llu, ", uwsgi.workers[i + 1].tx);
		stats_send_llu("\"avg_rt\": %llu, ", uwsgi.workers[i + 1].avg_response_time);

		fprintf(output, "\"apps\": [\n");

		for (j = 0; j < uwsgi.workers[i + 1].apps_cnt; j++) {
			ua = &uwsgi.workers[i + 1].apps[j];
			fprintf(output, "\t\t{ ");

			fprintf(output, "\"id\": %d, ", j);
			fprintf(output, "\"modifier1\": %d, ", ua->modifier1);
			fprintf(output, "\"mountpoint\": \"%.*s\", ", ua->mountpoint_len, ua->mountpoint);


			stats_send_llu("\"startup_time\": %llu, ", ua->startup_time);

			stats_send_llu("\"requests\": %llu, ", ua->requests);
			stats_send_llu("\"exceptions\": %llu, ", ua->exceptions);

			if (ua->chdir) {
				fprintf(output, "\"chdir\": \"%s\", ", ua->chdir);
			}
			else {
				fprintf(output, "\"chdir\": \"\" ");
			}

			if (j == uwsgi.workers[i + 1].apps_cnt - 1) {
				fprintf(output, "}\n");
			}
			else {
				fprintf(output, "},\n");
			}
		}

		fprintf(output, "\t\t]");

		if (i == uwsgi.numproc - 1) {
			fprintf(output, "}\n");
		}
		else {
			fprintf(output, "},\n");
		}
	}

	fprintf(output, "]}\n");
	fclose(output);
}

void uwsgi_register_cheaper_algo(char *name, int(*func) (void)) {

        struct uwsgi_cheaper_algo *uca = uwsgi.cheaper_algos;

        if (!uca) {
                uwsgi.cheaper_algos = uwsgi_malloc(sizeof(struct uwsgi_cheaper_algo));
                uca = uwsgi.cheaper_algos;
        }
        else {
                while (uca) {
			if (!uca->next) {
				uca->next = uwsgi_malloc(sizeof(struct uwsgi_cheaper_algo));
				uca = uca->next;	
				break;
			}
                        uca = uca->next;
                }

        }

        uca->name = name;
        uca->func = func;
        uca->next = NULL;

#ifdef UWSGI_DEBUG
        uwsgi_log("[uwsgi-cheaper-algo] registered \"%s\"\n", uca->name);
#endif
}

