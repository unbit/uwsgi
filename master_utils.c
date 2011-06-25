#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

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


int uwsgi_respawn_worker(int wid) {

	int respawns = uwsgi.workers[wid].respawn_count;
	int i;

	pid_t pid = fork();

	if (pid == 0) {
		uwsgi.mywid = wid;
		// fix the communication pipe
		close(uwsgi.shared->worker_signal_pipe[0]);
		uwsgi.mypid = getpid();
		uwsgi.workers[uwsgi.mywid].pid = uwsgi.mypid;
		uwsgi.workers[uwsgi.mywid].id = uwsgi.mywid;
		uwsgi.workers[uwsgi.mywid].harakiri = 0;
		uwsgi.workers[uwsgi.mywid].requests = 0;
		uwsgi.workers[uwsgi.mywid].failed_requests = 0;
		uwsgi.workers[uwsgi.mywid].respawn_count++;
		uwsgi.workers[uwsgi.mywid].last_spawn = uwsgi.current_time;
		uwsgi.workers[uwsgi.mywid].manage_next_request = 1;

		if (uwsgi.master_process && (uwsgi.workers[uwsgi.mywid].respawn_count || uwsgi.cheap)) {
			for (i = 0; i < 0xFF; i++) {
                		if (uwsgi.p[i]->master_fixup) {
                        		uwsgi.p[i]->master_fixup(1);
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

			// mday and wday are ORed
			if (ucron->day == -1 && ucron->week == -1) {
				if (ucron->day == -1)
					uc_day = uwsgi_cron_delta->tm_mday;
				if (ucron->week == -1)
					uc_week = uwsgi_cron_delta->tm_wday;
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

			if (uwsgi_cron_delta->tm_min == uc_minute && uwsgi_cron_delta->tm_hour == uc_hour && uwsgi_cron_delta->tm_mon == uc_month && uwsgi_cron_delta->tm_mday == uc_day && uwsgi_cron_delta->tm_wday == uc_week) {


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

		// mday and wday are ORed
		if (current_cron->day == -1 && current_cron->week == -1) {
			if (current_cron->day == -1)
				uc_day = uwsgi_cron_delta->tm_mday;
			if (current_cron->week == -1)
				uc_week = uwsgi_cron_delta->tm_wday;
		}
		else if (current_cron->day == -1) {
			current_cron->day = uwsgi_cron_delta->tm_mday;
		}
		else if (current_cron->week == -1) {
			current_cron->week = uwsgi_cron_delta->tm_wday;
		}
		else {
			if (current_cron->day == uwsgi_cron_delta->tm_mday) {
				current_cron->week = uwsgi_cron_delta->tm_wday;
			}
			else if (current_cron->week == uwsgi_cron_delta->tm_wday) {
				current_cron->day = uwsgi_cron_delta->tm_mday;
			}
		}

		if (uwsgi_cron_delta->tm_min == uc_minute && uwsgi_cron_delta->tm_hour == uc_hour && uwsgi_cron_delta->tm_mon == uc_month && uwsgi_cron_delta->tm_mday == uc_day && uwsgi_cron_delta->tm_wday == uc_week) {


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
