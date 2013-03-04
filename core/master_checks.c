#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

// check if all of the workers are dead and exit uWSGI
void uwsgi_master_check_death() {
	if (uwsgi_instance_is_dying) {
		int i;
		for(i=1;i<=uwsgi.numproc;i++) {
			if (uwsgi.workers[i].pid > 0) {
				return;
			}
		}
		uwsgi_log("goodbye to uWSGI.\n");
		exit(0);
	}
}

// check if all of the workers are dead, and trigger a reload
int uwsgi_master_check_reload(char **argv) {
        if (uwsgi_instance_is_reloading) {
                int i;
                for(i=1;i<=uwsgi.numproc;i++) {
                        if (uwsgi.workers[i].pid > 0) {
                                return 0;
                        }
                }
		uwsgi_reload(argv);
		// never here (unless in shared library mode)
		return -1;
        }
	return 0;
}

// check for chain reload
void uwsgi_master_check_chain() {
	if (!uwsgi.status.chain_reloading) return;
	if (uwsgi.status.chain_reloading > uwsgi.numproc) {
		uwsgi.status.chain_reloading = 0;
                uwsgi_log_verbose("chain reloading complete\n");
	}
	int i;
	uwsgi_block_signal(SIGHUP);
	for(i=1;i<=uwsgi.numproc;i++) {
		if (uwsgi.workers[i].pid > 0 && uwsgi.workers[i].cheaped == 0 && uwsgi.workers[i].cursed_at == 0 && i == uwsgi.status.chain_reloading) {
			uwsgi_curse(i, SIGHUP);
			break;
		}
	}
	uwsgi_unblock_signal(SIGHUP);
}


// special function for assuming all of the workers are dead
void uwsgi_master_commit_status() {
	int i;
	for(i=1;i<=uwsgi.numproc;i++) {
		uwsgi.workers[i].pid = 0;
	}
}

void uwsgi_master_check_idle() {

	static time_t last_request_timecheck = 0;
	static uint64_t last_request_count = 0;
	int i;
	int waitpid_status;

	if (!uwsgi.idle || uwsgi.status.is_cheap)
		return;

	uwsgi.current_time = uwsgi_now();
	if (!last_request_timecheck)
		last_request_timecheck = uwsgi.current_time;

	// security check, stop the check if there are busy workers
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].cheaped == 0 && uwsgi.workers[i].pid > 0) {
			if (uwsgi_worker_is_busy(i)) {
				return;
			}
		}
	}

	if (last_request_count != uwsgi.workers[0].requests) {
		last_request_timecheck = uwsgi.current_time;
		last_request_count = uwsgi.workers[0].requests;
	}
	// a bit of over-engeneering to avoid clock skews
	else if (last_request_timecheck < uwsgi.current_time && (uwsgi.current_time - last_request_timecheck > uwsgi.idle)) {
		uwsgi_log("workers have been inactive for more than %d seconds (%llu-%llu)\n", uwsgi.idle, (unsigned long long) uwsgi.current_time, (unsigned long long) last_request_timecheck);
		uwsgi.status.is_cheap = 1;
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
			return;
		}
		for (i = 1; i <= uwsgi.numproc; i++) {
			uwsgi.workers[i].cheaped = 1;
			if (uwsgi.workers[i].pid == 0)
				continue;
			kill(uwsgi.workers[i].pid, SIGKILL);
			if (waitpid(uwsgi.workers[i].pid, &waitpid_status, 0) < 0) {
				if (errno != ECHILD)
					uwsgi_error("uwsgi_master_check_idle()/waitpid()");
			}
		}
		uwsgi_add_sockets_to_queue(uwsgi.master_queue, -1);
		uwsgi_log("cheap mode enabled: waiting for socket connection...\n");
		last_request_timecheck = 0;
	}

}

void uwsgi_master_check_workers_deadline() {
	int i;
	for (i = 1; i <= uwsgi.numproc; i++) {
		/* first check for harakiri */
		if (uwsgi.workers[i].harakiri > 0) {
			if (uwsgi.workers[i].harakiri < (time_t) uwsgi.current_time) {
				trigger_harakiri(i);
			}
		}
		/* then user-defined harakiri */
		if (uwsgi.workers[i].user_harakiri > 0) {
			if (uwsgi.workers[i].user_harakiri < (time_t) uwsgi.current_time) {
				trigger_harakiri(i);
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
		// check if worker was running longer than allowed lifetime
		if (uwsgi.workers[i].pid > 0 && uwsgi.workers[i].cheaped == 0 && uwsgi.shared->options[UWSGI_OPTION_MAX_WORKER_LIFETIME] > 0) {
			uint64_t lifetime = uwsgi_now() - uwsgi.workers[i].last_spawn;
			if (lifetime > uwsgi.shared->options[UWSGI_OPTION_MAX_WORKER_LIFETIME] && uwsgi.workers[i].manage_next_request == 1) {
				uwsgi_log("worker %d lifetime reached, it was running for %llu second(s)\n", i, (unsigned long long) lifetime);
				uwsgi.workers[i].manage_next_request = 0;
				kill(uwsgi.workers[i].pid, SIGWINCH);
			}
		}

		// need to find a better way
		//uwsgi.workers[i].last_running_time = uwsgi.workers[i].running_time;
	}



}


void uwsgi_master_check_gateways_deadline() {

	int i;

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
}

void uwsgi_master_check_mules_deadline() {
	int i;

	for (i = 0; i < uwsgi.mules_cnt; i++) {
		if (uwsgi.mules[i].harakiri > 0) {
			if (uwsgi.mules[i].harakiri < (time_t) uwsgi.current_time) {
				uwsgi_log("*** HARAKIRI ON MULE %d HANDLING SIGNAL %d (pid: %d) ***\n", i + 1, uwsgi.mules[i].signum, uwsgi.mules[i].pid);
				kill(uwsgi.mules[i].pid, SIGKILL);
				uwsgi.mules[i].harakiri = 0;
			}
		}
	}
}

void uwsgi_master_check_spoolers_deadline() {
	struct uwsgi_spooler *uspool = uwsgi.spoolers;
	while (uspool) {
		if (uspool->harakiri > 0 && uspool->harakiri < (time_t) uwsgi.current_time) {
			uwsgi_log("*** HARAKIRI ON THE SPOOLER (pid: %d) ***\n", uspool->pid);
			kill(uspool->pid, SIGKILL);
			uspool->harakiri = 0;
		}
		uspool = uspool->next;
	}
}


int uwsgi_master_check_spoolers_death(int diedpid) {

	struct uwsgi_spooler *uspool = uwsgi.spoolers;
	while (uspool) {
		if (uspool->pid > 0 && diedpid == uspool->pid) {
			uwsgi_log("OOOPS the spooler is no more...trying respawn...\n");
			uspool->respawned++;
			uspool->pid = spooler_start(uspool);
			return -1;
		}
		uspool = uspool->next;
	}
	return 0;
}

int uwsgi_master_check_emperor_death(int diedpid) {
	if (uwsgi.emperor_pid >= 0 && diedpid == uwsgi.emperor_pid) {
		uwsgi_log_verbose("!!! Emperor died !!!\n");
		uwsgi_emperor_start();
		return -1;
	}
	return 0;
}

int uwsgi_master_check_mules_death(int diedpid) {
	int i;
	for (i = 0; i < uwsgi.mules_cnt; i++) {
		if (uwsgi.mules[i].pid == diedpid) {
			uwsgi_log("OOOPS mule %d (pid: %d) crippled...trying respawn...\n", i + 1, uwsgi.mules[i].pid);
			uwsgi_mule(i + 1);
			return -1;
		}
	}
	return 0;
}

int uwsgi_master_check_gateways_death(int diedpid) {
	int i;
	for (i = 0; i < ushared->gateways_cnt; i++) {
		if (ushared->gateways[i].pid == diedpid) {
			gateway_respawn(i);
			return -1;
		}
	}
	return 0;
}

int uwsgi_master_check_daemons_death(int diedpid) {
	/* reload the daemons */
	if (uwsgi_daemon_check_pid_reload(diedpid)) {
		return -1;
	}
	return 0;
}

int uwsgi_worker_is_busy(int wid) {
	int i;
	for(i=0;i<uwsgi.cores;i++) {
		if (uwsgi.workers[wid].cores[i].in_request) {
			return 1;
		}
	}
	return 0;
}
