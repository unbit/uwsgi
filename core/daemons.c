#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

/*

	External uwsgi daemons

	There are 3 kind of daemons (read: external applications) that can be managed
	by uWSGI.

	1) dumb daemons (attached with --attach-daemon)
		they must not daemonize() and when they exit() the master is notified (via waitpid)
		and the process is respawned
	2) smart daemons with daemonization
		you specify a pidfile and a command
		- on startup - if the pidfile does not exists or contains a not-available pid (checked with kill(pid, 0))
		the daemon is respawned
		- on master ckeck - if the pidfile does not exist or if it point to a non-existent pid
                the daemon is respawned
	3) smart daemons without daemonization
		same as 2, but the daemonization and pidfile creation is managed by uWSGI

	status:

	0 -> never started
	1 -> just started
	2 -> started and monitored (only in pidfile based)

*/

void uwsgi_daemons_smart_check() {
	static time_t last_run = 0;

	time_t now = uwsgi_now();

	if (now - last_run <= 0) {
		return;
	}

	last_run = now;

	struct uwsgi_daemon *ud = uwsgi.daemons;
	while (ud) {
#ifdef UWSGI_SSL
		if (ud->legion) {
			if (uwsgi_legion_i_am_the_lord(ud->legion)) {
				// lord, spawn if not running
				if (ud->pid <= 0) {
					uwsgi_spawn_daemon(ud);
				}
			}
			else {
				// not lord, kill daemon if running
				if (ud->pid > 0) {
					if (!kill(ud->pid, 0)) {
						uwsgi_log("[uwsgi_daemons] stopping legion \"%s\" daemon: %s (pid: %d)\n", ud->legion, ud->command, ud->pid);
						kill(-ud->pid, SIGTERM);
					}
					else {
						// pid already died
						ud->pid = -1;
					}
				}
				ud = ud->next;
				continue;
			}
		}
#endif
		if (ud->pidfile) {
			int checked_pid = uwsgi_check_pidfile(ud->pidfile);
			if (checked_pid <= 0) {
				// monitored instance
				if (ud->status == 2) {
					uwsgi_spawn_daemon(ud);
				}
				else {
					ud->pidfile_checks++;
					if (ud->pidfile_checks >= (unsigned int) ud->freq) {
						if (!ud->has_daemonized) {
							uwsgi_log_verbose("[uwsgi-daemons] \"%s\" (pid: %d) did not daemonize !!!\n", ud->command, (int) ud->pid);
							ud->pidfile_checks = 0;
						}
						else {
							uwsgi_log("[uwsgi-daemons] found changed pidfile for \"%s\" (old_pid: %d new_pid: %d)\n", ud->command, (int) ud->pid, (int) checked_pid);
							uwsgi_spawn_daemon(ud);
						}
					}
				}
			}
			else if (checked_pid != ud->pid) {
				uwsgi_log("[uwsgi-daemons] found changed pid for \"%s\" (old_pid: %d new_pid: %d)\n", ud->command, (int) ud->pid, (int) checked_pid);
				ud->pid = checked_pid;
			}
			// all ok, pidfile and process found
			else {
				ud->status = 2;
			}
		}
		ud = ud->next;
	}
}

// this function is called when a dumb daemon dies and we do not want to respawn it
int uwsgi_daemon_check_pid_death(pid_t diedpid) {
	struct uwsgi_daemon *ud = uwsgi.daemons;
	while (ud) {
		if (ud->pid == diedpid) {
			if (!ud->pidfile) {
				uwsgi_log("daemon \"%s\" (pid: %d) annihilated\n", ud->command, (int) diedpid);
				ud->pid = -1;
				return -1;
			}
			else {
				if (!ud->has_daemonized) {
					ud->has_daemonized = 1;
				}
				else {
					uwsgi_log("[uwsgi-daemons] BUG !!! daemon \"%s\" has already daemonized !!!\n", ud->command);
				}
			}
		}
		ud = ud->next;
	}
	return 0;
}

// this function is called when a dumb daemon dies and we want to respawn it
int uwsgi_daemon_check_pid_reload(pid_t diedpid) {
	struct uwsgi_daemon *ud = uwsgi.daemons;
	while (ud) {
#ifdef UWSGI_SSL
		if (ud->pid == diedpid && ud->legion && !uwsgi_legion_i_am_the_lord(ud->legion)) {
			// part of legion but not lord, don't respawn
			ud->pid = -1;
			uwsgi_log("uwsgi-daemons] legion \"%s\" daemon \"%s\" (pid: %d) annihilated\n", ud->legion, ud->command, (int) diedpid);
			ud = ud->next;
			continue;
		}
#endif
		if (ud->pid == diedpid && !ud->pidfile) {
			if (ud->control) {
				gracefully_kill_them_all(0);
				return 0;
			}
			uwsgi_spawn_daemon(ud);
			return 1;
		}
		ud = ud->next;
	}
	return 0;
}



int uwsgi_check_pidfile(char *filename) {
	struct stat st;
	pid_t ret = -1;
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_error_open(filename);
		goto end;
	}
	if (fstat(fd, &st)) {
		uwsgi_error("fstat()");
		goto end2;
	}
	char *pidstr = uwsgi_calloc(st.st_size + 1);
	if (read(fd, pidstr, st.st_size) != st.st_size) {
		uwsgi_error("read()");
		goto end3;
	}
	pid_t pid = atoi(pidstr);
	if (pid <= 0)
		goto end3;
	if (!kill(pid, 0)) {
		ret = pid;
	}
end3:
	free(pidstr);
end2:
	close(fd);
end:
	return ret;
}

void uwsgi_daemons_spawn_all() {
	struct uwsgi_daemon *ud = uwsgi.daemons;
	while (ud) {
		if (!ud->registered) {
#ifdef UWSGI_SSL
			if (ud->legion && !uwsgi_legion_i_am_the_lord(ud->legion)) {
				// part of legion, register but don't spawn it yet
				if (ud->pidfile) {
					ud->pid = uwsgi_check_pidfile(ud->pidfile);
					if (ud->pid > 0)
						uwsgi_log("[uwsgi-daemons] found valid/active pidfile for \"%s\" (pid: %d)\n", ud->command, (int) ud->pid);
				}
				ud->registered = 1;
				ud = ud->next;
				continue;
			}
#endif
			ud->registered = 1;
			if (ud->pidfile) {
				int checked_pid = uwsgi_check_pidfile(ud->pidfile);
				if (checked_pid <= 0) {
					uwsgi_spawn_daemon(ud);
				}
				else {
					ud->pid = checked_pid;
					uwsgi_log("[uwsgi-daemons] found valid/active pidfile for \"%s\" (pid: %d)\n", ud->command, (int) ud->pid);
				}
			}
			else {
				uwsgi_spawn_daemon(ud);
			}
		}
		ud = ud->next;
	}
}


void uwsgi_detach_daemons() {
	struct uwsgi_daemon *ud = uwsgi.daemons;
	while (ud) {
#ifdef UWSGI_SSL
		// stop any legion daemon, doesn't matter if dumb or smart
		if (ud->pid > 0 && (ud->legion || !ud->pidfile)) {
#else
		// stop only dumb daemons
		if (ud->pid > 0 && !ud->pidfile) {
#endif
			uwsgi_log("[uwsgi-daemons] stopping daemon (pid: %d): %s\n", (int) ud->pid, ud->command);
			// try to gracefully stop daemon, kill it if it won't die
			// if mercy is not set then wait up to 3 seconds
			time_t timeout = uwsgi_now() + (uwsgi.reload_mercy ? uwsgi.reload_mercy : 3);
			int waitpid_status;
			while (!kill(ud->pid, 0)) {
				kill(-ud->pid, SIGTERM);
				sleep(1);
				waitpid(-ud->pid, &waitpid_status, WNOHANG);
				if (uwsgi_now() >= timeout) {
					uwsgi_log("[uwsgi-daemons] daemon did not die in time, killing (pid: %d): %s\n", (int) ud->pid, ud->command);
					kill(-ud->pid, SIGKILL);
					break;
				}
			}
			// unregister daemon to prevent it from being respawned
			ud->registered = 0;
		}
		ud = ud->next;
	}
}


void uwsgi_spawn_daemon(struct uwsgi_daemon *ud) {

	// skip unregistered daemons
	if (!ud->registered) return;

	int throttle = 0;

	if (uwsgi.current_time - ud->last_spawn <= 3) {
		throttle = ud->respawns - (uwsgi.current_time - ud->last_spawn);
		// if ud->respawns == 0 then we can end up with throttle < 0
		if (throttle <= 0) throttle = 1;
	}

	pid_t pid = uwsgi_fork("uWSGI external daemon");
	if (pid < 0) {
		uwsgi_error("fork()");
		return;
	}

	if (pid > 0) {
		ud->has_daemonized = 0;
		ud->pid = pid;
		ud->status = 1;
		ud->pidfile_checks = 0;
		if (ud->respawns == 0) {
			ud->born = uwsgi_now();
		}

		ud->respawns++;
		ud->last_spawn = uwsgi_now();

	}
	else {
		// close uwsgi sockets
		uwsgi_close_all_sockets();
		uwsgi_close_all_fds();

		if (ud->daemonize) {
			/* refork... */
			pid = fork();
			if (pid < 0) {
				uwsgi_error("fork()");
				exit(1);
			}
			if (pid != 0) {
				_exit(0);
			}
			uwsgi_write_pidfile(ud->pidfile);
		}

		if (!uwsgi.daemons_honour_stdin) {
			// /dev/null will became stdin
			uwsgi_remap_fd(0, "/dev/null");
		}

		if (setsid() < 0) {
			uwsgi_error("setsid()");
			exit(1);
		}

		if (!ud->pidfile) {
#ifdef __linux__
			if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
				uwsgi_error("prctl()");
			}
#endif
		}


		if (throttle) {
			uwsgi_log("[uwsgi-daemons] throttling \"%s\" for %d seconds\n", ud->command, throttle);
			sleep((unsigned int) throttle);
		}

		uwsgi_log("[uwsgi-daemons] %sspawning \"%s\"\n", ud->respawns > 0 ? "re" : "", ud->command);
		uwsgi_exec_command_with_args(ud->command);
		uwsgi_log("[uwsgi-daemons] unable to spawn \"%s\"\n", ud->command);

		// never here;
		exit(1);
	}

	return;
}


void uwsgi_opt_add_daemon(char *opt, char *value, void *none) {

	struct uwsgi_daemon *uwsgi_ud = uwsgi.daemons, *old_ud;
	char *pidfile = NULL;
	int daemonize = 0;
	int freq = 10;
	char *space = NULL;

	char *command = uwsgi_str(value);

#ifdef UWSGI_SSL
	char *legion = NULL;
	if (!uwsgi_starts_with(opt, strlen(command), "legion-", 7)) {
		space = strchr(command, ' ');
		if (!space) {
			uwsgi_log("invalid legion daemon syntax: %s\n", command);
			exit(1);
		}
		*space = 0;
		legion = command;
		command = space+1;
	}
#endif

	if (!strcmp(opt, "smart-attach-daemon") || !strcmp(opt, "smart-attach-daemon2") || !strcmp(opt, "legion-smart-attach-daemon") || !strcmp(opt, "legion-smart-attach-daemon2")) {
		space = strchr(command, ' ');
		if (!space) {
			uwsgi_log("invalid smart-attach-daemon syntax: %s\n", command);
			exit(1);
		}
		*space = 0;
		pidfile = command;
		// check for freq
		char *comma = strchr(pidfile, ',');
		if (comma) {
			*comma = 0;
			freq = atoi(comma + 1);
		}
		command = space + 1;
		if (!strcmp(opt, "smart-attach-daemon2") || !strcmp(opt, "legion-smart-attach-daemon2")) {
			daemonize = 1;
		}
	}

	if (!uwsgi_ud) {
		uwsgi.daemons = uwsgi_malloc(sizeof(struct uwsgi_daemon));
		uwsgi_ud = uwsgi.daemons;
	}
	else {
		while (uwsgi_ud) {
			old_ud = uwsgi_ud;
			uwsgi_ud = uwsgi_ud->next;
		}

		uwsgi_ud = uwsgi_malloc(sizeof(struct uwsgi_daemon));
		old_ud->next = uwsgi_ud;
	}

	uwsgi_ud->command = command;
	uwsgi_ud->pid = 0;
	uwsgi_ud->status = 0;
	uwsgi_ud->freq = freq;
	uwsgi_ud->registered = 0;
	uwsgi_ud->next = NULL;
	uwsgi_ud->respawns = 0;
	uwsgi_ud->last_spawn = 0;
	uwsgi_ud->daemonize = daemonize;
	uwsgi_ud->pidfile = pidfile;
	uwsgi_ud->control = 0;
	if (!strcmp(opt, "attach-control-daemon")) {
		uwsgi_ud->control = 1;
	}
#ifdef UWSGI_SSL
	uwsgi_ud->legion = legion;
#endif

	uwsgi.daemons_cnt++;

}
