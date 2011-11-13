#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_signal_handler(uint8_t sig) {

	struct uwsgi_signal_entry *use = NULL; 

	use = &uwsgi.shared->signal_table[sig];

	if (!uwsgi.p[use->modifier1]->signal_handler) {
		return -1;
	}	

        // set harakiri here (if required and if i am a worker)
	
	if (uwsgi.mywid > 0) {
                uwsgi.workers[uwsgi.mywid].sig = 1;
                uwsgi.workers[uwsgi.mywid].signum = sig;
		uwsgi.workers[uwsgi.mywid].signals++;
		if(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
                	set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
		}
        }
	else if (uwsgi.muleid > 0) {
                uwsgi.mules[uwsgi.muleid-1].sig = 1;
                uwsgi.mules[uwsgi.muleid-1].signum = sig;
		uwsgi.mules[uwsgi.muleid-1].signals++;
		if(uwsgi.shared->options[UWSGI_OPTION_MULE_HARAKIRI] > 0) {
                	set_mule_harakiri(uwsgi.shared->options[UWSGI_OPTION_MULE_HARAKIRI]);
		}
	}
#ifdef UWSGI_SPOOLER
        else if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0 && (getpid() == uwsgi.shared->spooler_pid)) {
		if(uwsgi.shared->options[UWSGI_OPTION_SPOOLER_HARAKIRI] > 0) {
                        set_spooler_harakiri(uwsgi.shared->options[UWSGI_OPTION_SPOOLER_HARAKIRI]);
                }
        }
#endif

	int ret = uwsgi.p[use->modifier1]->signal_handler(sig, use->handler);

	if (uwsgi.mywid > 0) {
                uwsgi.workers[uwsgi.mywid].sig = 0;
		if(uwsgi.workers[uwsgi.mywid].harakiri > 0) {
                	set_harakiri(0);
		}
        }
	else if (uwsgi.muleid > 0) {
                uwsgi.mules[uwsgi.muleid-1].sig = 0;
		if(uwsgi.mules[uwsgi.muleid-1].harakiri > 0) {
                	set_mule_harakiri(0);
		}
        }
#ifdef UWSGI_SPOOLER
        else if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0 && (getpid() == uwsgi.shared->spooler_pid)) {
		if(uwsgi.shared->options[UWSGI_OPTION_SPOOLER_HARAKIRI] > 0) {
                        set_spooler_harakiri(0);
                }
        }
#endif

	return ret;
}

int uwsgi_signal_registered(uint8_t sig) {

	if (uwsgi.shared->signal_table[sig].handler != NULL)
		return 1;

	return 0;
}

int uwsgi_register_signal(uint8_t sig, char *receiver, void *handler, uint8_t modifier1) {

	struct uwsgi_signal_entry *use = NULL;

	if (strlen(receiver) > 63) return -1;

	uwsgi_lock(uwsgi.signal_table_lock);

	use = &uwsgi.shared->signal_table[sig];

	strcpy(use->receiver, receiver);
	use->handler = handler;
	use->modifier1 = modifier1;
	
	uwsgi_log("registered signal %d\n", sig);

	uwsgi_unlock(uwsgi.signal_table_lock);

	return 0;
}


int uwsgi_add_file_monitor(uint8_t sig, char *filename) {

	if (strlen(filename) > (0xff-1)) {
		uwsgi_log("uwsgi_add_file_monitor: invalid filename length\n");
		return -1;
	}

	uwsgi_lock(uwsgi.fmon_table_lock);

	if (ushared->files_monitored_cnt < 64) {

		// fill the fmon table, the master will use it to add items to the event queue
		memcpy(ushared->files_monitored[ushared->files_monitored_cnt].filename, filename, strlen(filename));
                ushared->files_monitored[ushared->files_monitored_cnt].registered = 0;
		ushared->files_monitored[ushared->files_monitored_cnt].sig = sig;
	
		ushared->files_monitored_cnt++;
	}
	else {
		uwsgi_log("you can register max 64 file monitors !!!\n");
		uwsgi_unlock(uwsgi.fmon_table_lock);
		return -1;
	}

	uwsgi_unlock(uwsgi.fmon_table_lock);

	return 0;

}

int uwsgi_add_timer(uint8_t sig, int secs) {

	uwsgi_lock(uwsgi.timer_table_lock);

	if (ushared->timers_cnt < 64) {

		// fill the timer table, the master will use it to add items to the event queue
		ushared->timers[ushared->timers_cnt].value = secs;
		ushared->timers[ushared->timers_cnt].registered = 0;
		ushared->timers[ushared->timers_cnt].sig = sig;
		ushared->timers_cnt++;
	}
	else {
		uwsgi_log("you can register max 64 timers !!!\n");
		uwsgi_unlock(uwsgi.timer_table_lock);
		return -1;
	}

	uwsgi_unlock(uwsgi.timer_table_lock);

	return 0;

}

int uwsgi_signal_add_cron(uint8_t sig, int minute, int hour, int day, int month, int week) {

	uwsgi_lock(uwsgi.cron_table_lock);

        if (ushared->cron_cnt < MAX_CRONS) {

                ushared->cron[ushared->cron_cnt].sig = sig;
                ushared->cron[ushared->cron_cnt].minute = minute;
                ushared->cron[ushared->cron_cnt].hour = hour;
                ushared->cron[ushared->cron_cnt].day = day;
                ushared->cron[ushared->cron_cnt].month = month;
                ushared->cron[ushared->cron_cnt].week = week;
                ushared->cron_cnt++;
        }
        else {
                uwsgi_log("you can register max %d cron !!!\n", MAX_CRONS);
                uwsgi_unlock(uwsgi.cron_table_lock);
                return -1;
        }

        uwsgi_unlock(uwsgi.cron_table_lock);

        return 0;
}

int uwsgi_signal_add_rb_timer(uint8_t sig, int secs, int iterations) {

        uwsgi_lock(uwsgi.rb_timer_table_lock);

        if (ushared->rb_timers_cnt < 64) {

                // fill the timer table, the master will use it to add items to the event queue
                ushared->rb_timers[ushared->rb_timers_cnt].value = secs;
                ushared->rb_timers[ushared->rb_timers_cnt].registered = 0;
                ushared->rb_timers[ushared->rb_timers_cnt].iterations = iterations;
                ushared->rb_timers[ushared->rb_timers_cnt].iterations_done = 0;
                ushared->rb_timers[ushared->rb_timers_cnt].sig = sig;
                ushared->rb_timers_cnt++;
        }
        else {
                uwsgi_log("you can register max 64 rb_timers !!!\n");
                uwsgi_unlock(uwsgi.rb_timer_table_lock);
                return -1;
        }

        uwsgi_unlock(uwsgi.rb_timer_table_lock);

        return 0;

}

void create_signal_pipe(int *sigpipe) {

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sigpipe)) {
        	uwsgi_error("socketpair()\n");
        	exit(1);
        }
        uwsgi_socket_nb(sigpipe[0]);
        uwsgi_socket_nb(sigpipe[1]);

	if (uwsgi.signal_bufsize) {
		if (setsockopt(sigpipe[0],  SOL_SOCKET, SO_SNDBUF, &uwsgi.signal_bufsize, sizeof(int))) {
                        	uwsgi_error("setsockopt()");
		}
		if (setsockopt(sigpipe[0],  SOL_SOCKET, SO_RCVBUF, &uwsgi.signal_bufsize, sizeof(int))) {
                        	uwsgi_error("setsockopt()");
		}

		if (setsockopt(sigpipe[1],  SOL_SOCKET, SO_SNDBUF, &uwsgi.signal_bufsize, sizeof(int))) {
                        	uwsgi_error("setsockopt()");
		}
		if (setsockopt(sigpipe[1],  SOL_SOCKET, SO_RCVBUF, &uwsgi.signal_bufsize, sizeof(int))) {
                        	uwsgi_error("setsockopt()");
		}
	}
}

int uwsgi_signal_send(int fd, uint8_t sig) {

	socklen_t so_bufsize_len = sizeof(int);
	int so_bufsize = 0;

	if (write(fd, &sig, 1) != 1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
                	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &so_bufsize, &so_bufsize_len)) {
                        	uwsgi_error("getsockopt()");
                	}
                	uwsgi_log("*** SIGNAL QUEUE IS FULL: buffer size %d bytes (you can tune it with --signal-bufsize) ***\n", so_bufsize);
		}
		else {
			uwsgi_error("uwsgi_signal_send()");
		}
		return -1;
        }
	return 0;

}

void uwsgi_route_signal(uint8_t sig) {

	struct uwsgi_signal_entry *use = &ushared->signal_table[sig];
	int i;

	// send to first available worker
	if (use->receiver[0] == 0 || !strcmp(use->receiver, "worker") || !strcmp(use->receiver, "worker0")) {
		if (uwsgi_signal_send(ushared->worker_signal_pipe[0], sig)) {
			uwsgi_log("could not deliver signal %d to workers pool\n", sig);
		}
	}
	// send to all workers
	else if (!strcmp(use->receiver, "workers")) {
		for(i=1;i<=uwsgi.numproc;i++) {
			if (uwsgi_signal_send(uwsgi.workers[i].signal_pipe[0], sig)) {
				uwsgi_log("could not deliver signal %d to worker %d\n", sig, i);
			}
		}
	}
	// route to specific worker
	else if (!strncmp(use->receiver, "worker", 6)) {
		i = atoi(use->receiver+6);
		if (i > uwsgi.numproc) {
			uwsgi_log("invalid signal target: %s\n", use->receiver);
		}
		if (uwsgi_signal_send(uwsgi.workers[i].signal_pipe[0], sig)) {
                	uwsgi_log("could not deliver signal %d to worker %d\n", sig, i);
                }
	}
	// route to subscribed
	else if (!strcmp(use->receiver, "subscribed")) {
	}
	// route to spooler
#ifdef UWSGI_SPOOLER
	else if (!strcmp(use->receiver, "spooler")) {
		if (ushared->worker_signal_pipe[0] != -1) {
			if (uwsgi_signal_send(ushared->spooler_signal_pipe[0], sig)) {
                        	uwsgi_log("could not deliver signal %d to the spooler\n", sig);
                	}
		}
	}
#endif
	else if (!strcmp(use->receiver, "mules")) {
		for(i=0;i<uwsgi.mules_cnt;i++) {
			if (uwsgi_signal_send(uwsgi.mules[i].signal_pipe[0], sig)) {
                                uwsgi_log("could not deliver signal %d to mule %d\n", sig, i+1);
                        }
		}
	}
	else if (!strncmp(use->receiver, "mule", 4)) {
		i = atoi(use->receiver+4);
		if (i > uwsgi.mules_cnt) {
			uwsgi_log("invalid signal target: %s\n", use->receiver);
		}
		else if (i == 0) {
			if (uwsgi_signal_send(ushared->mule_signal_pipe[0], sig)) {
                                uwsgi_log("could not deliver signal %d to a mule\n", sig);
                        }
		}
		else {
			if (uwsgi_signal_send(uwsgi.mules[i-1].signal_pipe[0], sig)) {
                                uwsgi_log("could not deliver signal %d to mule %d\n", sig, i);
                        }
		}
	}
	else if (!strncmp(use->receiver, "farm_", 5)) {
		char *name = use->receiver+5;
		struct uwsgi_farm *uf = get_farm_by_name(name);
		if (!uf) {
			uwsgi_log("unknown farm: %s\n", name);
			return;
		}
		if (uwsgi_signal_send(uf->signal_pipe[0], sig)) {
                        uwsgi_log("could not deliver signal %d to farm %d (%s)\n", sig, uf->id, uf->name);
                }
	}
	else if (!strncmp(use->receiver, "farm", 4)) {
		i = atoi(use->receiver+4);
		if (i > uwsgi.farms_cnt || i <= 0) {
			uwsgi_log("invalid signal target: %s\n", use->receiver);
		}
		else {
			if (uwsgi_signal_send(uwsgi.farms[i-1].signal_pipe[0], sig)) {
                                uwsgi_log("could not deliver signal %d to farm %d (%s)\n", sig, i, uwsgi.farms[i-1].name);
                        }
		}
	}

	else {
		// unregistered signal, sending it to all the workers
		uwsgi_log("^^^ UNSUPPORTED SIGNAL TARGET: %s ^^^\n", use->receiver);
	}

}

uint8_t uwsgi_signal_wait(int signum) {

        int wait_for_specific_signal = 0;
        uint8_t uwsgi_signal = 0;
        uint8_t received_signal;
        int ret;
        struct pollfd pfd[2];

	if (signum > -1) {
                wait_for_specific_signal = 1;
        }

        pfd[0].fd = uwsgi.signal_socket;
        pfd[0].events = POLLIN;
        pfd[1].fd = uwsgi.my_signal_socket;
        pfd[1].events = POLLIN;
cycle:
        ret = poll(pfd, 2, -1);
        if (ret > 0) {
        	if (pfd[0].revents == POLLIN) {
                          if (read(uwsgi.signal_socket, &received_signal, 1) != 1) {
                          	uwsgi_error("read()");
                          }
                          else {
                          	(void)uwsgi_signal_handler(received_signal);
                                if (wait_for_specific_signal) {
                                	if (received_signal != uwsgi_signal) goto cycle;
                                }
                           }
		}
                if (pfd[1].revents == POLLIN) {
                               if (read(uwsgi.my_signal_socket, &received_signal, 1) != 1) {
                                       uwsgi_error("read()");
                               }
                               else {
                                       (void)uwsgi_signal_handler(received_signal);
                                       if (wait_for_specific_signal) {
                                               if (received_signal != uwsgi_signal) goto cycle;
                                       }
                               }
                        }

                }

        return received_signal;
}

