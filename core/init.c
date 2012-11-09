#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void uwsgi_init_default() {

	uwsgi.cpus = 1;

	uwsgi.backtrace_depth = 64;
	uwsgi.max_apps = 64;

	uwsgi.master_queue = -1;

	uwsgi.signal_socket = -1;
	uwsgi.my_signal_socket = -1;
	uwsgi.cache_server_fd = -1;
	uwsgi.stats_fd = -1;

	uwsgi.stats_pusher_default_freq = 3;

	uwsgi.original_log_fd = -1;

	uwsgi.emperor_fd_config = -1;
	// default emperor scan frequency
	uwsgi.emperor_freq = 3;
	uwsgi.emperor_throttle = 1000;
	uwsgi.emperor_heartbeat = 30;
	// max 3 minutes throttling
	uwsgi.emperor_max_throttle = 1000 * 180;
	uwsgi.emperor_pid = -1;

	uwsgi.subscribe_freq = 10;
	uwsgi.subscription_tolerance = 17;

	uwsgi.cluster_fd = -1;
	uwsgi.cores = 1;
	uwsgi.threads = 1;

	uwsgi.offload_threads_events = 64;

	uwsgi.default_app = -1;

	uwsgi.buffer_size = 4096;
	uwsgi.numproc = 1;

	uwsgi.forkbomb_delay = 2;

	uwsgi.async = 1;
	uwsgi.listen_queue = 100;

	uwsgi.cheaper_overload = 3;

	uwsgi.log_master_bufsize = 8192;

	uwsgi.max_vars = MAX_VARS;
	uwsgi.vec_size = 4 + 1 + (4 * MAX_VARS);

	uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT] = 4;
	uwsgi.shared->options[UWSGI_OPTION_LOGGING] = 1;

#ifdef UWSGI_SPOOLER
	uwsgi.shared->spooler_frequency = 30;

	uwsgi.shared->spooler_signal_pipe[0] = -1;
	uwsgi.shared->spooler_signal_pipe[1] = -1;
#endif
	uwsgi.shared->mule_signal_pipe[0] = -1;
	uwsgi.shared->mule_signal_pipe[1] = -1;

	uwsgi.shared->mule_queue_pipe[0] = -1;
	uwsgi.shared->mule_queue_pipe[1] = -1;

	uwsgi.shared->worker_log_pipe[0] = -1;
	uwsgi.shared->worker_log_pipe[1] = -1;

#ifdef UWSGI_SSL
	// 1 day of tolerance
	uwsgi.subscriptions_sign_check_tolerance = 3600 * 24;
#endif

#ifdef UWSGI_ALARM
	uwsgi.alarm_freq = 3;
#endif


#ifdef UWSGI_MULTICAST
	uwsgi.multicast_ttl = 1;
#endif

}

void uwsgi_setup_reload() {

	char env_reload_buf[11];

	char *env_reloads = getenv("UWSGI_RELOADS");
	if (env_reloads) {
		//convert env value to int
		uwsgi.reloads = atoi(env_reloads);
		uwsgi.reloads++;
		//convert reloads to string
		int rlen = snprintf(env_reload_buf, 10, "%u", uwsgi.reloads);
		if (rlen > 0) {
			env_reload_buf[rlen] = 0;
			if (setenv("UWSGI_RELOADS", env_reload_buf, 1)) {
				uwsgi_error("setenv()");
			}
		}
		uwsgi.is_a_reload = 1;
	}
	else {
		if (setenv("UWSGI_RELOADS", "0", 1)) {
			uwsgi_error("setenv()");
		}
	}

}

void uwsgi_autoload_plugins_by_name(char *argv_zero) {

	char *plugins_requested = NULL;

	char *original_proc_name = getenv("UWSGI_ORIGINAL_PROC_NAME");
	if (!original_proc_name) {
		// here we use argv[0];
		original_proc_name = argv_zero;
		setenv("UWSGI_ORIGINAL_PROC_NAME", original_proc_name, 1);
	}
	char *p = strrchr(original_proc_name, '/');
	if (p == NULL)
		p = original_proc_name;
	p = strstr(p, "uwsgi_");
	if (p != NULL) {
		plugins_requested = strtok(uwsgi_str(p + 6), "_");
		while (plugins_requested) {
			uwsgi_log("[uwsgi] implicit plugin requested %s\n", plugins_requested);
			uwsgi_load_plugin(-1, plugins_requested, NULL);
			plugins_requested = strtok(NULL, "_");
		}
	}

	plugins_requested = getenv("UWSGI_PLUGINS");
	if (plugins_requested) {
		plugins_requested = uwsgi_concat2(plugins_requested, "");
		char *p = strtok(plugins_requested, ",");
		while (p != NULL) {
			uwsgi_load_plugin(-1, p, NULL);
			p = strtok(NULL, ",");
		}
	}

}

void uwsgi_commandline_config() {
	int i;

	uwsgi.option_index = -1;

	char *optname;
	while ((i = getopt_long(uwsgi.argc, uwsgi.argv, uwsgi.short_options, uwsgi.long_options, &uwsgi.option_index)) != -1) {

		if (i == '?') {
			uwsgi_log("getopt_long() error\n");
			exit(1);
		}

		if (uwsgi.option_index > -1) {
			optname = (char *) uwsgi.long_options[uwsgi.option_index].name;
		}
		else {
			optname = uwsgi_get_optname_by_index(i);
		}
		if (!optname) {
			uwsgi_log("unable to parse command line options\n");
			exit(1);
		}
		uwsgi.option_index = -1;
		add_exported_option(optname, optarg, 0);
	}


#ifdef UWSGI_DEBUG
	uwsgi_log("optind:%d argc:%d\n", optind, uwsgi.argc);
#endif

	if (optind < uwsgi.argc) {
		for (i = optind; i < uwsgi.argc; i++) {
			char *lazy = uwsgi.argv[i];
			if (lazy[0] != '[') {
				uwsgi_opt_load(NULL, lazy, NULL);
				// manage magic mountpoint
				int magic = 0;
				int j;
				for (j = 0; j < uwsgi.gp_cnt; j++) {
					if (uwsgi.gp[j]->magic) {
						if (uwsgi.gp[j]->magic(NULL, lazy)) {
							magic = 1;
							break;
						}
					}
				}
				if (!magic) {
					for (j = 0; j < 256; j++) {
						if (uwsgi.p[j]->magic) {
							if (uwsgi.p[j]->magic(NULL, lazy)) {
								magic = 1;
								break;
							}
						}
					}
				}
			}
		}
	}

}

void uwsgi_setup_workers() {
	int i, j;
	// allocate shared memory for workers + master
	uwsgi.workers = (struct uwsgi_worker *) uwsgi_calloc_shared(sizeof(struct uwsgi_worker) * (uwsgi.numproc + 1 + uwsgi.grunt));

	for (i = 0; i <= uwsgi.numproc; i++) {
		// allocate memory for apps
		uwsgi.workers[i].apps = (struct uwsgi_app *) uwsgi_calloc_shared(sizeof(struct uwsgi_app) * uwsgi.max_apps);

		// allocate memory for cores
		uwsgi.workers[i].cores = (struct uwsgi_core *) uwsgi_calloc_shared(sizeof(struct uwsgi_core) * uwsgi.cores);

		// this is a trick for avoiding too much memory areas
		void *ts = uwsgi_calloc_shared(sizeof(void *) * uwsgi.max_apps * uwsgi.cores);
		void *buffers = uwsgi_malloc_shared(uwsgi.buffer_size * uwsgi.cores);
		void *hvec = uwsgi_malloc_shared(sizeof(struct iovec) * uwsgi.vec_size * uwsgi.cores);
		void *post_buf = NULL;
		if (uwsgi.post_buffering > 0)
			post_buf = uwsgi_malloc_shared(uwsgi.post_buffering_bufsize * uwsgi.cores);


		for (j = 0; j < uwsgi.cores; j++) {
			// allocate shared memory for thread states (required for some language, like python)
			uwsgi.workers[i].cores[j].ts = ts + ((sizeof(void *) * uwsgi.max_apps) * j);
			// raw per-request buffer
			uwsgi.workers[i].cores[j].buffer = buffers + (uwsgi.buffer_size * j);
			// iovec for uwsgi vars
			uwsgi.workers[i].cores[j].hvec = hvec + ((sizeof(struct iovec) * uwsgi.vec_size) * j);
			if (post_buf)
				uwsgi.workers[i].cores[j].post_buf = post_buf + (uwsgi.post_buffering_bufsize * j);
		}

		// master does not need to following steps...
		if (i == 0)
			continue;
		uwsgi.workers[i].signal_pipe[0] = -1;
		uwsgi.workers[i].signal_pipe[1] = -1;
		snprintf(uwsgi.workers[i].name, 0xff, "uWSGI worker %d", i);
		snprintf(uwsgi.workers[i].snapshot_name, 0xff, "uWSGI snapshot %d", i);
	}

	uint64_t total_memory = (sizeof(struct uwsgi_app) * uwsgi.max_apps) + (sizeof(struct uwsgi_core) * uwsgi.cores) + (sizeof(void *) * uwsgi.max_apps * uwsgi.cores) + (uwsgi.buffer_size * uwsgi.cores) + (sizeof(struct iovec) * uwsgi.vec_size * uwsgi.cores);
	if (uwsgi.post_buffering > 0) {
		total_memory += (uwsgi.post_buffering_bufsize * uwsgi.cores);
	}

	total_memory *= (uwsgi.numproc + uwsgi.master_process);
	uwsgi_log("mapped %llu bytes (%llu KB) for %d cores\n", total_memory, total_memory / 1024, uwsgi.cores * uwsgi.numproc);

}

pid_t uwsgi_daemonize2() {
	if (uwsgi.has_emperor) {
		logto(uwsgi.daemonize2);
	}
	else {
		if (!uwsgi.is_a_reload) {
			uwsgi_log("*** daemonizing uWSGI ***\n");
			daemonize(uwsgi.daemonize2);
		}
		else if (uwsgi.log_reopen) {
			logto(uwsgi.daemonize2);
		}
	}
	uwsgi.mypid = getpid();

	uwsgi.workers[0].pid = uwsgi.mypid;

	if (uwsgi.pidfile && !uwsgi.is_a_reload) {
		uwsgi_write_pidfile(uwsgi.pidfile);
	}

	if (uwsgi.pidfile2 && !uwsgi.is_a_reload) {
		uwsgi_write_pidfile(uwsgi.pidfile2);
	}

	return uwsgi.mypid;
}
