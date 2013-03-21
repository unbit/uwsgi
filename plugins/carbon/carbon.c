#include <uwsgi.h>

/*

	Author:	Łukasz Mierzwa

*/

extern struct uwsgi_server uwsgi;

struct carbon_server_list {
	int healthy;
	int errors;
	char *hostname;
	char *port;
	struct carbon_server_list *next;
};

struct uwsgi_carbon {
	struct uwsgi_string_list *servers;
	struct carbon_server_list *servers_data;
	int freq;
	int timeout;
	char *id;
	int no_workers;
	unsigned long long *last_busyness_values;
	unsigned long long *current_busyness_values;
	int *was_busy;
	int need_retry;
	time_t last_update;
	time_t next_retry;
	int max_retries;
	int retry_delay;
	char *root_node;
	char *hostname_dot_replacement;
	char *hostname;
	int resolve_hostname;
	struct uwsgi_stats_pusher *pusher;
} u_carbon;

static struct uwsgi_option carbon_options[] = {
	{"carbon", required_argument, 0, "push statistics to the specified carbon server", uwsgi_opt_add_string_list, &u_carbon.servers, UWSGI_OPT_MASTER},
	{"carbon-timeout", required_argument, 0, "set carbon connection timeout in seconds (default 3)", uwsgi_opt_set_int, &u_carbon.timeout, 0},
	{"carbon-freq", required_argument, 0, "set carbon push frequency in seconds (default 60)", uwsgi_opt_set_int, &u_carbon.freq, 0},
	{"carbon-id", required_argument, 0, "set carbon id", uwsgi_opt_set_str, &u_carbon.id, 0},
	{"carbon-no-workers", no_argument, 0, "disable generation of single worker metrics", uwsgi_opt_true, &u_carbon.no_workers, 0},
	{"carbon-max-retry", required_argument, 0, "set maximum number of retries in case of connection errors (default 1)", uwsgi_opt_set_int, &u_carbon.max_retries, 0},
	{"carbon-retry-delay", required_argument, 0, "set connection retry delay in seconds (default 7)", uwsgi_opt_set_int, &u_carbon.retry_delay, 0},
	{"carbon-root", required_argument, 0, "set carbon metrics root node (default 'uwsgi')", uwsgi_opt_set_str, &u_carbon.root_node, 0},
	{"carbon-hostname-dots", required_argument, 0, "set char to use as a replacement for dots in hostname (dots are not replaced by default)", uwsgi_opt_set_str, &u_carbon.hostname_dot_replacement, 0},
	{"carbon-name-resolve", no_argument, 0, "allow using hostname as carbon server address (default disabled)", uwsgi_opt_true, &u_carbon.resolve_hostname, 0},
	{"carbon-resolve-names", no_argument, 0, "allow using hostname as carbon server address (default disabled)", uwsgi_opt_true, &u_carbon.resolve_hostname, 0},
	{0, 0, 0, 0, 0, 0, 0},

};

static void carbon_post_init() {

	int i;
	struct uwsgi_string_list *usl = u_carbon.servers;
	if (!uwsgi.sockets) return;
	if (!u_carbon.servers) return;

	while(usl) {
		struct carbon_server_list *u_server = uwsgi_calloc(sizeof(struct carbon_server_list));
		u_server->healthy = 1;
		u_server->errors = 0;

		char *p = strtok(usl->value, ":");
		while (p) {
			if (!u_server->hostname) {
				u_server->hostname = uwsgi_str(p);
			}
			else if (!u_server->port) {
				u_server->port = uwsgi_str(p);
			}
			else break;
			p = strtok(NULL, ":");
		}
		if (!u_server->hostname || !u_server->port) {
			uwsgi_log("[carbon] invalid carbon server address (%s)\n", usl->value);
			usl = usl->next;
			continue;
		}

		if (u_carbon.servers_data) {
			u_server->next = u_carbon.servers_data;
		}
		u_carbon.servers_data = u_server;

		uwsgi_log("[carbon] added server %s:%s\n", u_server->hostname, u_server->port);
		usl = usl->next;
	}

	if (!u_carbon.root_node) u_carbon.root_node = "uwsgi.";
	if (strlen(u_carbon.root_node) && !uwsgi_endswith(u_carbon.root_node, ".")) {
		u_carbon.root_node = uwsgi_concat2(u_carbon.root_node, ".");
	}

	if (u_carbon.freq < 1) u_carbon.freq = 60;
	if (u_carbon.timeout < 1) u_carbon.timeout = 3;
	if (u_carbon.max_retries <= 0) u_carbon.max_retries = 1;
	if (u_carbon.retry_delay <= 0) u_carbon.retry_delay = 7;
	if (!u_carbon.id) {
		u_carbon.id = uwsgi_str(uwsgi.sockets->name);

		for(i=0;i<(int)strlen(u_carbon.id);i++) {
			if (u_carbon.id[i] == '.') u_carbon.id[i] = '_';
		}
	}

	u_carbon.hostname = uwsgi_str(uwsgi.hostname);
	if (u_carbon.hostname_dot_replacement) {
		for(i=0;i<(int)strlen(u_carbon.hostname);i++) {
			if (u_carbon.hostname[i] == '.') u_carbon.hostname[i] = u_carbon.hostname_dot_replacement[0];
		}
	}

	if (!u_carbon.last_busyness_values) {
		u_carbon.last_busyness_values = uwsgi_calloc(sizeof(unsigned long long) * uwsgi.numproc);
	}

	if (!u_carbon.current_busyness_values) {
		u_carbon.current_busyness_values = uwsgi_calloc(sizeof(unsigned long long) * uwsgi.numproc);
	}

	if (!u_carbon.was_busy) {
		u_carbon.was_busy = uwsgi_calloc(sizeof(int) * uwsgi.numproc);
	}

	// set next update to now()+retry_delay, this way we will have first flush just after start
	u_carbon.last_update = uwsgi_now() - u_carbon.freq + u_carbon.retry_delay;

	uwsgi_log("[carbon] carbon plugin started, %is frequency, %is timeout, max retries %i, retry delay %is\n",
		u_carbon.freq, u_carbon.timeout, u_carbon.max_retries, u_carbon.retry_delay);

	struct uwsgi_stats_pusher_instance *uspi = uwsgi_stats_pusher_add(u_carbon.pusher, NULL);
	uspi->freq = u_carbon.freq;
	// no need to generate the json
	uspi->raw=1;
}

static int carbon_write(int fd, char *fmt,...) {
	va_list ap;
	va_start(ap, fmt);

	char ptr[4096];
	int rlen;

	rlen = vsnprintf(ptr, 4096, fmt, ap);
	va_end(ap);

	if (rlen < 1) return 0;

	if (uwsgi_write_nb(fd, ptr, rlen, u_carbon.timeout)) {
		uwsgi_error("carbon_write()");
		return 0;
	}

	return 1;
}

static void carbon_push_stats(int retry_cycle, time_t now) {
	struct carbon_server_list *usl = u_carbon.servers_data;
	if (!u_carbon.servers_data) return;
	int i;
	int fd;
	int wok;
	char *ip;
	char *carbon_address = NULL;

	for (i = 0; i < uwsgi.numproc; i++) {
		u_carbon.current_busyness_values[i] = uwsgi.workers[i+1].running_time - u_carbon.last_busyness_values[i];
		u_carbon.last_busyness_values[i] = uwsgi.workers[i+1].running_time;
		u_carbon.was_busy[i-1] += uwsgi_worker_is_busy(i+1);
	}

	u_carbon.need_retry = 0;
	while(usl) {
		if (retry_cycle && usl->healthy)
			// skip healthy servers during retry cycle
			goto nxt;

		if (retry_cycle && usl->healthy == 0)
			uwsgi_log("[carbon] Retrying failed server at %s (%d)\n", usl->hostname, usl->errors);

		if (!retry_cycle) {
			usl->healthy = 1;
			usl->errors = 0;
		}

		if (u_carbon.resolve_hostname) {
			ip = uwsgi_resolve_ip(usl->hostname);
			if (!ip) {
				uwsgi_log("[carbon] Could not resolve hostname %s\n", usl->hostname);
				goto nxt;
			}
			carbon_address = uwsgi_concat3(ip, ":", usl->port);
		}
		else {
			carbon_address = uwsgi_concat3(usl->hostname, ":", usl->port);
		}
		fd = uwsgi_connect(carbon_address, u_carbon.timeout, 0);
		if (fd < 0) {
			uwsgi_log("[carbon] Could not connect to carbon server at %s\n", carbon_address);
			if (usl->errors < u_carbon.max_retries) {
				u_carbon.need_retry = 1;
				u_carbon.next_retry = uwsgi_now() + u_carbon.retry_delay;
			} else {
				uwsgi_log("[carbon] Maximum number of retries for %s (%d)\n",
					carbon_address, u_carbon.max_retries);
				usl->healthy = 0;
				usl->errors = 0;
			}
			usl->healthy = 0;
			usl->errors++;
			free(carbon_address);
			goto nxt;
		}
		free(carbon_address);
		// put the socket in non-blocking mode
		uwsgi_socket_nb(fd);

		unsigned long long total_rss = 0;
		unsigned long long total_vsz = 0;
		unsigned long long total_tx = 0;
		unsigned long long total_avg_rt = 0; // total avg_rt
		unsigned long long avg_rt = 0; // per worker avg_rt reported to carbon
		unsigned long long active_workers = 0; // number of workers used to calculate total avg_rt
		unsigned long long total_busyness = 0;
		unsigned long long total_avg_busyness = 0;
		unsigned long long worker_busyness = 0;
		unsigned long long total_harakiri = 0;

		wok = carbon_write(fd, "%s%s.%s.requests %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, (unsigned long long) uwsgi.workers[0].requests, (unsigned long long) now);
		if (!wok) goto clear;

		for(i=1;i<=uwsgi.numproc;i++) {
			total_tx += uwsgi.workers[i].tx;
			total_harakiri += uwsgi.workers[i].harakiri_count;

			if (uwsgi.workers[i].cheaped) {
				// also if worker is cheaped than we report its average response time as zero, sending last value might be confusing
				avg_rt = 0;
				worker_busyness = 0;
			}
			else {
				// global average response time is calculated from active/idle workers, cheaped workers are excluded, otherwise it is not accurate
				avg_rt = uwsgi.workers[i].avg_response_time;
				active_workers++;
				total_avg_rt += uwsgi.workers[i].avg_response_time;

				// calculate worker busyness
				if (u_carbon.current_busyness_values[i-1] == 0 && u_carbon.was_busy[i-1]) {
					worker_busyness = 100;
				}
				else {
					worker_busyness = ((u_carbon.current_busyness_values[i-1]*100) / (u_carbon.freq*1000000));
					if (worker_busyness > 100) worker_busyness = 100;
				}
				total_busyness += worker_busyness;
				u_carbon.was_busy[i-1] = 0;

				if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1 || uwsgi.force_get_memusage) {
					// only running workers are counted in total memory stats and if memory-report option is enabled
					total_rss += uwsgi.workers[i].rss_size;
					total_vsz += uwsgi.workers[i].vsz_size;
				}
			}

			//skip per worker metrics when disabled
			if (u_carbon.no_workers) continue;

			wok = carbon_write(fd, "%s%s.%s.worker%d.requests %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, i, (unsigned long long) uwsgi.workers[i].requests, (unsigned long long) now);
			if (!wok) goto clear;

			if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1 || uwsgi.force_get_memusage) {
				wok = carbon_write(fd, "%s%s.%s.worker%d.rss_size %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, i, (unsigned long long) uwsgi.workers[i].rss_size, (unsigned long long) now);
				if (!wok) goto clear;

				wok = carbon_write(fd, "%s%s.%s.worker%d.vsz_size %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, i, (unsigned long long) uwsgi.workers[i].vsz_size, (unsigned long long) now);
				if (!wok) goto clear;
			}

			wok = carbon_write(fd, "%s%s.%s.worker%d.avg_rt %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, i, (unsigned long long) avg_rt, (unsigned long long) now);
			if (!wok) goto clear;

			wok = carbon_write(fd, "%s%s.%s.worker%d.tx %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, i, (unsigned long long) uwsgi.workers[i].tx, (unsigned long long) now);
			if (!wok) goto clear;

			wok = carbon_write(fd, "%s%s.%s.worker%d.busyness %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, i, (unsigned long long) worker_busyness, (unsigned long long) now);
			if (!wok) goto clear;

			wok = carbon_write(fd, "%s%s.%s.worker%d.harakiri %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, i, (unsigned long long) uwsgi.workers[i].harakiri_count, (unsigned long long) now);
			if (!wok) goto clear;

		}

		if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1 || uwsgi.force_get_memusage) {
			wok = carbon_write(fd, "%s%s.%s.rss_size %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, (unsigned long long) total_rss, (unsigned long long) now);
			if (!wok) goto clear;

			wok = carbon_write(fd, "%s%s.%s.vsz_size %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, (unsigned long long) total_vsz, (unsigned long long) now);
			if (!wok) goto clear;
		}

		wok = carbon_write(fd, "%s%s.%s.avg_rt %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, (unsigned long long) (active_workers ? total_avg_rt / active_workers : 0), (unsigned long long) now);
		if (!wok) goto clear;

		wok = carbon_write(fd, "%s%s.%s.tx %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, (unsigned long long) total_tx, (unsigned long long) now);
		if (!wok) goto clear;

		if (active_workers > 0) {
			total_avg_busyness = total_busyness / active_workers;
			if (total_avg_busyness > 100) total_avg_busyness = 100;
		} else {
			total_avg_busyness = 0;
		}
		wok = carbon_write(fd, "%s%s.%s.busyness %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, (unsigned long long) total_avg_busyness, (unsigned long long) now);
		if (!wok) goto clear;

		wok = carbon_write(fd, "%s%s.%s.active_workers %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, (unsigned long long) active_workers, (unsigned long long) now);
		if (!wok) goto clear;

		if (uwsgi.cheaper) {
			wok = carbon_write(fd, "%s%s.%s.cheaped_workers %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, (unsigned long long) uwsgi.numproc - active_workers, (unsigned long long) now);
			if (!wok) goto clear;
		}

		wok = carbon_write(fd, "%s%s.%s.harakiri %llu %llu\n", u_carbon.root_node, u_carbon.hostname, u_carbon.id, (unsigned long long) total_harakiri, (unsigned long long) now);
		if (!wok) goto clear;

		usl->healthy = 1;
		usl->errors = 0;

clear:
		close(fd);
nxt:
		usl = usl->next;
	}
	if (!retry_cycle) u_carbon.last_update = uwsgi_now();
	if (u_carbon.need_retry)
		// timeouts and retries might cause additional lags in carbon cycles, we will adjust timer to fix that
		u_carbon.last_update -= u_carbon.timeout;
}

static void carbon_push(struct uwsgi_stats_pusher_instance *uspi, time_t now, char *json, size_t json_len) {

	if (u_carbon.need_retry && now >= u_carbon.next_retry) {
		carbon_push_stats(1, now);
	}
	else {
		// update
		u_carbon.need_retry = 0;
		carbon_push_stats(0, now);

	}
}

static void carbon_cleanup() {
	carbon_push_stats(0, uwsgi_now());
}

static void carbon_register() {
	u_carbon.pusher = uwsgi_register_stats_pusher("carbon", carbon_push);
}

struct uwsgi_plugin carbon_plugin = {

	.name = "carbon",
	
	.master_cleanup = carbon_cleanup,

	.options = carbon_options,
	.on_load = carbon_register,
	.post_init = carbon_post_init,
};
