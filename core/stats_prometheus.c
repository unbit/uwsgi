#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

/*
 * Prometheus text exposition format generator for uWSGI stats.
 *
 * Metric names and semantics are aligned with timonwong/uwsgi_exporter
 * for drop-in compatibility.
 */

/* Helper: ensure buffer has room for 'needed' more bytes */
static int prom_ensure(struct uwsgi_stats *us, size_t needed) {
	while (us->pos + needed >= us->size) {
		size_t new_size = us->size + us->chunk;
		char *new_base = realloc(us->base, new_size);
		if (!new_base) return -1;
		us->base = new_base;
		us->size = new_size;
	}
	return 0;
}

/* Append raw string to buffer */
static int prom_append(struct uwsgi_stats *us, const char *str) {
	size_t len = strlen(str);
	if (prom_ensure(us, len)) return -1;
	memcpy(us->base + us->pos, str, len);
	us->pos += len;
	return 0;
}

/* Append a formatted string to buffer */
static int prom_printf(struct uwsgi_stats *us, const char *fmt, ...) {
	char buf[4096];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0) return -1;
	if ((size_t)n >= sizeof(buf)) return -1;
	return prom_append(us, buf);
}

/* Escape a label value per Prometheus spec: \ -> \\, " -> \", \n -> \n */
static int prom_append_escaped(struct uwsgi_stats *us, const char *val, size_t len) {
	/* Worst case: every char needs escaping -> 2x */
	if (prom_ensure(us, len * 2 + 1)) return -1;
	size_t i;
	for (i = 0; i < len; i++) {
		char c = val[i];
		if (c == '\\') {
			us->base[us->pos++] = '\\';
			us->base[us->pos++] = '\\';
		} else if (c == '"') {
			us->base[us->pos++] = '\\';
			us->base[us->pos++] = '"';
		} else if (c == '\n') {
			us->base[us->pos++] = '\\';
			us->base[us->pos++] = 'n';
		} else {
			us->base[us->pos++] = c;
		}
	}
	return 0;
}

/* Write HELP + TYPE header for a metric */
static int prom_header(struct uwsgi_stats *us, const char *name, const char *type, const char *help) {
	if (prom_printf(us, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, type)) return -1;
	return 0;
}

/* Write a metric line with no labels: name value\n */
static int prom_metric(struct uwsgi_stats *us, const char *name, const char *type, const char *help, unsigned long long val) {
	if (prom_header(us, name, type, help)) return -1;
	if (prom_printf(us, "%s %llu\n", name, val)) return -1;
	return 0;
}

/* --- Sanitize metric name for Prometheus: must match [a-zA-Z_:][a-zA-Z0-9_:]* --- */
static void sanitize_metric_name(char *dst, const char *src, size_t dst_size) {
	size_t i;
	size_t slen = strlen(src);
	if (dst_size == 0) return;
	if (slen >= dst_size) slen = dst_size - 1;
	for (i = 0; i < slen; i++) {
		char c = src[i];
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '_' || c == ':') {
			dst[i] = c;
		} else {
			dst[i] = '_';
		}
	}
	dst[i] = '\0';
	/* Prometheus names must not start with a digit */
	if (i > 0 && dst[0] >= '0' && dst[0] <= '9') {
		/* Shift right and prepend underscore if there's room */
		if (i + 1 < dst_size) {
			memmove(dst + 1, dst, i + 1);
			dst[0] = '_';
		} else {
			dst[0] = '_';
		}
	}
}


/* Check if this socket name+proto was already seen earlier in the list */
static int prom_socket_is_duplicate(struct uwsgi_socket *head, struct uwsgi_socket *current) {
	const char *cur_proto = current->proto_name ? current->proto_name : "uwsgi";
	struct uwsgi_socket *s = head;
	while (s != current) {
		const char *s_proto = s->proto_name ? s->proto_name : "uwsgi";
		if (!strcmp(s->name, current->name) && !strcmp(s_proto, cur_proto)) {
			return 1;
		}
		s = s->next;
	}
	return 0;
}

struct uwsgi_stats *uwsgi_master_generate_stats_prometheus(void) {
	int i;

	struct uwsgi_stats *us = uwsgi_malloc(sizeof(struct uwsgi_stats));
	us->chunk = 8192;
	us->size = us->chunk;
	us->base = uwsgi_malloc(us->size);
	us->pos = 0;
	us->tabs = 0;
	us->dirty = 0;
	us->minified = 1;

	/* ============================================================
	 * 2.1 Global metrics
	 * ============================================================ */

#ifdef __linux__
	if (prom_metric(us, "uwsgi_listen_queue_length", "gauge",
			"Length of listen queue.",
			(unsigned long long)uwsgi.shared->backlog))
		goto end;
	if (prom_metric(us, "uwsgi_listen_queue_errors", "gauge",
			"Number of listen queue errors.",
			(unsigned long long)uwsgi.shared->backlog_errors))
		goto end;
#endif

	int signal_queue = 0;
	if (ioctl(uwsgi.shared->worker_signal_pipe[1], FIONREAD, &signal_queue)) {
		uwsgi_error("uwsgi_master_generate_stats_prometheus() -> ioctl()\n");
	}
	if (prom_metric(us, "uwsgi_signal_queue_length", "gauge",
			"Length of signal queue.",
			(unsigned long long)signal_queue))
		goto end;

	/* Count workers with id != 0 */
	{
		int worker_count = 0;
		for (i = 0; i < uwsgi.numproc; i++) {
			if (uwsgi.workers[i + 1].id != 0) worker_count++;
		}
		if (prom_metric(us, "uwsgi_workers", "gauge",
				"Number of workers.",
				(unsigned long long)worker_count))
			goto end;
	}

	/* ============================================================
	 * 2.2 Socket metrics (labels: name, proto)
	 * ============================================================ */

	{
		struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;

		/* socket_queue_length */
		if (prom_header(us, "uwsgi_socket_queue_length", "gauge", "Length of socket queue.")) goto end;
		uwsgi_sock = uwsgi.sockets;
		while (uwsgi_sock) {
			if (prom_socket_is_duplicate(uwsgi.sockets, uwsgi_sock)) { uwsgi_sock = uwsgi_sock->next; continue; }
			const char *proto = uwsgi_sock->proto_name ? uwsgi_sock->proto_name : "uwsgi";
			if (prom_printf(us, "uwsgi_socket_queue_length{name=\"")) goto end;
			if (prom_append_escaped(us, uwsgi_sock->name, strlen(uwsgi_sock->name))) goto end;
			if (prom_printf(us, "\",proto=\"%s\"} %llu\n", proto, (unsigned long long)uwsgi_sock->queue)) goto end;
			uwsgi_sock = uwsgi_sock->next;
		}

		/* socket_max_queue_length */
		if (prom_header(us, "uwsgi_socket_max_queue_length", "gauge", "Max length of socket queue.")) goto end;
		uwsgi_sock = uwsgi.sockets;
		while (uwsgi_sock) {
			if (prom_socket_is_duplicate(uwsgi.sockets, uwsgi_sock)) { uwsgi_sock = uwsgi_sock->next; continue; }
			const char *proto = uwsgi_sock->proto_name ? uwsgi_sock->proto_name : "uwsgi";
			if (prom_printf(us, "uwsgi_socket_max_queue_length{name=\"")) goto end;
			if (prom_append_escaped(us, uwsgi_sock->name, strlen(uwsgi_sock->name))) goto end;
			if (prom_printf(us, "\",proto=\"%s\"} %llu\n", proto, (unsigned long long)uwsgi_sock->max_queue)) goto end;
			uwsgi_sock = uwsgi_sock->next;
		}

		/* socket_shared */
		if (prom_header(us, "uwsgi_socket_shared", "gauge", "Is shared socket?")) goto end;
		uwsgi_sock = uwsgi.sockets;
		while (uwsgi_sock) {
			if (prom_socket_is_duplicate(uwsgi.sockets, uwsgi_sock)) { uwsgi_sock = uwsgi_sock->next; continue; }
			const char *proto = uwsgi_sock->proto_name ? uwsgi_sock->proto_name : "uwsgi";
			if (prom_printf(us, "uwsgi_socket_shared{name=\"")) goto end;
			if (prom_append_escaped(us, uwsgi_sock->name, strlen(uwsgi_sock->name))) goto end;
			if (prom_printf(us, "\",proto=\"%s\"} %llu\n", proto, (unsigned long long)uwsgi_sock->shared)) goto end;
			uwsgi_sock = uwsgi_sock->next;
		}

		/* socket_can_offload */
		if (prom_header(us, "uwsgi_socket_can_offload", "gauge", "Can socket offload?")) goto end;
		uwsgi_sock = uwsgi.sockets;
		while (uwsgi_sock) {
			if (prom_socket_is_duplicate(uwsgi.sockets, uwsgi_sock)) { uwsgi_sock = uwsgi_sock->next; continue; }
			const char *proto = uwsgi_sock->proto_name ? uwsgi_sock->proto_name : "uwsgi";
			if (prom_printf(us, "uwsgi_socket_can_offload{name=\"")) goto end;
			if (prom_append_escaped(us, uwsgi_sock->name, strlen(uwsgi_sock->name))) goto end;
			if (prom_printf(us, "\",proto=\"%s\"} %llu\n", proto, (unsigned long long)uwsgi_sock->can_offload)) goto end;
			uwsgi_sock = uwsgi_sock->next;
		}
	}

	/* ============================================================
	 * 2.3 Worker metrics (label: worker_id)
	 * ============================================================ */

#define WORKER_METRIC_HEADER(metric_name, metric_type, metric_help) \
	if (prom_header(us, metric_name, metric_type, metric_help)) goto end;

#define WORKER_METRIC_ULL(metric_name, value) \
	if (prom_printf(us, "%s{worker_id=\"%d\"} %llu\n", metric_name, uwsgi.workers[i+1].id, (unsigned long long)(value))) goto end;

#define WORKER_METRIC_FLOAT(metric_name, value) \
	if (prom_printf(us, "%s{worker_id=\"%d\"} %.6f\n", metric_name, uwsgi.workers[i+1].id, (double)(value))) goto end;

	/* uwsgi_worker_accepting */
	WORKER_METRIC_HEADER("uwsgi_worker_accepting", "gauge", "Is this worker accepting requests?")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_accepting", uwsgi.workers[i+1].accepting)
	}

	/* uwsgi_worker_requests_total */
	WORKER_METRIC_HEADER("uwsgi_worker_requests_total", "counter", "Total number of requests.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_requests_total", uwsgi.workers[i+1].requests)
	}

	/* uwsgi_worker_delta_requests */
	WORKER_METRIC_HEADER("uwsgi_worker_delta_requests", "gauge", "Number of delta requests.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_delta_requests", uwsgi.workers[i+1].delta_requests)
	}

	/* uwsgi_worker_exceptions_total */
	WORKER_METRIC_HEADER("uwsgi_worker_exceptions_total", "counter", "Total number of exceptions.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_exceptions_total", uwsgi_worker_exceptions(i+1))
	}

	/* uwsgi_worker_harakiri_count_total */
	WORKER_METRIC_HEADER("uwsgi_worker_harakiri_count_total", "counter", "Total number of harakiri count.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_harakiri_count_total", uwsgi.workers[i+1].harakiri_count)
	}

	/* uwsgi_worker_signals_total */
	WORKER_METRIC_HEADER("uwsgi_worker_signals_total", "counter", "Total number of signals.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_signals_total", uwsgi.workers[i+1].signals)
	}

	/* uwsgi_worker_signal_queue_length */
	WORKER_METRIC_HEADER("uwsgi_worker_signal_queue_length", "gauge", "Length of signal queue.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		int wq = 0;
		if (ioctl(uwsgi.workers[i+1].signal_pipe[1], FIONREAD, &wq)) {
			uwsgi_error("uwsgi_master_generate_stats_prometheus() -> ioctl()\n");
		}
		WORKER_METRIC_ULL("uwsgi_worker_signal_queue_length", wq)
	}

	/* uwsgi_worker_rss_bytes */
	WORKER_METRIC_HEADER("uwsgi_worker_rss_bytes", "gauge", "Worker RSS bytes.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_rss_bytes", uwsgi.workers[i+1].rss_size)
	}

	/* uwsgi_worker_vsz_bytes */
	WORKER_METRIC_HEADER("uwsgi_worker_vsz_bytes", "gauge", "Worker VSZ bytes.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_vsz_bytes", uwsgi.workers[i+1].vsz_size)
	}

	/* uwsgi_worker_running_time_seconds (microseconds -> seconds) */
	WORKER_METRIC_HEADER("uwsgi_worker_running_time_seconds", "gauge", "Worker running time in seconds.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_FLOAT("uwsgi_worker_running_time_seconds", (double)uwsgi.workers[i+1].running_time / 1000000.0)
	}

	/* uwsgi_worker_last_spawn_time_seconds */
	WORKER_METRIC_HEADER("uwsgi_worker_last_spawn_time_seconds", "gauge", "Last spawn time in seconds since epoch.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_last_spawn_time_seconds", uwsgi.workers[i+1].last_spawn)
	}

	/* uwsgi_worker_average_response_time_seconds (microseconds -> seconds) */
	WORKER_METRIC_HEADER("uwsgi_worker_average_response_time_seconds", "gauge", "Average response time in seconds.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_FLOAT("uwsgi_worker_average_response_time_seconds", (double)uwsgi.workers[i+1].avg_response_time / 1000000.0)
	}

	/* uwsgi_worker_apps */
	WORKER_METRIC_HEADER("uwsgi_worker_apps", "gauge", "Number of apps.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_apps", uwsgi.workers[i+1].apps_cnt)
	}

	/* uwsgi_worker_cores */
	WORKER_METRIC_HEADER("uwsgi_worker_cores", "gauge", "Number of cores.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_cores", uwsgi.cores)
	}

	/* uwsgi_worker_busy */
	WORKER_METRIC_HEADER("uwsgi_worker_busy", "gauge", "Is core in busy?")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		int is_busy = 0;
		/* Match canonical JSON status logic from master_utils.c:
		   cheaped -> "cheap", suspended && !busy -> "pause",
		   sig -> "sig", busy -> "busy", else -> "idle" */
		if (!uwsgi.workers[i+1].cheaped &&
		    !(uwsgi.workers[i+1].suspended && !uwsgi_worker_is_busy(i+1)) &&
		    !uwsgi.workers[i+1].sig &&
		    uwsgi_worker_is_busy(i+1)) is_busy = 1;
		WORKER_METRIC_ULL("uwsgi_worker_busy", is_busy)
	}

	/* uwsgi_worker_idle */
	WORKER_METRIC_HEADER("uwsgi_worker_idle", "gauge", "Is core in idle?")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		int is_idle = 0;
		/* Match canonical JSON status logic: idle only when not cheaped,
		   not paused, not signaled, and not busy */
		if (!uwsgi.workers[i+1].cheaped &&
		    !(uwsgi.workers[i+1].suspended && !uwsgi_worker_is_busy(i+1)) &&
		    !uwsgi.workers[i+1].sig &&
		    !uwsgi_worker_is_busy(i+1)) is_idle = 1;
		WORKER_METRIC_ULL("uwsgi_worker_idle", is_idle)
	}

	/* uwsgi_worker_cheap */
	WORKER_METRIC_HEADER("uwsgi_worker_cheap", "gauge", "Is core in cheap mode?")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_cheap", uwsgi.workers[i+1].cheaped ? 1 : 0)
	}

	/* uwsgi_worker_respawn_count_total */
	WORKER_METRIC_HEADER("uwsgi_worker_respawn_count_total", "counter", "Total number of respawn count.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_respawn_count_total", uwsgi.workers[i+1].respawn_count)
	}

	/* uwsgi_worker_transmitted_bytes_total */
	WORKER_METRIC_HEADER("uwsgi_worker_transmitted_bytes_total", "counter", "Worker transmitted bytes.")
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		WORKER_METRIC_ULL("uwsgi_worker_transmitted_bytes_total", uwsgi.workers[i+1].tx)
	}

#undef WORKER_METRIC_HEADER
#undef WORKER_METRIC_ULL
#undef WORKER_METRIC_FLOAT

	/* ============================================================
	 * 2.4 Worker app metrics (labels: worker_id, app_id, mountpoint, chdir)
	 * ============================================================ */

	/* uwsgi_worker_app_startup_time_seconds */
	if (prom_header(us, "uwsgi_worker_app_startup_time_seconds", "gauge", "How long this app took to start.")) goto end;
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		int j;
		for (j = 0; j < uwsgi.workers[i+1].apps_cnt; j++) {
			struct uwsgi_app *ua = &uwsgi.workers[i+1].apps[j];
			if (prom_printf(us, "uwsgi_worker_app_startup_time_seconds{worker_id=\"%d\",app_id=\"%d\",mountpoint=\"",
					uwsgi.workers[i+1].id, j)) goto end;
			if (prom_append_escaped(us, ua->mountpoint, ua->mountpoint_len)) goto end;
			if (prom_append(us, "\",chdir=\"")) goto end;
			if (prom_append_escaped(us, ua->chdir, strlen(ua->chdir))) goto end;
			if (prom_printf(us, "\"} %llu\n", (unsigned long long)ua->startup_time)) goto end;
		}
	}

	/* uwsgi_worker_app_requests_total */
	if (prom_header(us, "uwsgi_worker_app_requests_total", "counter", "Total number of requests.")) goto end;
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		int j;
		for (j = 0; j < uwsgi.workers[i+1].apps_cnt; j++) {
			struct uwsgi_app *ua = &uwsgi.workers[i+1].apps[j];
			if (prom_printf(us, "uwsgi_worker_app_requests_total{worker_id=\"%d\",app_id=\"%d\",mountpoint=\"",
					uwsgi.workers[i+1].id, j)) goto end;
			if (prom_append_escaped(us, ua->mountpoint, ua->mountpoint_len)) goto end;
			if (prom_append(us, "\",chdir=\"")) goto end;
			if (prom_append_escaped(us, ua->chdir, strlen(ua->chdir))) goto end;
			if (prom_printf(us, "\"} %llu\n", (unsigned long long)ua->requests)) goto end;
		}
	}

	/* uwsgi_worker_app_exceptions_total */
	if (prom_header(us, "uwsgi_worker_app_exceptions_total", "counter", "Total number of exceptions.")) goto end;
	for (i = 0; i < uwsgi.numproc; i++) {
		if (uwsgi.workers[i+1].id == 0) continue;
		int j;
		for (j = 0; j < uwsgi.workers[i+1].apps_cnt; j++) {
			struct uwsgi_app *ua = &uwsgi.workers[i+1].apps[j];
			if (prom_printf(us, "uwsgi_worker_app_exceptions_total{worker_id=\"%d\",app_id=\"%d\",mountpoint=\"",
					uwsgi.workers[i+1].id, j)) goto end;
			if (prom_append_escaped(us, ua->mountpoint, ua->mountpoint_len)) goto end;
			if (prom_append(us, "\",chdir=\"")) goto end;
			if (prom_append_escaped(us, ua->chdir, strlen(ua->chdir))) goto end;
			if (prom_printf(us, "\"} %llu\n", (unsigned long long)ua->exceptions)) goto end;
		}
	}

	/* ============================================================
	 * 2.5 Worker core metrics (labels: worker_id, core_id)
	 *     Skip if --stats-no-cores
	 * ============================================================ */

	if (!uwsgi.stats_no_cores) {

		/* uwsgi_worker_core_busy */
		if (prom_header(us, "uwsgi_worker_core_busy", "gauge", "Is core busy.")) goto end;
		for (i = 0; i < uwsgi.numproc; i++) {
			if (uwsgi.workers[i+1].id == 0) continue;
			int j;
			for (j = 0; j < uwsgi.cores; j++) {
				struct uwsgi_core *uc = &uwsgi.workers[i+1].cores[j];
				if (prom_printf(us, "uwsgi_worker_core_busy{worker_id=\"%d\",core_id=\"%d\"} %llu\n",
						uwsgi.workers[i+1].id, j, (unsigned long long)uc->in_request)) goto end;
			}
		}

		/* uwsgi_worker_core_requests_total */
		if (prom_header(us, "uwsgi_worker_core_requests_total", "counter", "Total number of requests.")) goto end;
		for (i = 0; i < uwsgi.numproc; i++) {
			if (uwsgi.workers[i+1].id == 0) continue;
			int j;
			for (j = 0; j < uwsgi.cores; j++) {
				struct uwsgi_core *uc = &uwsgi.workers[i+1].cores[j];
				if (prom_printf(us, "uwsgi_worker_core_requests_total{worker_id=\"%d\",core_id=\"%d\"} %llu\n",
						uwsgi.workers[i+1].id, j, (unsigned long long)uc->requests)) goto end;
			}
		}

		/* uwsgi_worker_core_static_requests_total */
		if (prom_header(us, "uwsgi_worker_core_static_requests_total", "counter", "Total number of static requests.")) goto end;
		for (i = 0; i < uwsgi.numproc; i++) {
			if (uwsgi.workers[i+1].id == 0) continue;
			int j;
			for (j = 0; j < uwsgi.cores; j++) {
				struct uwsgi_core *uc = &uwsgi.workers[i+1].cores[j];
				if (prom_printf(us, "uwsgi_worker_core_static_requests_total{worker_id=\"%d\",core_id=\"%d\"} %llu\n",
						uwsgi.workers[i+1].id, j, (unsigned long long)uc->static_requests)) goto end;
			}
		}

		/* uwsgi_worker_core_routed_requests_total */
		if (prom_header(us, "uwsgi_worker_core_routed_requests_total", "counter", "Total number of routed requests.")) goto end;
		for (i = 0; i < uwsgi.numproc; i++) {
			if (uwsgi.workers[i+1].id == 0) continue;
			int j;
			for (j = 0; j < uwsgi.cores; j++) {
				struct uwsgi_core *uc = &uwsgi.workers[i+1].cores[j];
				if (prom_printf(us, "uwsgi_worker_core_routed_requests_total{worker_id=\"%d\",core_id=\"%d\"} %llu\n",
						uwsgi.workers[i+1].id, j, (unsigned long long)uc->routed_requests)) goto end;
			}
		}

		/* uwsgi_worker_core_offloaded_requests_total */
		if (prom_header(us, "uwsgi_worker_core_offloaded_requests_total", "counter", "Total number of offloaded requests.")) goto end;
		for (i = 0; i < uwsgi.numproc; i++) {
			if (uwsgi.workers[i+1].id == 0) continue;
			int j;
			for (j = 0; j < uwsgi.cores; j++) {
				struct uwsgi_core *uc = &uwsgi.workers[i+1].cores[j];
				if (prom_printf(us, "uwsgi_worker_core_offloaded_requests_total{worker_id=\"%d\",core_id=\"%d\"} %llu\n",
						uwsgi.workers[i+1].id, j, (unsigned long long)uc->offloaded_requests)) goto end;
			}
		}

		/* uwsgi_worker_core_write_errors_total */
		if (prom_header(us, "uwsgi_worker_core_write_errors_total", "counter", "Total number of write errors.")) goto end;
		for (i = 0; i < uwsgi.numproc; i++) {
			if (uwsgi.workers[i+1].id == 0) continue;
			int j;
			for (j = 0; j < uwsgi.cores; j++) {
				struct uwsgi_core *uc = &uwsgi.workers[i+1].cores[j];
				if (prom_printf(us, "uwsgi_worker_core_write_errors_total{worker_id=\"%d\",core_id=\"%d\"} %llu\n",
						uwsgi.workers[i+1].id, j, (unsigned long long)uc->write_errors)) goto end;
			}
		}

		/* uwsgi_worker_core_read_errors_total */
		if (prom_header(us, "uwsgi_worker_core_read_errors_total", "counter", "Total number of read errors.")) goto end;
		for (i = 0; i < uwsgi.numproc; i++) {
			if (uwsgi.workers[i+1].id == 0) continue;
			int j;
			for (j = 0; j < uwsgi.cores; j++) {
				struct uwsgi_core *uc = &uwsgi.workers[i+1].cores[j];
				if (prom_printf(us, "uwsgi_worker_core_read_errors_total{worker_id=\"%d\",core_id=\"%d\"} %llu\n",
						uwsgi.workers[i+1].id, j, (unsigned long long)uc->read_errors)) goto end;
			}
		}
	}

	/* ============================================================
	 * 2.6 Cache metrics (label: name)
	 * ============================================================ */

	if (uwsgi.caches) {
		struct uwsgi_cache *uc;

		/* uwsgi_cache_hits */
		if (prom_header(us, "uwsgi_cache_hits", "counter", "Total number of hits.")) goto end;
		uc = uwsgi.caches;
		while (uc) {
			const char *name = uc->name ? uc->name : "default";
			if (prom_printf(us, "uwsgi_cache_hits{name=\"")) goto end;
			if (prom_append_escaped(us, name, strlen(name))) goto end;
			if (prom_printf(us, "\"} %llu\n", (unsigned long long)uc->hits)) goto end;
			uc = uc->next;
		}

		/* uwsgi_cache_misses */
		if (prom_header(us, "uwsgi_cache_misses", "counter", "Total number of misses.")) goto end;
		uc = uwsgi.caches;
		while (uc) {
			const char *name = uc->name ? uc->name : "default";
			if (prom_printf(us, "uwsgi_cache_misses{name=\"")) goto end;
			if (prom_append_escaped(us, name, strlen(name))) goto end;
			if (prom_printf(us, "\"} %llu\n", (unsigned long long)uc->miss)) goto end;
			uc = uc->next;
		}

		/* uwsgi_cache_full */
		if (prom_header(us, "uwsgi_cache_full", "counter", "Total number of times cache full was hit.")) goto end;
		uc = uwsgi.caches;
		while (uc) {
			const char *name = uc->name ? uc->name : "default";
			if (prom_printf(us, "uwsgi_cache_full{name=\"")) goto end;
			if (prom_append_escaped(us, name, strlen(name))) goto end;
			if (prom_printf(us, "\"} %llu\n", (unsigned long long)uc->full)) goto end;
			uc = uc->next;
		}

		/* uwsgi_cache_items */
		if (prom_header(us, "uwsgi_cache_items", "gauge", "Items in cache.")) goto end;
		uc = uwsgi.caches;
		while (uc) {
			const char *name = uc->name ? uc->name : "default";
			if (prom_printf(us, "uwsgi_cache_items{name=\"")) goto end;
			if (prom_append_escaped(us, name, strlen(name))) goto end;
			if (prom_printf(us, "\"} %llu\n", (unsigned long long)uc->n_items)) goto end;
			uc = uc->next;
		}

		/* uwsgi_cache_max_items */
		if (prom_header(us, "uwsgi_cache_max_items", "gauge", "Max items for this cache.")) goto end;
		uc = uwsgi.caches;
		while (uc) {
			const char *name = uc->name ? uc->name : "default";
			if (prom_printf(us, "uwsgi_cache_max_items{name=\"")) goto end;
			if (prom_append_escaped(us, name, strlen(name))) goto end;
			if (prom_printf(us, "\"} %llu\n", (unsigned long long)uc->max_items)) goto end;
			uc = uc->next;
		}
	}

	/* ============================================================
	 * 2.7 Custom metrics from uWSGI metrics subsystem
	 * ============================================================ */

	if (uwsgi.has_metrics && !uwsgi.stats_no_metrics) {
		uwsgi_rlock(uwsgi.metrics_lock);

		/* First pass: count metrics to size the seen-names array */
		int num_custom = 0;
		struct uwsgi_metric *um = uwsgi.metrics;
		while (um) {
			if (um->type != UWSGI_METRIC_ALIAS) num_custom++;
			um = um->next;
		}

		/* Track emitted sanitized names to detect collisions from
		   sanitization (e.g. "foo.bar" and "foo_bar" both become
		   "uwsgi_custom_foo_bar"). Skip duplicates to avoid invalid
		   Prometheus output with repeated family declarations. */
		char **seen_names = NULL;
		int seen_count = 0;
		if (num_custom > 0) {
			seen_names = (char **)malloc(sizeof(char *) * num_custom);
			if (!seen_names) {
				uwsgi_rwunlock(uwsgi.metrics_lock);
				goto end;
			}
		}

		um = uwsgi.metrics;
		while (um) {
			/* Skip aliases to avoid duplicates */
			if (um->type == UWSGI_METRIC_ALIAS) {
				um = um->next;
				continue;
			}

			int64_t um_val = *um->value;

			/* Sanitize metric name */
			char sanitized[256];
			char prefixed[512];
			sanitize_metric_name(sanitized, um->name, sizeof(sanitized));
			int plen = snprintf(prefixed, sizeof(prefixed), "uwsgi_custom_%s", sanitized);
			if (plen < 0 || (size_t)plen >= sizeof(prefixed)) {
				um = um->next;
				continue; /* skip metrics with names too long to prefix */
			}

			/* Check for sanitized name collision */
			int is_dup = 0;
			for (int si = 0; si < seen_count; si++) {
				if (!strcmp(seen_names[si], prefixed)) {
					is_dup = 1;
					break;
				}
			}
			if (is_dup) {
				um = um->next;
				continue;
			}
			seen_names[seen_count] = strdup(prefixed);
			if (!seen_names[seen_count]) {
				um = um->next;
				continue; /* skip metric if we cannot track its name */
			}
			seen_count++;

			const char *prom_type;
			switch (um->type) {
				case UWSGI_METRIC_COUNTER:
					prom_type = "counter";
					break;
				case UWSGI_METRIC_GAUGE:
					prom_type = "gauge";
					break;
				case UWSGI_METRIC_ABSOLUTE:
					prom_type = "gauge";
					break;
				default:
					prom_type = "gauge";
					break;
			}

			/* Truncate help text to avoid overflowing prom_printf's
			   4096-byte buffer when metric names are very long */
			char help_buf[1024];
			size_t name_len = strlen(um->name);
			if (name_len >= sizeof(help_buf)) {
				memcpy(help_buf, um->name, sizeof(help_buf) - 4);
				help_buf[sizeof(help_buf) - 4] = '.';
				help_buf[sizeof(help_buf) - 3] = '.';
				help_buf[sizeof(help_buf) - 2] = '.';
				help_buf[sizeof(help_buf) - 1] = '\0';
			} else {
				memcpy(help_buf, um->name, name_len + 1);
			}

			if (prom_header(us, prefixed, prom_type, help_buf)) {
				for (int si = 0; si < seen_count; si++) free(seen_names[si]);
				free(seen_names);
				uwsgi_rwunlock(uwsgi.metrics_lock);
				goto end;
			}

			if (prom_printf(us, "%s %lld\n", prefixed, (long long)um_val)) {
				for (int si = 0; si < seen_count; si++) free(seen_names[si]);
				free(seen_names);
				uwsgi_rwunlock(uwsgi.metrics_lock);
				goto end;
			}

			um = um->next;
		}
		for (int si = 0; si < seen_count; si++) free(seen_names[si]);
		free(seen_names);
		uwsgi_rwunlock(uwsgi.metrics_lock);
	}

	/* Null-terminate the buffer */
	if (prom_ensure(us, 1)) goto end;
	us->base[us->pos] = '\0';

	return us;

end:
	free(us->base);
	free(us);
	return NULL;
}
