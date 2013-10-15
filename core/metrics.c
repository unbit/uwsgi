#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

/*

	uWSGI metrics subsystem

	a metric is a node in a tree reachable via a numeric id (OID, in SNMP way) or a simple string:

	uwsgi.worker.1.requests
	uwsgi.custom.foo.bar

	the oid representation:

		1.3.6.1.4.1.35156.17 = iso.org.dod.internet.private.enterprise.unbit.uwsgi
		1.3.6.1.4.1.35156.17.3.1.1 = iso.org.dod.internet.private.enterprise.unbit.uwsgi.worker.1.requests
		1.3.6.1.4.1.35156.17.3.1.1 = iso.org.dod.internet.private.enterprise.unbit.uwsgi.worker.1.requests
		1.3.6.1.4.1.35156.17.3.1.2.1.1 = iso.org.dod.internet.private.enterprise.unbit.uwsgi.worker.1.core.1.requests
		1.3.6.1.4.1.35156.17.4.1 = iso.org.dod.internet.private.enterprise.unbit.uwsgi.system.load_avg
		...

	each metric is a collected value with a specific frequency (a frequency of zero means the value is re-computed every time)
	metrics are meant for numeric values signed 64 bit, but they can be exposed as:

	gauge
	counter
	absolute

	both 32 and 64bit, both signed and unsigned

	metrics are managed by a dedicated thread (in the master) holding a linked list of all the items. For few metrics it is a good (read: simple) approach,
	but you can cache lookups in a uWSGI cache for really big list.

	struct uwsgi_metric *um = uwsgi_register_metric("worker.1.requests", "3.1.1", UWSGI_METRIC_COUNTER, UWSGI_METRIC_PTR, &uwsgi.workers[1].requests, 0, NULL);
	prototype: struct uwsgi_metric *uwsgi_register_metric(char *name, char *oid, uint8_t value_type, uint8_t collect_way, void *ptr, uint32_t freq, void *custom);

	value_type = UWSGI_METRIC_COUNTER/UWSGI_METRIC_GAUGE/UWSGI_METRIC_ABSOLUTE
	collect_way = UWSGI_METRIC_PTR -> get from a pointer / UWSGI_METRIC_FUNC -> get from a func with the prototype int64_t func(struct uwsgi_metric *); / UWSGI_METRIC_FILE -> get the value from a file, ptr is the filename

	when freq is zero the value is recomputed whenever requested, otherwise the metrics thread compute it every time the frequency is elapsed and caches it

	For some metric (or all ?) you may want to hold a value even after a server reload. For such a reason you can specify a directory on wich the server (on startup/restart) will look for
	a file named like the metric and will read the initial value from it. It may look an old-fashioned and quite inefficient way, but it is the most versatile for a sysadmin (allowing him/her
	to even modify the values manually)

	When registering a metric with the same name of an already registered one, the new one will overwrite the previous one. This allows plugins writer to override default behaviours

	Applications are allowed to update metrics (but they cannot register new ones), with simple api funcs:

	uwsgi.metric_set("worker.1.requests", N)
	uwsgi.metric_inc("worker.1.requests", N=1)
	uwsgi.metric_dec("worker.1.requests", N=1)
	uwsgi.metric_mul("worker.1.requests", N=1)
	uwsgi.metric_div("worker.1.requests", N=1)

	and obviously they can get values:

	uwsgi.metric_get("worker.1.requests", no_cache|force=False)
	if the second parameter is True, the value is recomputed (but if it is a metric with a cache, the cache value will not be updated accordingly, this is the job of the metric thread)

	Updating metrics from your app MUST BE ATOMIC, for such a reason a uWSGI rwlock is initialized on startup and used for each operation (simple reading from a metric does not require locking)

	Metrics can be updated from the internal routing subsystem too:

		route-if = equal:${REQUEST_URI};/foobar metricinc:foobar.test 2

	and can be accessed as ${metric[foobar.test]}

	The stats server exports the metrics list in the "metrics" attribute (obviously some info could be redundant)

*/


int64_t uwsgi_metric_get_from_file(char *filename, int split_pos) {
	char buf[4096];
	int64_t ret = 0;
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_error_open(filename);
		return 0;
	}

	ssize_t rlen = read(fd, buf, 4096);
	if (rlen <= 0) goto end;

	char *ptr = buf;
	ssize_t i;
	int pos = 0;
	for(i=0;i<rlen;i++) {
		if (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\r' || buf[i] == 0 || buf[i] == '\n') {
			if (pos == split_pos) goto found;
			pos++;
			ptr = buf + i;
		}
	}

	if (pos == split_pos) goto found;
	goto end;
found:
	ret = strtoll(ptr, NULL, 10);
end:
	close(fd);
	return ret;

}



/*

	allowed chars for metrics name

	0-9
	a-z
	A-Z
	.
	-
	_

*/

static int uwsgi_validate_metric_name(char *buf) {
	size_t len = strlen(buf);
	size_t i;
	for(i=0;i<len;i++) {
		if ( !(
			(buf[i] >= '0' && buf[i] <= '9') ||
			(buf[i] >= 'a' && buf[i] <= 'z') ||
			(buf[i] >= 'A' && buf[i] <= 'Z') ||
			buf[i] == '.' || buf[i] == '-' || buf[i] == '_'
		)) {

			return 0;
		
		}
	}	

	return 1;
}

/*

	allowed chars for metrics oid

	0-9
	.

	oids can be null
*/

static int uwsgi_validate_metric_oid(char *buf) {
	if (!buf) return 1;
        size_t len = strlen(buf);
        size_t i;
        for(i=0;i<len;i++) {
                if ( !(
                        (buf[i] >= '0' && buf[i] <= '9') ||
                        buf[i] == '.'
                )) {
                
                        return 0;
                
                }
        }

        return 1;
}

void uwsgi_metric_append(struct uwsgi_metric *um) {
	struct uwsgi_metric *old_metric=NULL,*metric=uwsgi.metrics;
	while(metric) {
		old_metric = metric;
                metric = metric->next;
	}

	if (old_metric) {
                       old_metric->next = um;
        }
        else {
        	uwsgi.metrics = um;
        }

        uwsgi.metrics_cnt++;
}

struct uwsgi_metric *uwsgi_register_metric_do(char *name, char *oid, uint8_t value_type, uint8_t collect_way, void *ptr, uint32_t freq, void *custom, int do_not_push) {
	struct uwsgi_metric *old_metric=NULL,*metric=uwsgi.metrics;

	if (!uwsgi_validate_metric_name(name)) {
		uwsgi_log("invalid metric name: %s\n", name);
		exit(1);
	}

	if (!uwsgi_validate_metric_oid(oid)) {
		uwsgi_log("invalid metric oid: %s\n", oid);
		exit(1);
	}

	while(metric) {
		if (!strcmp(metric->name, name)) {
			goto found;
		}
		old_metric = metric;
		metric = metric->next;
	}

	metric = uwsgi_calloc(sizeof(struct uwsgi_metric));
	// always make a copy of the name (se we can use stack for building strings)
	metric->name = uwsgi_str(name);
	metric->name_len = strlen(metric->name);

	if (!do_not_push) {
		if (old_metric) {
			old_metric->next = metric;
		}
		else {
			uwsgi.metrics = metric;
		}

		uwsgi.metrics_cnt++;
	}

found:
	metric->oid = oid;
	metric->type = value_type;
	metric->collect_way = collect_way;
	metric->ptr = ptr;
	metric->freq = freq;
	if (!metric->freq) metric->freq = 1;
	metric->custom = custom;

	if (uwsgi.metrics_dir) {
		char *filename = uwsgi_concat3(uwsgi.metrics_dir, "/", name);
		int fd = open(filename, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP);
		if (fd < 0) {
			uwsgi_error_open(filename);
			exit(1);
		}
		// fill the file
		if (lseek(fd, uwsgi.page_size-1, SEEK_SET) < 0) {
			uwsgi_error("uwsgi_register_metric()/lseek()");
			uwsgi_log("unable to register metric: %s\n", name);
			exit(1);
		}
		if (write(fd, "\0", 1) != 1) {
			uwsgi_error("uwsgi_register_metric()/write()");
			uwsgi_log("unable to register metric: %s\n", name);
			exit(1);
		}
		metric->map = mmap(NULL, uwsgi.page_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if (metric->map == MAP_FAILED) {
			uwsgi_error("uwsgi_register_metric()/mmap()");
			uwsgi_log("unable to register metric: %s\n", name);
			exit(1);
		}
		
		// we can now safely close the file descriptor and update the file from memory
		close(fd);
		free(filename);
	}

	return metric;
}

struct uwsgi_metric *uwsgi_register_metric(char *name, char *oid, uint8_t value_type, uint8_t collect_way, void *ptr, uint32_t freq, void *custom) {
	return uwsgi_register_metric_do(name, oid, value_type, collect_way, ptr, freq, custom, 0);
}

struct uwsgi_metric *uwsgi_register_keyval_metric(char *arg) {
	char *m_name = NULL;
	char *m_oid = NULL;
	char *m_type = NULL;
	char *m_collector = NULL;
	char *m_freq = NULL;
	char *m_arg1 = NULL;
	char *m_arg2 = NULL;
	char *m_arg3 = NULL;

	if (uwsgi_kvlist_parse(arg, strlen(arg), ',', '=',
		"name", &m_name,
		"oid", &m_oid,
		"type", &m_type,
		"collector", &m_collector,
		"freq", &m_freq,
		"arg1", &m_arg1,
		"arg2", &m_arg2,
		"arg3", &m_arg3,
		NULL)) {
		uwsgi_log("invalid metric keyval syntax: %s\n", arg);
		exit(1);
	}

	if (!m_name) {
		uwsgi_log("you need to specify a metric name: %s\n", arg);
		exit(1);
	}

	uint8_t type = UWSGI_METRIC_COUNTER;
	uint8_t collector = UWSGI_METRIC_MANUAL;
	uint32_t freq = 0;

	if (m_type) {
		if (!strcmp(m_type, "gauge")) {
			type = UWSGI_METRIC_GAUGE;
		}
		else if (!strcmp(m_type, "absolute")) {
			type = UWSGI_METRIC_ABSOLUTE;
		}
	}

	if (m_collector) {
		if (!strcmp(m_collector, "file")) {
			uwsgi_log("FILE\n");
			collector = UWSGI_METRIC_FILE;	
		}
	}

	if (m_freq) freq = strtoul(m_freq, NULL, 0);

	struct uwsgi_metric* um =  uwsgi_register_metric(m_name, m_oid, type, collector, NULL, freq, NULL);
	free(m_name);
	if (m_oid) free(m_oid);
	if (m_type) free(m_type);
	if (m_collector) free(m_collector);
	if (m_freq) free(m_freq);
	if (m_arg1) free(m_arg1);
	if (m_arg2) free(m_arg2);
	if (m_arg3) free(m_arg3);
	return um;
}

static int64_t uwsgi_metric_sum(struct uwsgi_metric *um) {
	int64_t total = 0;
	struct uwsgi_metric_child *umc = um->children;
	while(umc) {
		struct uwsgi_metric *c = umc->um;
		total += c->initial_value + *c->value;
		umc = umc->next;
	}

	return total;
}

static void *uwsgi_metrics_loop(void *arg) {

	// block signals on this thread
        sigset_t smask;
        sigfillset(&smask);
#ifndef UWSGI_DEBUG
        sigdelset(&smask, SIGSEGV);
#endif
        pthread_sigmask(SIG_BLOCK, &smask, NULL);

	for(;;) {
		struct uwsgi_metric *metric = uwsgi.metrics;
		// every second scan the whole metrics tree
		time_t now = uwsgi_now();
		while(metric) {
			if (!metric->last_update) {
				metric->last_update = now;
			}
			else {
				if (now - metric->last_update < metric->freq) goto next;
			}
			uwsgi_wlock(uwsgi.metrics_lock);
			int64_t value = *metric->value;
			// gather the new value based on the type of collection strategy
			switch(metric->collect_way) {
				case UWSGI_METRIC_PTR:
					*metric->value = *metric->ptr;
					break;
				case UWSGI_METRIC_SUM:
					*metric->value = uwsgi_metric_sum(metric);
					break;
				case UWSGI_METRIC_FILE:
					uwsgi_log("reading from file\n");
					(*metric->value)++;
					break;
				default:
					break;
			};
			int64_t new_value = *metric->value;
			uwsgi_rwunlock(uwsgi.metrics_lock);

			metric->last_update = now;

			if (uwsgi.metrics_dir && metric->map) {
				if (value != new_value) {
					int ret = snprintf(metric->map, uwsgi.page_size, "%lld\n", new_value);
					if (ret > 0) {
						memset(metric->map+ret, 0, 4096-ret);
					}
				}
			}
next:
			metric = metric->next;
		}
		sleep(1);
	}

	return NULL;
	
}

void uwsgi_metrics_start_collector() {
	if (!uwsgi.has_metrics) return;
	pthread_t t;
        pthread_create(&t, NULL, uwsgi_metrics_loop, NULL);
	uwsgi_log("metrics collector thread started\n");
}

struct uwsgi_metric *uwsgi_metric_find_by_name(char *name) {
	struct uwsgi_metric *um = uwsgi.metrics;
	while(um) {
		if (!strcmp(um->name, name)) {
			return um;
		}	
		um = um->next;
	}

	return NULL;
}

struct uwsgi_metric_child *uwsgi_metric_add_child(struct uwsgi_metric *parent, struct uwsgi_metric *child) {
	struct uwsgi_metric_child *umc = parent->children, *old_umc = NULL;
	while(umc) {
		old_umc = umc;
		umc = umc->next;
	}

	umc = uwsgi_calloc(sizeof(struct uwsgi_metric_child));
	umc->um = child;
	if (old_umc) {
		old_umc->next = umc;
	}
	else {
		parent->children = umc;
	}
	return umc;
}

struct uwsgi_metric *uwsgi_metric_find_by_oid(char *oid) {
        struct uwsgi_metric *um = uwsgi.metrics;
        while(um) {
                if (um->oid && !strcmp(um->oid, oid)) {
                        return um;
                }
                um = um->next;
        }

        return NULL;
}

int64_t uwsgi_metric_get(char *name, char *oid) {
	int64_t ret = 0;
	struct uwsgi_metric *um = NULL;
	if (name) {
		um = uwsgi_metric_find_by_name(name);
	}
	else if (oid) {
		um = uwsgi_metric_find_by_oid(oid);
	}
	if (!um) return 0;

	// now (in rlocked context) we get the value from
	// the map
	uwsgi_rlock(uwsgi.metrics_lock);
	ret = um->initial_value+*um->value;
	// unlock
	uwsgi_rwunlock(uwsgi.metrics_lock);
	return ret;
}

#define uwsgi_metric_name(f, n) if (snprintf(buf, 4096, f, n) <= 1) { uwsgi_log("unable to register metric name %s\n", f); exit(1);}
#define uwsgi_metric_name2(f, n, n2) if (snprintf(buf, 4096, f, n, n2) <= 1) { uwsgi_log("unable to register metric name %s\n", f); exit(1);}

#define uwsgi_metric_oid(f, n) if (snprintf(buf2, 4096, f, n) <= 1) { uwsgi_log("unable to register metric oid %s\n", f); exit(1);}
#define uwsgi_metric_oid2(f, n, n2) if (snprintf(buf2, 4096, f, n, n2) <= 1) { uwsgi_log("unable to register metric oid %s\n", f); exit(1);}

void uwsgi_setup_metrics() {

	if (!uwsgi.has_metrics) return;

	char buf[4096];
	char buf2[4096];

	// create the main rwlock
	uwsgi.metrics_lock = uwsgi_rwlock_init("metrics");
	
	// get realpath of the storage dir
	if (uwsgi.metrics_dir) {
		char *dir = uwsgi_expand_path(uwsgi.metrics_dir, strlen(uwsgi.metrics_dir), NULL);
		if (!dir) {
			uwsgi_error("uwsgi_setup_metrics()/uwsgi_expand_path()");
			exit(1);
		}
		uwsgi.metrics_dir = dir;
	}

	// the 'core' namespace

	// parents are appended only at the end
	struct uwsgi_metric *total_tx = uwsgi_register_metric_do("core.total_tx", "5.100", UWSGI_METRIC_COUNTER, UWSGI_METRIC_SUM, NULL, 0, NULL, 1);
	struct uwsgi_metric *total_rss = uwsgi_register_metric_do("core.total_rss", "5.101", UWSGI_METRIC_GAUGE, UWSGI_METRIC_SUM, NULL, 0, NULL, 1);
	struct uwsgi_metric *total_vsz = uwsgi_register_metric_do("core.total_vsz", "5.102", UWSGI_METRIC_GAUGE, UWSGI_METRIC_SUM, NULL, 0, NULL, 1);

	// create the 'worker' namespace
	int i;
	for(i=0;i<=uwsgi.numproc;i++) {

		uwsgi_metric_name("worker.%d.requests", i) ; uwsgi_metric_oid("3.%d.1", i);
		uwsgi_register_metric(buf, buf2, UWSGI_METRIC_COUNTER, UWSGI_METRIC_PTR, &uwsgi.workers[i].requests, 0, NULL);

		uwsgi_metric_name("worker.%d.delta_requests", i) ; uwsgi_metric_oid("3.%d.2", i);
		uwsgi_register_metric(buf, buf2, UWSGI_METRIC_ABSOLUTE, UWSGI_METRIC_PTR, &uwsgi.workers[i].delta_requests, 0, NULL);

		uwsgi_metric_name("worker.%d.avg_response_time", i) ; uwsgi_metric_oid("3.%d.8", i);
		uwsgi_register_metric(buf, buf2, UWSGI_METRIC_GAUGE, UWSGI_METRIC_PTR, &uwsgi.workers[i].avg_response_time, 0, NULL);

		uwsgi_metric_name("worker.%d.total_rx", i) ; uwsgi_metric_oid("3.%d.9", i);
		struct uwsgi_metric *tx = uwsgi_register_metric(buf, buf2, UWSGI_METRIC_COUNTER, UWSGI_METRIC_PTR, &uwsgi.workers[i].tx, 0, NULL);
		uwsgi_metric_add_child(total_tx, tx);

		uwsgi_metric_name("worker.%d.rss_size", i) ; uwsgi_metric_oid("3.%d.11", i);
		struct uwsgi_metric *rss = uwsgi_register_metric(buf, buf2, UWSGI_METRIC_GAUGE, UWSGI_METRIC_PTR, &uwsgi.workers[i].rss_size, 0, NULL);
		uwsgi_metric_add_child(total_rss, rss);

		uwsgi_metric_name("worker.%d.vsz_size", i) ; uwsgi_metric_oid("3.%d.12", i);
                struct uwsgi_metric *vsz = uwsgi_register_metric(buf, buf2, UWSGI_METRIC_GAUGE, UWSGI_METRIC_PTR, &uwsgi.workers[i].vsz_size, 0, NULL);
                uwsgi_metric_add_child(total_vsz, vsz);

		int j;
		for(j=0;j<uwsgi.cores;j++) {
			uwsgi_metric_name2("worker.%d.core.%d.requests", i, j) ; uwsgi_metric_oid2("3.%d.2.%d.1", i, j);
			uwsgi_register_metric(buf, buf2, UWSGI_METRIC_COUNTER, UWSGI_METRIC_PTR, &uwsgi.workers[i].cores[j].requests, 0, NULL);

			uwsgi_metric_name2("worker.%d.core.%d.write_errors", i, j) ; uwsgi_metric_oid2("3.%d.2.%d.3", i, j);
			uwsgi_register_metric(buf, buf2, UWSGI_METRIC_COUNTER, UWSGI_METRIC_PTR, &uwsgi.workers[i].cores[j].write_errors, 0, NULL);

			uwsgi_metric_name2("worker.%d.core.%d.routed_requests", i, j) ; uwsgi_metric_oid2("3.%d.2.%d.4", i, j);
			uwsgi_register_metric(buf, buf2, UWSGI_METRIC_COUNTER, UWSGI_METRIC_PTR, &uwsgi.workers[i].cores[j].routed_requests, 0, NULL);

			uwsgi_metric_name2("worker.%d.core.%d.static_requests", i, j) ; uwsgi_metric_oid2("3.%d.2.%d.5", i, j);
			uwsgi_register_metric(buf, buf2, UWSGI_METRIC_COUNTER, UWSGI_METRIC_PTR, &uwsgi.workers[i].cores[j].static_requests, 0, NULL);

			uwsgi_metric_name2("worker.%d.core.%d.offloaded_requests", i, j) ; uwsgi_metric_oid2("3.%d.2.%d.6", i, j);
			uwsgi_register_metric(buf, buf2, UWSGI_METRIC_COUNTER, UWSGI_METRIC_PTR, &uwsgi.workers[i].cores[j].offloaded_requests, 0, NULL);

			uwsgi_metric_name2("worker.%d.core.%d.exceptions", i, j) ; uwsgi_metric_oid2("3.%d.2.%d.7", i, j);
			uwsgi_register_metric(buf, buf2, UWSGI_METRIC_COUNTER, UWSGI_METRIC_PTR, &uwsgi.workers[i].cores[j].exceptions, 0, NULL);
		}
	}

	// append parents
	uwsgi_metric_append(total_tx);
	uwsgi_metric_append(total_rss);
	uwsgi_metric_append(total_vsz);

	// create custom/user-defined metrics
	struct uwsgi_string_list *usl;
	uwsgi_foreach(usl, uwsgi.additional_metrics) {
		uwsgi_register_keyval_metric(usl->value);
	}

	// allocate shared memory
	int64_t *values = uwsgi_calloc_shared(sizeof(int64_t) * uwsgi.metrics_cnt);
	int pos = 0;

	struct uwsgi_metric *metric = uwsgi.metrics;
	while(metric) {
		metric->value = &values[pos];
		pos++;
		metric = metric->next;
	}

	uwsgi_log("initialized %llu metrics\n", uwsgi.metrics_cnt);

	if (uwsgi.metrics_dir) {
		uwsgi_log("memory allocated for metrics storage: %llu bytes (%llu MB)\n", uwsgi.metrics_cnt * uwsgi.page_size, (uwsgi.metrics_cnt * uwsgi.page_size)/1024/1024);
	}
}
