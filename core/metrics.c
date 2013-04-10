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

struct uwsgi_metric {
	char *name;
	char *oid;

	// pre-computed snmp representation
	char *asn;
	size_t asn_size;

	// ABSOLUTE/COUNTER/GAUGE
	uint8_t type;

	// MANUAL/PTR/FUNC/FILE
	uint8_t collect_way

	// this could be taken from a file storage and must laways be added to value when reporting (default 0)
	int64_t initial_value;
	// the value of the metric (point to a shared memory area)
	*int64_t value;

	// a custom blob you can attach to a metric
	void *custom;

	// the collection frequency
	uint32_t freq;
	time_t last_update;

	// run this function to collect the value
	int64_t (*collector)(struct uwsgi_metric *);
	// take the value from this pointer to a 64bit value
	int64_t *ptr;
	// get the initial value from this file, and store each update in it
	char *filename;

	struct uwsgi_metric *next;
};

struct uwsgi_metric *uwsgi_register_metric(char *name, char *oid, uint8_t value_type, uint8_t collect_way, void *ptr, uint32_t freq, void *custom) {
	struct uwsgi_metric *old_metric=NULL,*metric=uwsgi.metric;

	while(metric) {
		metric = metric->next;
	}
}

void uwsgi_metric_loop() {
	// every second scan the whole metrics tree
	time_t now = uwsgi_now();
}

int64_t uwsgi_metric_get(char *name, char *oid) {
	struct uwsgi_metric *um = NULL;
	if (name) {
		um = uwsgi_metric_find_by_name(name);
	}
	else if (oid) {
		um = uwsgi_metric_find_by_oid(oid);
	}
	if (!um) return 0;

	//
	switch(um->collect_way) {
		case UWSGI_METRIC_MANUAL:
			return um->initial_value+*um->value;
		case UWSGI_METRIC_PTR:
			return um->initial_value+*um->ptr;
		case UWSGI_METRIC_FUNC:
		case UWSGI_METRIC_FILE:
	}
}
