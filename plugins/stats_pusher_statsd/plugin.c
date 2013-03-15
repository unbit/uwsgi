#include <uwsgi.h>

/*

this is a stats pusher plugin for the statsd server:

--stats-push statsd:address[,prefix]

example:

--stats-push statsd:127.0.0.1:8125,myinstance

it is pretty minimal, but will be extended after the 2.0 metric subsystem will be released

*/

extern struct uwsgi_server uwsgi;

// configuration of a statsd node
struct statsd_node {
	int fd;
	union uwsgi_sockaddr addr;
	socklen_t addr_len;
	char *prefix;
	uint16_t prefix_len;
};

static int statsd_send_worker_gauge(struct uwsgi_buffer *ub, struct uwsgi_stats_pusher_instance *uspi, int wid, char *metric, uint16_t metric_len, int64_t value) {
	struct statsd_node *sn = (struct statsd_node *) uspi->data;
	// reset the buffer
	ub->pos = 0;
	if (uwsgi_buffer_append(ub, sn->prefix, sn->prefix_len)) return -1;	
	if (uwsgi_buffer_append(ub, ".worker", 7)) return -1;	
	if (uwsgi_buffer_num64(ub, wid)) return -1;	
	if (uwsgi_buffer_append(ub, ".", 1)) return -1;	
	if (uwsgi_buffer_append(ub, metric, metric_len)) return -1;	
	if (uwsgi_buffer_append(ub, ":", 1)) return -1;	
	if (uwsgi_buffer_num64(ub, value)) return -1;	
	if (uwsgi_buffer_append(ub, "|g", 2)) return -1;	

	if (sendto(sn->fd, ub->buf, ub->pos, 0, (struct sockaddr *) &sn->addr.sa_in, sn->addr_len) < 0) {
		uwsgi_error("stats_pusher_statsd()/sendto()");
	}
	return 0;
}

static int statsd_send_core_gauge(struct uwsgi_buffer *ub, struct uwsgi_stats_pusher_instance *uspi, int wid, int coreid, char *metric, uint16_t metric_len, int64_t value) {
	struct statsd_node *sn = (struct statsd_node *) uspi->data;
        // reset the buffer
        ub->pos = 0;
        if (uwsgi_buffer_append(ub, sn->prefix, sn->prefix_len)) return -1;
        if (uwsgi_buffer_append(ub, ".worker", 7)) return -1;
        if (uwsgi_buffer_num64(ub, wid)) return -1;
        if (uwsgi_buffer_append(ub, ".core", 5)) return -1;
        if (uwsgi_buffer_num64(ub, coreid)) return -1;
        if (uwsgi_buffer_append(ub, ".", 1)) return -1;
        if (uwsgi_buffer_append(ub, metric, metric_len)) return -1;
        if (uwsgi_buffer_append(ub, ":", 1)) return -1;
        if (uwsgi_buffer_num64(ub, value)) return -1;
        if (uwsgi_buffer_append(ub, "|g", 2)) return -1;

	if (sendto(sn->fd, ub->buf, ub->pos, 0, (struct sockaddr *) &sn->addr.sa_in, sn->addr_len) < 0) {
		uwsgi_error("stats_pusher_statsd()/sendto()");
	}

	return 0;
}


static void stats_pusher_statsd(struct uwsgi_stats_pusher_instance *uspi, time_t now, char *json, size_t json_len) {

	if (!uspi->configured) {
		struct statsd_node *sn = uwsgi_calloc(sizeof(struct statsd_node));
		char *comma = strchr(uspi->arg, ',');
		if (comma) {
			sn->prefix = comma+1;
			sn->prefix_len = strlen(sn->prefix);
			*comma = 0;
		}
		else {
			sn->prefix = "uwsgi";
			sn->prefix_len = 5;
		}

		char *colon = strchr(uspi->arg, ':');
		if (!colon) {
			uwsgi_log("invalid statsd address %s\n", uspi->arg);
			if (comma) *comma = ',';
			free(sn);
			return;
		}
		sn->addr_len = socket_to_in_addr(uspi->arg, colon, 0, &sn->addr.sa_in);

		sn->fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sn->fd < 0) {
			uwsgi_error("stats_pusher_statsd()/socket()");
			if (comma) *comma = ',';
                        free(sn);
                        return;
		}
		uwsgi_socket_nb(sn->fd);
		if (comma) *comma = ',';
		uspi->data = sn;
		uspi->configured = 1;
	}

	// we use the same buffer for all of the packets
	struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);

	int i, j;
	// send workers metrics
	for(i=1;i<=uwsgi.numproc;i++) {
		if (statsd_send_worker_gauge(ub, uspi, i, "requests", 8, uwsgi.workers[i].requests)) goto end;
		for(j=0;j<uwsgi.cores;j++) {
			if (statsd_send_core_gauge(ub, uspi, i, j, "exceptions", 10, uwsgi.workers[i].cores[j].exceptions)) goto end;
			if (statsd_send_core_gauge(ub, uspi, i, j, "requests", 8, uwsgi.workers[i].cores[j].requests)) goto end;
			if (statsd_send_core_gauge(ub, uspi, i, j, "routed_requests", 15, uwsgi.workers[i].cores[j].routed_requests)) goto end;
			if (statsd_send_core_gauge(ub, uspi, i, j, "static_requests", 15, uwsgi.workers[i].cores[j].static_requests)) goto end;
			if (statsd_send_core_gauge(ub, uspi, i, j, "offloaded_requests", 18, uwsgi.workers[i].cores[j].offloaded_requests)) goto end;
		}
	}
end:
	uwsgi_buffer_destroy(ub);
}

static void stats_pusher_statsd_init(void) {
        struct uwsgi_stats_pusher *usp = uwsgi_register_stats_pusher("statsd", stats_pusher_statsd);
	// we use a custom format not the JSON one
	usp->raw = 1;
}

struct uwsgi_plugin stats_pusher_statsd_plugin = {

        .name = "stats_pusher_statsd",
        .on_load = stats_pusher_statsd_init,
};

