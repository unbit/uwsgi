#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

struct uwsgi_ping {
	char *ping;
	int ping_timeout;
} uping;

struct option uwsgi_ping_options[] = {
	{"ping", required_argument, 0, LONG_ARGS_PING},
	{"ping-timeout", required_argument, 0, LONG_ARGS_PING_TIMEOUT},
	{ 0, 0, 0, 0 }
};

static void ping() {

	struct wsgi_request ping_req;
	char *buf = uwsgi_malloc(uwsgi.buffer_size);

	// use a 3 secs timeout by default
	if (!uping.ping_timeout) uping.ping_timeout = 3;

	uwsgi_log("PING uwsgi host %s (timeout: %d)\n", uping.ping, uping.ping_timeout);

	int fd = uwsgi_connect(uping.ping, uping.ping_timeout, 0);
	if (fd < 0) {
		exit(1);
	}

	memset(&ping_req, 0, sizeof(struct wsgi_request));
	ping_req.uh.modifier1 = UWSGI_MODIFIER_PING;
	ping_req.uh.pktsize = 0;
	ping_req.uh.modifier2 = 0;
	if (write(fd, &ping_req.uh, 4) != 4) {
		uwsgi_error("write()");
		exit(2);
	}
	ping_req.poll.fd = fd;
	ping_req.poll.events = POLLIN;

	ping_req.buffer = buf;

	if (!uwsgi_parse_packet(&ping_req, uping.ping_timeout)) {
		exit(1);
	}
	else {
		if (ping_req.uh.pktsize > 0) {
			uwsgi_log("[WARNING] node %s message: %.*s\n", uping.ping, ping_req.uh.pktsize, buf);
			exit(2);
		}
		else {
			exit(0);
		}
	}

}


int ping_init() {

	if (uping.ping) {
		ping();
		//never here
	}

	return 1;
}

/* uwsgi PING|100 */
int uwsgi_request_ping(struct wsgi_request *wsgi_req) {
	char len;

	uwsgi_log( "PING\n");
	wsgi_req->uh.modifier2 = 1;
	wsgi_req->uh.pktsize = 0;

	len = strlen(uwsgi.shared->warning_message);
	if (len > 0) {
		// TODO: check endianess ?
		wsgi_req->uh.pktsize = len;
	}
	if (write(wsgi_req->poll.fd, wsgi_req, 4) != 4) {
		uwsgi_error("write()");
	}

	if (len > 0) {
		if (write(wsgi_req->poll.fd, uwsgi.shared->warning_message, len)
				!= len) {
			uwsgi_error("write()");
		}
	}

	return UWSGI_OK;
}

int uwsgi_ping_manage_options(int i, char *optarg) {

	switch(i) {
		case LONG_ARGS_PING:
			uwsgi.no_server = 1;
			uping.ping = optarg;
			return 1;
		case LONG_ARGS_PING_TIMEOUT:
			uping.ping_timeout = atoi(optarg);
			return 1;
	}

	return 0;
}

struct uwsgi_plugin ping_plugin = {

	.name = "ping",
	.modifier1 = 100,
	.options = uwsgi_ping_options,
	.manage_opt = uwsgi_ping_manage_options,
	.request = uwsgi_request_ping,
	.init = ping_init,
};
