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

	struct uwsgi_header uh;
	struct pollfd uwsgi_poll;

	// use a 3 secs timeout by default
	if (!uping.ping_timeout) uping.ping_timeout = 3;

	uwsgi_log("PING uwsgi host %s (timeout: %d)\n", uping.ping, uping.ping_timeout);

	uwsgi_poll.fd = uwsgi_connect(uping.ping, uping.ping_timeout, 0);
	if (uwsgi_poll.fd < 0) {
		exit(1);
	}

	uh.modifier1 = UWSGI_MODIFIER_PING;
	uh.pktsize = 0;
	uh.modifier2 = 0;
	if (write(uwsgi_poll.fd, &uh, 4) != 4) {
		uwsgi_error("write()");
		exit(2);
	}
	uwsgi_poll.events = POLLIN;
	if (!uwsgi_parse_response(&uwsgi_poll, uping.ping_timeout, &uh, NULL, uwsgi_proto_uwsgi_parser)) {
		exit(1);
	}
	else {
		if (uh.pktsize > 0) {
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
