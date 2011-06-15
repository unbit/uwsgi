#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;
int use_nagios = 0;

#define LONG_ARGS_NAGIOS 40000

struct option nagios_options[] = {

	{"nagios", no_argument, 0, LONG_ARGS_NAGIOS},
        {0, 0, 0, 0},

};


int nagios() {

	char *tcp_port;
	struct wsgi_request nagios_req;
// connect and send

	if (!use_nagios) {
		return 1;
	}
	if (!uwsgi.sockets) {
		fprintf(stdout, "UWSGI UNKNOWN: you have specified an invalid socket\n");
		exit(3);
	}
	tcp_port = strchr(uwsgi.sockets->name, ':');
	if (tcp_port == NULL) {
		fprintf(stdout, "UWSGI UNKNOWN: you have specified an invalid socket\n");
		exit(3);
	}

	tcp_port[0] = 0;

	int fd = connect_to_tcp(uwsgi.sockets->name, atoi(tcp_port + 1), uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], 0);
	if (fd < 0) {
		fprintf(stdout, "UWSGI CRITICAL: could not connect() to workers\n");
		exit(2);
	}
	nagios_req.uh.modifier1 = UWSGI_MODIFIER_PING;
	nagios_req.uh.pktsize = 0;
	nagios_req.uh.modifier2 = 0;
	if (write(fd, &nagios_req.uh, 4) != 4) {
		uwsgi_error("write()");
		fprintf(stdout, "UWSGI CRITICAL: could not send ping packet to workers\n");
		exit(2);
	}

	nagios_req.poll.fd = fd;
	nagios_req.poll.events = POLLIN;

	if (!uwsgi_parse_packet(&nagios_req, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT])) {
		fprintf(stdout, "UWSGI CRITICAL: timed out waiting for response\n");
		exit(2);
	}
	else {
		if (nagios_req.uh.pktsize > 0) {
			fprintf(stdout, "UWSGI WARNING: %.*s\n", nagios_req.uh.pktsize, nagios_req.buffer);
			exit(1);
		}
		else {
			fprintf(stdout, "UWSGI OK: armed and ready\n");
			exit(0);
		}
	}

	// never here
	fprintf(stdout, "UWSGI UNKNOWN: probably you hit a bug of uWSGI !!!\n");
	exit(3);
}

int nagios_opt(int i, char *optarg) {

	switch(i) {
		case LONG_ARGS_NAGIOS:
			uwsgi.no_initial_output = 1;
			use_nagios = 1;
			return 1;
	}

	return 0;
}

struct uwsgi_plugin nagios_plugin = {
	
	.options = nagios_options,
	.manage_opt = nagios_opt,
	.init = nagios,
};
