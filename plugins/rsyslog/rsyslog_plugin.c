#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#define MAX_SYSLOG_PKT 1024

ssize_t uwsgi_rsyslog_logger(struct uwsgi_logger *ul, char *message, size_t len) {

	char buf[MAX_SYSLOG_PKT];
	time_t current_time;
	int portn = 514;
	int rlen;

	if (!ul->configured) {

                if (!uwsgi.choosen_logger_arg) return -1;

                ul->fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (ul->fd < 0) return -1 ;

		uwsgi_socket_nb(ul->fd);

                char *comma = strchr(uwsgi.choosen_logger_arg, ',');
		if (comma) {
			ul->data = comma+1;
                	*comma = 0;
		}
		else {
			ul->data = "uwsgi";
		}


                char *port = strchr(uwsgi.choosen_logger_arg, ':');
                if (port) {
			portn = atoi(port+1);
			*port = 0;
		}

                memset(&ul->sin, 0, sizeof(struct sockaddr_in));
                ul->sin.sin_family = AF_INET;
                ul->sin.sin_port = htons(portn);

                ul->sin.sin_addr.s_addr = inet_addr(uwsgi.choosen_logger_arg);

		if (port) *port = ':';
		if (comma) *comma = ',';

                ul->configured = 1;
        }


	current_time = time(NULL);

	// drop newline
	if (message[len-1] == '\n') len--;

 	rlen = snprintf(buf, MAX_SYSLOG_PKT, "<29>%.*s %s %s: %.*s", 19, ctime(&current_time), uwsgi.hostname, (char *) ul->data, (int) len, message);
	if (rlen > 0) {
		return sendto(ul->fd, buf, rlen, 0, (const struct sockaddr *) &ul->sin, sizeof(struct sockaddr_in));
	}
	return -1;

}

void uwsgi_rsyslog_register() {
	uwsgi_register_logger("rsyslog", uwsgi_rsyslog_logger);
}

int uwsgi_rsyslog_init() {
	return 0;
}

struct uwsgi_plugin rsyslog_plugin = {

        .name = "rsyslog",
        .on_load = uwsgi_rsyslog_register,
	.init = uwsgi_rsyslog_init

};

