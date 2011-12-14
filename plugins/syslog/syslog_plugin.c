#include "../../uwsgi.h"

#include <syslog.h>

extern struct uwsgi_server uwsgi;

ssize_t uwsgi_syslog_logger(struct uwsgi_logger *ul, char *message, size_t len) {

	char *syslog_opts;

	if (!ul->configured) {

        	setlinebuf(stderr);

        	if (uwsgi.choosen_logger_arg == NULL) {
                	syslog_opts = "uwsgi";
        	}
		else {
			syslog_opts = uwsgi.choosen_logger_arg;
		}

        	openlog(syslog_opts, 0, LOG_DAEMON);

		ul->configured = 1;
	}

	syslog(LOG_INFO, "%.*s", (int) len, message);
	return 0;

}

void uwsgi_syslog_register() {
	uwsgi_register_logger("syslog", uwsgi_syslog_logger);
}

int uwsgi_syslog_init() {
	return 0;
}

struct uwsgi_plugin syslog_plugin = {

        .name = "syslog",
        .on_load = uwsgi_syslog_register,
	.init = uwsgi_syslog_init

};

