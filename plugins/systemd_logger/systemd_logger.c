#include "../../uwsgi.h"

#include <systemd/sd-journal.h>

ssize_t uwsgi_systemd_logger(struct uwsgi_logger *ul, char *message, size_t len) {

	// split multiline log messages to multiple journal lines
	size_t i;
	char *base = message;
	for(i=0;i<len;i++) {
		if (message[i] == '\n') {
			message[i] = 0;
			sd_journal_print(LOG_INFO, "%s", base);
			base = message+i+1;
		}
	}

	// last \n is missing...
	if (base < message+len) {
		sd_journal_print(LOG_INFO, "%.*s", (int) ((message+len) - base), base);
	}
	return 0;

}

void uwsgi_systemd_logger_register() {
	uwsgi_register_logger("systemd", uwsgi_systemd_logger);
}

struct uwsgi_plugin systemd_logger_plugin = {

        .name = "systemd_logger",
        .on_load = uwsgi_systemd_logger_register,

};

