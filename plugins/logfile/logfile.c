#include "../../uwsgi.h"

ssize_t uwsgi_file_logger(struct uwsgi_logger *ul, char *message, size_t len) {

	if (!ul->configured) {
		if (ul->arg) {
			ul->fd = open(ul->arg, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP);
			if (ul->fd >= 0) {
				ul->configured = 1;
			}	
		}
	}

	if (ul->fd >= 0) {
		return write(ul->fd, message, len);
	}
	return 0;

}

void uwsgi_file_logger_register() {
	uwsgi_register_logger("file", uwsgi_file_logger);
}

struct uwsgi_plugin logfile_plugin = {

        .name = "logfile",
        .on_load = uwsgi_file_logger_register,

};

