#include <uwsgi.h>
extern struct uwsgi_server uwsgi;

struct logfile_data {
	char *logfile;
	char *backupname;
	uint64_t maxsize;
};

static void uwsgi_cron_trigger_rotate_func(struct uwsgi_cron *uc, time_t now){
    struct uwsgi_logger *ul = uc->data;
	struct logfile_data *data = ul->data;
	off_t logsize = lseek(ul->fd, 0, SEEK_CUR);

	uwsgi_log_do_rotate(data->logfile, data->backupname, logsize, ul->fd);
}

static ssize_t uwsgi_file_logger(struct uwsgi_logger *ul, char *message, size_t len) {

	if (!ul->configured) {
		if (ul->arg) {
			int is_keyval = 0;
			char *backupname = NULL;
			char *maxsize = NULL;
			char *logfile = NULL;
			char *cron = NULL;

			if (strchr(ul->arg, '=')) {
				if (uwsgi_kvlist_parse(ul->arg, strlen(ul->arg), ',', '=',
					"logfile", &logfile, "backupname", &backupname, "maxsize", &maxsize, "cron", &cron, NULL)) {
					uwsgi_log("[uwsgi-logfile] invalid keyval syntax\n");
					exit(1);
				}
				is_keyval = 1;
			}
			if (is_keyval) {
				if (!logfile) {
					uwsgi_log("[uwsgi-logfile] missing logfile key\n");
					return 0;
				}
				
				struct logfile_data *data = uwsgi_malloc(sizeof(struct logfile_data));
				data->logfile = logfile;
				data->backupname = backupname;
				if (maxsize) {
					data->maxsize = (uint64_t)strtoull(maxsize, NULL, 10);
					free(maxsize);
					maxsize = NULL;
				} else {
					data->maxsize = (uint64_t) 0;
				}
				if (cron) {
					struct uwsgi_cron *uc = uwsgi_cron_add(cron);
					uc->data = ul;
					uc->func = uwsgi_cron_trigger_rotate_func;
				}
				ul->data = data;
			} else {
				logfile = ul->arg;
			}

			ul->fd = open(logfile, O_RDWR | O_CREAT | O_APPEND, uwsgi_get_logfile_chmod_value());
			if (ul->fd >= 0) {
				ul->configured = 1;
			}	
		}
	}

	if (ul->fd >= 0) {
		ssize_t written = write(ul->fd, message, len);

		if (ul->data) {
			struct logfile_data *data = ul->data;
			off_t logsize = lseek(ul->fd, 0, SEEK_CUR);

			if (data->maxsize > 0 && (uint64_t) logsize > data->maxsize) {
				uwsgi_log_do_rotate(data->logfile, data->backupname, logsize, ul->fd);
			}
		}

		return written;
	}

	return 0;
}

static ssize_t uwsgi_fd_logger(struct uwsgi_logger *ul, char *message, size_t len) {

        if (!ul->configured) {
		ul->fd = -1;
                if (ul->arg) ul->fd = atoi(ul->arg);
                ul->configured = 1;
        }

        if (ul->fd >= 0) {
                return write(ul->fd, message, len);
        }
        return 0;

}

static ssize_t uwsgi_stdio_logger(struct uwsgi_logger *ul, char *message, size_t len) {

        if (uwsgi.original_log_fd >= 0) {
                return write(uwsgi.original_log_fd, message, len);
        }
        return 0;
}


void uwsgi_file_logger_register() {
	uwsgi_register_logger("file", uwsgi_file_logger);
	uwsgi_register_logger("fd", uwsgi_fd_logger);
	uwsgi_register_logger("stdio", uwsgi_stdio_logger);
}

struct uwsgi_plugin logfile_plugin = {

        .name = "logfile",
        .on_load = uwsgi_file_logger_register,

};

