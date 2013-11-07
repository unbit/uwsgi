#include <uwsgi.h>

struct uwsgi_stats_pusher_file_conf {
        char *path;
        char *freq;
        char *separator;
};

static void stats_pusher_file(struct uwsgi_stats_pusher_instance *uspi, time_t now, char *json, size_t json_len) {
        struct uwsgi_stats_pusher_file_conf *uspic = (struct uwsgi_stats_pusher_file_conf *) uspi->data;
        if (!uspi->configured) {
                uspic = uwsgi_calloc(sizeof(struct uwsgi_stats_pusher_file_conf));
                if (uspi->arg) {
                        if (uwsgi_kvlist_parse(uspi->arg, strlen(uspi->arg), ',', '=', "path", &uspic->path, "separator", &uspic->separator, "freq", &uspic->freq, NULL)) {
                                free(uspi);
                                return;
                        }
                }
                if (!uspic->path)
                        uspic->path = "uwsgi.stats";
                if (!uspic->separator)
                        uspic->separator = "\n\n";
                if (uspic->freq)
                        uspi->freq = atoi(uspic->freq);
                uspi->configured = 1;
                uspi->data = uspic;
        }

        int fd = open(uspic->path, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP);
        if (fd < 0) {
                uwsgi_error_open(uspic->path);
                return;
        }
        ssize_t rlen = write(fd, json, json_len);
        if (rlen != (ssize_t) json_len) {
                uwsgi_error("uwsgi_stats_pusher_file() -> write()\n");
        }

        rlen = write(fd, uspic->separator, strlen(uspic->separator));
        if (rlen != (ssize_t) strlen(uspic->separator)) {
                uwsgi_error("uwsgi_stats_pusher_file() -> write()\n");
        }

        close(fd);
}


static void stats_pusher_file_init(void) {
	uwsgi_register_stats_pusher("file", stats_pusher_file);
}

struct uwsgi_plugin stats_pusher_file_plugin = {

        .name = "stats_pusher_file",
        .on_load = stats_pusher_file_init,
};

