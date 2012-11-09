#include "uwsgi.h"
/*
	utility functions for fast generating json output for the stats subsystem
*/

extern struct uwsgi_server uwsgi;

struct uwsgi_stats *uwsgi_stats_new(size_t chunk_size) {
	struct uwsgi_stats *us = uwsgi_malloc(sizeof(struct uwsgi_stats));
	us->base = uwsgi_malloc(chunk_size);
	us->base[0] = '{';
	us->pos = 1;
	us->chunk = chunk_size;
	us->size = chunk_size;
	us->tabs = 1;
	us->minified = uwsgi.stats_minified;
	if (!us->minified) {
		us->base[1] = '\n';
		us->pos++;
	}
	return us;
}

int uwsgi_stats_symbol(struct uwsgi_stats *us, char sym) {
	char *ptr = us->base + us->pos;
	char *watermark = us->base + us->size;

	if (ptr + 1 > watermark) {
		char *new_base = realloc(us->base, us->size + us->chunk);
		if (!new_base)
			return -1;
		us->base = new_base;
		us->size += us->chunk;
		ptr = us->base + us->pos;
	}

	*ptr = sym;
	us->pos++;
	return 0;
}

int uwsgi_stats_symbol_nl(struct uwsgi_stats *us, char sym) {
	if (uwsgi_stats_symbol(us, sym)) {
		return -1;
	}
	if (us->minified)
		return 0;
	return uwsgi_stats_symbol(us, '\n');
}


int uwsgi_stats_comma(struct uwsgi_stats *us) {
	return uwsgi_stats_symbol_nl(us, ',');
}

int uwsgi_stats_apply_tabs(struct uwsgi_stats *us) {
	if (us->minified)
		return 0;
	size_t i;
	for (i = 0; i < us->tabs; i++) {
		if (uwsgi_stats_symbol(us, '\t'))
			return -1;
	};
	return 0;
}


int uwsgi_stats_object_open(struct uwsgi_stats *us) {
	if (uwsgi_stats_apply_tabs(us))
		return -1;
	if (!us->minified)
		us->tabs++;
	return uwsgi_stats_symbol_nl(us, '{');
}

int uwsgi_stats_object_close(struct uwsgi_stats *us) {
	if (!us->minified) {
		if (uwsgi_stats_symbol(us, '\n'))
			return -1;
		us->tabs--;
		if (uwsgi_stats_apply_tabs(us))
			return -1;
	}
	return uwsgi_stats_symbol(us, '}');
}

int uwsgi_stats_list_open(struct uwsgi_stats *us) {
	us->tabs++;
	return uwsgi_stats_symbol_nl(us, '[');
}

int uwsgi_stats_list_close(struct uwsgi_stats *us) {
	if (!us->minified) {
		if (uwsgi_stats_symbol(us, '\n'))
			return -1;
		us->tabs--;
		if (uwsgi_stats_apply_tabs(us))
			return -1;
	}
	return uwsgi_stats_symbol(us, ']');
}

int uwsgi_stats_keyval(struct uwsgi_stats *us, char *key, char *value) {

	if (uwsgi_stats_apply_tabs(us))
		return -1;

	char *ptr = us->base + us->pos;
	char *watermark = us->base + us->size;
	size_t available = watermark - ptr;

	int ret = snprintf(ptr, available, "\"%s\":\"%s\"", key, value);
	if (ret < 0)
		return -1;
	while (ret >= (int) available) {
		char *new_base = realloc(us->base, us->size + us->chunk);
		if (!new_base)
			return -1;
		us->base = new_base;
		us->size += us->chunk;
		ptr = us->base + us->pos;
		watermark = us->base + us->size;
		available = watermark - ptr;
		ret = snprintf(ptr, available, "\"%s\":\"%s\"", key, value);
		if (ret < 0)
			return -1;
	}

	us->pos += ret;
	return 0;

}

int uwsgi_stats_keyval_comma(struct uwsgi_stats *us, char *key, char *value) {
	int ret = uwsgi_stats_keyval(us, key, value);
	if (ret)
		return -1;
	return uwsgi_stats_comma(us);
}

int uwsgi_stats_keyvalnum(struct uwsgi_stats *us, char *key, char *value, unsigned long long num) {

	if (uwsgi_stats_apply_tabs(us))
		return -1;

	char *ptr = us->base + us->pos;
	char *watermark = us->base + us->size;
	size_t available = watermark - ptr;

	int ret = snprintf(ptr, available, "\"%s\":\"%s%llu\"", key, value, num);
	if (ret < 0)
		return -1;
	while (ret >= (int) available) {
		char *new_base = realloc(us->base, us->size + us->chunk);
		if (!new_base)
			return -1;
		us->base = new_base;
		us->size += us->chunk;
		ptr = us->base + us->pos;
		watermark = us->base + us->size;
		available = watermark - ptr;
		ret = snprintf(ptr, available, "\"%s\":\"%s%llu\"", key, value, num);
		if (ret < 0)
			return -1;
	}

	us->pos += ret;
	return 0;

}

int uwsgi_stats_keyvalnum_comma(struct uwsgi_stats *us, char *key, char *value, unsigned long long num) {
	int ret = uwsgi_stats_keyvalnum(us, key, value, num);
	if (ret)
		return -1;
	return uwsgi_stats_comma(us);
}


int uwsgi_stats_keyvaln(struct uwsgi_stats *us, char *key, char *value, int vallen) {

	if (uwsgi_stats_apply_tabs(us))
		return -1;

	char *ptr = us->base + us->pos;
	char *watermark = us->base + us->size;
	size_t available = watermark - ptr;

	int ret = snprintf(ptr, available, "\"%s\":\"%.*s\"", key, vallen, value);
	if (ret < 0)
		return -1;
	while (ret >= (int) available) {
		char *new_base = realloc(us->base, us->size + us->chunk);
		if (!new_base)
			return -1;
		us->base = new_base;
		us->size += us->chunk;
		ptr = us->base + us->pos;
		watermark = us->base + us->size;
		available = watermark - ptr;
		ret = snprintf(ptr, available, "\"%s\":\"%.*s\"", key, vallen, value);
		if (ret < 0)
			return -1;
	}

	us->pos += ret;
	return 0;

}

int uwsgi_stats_keyvaln_comma(struct uwsgi_stats *us, char *key, char *value, int vallen) {
	int ret = uwsgi_stats_keyvaln(us, key, value, vallen);
	if (ret)
		return -1;
	return uwsgi_stats_comma(us);
}


int uwsgi_stats_key(struct uwsgi_stats *us, char *key) {

	if (uwsgi_stats_apply_tabs(us))
		return -1;

	char *ptr = us->base + us->pos;
	char *watermark = us->base + us->size;
	size_t available = watermark - ptr;

	int ret = snprintf(ptr, available, "\"%s\":", key);
	if (ret < 0)
		return -1;
	while (ret >= (int) available) {
		char *new_base = realloc(us->base, us->size + us->chunk);
		if (!new_base)
			return -1;
		us->base = new_base;
		us->size += us->chunk;
		ptr = us->base + us->pos;
		watermark = us->base + us->size;
		available = watermark - ptr;
		ret = snprintf(ptr, available, "\"%s\":", key);
		if (ret < 0)
			return -1;
	}

	us->pos += ret;
	return 0;
}

int uwsgi_stats_str(struct uwsgi_stats *us, char *str) {

	char *ptr = us->base + us->pos;
	char *watermark = us->base + us->size;
	size_t available = watermark - ptr;

	int ret = snprintf(ptr, available, "\"%s\"", str);
	if (ret < 0)
		return -1;
	while (ret >= (int) available) {
		char *new_base = realloc(us->base, us->size + us->chunk);
		if (!new_base)
			return -1;
		us->base = new_base;
		us->size += us->chunk;
		ptr = us->base + us->pos;
		watermark = us->base + us->size;
		available = watermark - ptr;
		ret = snprintf(ptr, available, "\"%s\"", str);
		if (ret < 0)
			return -1;
	}

	us->pos += ret;
	return 0;
}




int uwsgi_stats_keylong(struct uwsgi_stats *us, char *key, unsigned long long num) {

	if (uwsgi_stats_apply_tabs(us))
		return -1;

	char *ptr = us->base + us->pos;
	char *watermark = us->base + us->size;
	size_t available = watermark - ptr;

	int ret = snprintf(ptr, available, "\"%s\":%llu", key, num);
	if (ret < 0)
		return -1;
	while (ret >= (int) available) {
		char *new_base = realloc(us->base, us->size + us->chunk);
		if (!new_base)
			return -1;
		us->base = new_base;
		us->size += us->chunk;
		ptr = us->base + us->pos;
		watermark = us->base + us->size;
		available = watermark - ptr;
		ret = snprintf(ptr, available, "\"%s\":%llu", key, num);
		if (ret < 0)
			return -1;
	}

	us->pos += ret;
	return 0;
}


int uwsgi_stats_keylong_comma(struct uwsgi_stats *us, char *key, unsigned long long num) {
	int ret = uwsgi_stats_keylong(us, key, num);
	if (ret)
		return -1;
	return uwsgi_stats_comma(us);
}

void uwsgi_send_stats(int fd, struct uwsgi_stats *(*func) (void)) {

	struct sockaddr_un client_src;
	socklen_t client_src_len = 0;

	int client_fd = accept(fd, (struct sockaddr *) &client_src, &client_src_len);
	if (client_fd < 0) {
		uwsgi_error("accept()");
		return;
	}

	if (uwsgi.stats_http) {
		if (uwsgi_send_http_stats(client_fd)) {
			close(client_fd);
			return;
		}
	}

	struct uwsgi_stats *us = func();
	if (!us)
		goto end;

	size_t remains = us->pos;
	off_t pos = 0;
	while (remains > 0) {
		int ret = uwsgi_waitfd_write(client_fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (ret <= 0) {
			goto end0;
		}
		ssize_t res = write(client_fd, us->base + pos, remains);
		if (res <= 0) {
			if (res < 0) {
				uwsgi_error("write()");
			}
			goto end0;
		}
		pos += res;
		remains -= res;
	}

end0:
	free(us->base);
	free(us);

end:
	close(client_fd);
}

struct uwsgi_stats_pusher *uwsgi_stats_pusher_get(char *name) {
	struct uwsgi_stats_pusher *usp = uwsgi.stats_pushers;
	while (usp) {
		if (!strcmp(usp->name, name)) {
			return usp;
		}
		usp = usp->next;
	}
	return usp;
}

void uwsgi_stats_pusher_add(struct uwsgi_stats_pusher *pusher, char *arg) {
	struct uwsgi_stats_pusher_instance *old_uspi = NULL, *uspi = uwsgi.stats_pusher_instances;
	while (uspi) {
		old_uspi = uspi;
		uspi = uspi->next;
	}

	uspi = uwsgi_calloc(sizeof(struct uwsgi_stats_pusher_instance));
	uspi->pusher = pusher;
	uspi->arg = arg;
	if (old_uspi) {
		old_uspi->next = uspi;
	}
	else {
		uwsgi.stats_pusher_instances = uspi;
	}
}

void uwsgi_stats_pusher_loop(struct uwsgi_thread *ut) {
	void *events = event_queue_alloc(1);
	for (;;) {
		int nevents = event_queue_wait_multi(ut->queue, 1, events, 1);
		if (nevents > 0) {
			int interesting_fd = event_queue_interesting_fd(events, 0);
			char buf[4096];
			ssize_t len = read(interesting_fd, buf, 4096);
			if (len <= 0) {
				uwsgi_log("[uwsgi-stats-pusher] goodbye...\n");
				return;
			}
			uwsgi_log("[uwsgi-stats-pusher] message received from master: %.*s\n", (int) len, buf);
			continue;
		}

		time_t now = uwsgi_now();
		struct uwsgi_stats_pusher_instance *uspi = uwsgi.stats_pusher_instances;
		struct uwsgi_stats *us = NULL;
		while (uspi) {
			int delta = uspi->freq ? uspi->freq : uwsgi.stats_pusher_default_freq;
			if ((uspi->last_run + delta) <= now) {
				if (!us) {
					us = uwsgi_master_generate_stats();
					if (!us)
						goto next;
				}
				uspi->pusher->func(uspi, us->base, us->pos);
				uspi->last_run = now;
			}
next:
			uspi = uspi->next;
		}

		if (us) {
			free(us->base);
			free(us);
		}
	}
}

void uwsgi_stats_pusher_setup() {
	struct uwsgi_string_list *usl = uwsgi.requested_stats_pushers;
	while (usl) {
		char *ssp = uwsgi_str(usl->value);
		struct uwsgi_stats_pusher *pusher = NULL;
		char *colon = strchr(ssp, ':');
		if (colon) {
			*colon = 0;
		}
		pusher = uwsgi_stats_pusher_get(ssp);
		if (!pusher) {
			uwsgi_log("unable to find \"%s\" stats_pusher\n", ssp);
			exit(1);
		}
		char *arg = NULL;
		if (colon) {
			arg = colon + 1;
			*colon = ':';
		}
		uwsgi_stats_pusher_add(pusher, arg);
		usl = usl->next;
	}
}

void uwsgi_register_stats_pusher(char *name, void (*func) (struct uwsgi_stats_pusher_instance *, char *, size_t)) {

	struct uwsgi_stats_pusher *pusher = uwsgi.stats_pushers, *old_pusher = NULL;

	while (pusher) {
		old_pusher = pusher;
		pusher = pusher->next;
	}

	pusher = uwsgi_calloc(sizeof(struct uwsgi_stats_pusher));
	pusher->name = name;
	pusher->func = func;

	if (old_pusher) {
		old_pusher->next = pusher;
	}
	else {
		uwsgi.stats_pushers = pusher;
	}
}

struct uwsgi_stats_pusher_file_conf {
	char *path;
	char *freq;
	char *separator;
};

void uwsgi_stats_pusher_file(struct uwsgi_stats_pusher_instance *uspi, char *json, size_t json_len) {
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
