#include "../../uwsgi.h"
#include <zlib.h>

extern struct uwsgi_server uwsgi;

#define MAX_GELF 8192

struct graylog2_config {
	char *host;
	char json_buf[MAX_GELF];
	char escaped_buf[MAX_GELF];
	size_t escaped_len;
} g2c;

ssize_t uwsgi_graylog2_logger(struct uwsgi_logger *ul, char *message, size_t len) {

	size_t i;

	if (!ul->configured) {

		if (!ul->arg) {
			uwsgi_log_safe("invalid graylog2 syntax\n");
			exit(1);
		}

		ul->fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (ul->fd < 0) {
			uwsgi_error_safe("socket()");
			exit(1);
		}

		uwsgi_socket_nb(ul->fd);

		char *comma = strchr(ul->arg, ',');
		if (!comma) {
			uwsgi_log_safe("invalid graylog2 syntax\n");
                        exit(1);
		}

		g2c.host = comma + 1;

		*comma = 0;

		char *colon = strchr(ul->arg, ':');
		if (!colon) {
			uwsgi_log_safe("invalid graylog2 syntax\n");
                        exit(1);
		}

		ul->addr_len = socket_to_in_addr(ul->arg, colon, 0, &ul->addr.sa_in);

		*comma = ',';

		ul->buf = uwsgi_malloc(MAX_GELF);

		ul->configured = 1;
	}

	g2c.escaped_len = 0;

	int truncated = 0;
	char *ptr = g2c.escaped_buf;
	uLongf destLen = MAX_GELF;

	for(i=0;i<len;i++) {
		if (message[i] == '\\') {
			*ptr ++= '\\';
			g2c.escaped_len++;
		}
		else if (message[i] == '"') {
			*ptr ++= '\\';
			g2c.escaped_len++;
		}
		*ptr ++= message[i];
		g2c.escaped_len++;

		if (!truncated) {
			if (g2c.escaped_len == 128) {
				truncated = 1;
			}
			else if (g2c.escaped_len > 128) {
				truncated = 2;
			}
		}
	}

	if (truncated) truncated = 128 - (truncated-1);
	else (truncated = g2c.escaped_len);

	int rlen = snprintf(g2c.json_buf, MAX_GELF, "{ \"version\": \"1.0\", \"host\": \"%s\", \"short_message\": \"%.*s\", \"full_message\": \"%.*s\", \"timestamp\": %d, \"level\": 5, \"facility\": \"uWSGI-%s\" }",
		g2c.host, truncated, g2c.escaped_buf, (int)g2c.escaped_len, g2c.escaped_buf, (int) uwsgi_now(), UWSGI_VERSION);

	if (rlen > 0 && rlen < MAX_GELF) {
		if (compressBound((uLong) rlen) <= MAX_GELF) {
			if (compress((Bytef *) ul->buf, &destLen, (Bytef *) g2c.json_buf, (uLong) rlen) == Z_OK) {
				return sendto(ul->fd, ul->buf, destLen, 0, (const struct sockaddr *) &ul->addr, ul->addr_len);
			}
		}

	}
	return -1;

}


void uwsgi_graylog2_register() {
	uwsgi_register_logger("graylog2", uwsgi_graylog2_logger);
}

struct uwsgi_plugin graylog2_plugin = {

        .name = "graylog2",
        .on_load = uwsgi_graylog2_register,

};

