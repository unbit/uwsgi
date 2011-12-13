#include "../../uwsgi.h"
#include <zlib.h>

extern struct uwsgi_server uwsgi;

#define MAX_GELF 8192

struct graylog2_config {
	char *host;
	char json_buf[MAX_GELF];
	char escaped_buf[MAX_GELF];
	size_t escaped_len;
	char buffer[MAX_GELF];
} g2c;

ssize_t uwsgi_graylog2_logger(struct uwsgi_logger *ul, char *message, size_t len) {

	size_t i;

	if (!ul->configured) {

		if (!uwsgi.choosen_logger_arg) return -1;

		ul->fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (ul->fd < 0) return -1 ;

		uwsgi_socket_nb(ul->fd);

		char *comma = strchr(uwsgi.choosen_logger_arg, ',');
		if (!comma) return -1;

		g2c.host = comma + 1;

		*comma = 0;

		char *colon = strchr(uwsgi.choosen_logger_arg, ':');
		if (!colon) return -1;

		memset(&ul->sin, 0, sizeof(struct sockaddr_in));
        	ul->sin.sin_family = AF_INET;
        	ul->sin.sin_port = htons(atoi(colon + 1));

		*colon = 0;

                ul->sin.sin_addr.s_addr = inet_addr(uwsgi.choosen_logger_arg);

		*colon = ':';
		*comma = ',';

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

	int rlen = snprintf(g2c.json_buf, MAX_GELF, "{ \"version\": \"1.0\", \"host\": \"%s\", \"short_message\": \"%.*s\", \"full_message\": \"%.*s\", \"timestamp\": %d, \"facility\": \"uWSGI-%s\" }",
		g2c.host, truncated, g2c.escaped_buf, (int)g2c.escaped_len, g2c.escaped_buf, (int) time(NULL), UWSGI_VERSION);

	if (rlen > 0) {
		if (compressBound((uLong) rlen) <= MAX_GELF) {
			if (compress((Bytef *) g2c.buffer, &destLen, (Bytef *) g2c.json_buf, (uLong) rlen) == Z_OK) {
				return sendto(ul->fd, g2c.buffer, destLen, 0, (const struct sockaddr *) &ul->sin, sizeof(struct sockaddr_in));
			}
		}

	}
	return -1;

}


void uwsgi_graylog2_register() {
	uwsgi_register_logger("graylog2", uwsgi_graylog2_logger);
}

int uwsgi_graylog2_init() {
	return 0;
}

struct uwsgi_plugin graylog2_plugin = {

        .name = "graylog2",
        .on_load = uwsgi_graylog2_register,
	.init = uwsgi_graylog2_init

};

