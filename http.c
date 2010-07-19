#include "uwsgi.h"

struct uwsgi_server uwsgi;

enum {
	uwsgi_http_method,
	uwsgi_http_uri,
	uwsgi_http_protocol,
	uwsgi_http_protocol_r,

	uwsgi_http_header_key,
	uwsgi_http_header_key_colon,

	uwsgi_http_header_val,
	uwsgi_http_header_val_r,

	uwsgi_http_end
};

static char *add_uwsgi_var(char *up, char *key, uint16_t keylen, char *val, uint16_t vallen, int header)
{

	int i;

	if (!header) {
		*up++ = (unsigned char) (keylen & 0xff);
		*up++ = (unsigned char) ((keylen >> 8) & 0xff);

		memcpy(up, key, keylen);
		up += keylen;
	} else {


		for (i = 0; i < keylen; i++) {
			if (key[i] == '-') {
				key[i] = '_';
			} else {
				key[i] = toupper(key[i]);
			}
		}

		if (strncmp("CONTENT_TYPE", key, keylen) && strncmp("CONTENT_LENGTH", key, keylen)) {
			*up++ = (unsigned char) (((uint16_t) keylen + 5) & 0xff);
			*up++ = (unsigned char) ((((uint16_t) keylen + 5) >> 8) & 0xff);
			memcpy(up, "HTTP_", 5);
			up += 5;
		} else {
			*up++ = (unsigned char) (keylen & 0xff);
			*up++ = (unsigned char) ((keylen >> 8) & 0xff);
		}


		memcpy(up, key, keylen);
		up += keylen;
	}

	*up++ = (unsigned char) (vallen & 0xff);
	*up++ = (unsigned char) ((vallen >> 8) & 0xff);
	memcpy(up, val, vallen);
	up += vallen;

	return up;
}

void *http_request(void *);

void http_loop(struct uwsgi_server * uwsgi)
{


	int clientfd;

	struct sockaddr_in c_addr;
	socklen_t c_len;

	pthread_t a_new_thread[200];
	int c = 0 ;

	while ((clientfd = accept(uwsgi->http_fd, (struct sockaddr *) & c_addr, &c_len)) >= 0) {

		uwsgi_log("!!! ACCEPTED !!!\n");

		pthread_create(&a_new_thread[c], NULL, http_request, (void *) &clientfd);
		c++;

		uwsgi_log("READY TO ACCEPT\n");
	}
}


void *http_request(void *fd)
{

	char buf[4096];

	char tmp_buf[4096];
	char *ptr;

	char uwsgipkt[4096];
	char *up;

	int *clientfd_ptr = (int *) fd;

	int clientfd = *clientfd_ptr;
	int uwsgi_fd;

	int need_to_read = 1;
	int state = uwsgi_http_method;

	int http_body_len = 0;

	size_t len;

	int i,
	 j;

	char HTTP_header_key[1024];

	uint16_t ulen;

	struct sockaddr_in c_addr;
	socklen_t c_len;

	ptr = tmp_buf;

	up = uwsgipkt;


	up[0] = 0;
	up[3] = 0;
	up += 4;

	getpeername(clientfd, (struct sockaddr *) & c_addr, &c_len);

	while (need_to_read) {
		len = read(clientfd, buf, 4096);
		for (i = 0; i < len; i++) {

			if (buf[i] == ' ') {

				if (state == uwsgi_http_method) {

					up = add_uwsgi_var(up, "REQUEST_METHOD", 14, tmp_buf, ptr - tmp_buf, 0);
					ptr = tmp_buf;
					state = uwsgi_http_uri;

				} else if (state == uwsgi_http_uri) {

					up = add_uwsgi_var(up, "REQUEST_URI", 11, tmp_buf, ptr - tmp_buf, 0);

					int path_info_len = ptr - tmp_buf;
					for (j = 0; j < ptr - tmp_buf; j++) {
						if (tmp_buf[j] == '?') {
							path_info_len = j;
							if (j + 1 < (ptr - tmp_buf)) {
								up = add_uwsgi_var(up, "QUERY_STRING", 12, tmp_buf + j + 1, (ptr - tmp_buf) - (j + 1), 0);
							}
							break;
						}
					}
					up = add_uwsgi_var(up, "PATH_INFO", 9, tmp_buf, path_info_len, 0);

					ptr = tmp_buf;
					state = uwsgi_http_protocol;

				} else if (state == uwsgi_http_header_key_colon) {

					*ptr++ = 0;

					memset(HTTP_header_key, 0, sizeof(HTTP_header_key));
					memcpy(HTTP_header_key, tmp_buf, strlen(tmp_buf));
					ptr = tmp_buf;
					state = uwsgi_http_header_val;
				} else {
					//check for overflow
						*ptr++ = buf[i];
				}

			} else if (buf[i] == '\r') {

				if (state == uwsgi_http_protocol) {
					state = uwsgi_http_protocol_r;
				}
				if (state == uwsgi_http_header_val) {
					state = uwsgi_http_header_val_r;
				} else if (state == uwsgi_http_header_key) {
					state = uwsgi_http_end;
				}
			} else if (buf[i] == '\n') {

				if (state == uwsgi_http_header_val_r) {

					up = add_uwsgi_var(up, HTTP_header_key, strlen(HTTP_header_key), tmp_buf, ptr - tmp_buf, 1);
					if (!strcmp("CONTENT_LENGTH", HTTP_header_key)) {
						*ptr++ = 0;
						http_body_len = atoi(tmp_buf);
					}
					ptr = tmp_buf;
					state = uwsgi_http_header_key;
				} else if (state == uwsgi_http_protocol_r) {

					up = add_uwsgi_var(up, "SERVER_PROTOCOL", 15, tmp_buf, ptr - tmp_buf, 0);
					ptr = tmp_buf;
					state = uwsgi_http_header_key;
				} else if (state == uwsgi_http_end) {
					need_to_read = 0;


					if (uwsgi.http_server_name) {
						up = add_uwsgi_var(up, "SERVER_NAME", 11, uwsgi.http_server_name, strlen(uwsgi.http_server_name), 0);
					} else {
						up = add_uwsgi_var(up, "SERVER_NAME", 11, "localhost", 9, 0);
					}

					up = add_uwsgi_var(up, "SERVER_PORT", 11, uwsgi.http_server_port, strlen(uwsgi.http_server_port), 0);
					up = add_uwsgi_var(up, "SCRIPT_NAME", 11, "", 0, 0);

					char *ip = inet_ntoa(c_addr.sin_addr);
					up = add_uwsgi_var(up, "REMOTE_ADDR", 11, ip, strlen(ip), 0);

					uwsgi_fd = uwsgi_connect(uwsgi.socket_name, 10);
					if (uwsgi_fd >= 0) {
						ulen = (up - uwsgipkt) - 4;
						uwsgipkt[1] = (unsigned char) (ulen & 0xff);
						uwsgipkt[2] = (unsigned char) ((ulen >> 8) & 0xff);

						write(uwsgi_fd, uwsgipkt, ulen + 4);

						if (http_body_len > 0) {
							if (http_body_len >= len - (i + 1)) {
								write(uwsgi_fd, buf + i + 1, len - (i + 1));
								http_body_len -= len - (i + 1);
							} else {
								write(uwsgi_fd, buf + i, http_body_len);
								http_body_len = 0;
							}

							while (http_body_len > 0) {
								int to_read = 4096;
								if (http_body_len < to_read) {
									to_read = http_body_len;
								}
								len = read(clientfd, uwsgipkt, to_read);
								write(uwsgi_fd, uwsgipkt, len);
								http_body_len -= len;
							}
						}
						while ((len = read(uwsgi_fd, uwsgipkt, 4096)) > 0) {
							write(clientfd, uwsgipkt, len);
						}
						close(uwsgi_fd);
					}
				}
			} else if (buf[i] == ':') {

				if (state == uwsgi_http_header_key) {
					state = uwsgi_http_header_key_colon;
				} else {
					//check for overflow
						*ptr++ = buf[i];
				}
			} else {

				//check for overflow
					//uwsgi_log("CHAR: %d: %d\n", i, buf[i]);
				*ptr++ = buf[i];
				//uwsgi_log("PTR: %d\n", *ptr);
			}

		}

	}

	close(clientfd);

	uwsgi_log("HTTP CONNECTION CLOSED WITH: %d\n", clientfd);
	return NULL;
}
