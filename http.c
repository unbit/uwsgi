#include "uwsgi.h"

struct uwsgi_server uwsgi;

struct uwsgi_http_req {
	
	pthread_t a_new_thread;
	int fd;
	struct sockaddr_in c_addr;
	socklen_t c_len;
};

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

void http_end() {
	uwsgi_log("closing uWSGI embedded HTTP server.\n");
	exit(0);
}

void http_wait_end() {
	pid_t wp_p;
	int wp_c;
	wp_p = waitpid(-1, &wp_c, 0); 
	uwsgi_log("closing uWSGI embedded HTTP server.\n");
	exit(0);
}

static char *add_uwsgi_var(char *up, char *key, uint16_t keylen, char *val, uint16_t vallen, int header, char *watermark)
{

	int i;

	if (!header) {

		if ( (up + 2 + keylen + 2 + vallen) > watermark ) return up ;

		*up++ = (unsigned char) (keylen & 0xff);
		*up++ = (unsigned char) ((keylen >> 8) & 0xff);

		memcpy(up, key, keylen);
		up += keylen;
	} else {


		for (i = 0; i < keylen; i++) {
			if (key[i] == '-') {
				key[i] = '_';
			} else {
				key[i] = toupper( (int) key[i]);
			}
		}

		if (strncmp("CONTENT_TYPE", key, keylen) && strncmp("CONTENT_LENGTH", key, keylen)) {
			if ( (up + 2 + keylen + 5 + 2 + vallen) > watermark ) return up ;
			*up++ = (unsigned char) (((uint16_t) keylen + 5) & 0xff);
			*up++ = (unsigned char) ((((uint16_t) keylen + 5) >> 8) & 0xff);
			memcpy(up, "HTTP_", 5);
			up += 5;
		} else {
			if ( (up + 2 + keylen + 2 + vallen) > watermark ) return up ;
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

static void *http_request(void *);

void http_loop(struct uwsgi_server * uwsgi)
{


	struct uwsgi_http_req *ur;
	int ret;
	pthread_attr_t pa;
	int stat_loc ;

	ret = pthread_attr_init(&pa);
	if (ret) {
		uwsgi_log("pthread_attr_init() = %d\n", ret);
		exit(1);
	}

	ret = pthread_attr_setdetachstate(&pa, PTHREAD_CREATE_DETACHED);
	if (ret) {
		uwsgi_log("pthread_attr_setdetachstate() = %d\n", ret);
		exit(1);
	}

	// ignore broken pipes;
	signal(SIGPIPE, SIG_IGN);
	if (!uwsgi->http_only) {
		signal(SIGCHLD, &http_end);
		signal(SIGINT, &http_wait_end);
	}
	else {
		signal(SIGINT, &http_end);
	}

	uwsgi->http_server_name = malloc(256);
	if (!uwsgi->http_server_name) {
		uwsgi_error("malloc()");
		exit(1);
	}

	memset(uwsgi->http_server_name, 0, 256);
	if (gethostname(uwsgi->http_server_name, 255)) {
		uwsgi_error("gethostname()");
		memcpy(uwsgi->http_server_name, "localhost", 9);
	}

	uwsgi_log("starting HTTP loop on %s (pid: %d)\n", uwsgi->http_server_name, (int) getpid());
	for(;;) {

		if (!uwsgi->http_only) {
			if (waitpid(-1, &stat_loc, WNOHANG) != 0) {
				http_end();
			}
		}
		ur = malloc(sizeof(struct uwsgi_http_req));
		if (!ur) {
			uwsgi_error("malloc()");
			sleep(1);
			continue;
		}
		ur->c_len = sizeof(struct sockaddr_in) ;
		ur->fd = accept(uwsgi->http_fd, (struct sockaddr *) &ur->c_addr, &ur->c_len);

		if (ur->fd < 0) {
			uwsgi_error("accept()");
			free(ur);
			continue;
		}

		ret = pthread_create(&ur->a_new_thread, &pa, http_request, (void *) ur);
		if (ret) {
			uwsgi_log("pthread_create() = %d\n", ret);
			free(ur);
			// sleep a bit to allow some resource gaining
			sleep(1);
			continue;
		}
	}
}


static void *http_request(void *u_h_r)
{

	char buf[4096];

	char tmp_buf[4096];

	char uwsgipkt[4096];

	struct uwsgi_http_req *ur = (struct uwsgi_http_req *) u_h_r ;

	int clientfd = ur->fd;
	int uwsgi_fd = -1;

	int need_to_read = 1;
	int state = uwsgi_http_method;

	int http_body_len = 0;

	size_t len;

	int i, j;

	char HTTP_header_key[1024];

	uint16_t ulen;

	char *ptr = tmp_buf;

	int qs = 0;

	char *up = uwsgipkt;

	char *watermark = up + 4096 ;
	char *watermark2 = tmp_buf + 4096 ;
	
	int path_info_len;
	char *ip;

	up[0] = 0;
	up[3] = 0;
	up += 4;

	while (need_to_read) {
		len = read(clientfd, buf, 4096);
		if (len <= 0) {
			uwsgi_error("read()");
			break;
		}
		for (i = 0; i < (int) len; i++) {

			if (buf[i] == ' ') {

				if (state == uwsgi_http_method) {

					up = add_uwsgi_var(up, "REQUEST_METHOD", 14, tmp_buf, ptr - tmp_buf, 0, watermark);
					ptr = tmp_buf;
					state = uwsgi_http_uri;

				} else if (state == uwsgi_http_uri) {

					up = add_uwsgi_var(up, "REQUEST_URI", 11, tmp_buf, ptr - tmp_buf, 0, watermark);

					path_info_len = ptr - tmp_buf;
					for (j = 0; j < ptr - tmp_buf; j++) {
						if (tmp_buf[j] == '?') {
							path_info_len = j;
							if (j + 1 < (ptr - tmp_buf)) {
								up = add_uwsgi_var(up, "QUERY_STRING", 12, tmp_buf + j + 1, (ptr - tmp_buf) - (j + 1), 0, watermark);
								qs = 1 ;
							}
							break;
						}
					}

					if (!qs) {
						up = add_uwsgi_var(up, "QUERY_STRING", 12, NULL, 0, 0, watermark);
					}
					up = add_uwsgi_var(up, "PATH_INFO", 9, tmp_buf, path_info_len, 0, watermark);

					ptr = tmp_buf;
					state = uwsgi_http_protocol;

				} else if (state == uwsgi_http_header_key_colon) {

					if (ptr+1 > watermark2) { close(uwsgi_fd); goto clear;}
					*ptr++ = 0;

					memset(HTTP_header_key, 0, sizeof(HTTP_header_key));
					memcpy(HTTP_header_key, tmp_buf, strlen(tmp_buf));
					ptr = tmp_buf;
					state = uwsgi_http_header_val;
				} else {
					//check for overflow
					if (ptr+1 > watermark2) { close(uwsgi_fd); goto clear;}
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

					up = add_uwsgi_var(up, HTTP_header_key, strlen(HTTP_header_key), tmp_buf, ptr - tmp_buf, 1, watermark);
					if (!strcmp("CONTENT_LENGTH", HTTP_header_key)) {
						if (ptr+1 > watermark2) { close(uwsgi_fd); goto clear;}
						*ptr++ = 0;
						http_body_len = atoi(tmp_buf);
					}
					ptr = tmp_buf;
					state = uwsgi_http_header_key;
				} else if (state == uwsgi_http_protocol_r) {

					up = add_uwsgi_var(up, "SERVER_PROTOCOL", 15, tmp_buf, ptr - tmp_buf, 0, watermark);
					ptr = tmp_buf;
					state = uwsgi_http_header_key;
				} else if (state == uwsgi_http_end) {
					need_to_read = 0;


					up = add_uwsgi_var(up, "SERVER_NAME", 11, uwsgi.http_server_name, strlen(uwsgi.http_server_name), 0, watermark);
					up = add_uwsgi_var(up, "SERVER_PORT", 11, uwsgi.http_server_port, strlen(uwsgi.http_server_port), 0, watermark);

					up = add_uwsgi_var(up, "SCRIPT_NAME", 11, "", 0, 0, watermark);

					ip = inet_ntoa(ur->c_addr.sin_addr);
					up = add_uwsgi_var(up, "REMOTE_ADDR", 11, ip, strlen(ip), 0, watermark);

					//up = add_uwsgi_var(up, "REMOTE_ADDR", 11, "127.0.0.1", 9, 0, watermark);
					//up = add_uwsgi_var(up, "REMOTE_USER", 11, "unknown", 7, 0);

					for(j=0;j<uwsgi.http_vars_cnt;j++) {
						char *separator;
						
						separator = strchr(uwsgi.http_vars[j], '=');
						if (separator) {
							up = add_uwsgi_var(up, uwsgi.http_vars[j], separator - uwsgi.http_vars[j], separator + 1, strlen(separator + 1), 0, watermark);
						}
						else {
							up = add_uwsgi_var(up, uwsgi.http_vars[j], strlen(uwsgi.http_vars[j]), NULL, 0, 0, watermark);
						}
					}

					uwsgi_fd = uwsgi_connect(uwsgi.socket_name, 10);
					if (uwsgi_fd >= 0) {
						ulen = (up - uwsgipkt) - 4;
						uwsgipkt[1] = (unsigned char) (ulen & 0xff);
						uwsgipkt[2] = (unsigned char) ((ulen >> 8) & 0xff);

						if (write(uwsgi_fd, uwsgipkt, ulen + 4) < 0) {
							uwsgi_error("write()");
						}

						if (http_body_len > 0) {
							if (http_body_len >= (int) len - (i + 1)) {
								if (write(uwsgi_fd, buf + i + 1, len - (i + 1)) < 0) {
									uwsgi_error("write()");
								}
								http_body_len -= len - (i + 1);
							} else {
								if (write(uwsgi_fd, buf + i, http_body_len) < 0) {
									uwsgi_error("write()");
								}
								http_body_len = 0;
							}

							while (http_body_len > 0) {
								int to_read = 4096;
								if (http_body_len < to_read) {
									to_read = http_body_len;
								}
								len = read(clientfd, uwsgipkt, to_read);
								if (write(uwsgi_fd, uwsgipkt, len) < 0) {
									uwsgi_error("write()");
								}
								http_body_len -= len;
							}
						}
						while ((len = read(uwsgi_fd, uwsgipkt, 4096)) > 0) {
							if (write(clientfd, uwsgipkt, len) < 0) {
								uwsgi_error("write()");
							}
						}
						close(uwsgi_fd);
					}
					else {
						close(uwsgi_fd);
						goto clear;
					}
				}
			} else if (buf[i] == ':') {

				if (state == uwsgi_http_header_key) {
					state = uwsgi_http_header_key_colon;
				} else {
					//check for overflow
					if (ptr+1 > watermark2) { close(uwsgi_fd); goto clear;}
					*ptr++ = buf[i];
				}
			} else {

				//check for overflow
				if (ptr+1 > watermark2) { close(uwsgi_fd); goto clear;}
				*ptr++ = buf[i];
			}

		}

	}

clear:
	close(clientfd);

	free(ur);
	pthread_exit(NULL);
	
	return NULL;
}
