#include <uwsgi.h>

#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

struct fcgi_record {
	unsigned char version;
	unsigned char type;
	unsigned char requestIdB1;
	unsigned char requestIdB0;
	unsigned char contentLengthB1;
	unsigned char contentLengthB0;
	unsigned char paddingLength;
	unsigned char reserved;
	char *data;
} FCGI_Record;

static int fcgi_send(struct wsgi_request *wsgi_req, char *addr, struct uwsgi_buffer *ub, int timeout) {
	int fd = uwsgi_connect(addr, 0, 1);
	if (fd < 0)
		return -1;

	int ret = uwsgi.wait_write_hook(fd, timeout);
	if (ret <= 0)
		goto error;

	if (uwsgi_write_true_nb(fd, ub->buf, ub->pos, timeout))
		goto error;

	return fd;

error:
	close(fd);
	return -1;
}

static int uwsgi_routing_func_fcgi(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {
	struct uwsgi_buffer *ub = NULL, *headers = NULL;
	int ret = UWSGI_ROUTE_BREAK;
	int inbody = 0;

	// mark a route request
        wsgi_req->via = UWSGI_VIA_ROUTE;

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

	struct uwsgi_buffer *ub_addr = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, ur->data, ur->data_len);
	if (!ub_addr) return UWSGI_ROUTE_BREAK;

	// convert the wsgi_request to an fcgi request
	ub = uwsgi_to_fastcgi(wsgi_req, ur->custom ? FCGI_AUTHORIZER : FCGI_RESPONDER);

	if (!ub) {
		uwsgi_log("unable to generate fcgi request for %s\n", ub_addr->buf);
		uwsgi_buffer_destroy(ub_addr);
                return UWSGI_ROUTE_BREAK;
	}

	int fd = 0;

	fd = fcgi_send(wsgi_req, ub_addr->buf, ub, uwsgi.socket_timeout);
	uwsgi_buffer_destroy(ub);
	ub = NULL;

	if (fd == -1) {
		uwsgi_log("error routing request to fcgi server %s\n", ub_addr->buf);
		goto end;
	}

	headers = uwsgi_buffer_new(uwsgi.page_size);
	char buf[8192];
	char *ptr = buf;//, *rptr = NULL;
	ssize_t left = 0, n = 0, p = 0;
	int oversized = 0, done = 0;


	for (;;) {
                int r = uwsgi_waitfd(fd, uwsgi.socket_timeout);
                if (r <= 0) goto end;

		ssize_t rlen = 0;
		/* Amount left in buffer is not a full record header, so we
		 * need to fudge the next read to append to the current buffer. */
		if ((sizeof(buf) - (ptr - buf) - left) < 8) {
			memmove(buf, ptr, left);
			ptr = buf;
		}

		if ((!done || !left) && (sizeof(buf) - (ptr - buf) - left) > 0) {
			rlen = read(fd, ptr + left, sizeof(buf) - (ptr - buf) - left);

			if (rlen < 0)
				break;
			if (rlen == 0)
				done = 1;
		}

		if (done && !left) {
			uwsgi_log("[fastcgi] %s: truncated response\n", ub_addr->buf);
			goto end;
		}

		if (oversized) { /* n more bytes left in stdout record */
			if (uwsgi_response_write_body_do(wsgi_req, (char *) ptr, n > rlen ? rlen : n))
				goto end;

			if (n > rlen) {
				n -= rlen;
				ptr = buf;
				left = 0;
				continue;
			} else if (n == rlen) {
				oversized = 0;
				left = 0;
				ptr = buf;
				continue;
			} else {
				ptr += n;
				left = rlen - n;
				oversized = 0;
				continue;
			}
		} else {
			left += rlen;
		}

		while (left >= 8 && !oversized) {
			if (p) {
				if (left >= p) {
					left -= p;
					ptr += p;
					p = 0;
					continue;
				}
			}

			if (ptr[0] != 1) { /* version */
				uwsgi_log("[fastcgi] %s: unexpected protocol version %u\n", ub_addr->buf, (unsigned int) ptr[0]);
				goto end;
			}
			if (ptr[2] != 0 || ptr[3] != 1) { /* reqid */
				uwsgi_log("[fastcgi] %s: unexpected request id %d\n", ub_addr->buf, (int) ptr[3]);
				goto end;
			}
			n = (int)((unsigned char *)ptr)[4] << 8 | (int)((unsigned char *)ptr)[5];
			p = (int)((unsigned char *)ptr)[6];

			int type = ptr[1];
			ptr += 8;
			left -= 8;
			switch (type) {
			case FCGI_END_REQUEST:
				break;

			case FCGI_STDERR:
				uwsgi_log("[fastcgi] %s: stderr: %*s\n", ub_addr->buf, (int) (n > left ? left : n), ptr);
				if ((n + p) > left) {
					uwsgi_log("[fastcgi] %s: short record, (%d + %d) < %d\n", ub_addr->buf, (int) n, (int) p, (int) left);
					goto end;
				}
				ptr += (n + p);
				left -= (n + p);
				break;

			case FCGI_STDOUT:
				if (n == 0)
					goto end;

				if (!inbody) {
					ssize_t now = n < left ? n : left;
					if (uwsgi_buffer_append(headers, (char *) ptr, now))
						goto end;

					// check if we have a full HTTP response
					if (uwsgi_is_full_http(headers)) {
						inbody = 1;
						if (ur->custom && http_status_code(headers->buf, headers->pos) == 200) {
							ret = UWSGI_ROUTE_NEXT;
							/* XXX - add Variable headers */
							goto end;
						} else {
							uwsgi_blob_to_response(wsgi_req, headers->buf, headers->pos);
						}
						uwsgi_buffer_destroy(headers);
						headers = NULL;
					} else {
						/* we can't buffer > sizeof(buf) of headers - shouldn't be
						 * needed anyway. */
						if (n > left) {
							uwsgi_log("[fastcgi] %s: headers too long (%d)\n", ub_addr->buf, (int) n);
							goto end;
						}
					}

					ptr += now;
					left -= now;
					n -= now;
				}

				if (n) {
					ssize_t nleft = n > left ? left : n; /* min(left in buffer, record size) */
					if (uwsgi_response_write_body_do(wsgi_req, (char *) ptr, nleft))
						goto end;
					n -= nleft;
					left -= nleft;
					ptr += nleft;

					if (n > left) { /* more data in this record */
						oversized = 1;
						left = 0;
						ptr = buf;
						continue;
					}
				}

				break;

			default:
				uwsgi_log("[fastcgi] %s: unknown record type %d\n", ub_addr->buf, (int) ptr[1]);
				goto end;
			}
		}

		if (left == 0)
			ptr = buf;
	}

end:
	if (fd) close(fd);
	if (ub_addr) uwsgi_buffer_destroy(ub_addr);
	if (headers) uwsgi_buffer_destroy(headers);
	return ret;
}

static int uwsgi_router_fcgi(struct uwsgi_route *ur, char *args) {

	ur->func = uwsgi_routing_func_fcgi;
	ur->data = (void *) args;
	ur->data_len = strlen(args);
	return 0;
}

static int uwsgi_router_fcgiauth(struct uwsgi_route *ur, char *args) {

	ur->func = uwsgi_routing_func_fcgi;
	ur->data = (void *) args;
	ur->data_len = strlen(args);
	ur->custom = 1;
	return 0;
}
	
static void router_fcgi_register(void) {
	uwsgi_register_router("fcgiauth", uwsgi_router_fcgiauth);
	uwsgi_register_router("fcgi", uwsgi_router_fcgi);
}

struct uwsgi_plugin router_fcgi_plugin = {
	.name = "router_fcgi",
	.on_load = router_fcgi_register,
};
#else
struct uwsgi_plugin router_fcgi_plugin = {
	.name = "router_fcgi",
};
#endif
