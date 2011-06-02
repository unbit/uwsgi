/* async http protocol parser */

#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

static uint16_t http_add_uwsgi_header(struct wsgi_request *wsgi_req, char *hh, int hhlen) {

	char *buffer = wsgi_req->buffer + wsgi_req->uh.pktsize;
	char *watermark = wsgi_req->buffer + uwsgi.buffer_size;

	int i;
	int status = 0;
	char *val = hh;
	uint16_t keylen = 0, vallen = 0;
	int prefix = 0;
	char *ptr = buffer;

	for (i = 0; i < hhlen; i++) {
		if (!status) {
			hh[i] = toupper((int) hh[i]);
			if (hh[i] == '-')
				hh[i] = '_';
			if (hh[i] == ':') {
				status = 1;
				keylen = i;
			}
		}
		else if (status == 1 && hh[i] != ' ') {
			status = 2;
			val += i;
			vallen++;
		}
		else if (status == 2) {
			vallen++;
		}
	}

	if (!keylen)
		return 0;

	if (uwsgi_strncmp("CONTENT_TYPE", 12, hh, keylen) && uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		keylen += 5;
		prefix = 1;
	}
	else if (!uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		wsgi_req->post_cl = uwsgi_str_num(val, vallen);
	}

	if (buffer + keylen + vallen + 2 + 2 >= watermark) {
		if (prefix) {
			uwsgi_log("[WARNING] unable to add HTTP_%.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, hh, vallen, val);
		}
		else {
			uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, hh, vallen, val);
		}
		return 0;
	}


	*ptr++ = (uint8_t) (keylen & 0xff);
	*ptr++ = (uint8_t) ((keylen >> 8) & 0xff);

	if (prefix) {
		memcpy(ptr, "HTTP_", 5);
		ptr += 5;
		memcpy(ptr, hh, keylen - 5);
		ptr += (keylen - 5);
	}
	else {
		memcpy(ptr, hh, keylen);
		ptr += keylen;
	}

	*ptr++ = (uint8_t) (vallen & 0xff);
	*ptr++ = (uint8_t) ((vallen >> 8) & 0xff);
	memcpy(ptr, val, vallen);

#ifdef UWSGI_DEBUG
	uwsgi_log("add uwsgi var: %.*s = %.*s\n", keylen - (prefix * 5), hh, vallen, val);
#endif

	return 2 + keylen + 2 + vallen;
}


static int http_parse(struct wsgi_request *wsgi_req, char *watermark) {

	char *ptr = wsgi_req->proto_parser_buf;
	char *base = ptr;
	char *query_string = NULL;
	char ip[INET_ADDRSTRLEN+1];
	struct sockaddr_in *http_sin = (struct sockaddr_in *) &wsgi_req->c_addr;

	// REQUEST_METHOD 
	while (ptr < watermark) {
		if (*ptr == ' ') {
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_METHOD", 14, base, ptr - base);
			ptr++;
			break;
		}
		ptr++;
	}

	// REQUEST_URI / PATH_INFO / QUERY_STRING
	base = ptr;
	while (ptr < watermark) {
		if (*ptr == '?' && !query_string) {
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, base, ptr - base);
			query_string = ptr + 1;
		}
		else if (*ptr == ' ') {
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11, base, ptr - base);
			if (!query_string) {
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, base, ptr - base);
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "QUERY_STRING", 12, "", 0);
			}
			else {
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "QUERY_STRING", 12, query_string, ptr - query_string);
			}
			ptr++;
			break;
		}
		ptr++;
	}

	// SERVER_PROTOCOL
	base = ptr;
	while (ptr < watermark) {
		if (*ptr == '\r') {
			if (ptr + 1 >= watermark)
				return 0;
			if (*(ptr + 1) != '\n')
				return 0;
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_PROTOCOL", 15, base, ptr - base);
			ptr += 2;
			break;
		}
		ptr++;
	}

	// SCRIPT_NAME
	wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SCRIPT_NAME", 11, "", 0);

	// SERVER_NAME
	wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len);

	// SERVER_PORT
	wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, "3031", 4);

	// REMOTE_ADDR
	memset(ip, 0, INET_ADDRSTRLEN+1);
	if (inet_ntop(AF_INET, (void *) &http_sin->sin_addr.s_addr, ip, INET_ADDRSTRLEN)) {
		wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REMOTE_ADDR", 11, ip, strlen(ip));
	}
	else {
		uwsgi_error("inet_ntop()");
	}

	//HEADERS
	base = ptr;

	while (ptr < watermark) {
		if (*ptr == '\r') {
			if (ptr + 1 >= watermark)
				return 0;
			if (*(ptr + 1) != '\n')
				return 0;
			// multiline header ?
			if (ptr + 2 < watermark) {
				if (*(ptr + 2) == ' ' || *(ptr + 2) == '\t') {
					ptr += 2;
					continue;
				}
			}
			wsgi_req->uh.pktsize += http_add_uwsgi_header(wsgi_req, base, ptr - base);
			ptr++;
			base = ptr + 1;
		}
		ptr++;
	}

	return 0;

}



int uwsgi_proto_http_parser(struct wsgi_request *wsgi_req) {

	ssize_t len;
	int j;
	char *ptr;
	ssize_t remains;
	// make this buffer configurable
	char post_buf[8192];

	// first round ? this memory area will be freed by async_loop
	if (!wsgi_req->proto_parser_buf) {
		wsgi_req->proto_parser_buf = uwsgi_malloc(uwsgi.buffer_size);
	}

	if (wsgi_req->post_cl) {
		remains = wsgi_req->post_cl - wsgi_req->proto_parser_pos;
		if (remains > 0) {
			remains = UMIN(remains, 8192);
			len = read(wsgi_req->poll.fd, post_buf, remains);
			if (len <= 0) {
				uwsgi_error("read()");
				fclose(wsgi_req->async_post);
				return -1;
			}

			if (!fwrite(post_buf, len, 1, wsgi_req->async_post)) {
				uwsgi_error("fwrite()");
				fclose(wsgi_req->async_post);
				return -1;
			}
			wsgi_req->proto_parser_pos += len;

			if (wsgi_req->proto_parser_pos < wsgi_req->post_cl)
				return UWSGI_AGAIN;

		}
		rewind(wsgi_req->async_post);
		wsgi_req->body_as_file = 1;
		return UWSGI_OK;
	}

	len = read(wsgi_req->poll.fd, wsgi_req->proto_parser_buf + wsgi_req->proto_parser_pos, uwsgi.buffer_size - wsgi_req->proto_parser_pos);
	if (len <= 0) {
		free(wsgi_req->proto_parser_buf);
		uwsgi_error("recv()");
		return -1;
	}

	ptr = wsgi_req->proto_parser_buf + wsgi_req->proto_parser_pos;

	wsgi_req->proto_parser_pos += len;

	for (j = 0; j < len; j++) {
		if (*ptr == '\r' && (wsgi_req->proto_parser_status == 0 || wsgi_req->proto_parser_status == 2)) {
			wsgi_req->proto_parser_status++;
		}
		else if (*ptr == '\r') {
			wsgi_req->proto_parser_status = 1;
		}
		else if (*ptr == '\n' && wsgi_req->proto_parser_status == 1) {
			wsgi_req->proto_parser_status = 2;
		}
		else if (*ptr == '\n' && wsgi_req->proto_parser_status == 3) {
			ptr++;
			remains = len - (j + 1);
			http_parse(wsgi_req, ptr);
			//is there a Content_Length ?
			if (wsgi_req->post_cl) {
				wsgi_req->async_post = tmpfile();
				if (!wsgi_req->async_post) {
					free(wsgi_req->proto_parser_buf);
					uwsgi_error("tmpfile()");
					return -1;
				}
				wsgi_req->proto_parser_pos = 0;
				remains = UMIN((size_t) remains, wsgi_req->post_cl);
				if (remains) {
					if (!fwrite(ptr, remains, 1, wsgi_req->async_post)) {
						free(wsgi_req->proto_parser_buf);
						uwsgi_error("fwrite()");
						fclose(wsgi_req->async_post);
						return -1;
					}
					wsgi_req->proto_parser_pos += remains;
					if (wsgi_req->proto_parser_pos >= wsgi_req->post_cl) {
						free(wsgi_req->proto_parser_buf);
						rewind(wsgi_req->async_post);
						wsgi_req->body_as_file = 1;
						return UWSGI_OK;
					}
				}
				return UWSGI_AGAIN;
			}
			free(wsgi_req->proto_parser_buf);
			return UWSGI_OK;
		}
		else {
			wsgi_req->proto_parser_status = 0;
		}
		ptr++;
	}

	return UWSGI_AGAIN;
}

ssize_t uwsgi_proto_http_writev_header(struct wsgi_request * wsgi_req, struct iovec * iovec, size_t iov_len) {
	return writev(wsgi_req->poll.fd, iovec, iov_len);
}

ssize_t uwsgi_proto_http_writev(struct wsgi_request * wsgi_req, struct iovec * iovec, size_t iov_len) {
	return writev(wsgi_req->poll.fd, iovec, iov_len);
}

ssize_t uwsgi_proto_http_write(struct wsgi_request * wsgi_req, char *buf, size_t len) {
	return write(wsgi_req->poll.fd, buf, len);
}

ssize_t uwsgi_proto_http_write_header(struct wsgi_request * wsgi_req, char *buf, size_t len) {
	return write(wsgi_req->poll.fd, buf, len);
}
