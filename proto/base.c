
#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

uint16_t proto_base_add_uwsgi_header(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, char *val, uint16_t vallen) {


	int i;
	char *buffer = wsgi_req->buffer + wsgi_req->uh->pktsize;
	char *watermark = wsgi_req->buffer + uwsgi.buffer_size;
	char *ptr = buffer;


	for (i = 0; i < keylen; i++) {
		if (key[i] == '-') {
			key[i] = '_';
		}
		else {
			key[i] = toupper((int)key[i]);
		}
	}

	if (uwsgi_strncmp("CONTENT_TYPE", 12, key, keylen) && uwsgi_strncmp("CONTENT_LENGTH", 14, key, keylen)) {
		if (buffer + keylen + vallen + 2 + 2 + 5 >= watermark) {
			uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, key, vallen, val);
			return 0;
		}
		*ptr++ = (uint8_t) ((keylen + 5) & 0xff);
		*ptr++ = (uint8_t) (((keylen + 5) >> 8) & 0xff);
		memcpy(ptr, "HTTP_", 5);
		ptr += 5;
		memcpy(ptr, key, keylen);
		ptr += keylen;
		keylen += 5;
	}
	else {
		if (buffer + keylen + vallen + 2 + 2 >= watermark) {
			uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, key, vallen, val);
			return 0;
		}
		*ptr++ = (uint8_t) (keylen & 0xff);
		*ptr++ = (uint8_t) ((keylen >> 8) & 0xff);
		memcpy(ptr, key, keylen);
		ptr += keylen;
	}

	*ptr++ = (uint8_t) (vallen & 0xff);
	*ptr++ = (uint8_t) ((vallen >> 8) & 0xff);
	memcpy(ptr, val, vallen);

#ifdef UWSGI_DEBUG
	uwsgi_log("add uwsgi var: %.*s = %.*s\n", keylen, key, vallen, val);
#endif

	return keylen + vallen + 2 + 2;
}



uint16_t proto_base_add_uwsgi_var(struct wsgi_request * wsgi_req, char *key, uint16_t keylen, char *val, uint16_t vallen) {


	char *buffer = wsgi_req->buffer + wsgi_req->uh->pktsize;
	char *watermark = wsgi_req->buffer + uwsgi.buffer_size;
	char *ptr = buffer;

	if (buffer + keylen + vallen + 2 + 2 >= watermark) {
		uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, key, vallen, val);
		return 0;
	}


	*ptr++ = (uint8_t) (keylen & 0xff);
	*ptr++ = (uint8_t) ((keylen >> 8) & 0xff);
	memcpy(ptr, key, keylen);
	ptr += keylen;

	*ptr++ = (uint8_t) (vallen & 0xff);
	*ptr++ = (uint8_t) ((vallen >> 8) & 0xff);
	memcpy(ptr, val, vallen);

#ifdef UWSGI_DEBUG
	uwsgi_log("add uwsgi var: %.*s = %.*s\n", keylen, key, vallen, val);
#endif

	return keylen + vallen + 2 + 2;
}


int uwsgi_proto_base_accept(struct wsgi_request *wsgi_req, int fd) {

	wsgi_req->c_len = sizeof(struct sockaddr_un);
#if defined(__linux__) && defined(SOCK_NONBLOCK) && !defined(OBSOLETE_LINUX_KERNEL)
        return accept4(fd, (struct sockaddr *) &wsgi_req->c_addr, (socklen_t *) & wsgi_req->c_len, SOCK_NONBLOCK);
#elif defined(__linux__)
	int client_fd = accept(fd, (struct sockaddr *) &wsgi_req->c_addr, (socklen_t *) & wsgi_req->c_len);
	if (client_fd >= 0) {
		uwsgi_socket_nb(client_fd);
	}
	return client_fd;
#else
	return accept(fd, (struct sockaddr *) &wsgi_req->c_addr, (socklen_t *) & wsgi_req->c_len);
#endif
}

void uwsgi_proto_base_close(struct wsgi_request *wsgi_req) {
	close(wsgi_req->fd);
}

struct uwsgi_buffer *uwsgi_proto_base_add_header(struct wsgi_request *wsgi_req, char *k, uint16_t kl, char *v, uint16_t vl) {
	struct uwsgi_buffer *ub = NULL;
	if (kl > 0) {
		ub = uwsgi_buffer_new(kl + 2 + vl + 2);
		if (uwsgi_buffer_append(ub, k, kl)) goto end;
		if (uwsgi_buffer_append(ub, ": ", 2)) goto end;
		if (uwsgi_buffer_append(ub, v, vl)) goto end;
		if (uwsgi_buffer_append(ub, "\r\n", 2)) goto end;
	}
	else {
		ub = uwsgi_buffer_new(vl + 2);
		if (uwsgi_buffer_append(ub, v, vl)) goto end;
                if (uwsgi_buffer_append(ub, "\r\n", 2)) goto end;
	}
	return ub;
end:
	uwsgi_buffer_destroy(ub);
	return NULL;
}

struct uwsgi_buffer *uwsgi_proto_base_prepare_headers(struct wsgi_request *wsgi_req, char *s, uint16_t sl) {
        struct uwsgi_buffer *ub = NULL;
	if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
		if (wsgi_req->protocol_len) {
			ub = uwsgi_buffer_new(wsgi_req->protocol_len + 1 + sl + 2);
			if (uwsgi_buffer_append(ub, wsgi_req->protocol, wsgi_req->protocol_len)) goto end;
			if (uwsgi_buffer_append(ub, " ", 1)) goto end;
		}
		else {
			ub = uwsgi_buffer_new(9 + sl + 2);
			if (uwsgi_buffer_append(ub, "HTTP/1.0 ", 9)) goto end;
		}
	}
	else {
		ub = uwsgi_buffer_new(8 + sl + 2);
		if (uwsgi_buffer_append(ub, "Status: ", 8)) goto end;
	}
        if (uwsgi_buffer_append(ub, s, sl)) goto end;
	if (uwsgi_buffer_append(ub, "\r\n", 2)) goto end;
        return ub;
end:
        uwsgi_buffer_destroy(ub);
        return NULL;
}

struct uwsgi_buffer *uwsgi_proto_base_cgi_prepare_headers(struct wsgi_request *wsgi_req, char *s, uint16_t sl) {
	struct uwsgi_buffer *ub = uwsgi_buffer_new(8 + sl + 2);
	if (uwsgi_buffer_append(ub, "Status: ", 8)) goto end;
        if (uwsgi_buffer_append(ub, s, sl)) goto end;
	if (uwsgi_buffer_append(ub, "\r\n", 2)) goto end;
	return ub;	
end:
	uwsgi_buffer_destroy(ub);
	return NULL;
}


int uwsgi_proto_base_write(struct wsgi_request * wsgi_req, char *buf, size_t len) {
        ssize_t wlen = write(wsgi_req->fd, buf+wsgi_req->write_pos, len-wsgi_req->write_pos);
        if (wlen > 0) {
                wsgi_req->write_pos += wlen;
                if (wsgi_req->write_pos == len) {
                        return UWSGI_OK;
                }
                return UWSGI_AGAIN;
        }
        if (wlen < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                        return UWSGI_AGAIN;
                }
        }
        return -1;
}

int uwsgi_proto_base_sendfile(struct wsgi_request * wsgi_req, int fd, size_t pos, size_t len) {
        ssize_t wlen = uwsgi_sendfile_do(wsgi_req->fd, fd, pos+wsgi_req->write_pos, len-wsgi_req->write_pos);
        if (wlen > 0) {
                wsgi_req->write_pos += wlen;
                if (wsgi_req->write_pos == len) {
                        return UWSGI_OK;
                }
                return UWSGI_AGAIN;
        }
        if (wlen < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                        return UWSGI_AGAIN;
                }
        }
        return -1;
}

int uwsgi_proto_base_fix_headers(struct wsgi_request * wsgi_req) {
        return uwsgi_buffer_append(wsgi_req->headers, "\r\n", 2);
}

ssize_t uwsgi_proto_base_read_body(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	if (wsgi_req->proto_parser_remains > 0) {
		size_t remains = UMIN(wsgi_req->proto_parser_remains, len);
		memcpy(buf, wsgi_req->proto_parser_remains_buf, remains);
		wsgi_req->proto_parser_remains -= remains;
		wsgi_req->proto_parser_remains_buf += remains;
		return remains;
	}
	return read(wsgi_req->fd, buf, len);
}
