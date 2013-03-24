#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_response_add_content_length(struct wsgi_request *wsgi_req, uint64_t cl) {
	char buf[sizeof(UMAX64_STR)+1];
        int ret = snprintf(buf, sizeof(UMAX64_STR)+1, "%llu", (unsigned long long) cl);
        if (ret <= 0 || ret > (int) (sizeof(UMAX64_STR)+1)) {
		wsgi_req->write_errors++;
                return -1;
        }
	return uwsgi_response_add_header(wsgi_req, "Content-Length", 14, buf, ret); 
}

// status could be NNN or NNN message
int uwsgi_response_prepare_headers(struct wsgi_request *wsgi_req, char *status, uint16_t status_len) {

	if (wsgi_req->headers_sent || wsgi_req->headers_size || wsgi_req->response_size || status_len < 3 || wsgi_req->write_errors) return -1;

	if (!wsgi_req->headers) {
		wsgi_req->headers = uwsgi_buffer_new(uwsgi.page_size);
		wsgi_req->headers->limit = UMAX16;
	}

	// reset the buffer (could be useful for rollbacks...)
	wsgi_req->headers->pos = 0;
	struct uwsgi_buffer *hh = NULL;
	if (status_len <= 4) {
		char *new_sc = NULL;
		size_t new_sc_len = 0;
		uint16_t sc_len = 0;
		const char *sc = uwsgi_http_status_msg(status, &sc_len);
		if (sc) {
			new_sc = uwsgi_concat3n(status, 3, " ", 1, (char *)sc, sc_len);
			new_sc_len = 4+sc_len;
		}
		else {	
			new_sc = uwsgi_concat2n(status, 3, " Unknown", 8);
			new_sc_len = 11;
		}
		hh = wsgi_req->socket->proto_prepare_headers(wsgi_req, new_sc, new_sc_len);
		free(new_sc);
	}
	else {
		hh = wsgi_req->socket->proto_prepare_headers(wsgi_req, status, status_len);
	}
	if (!hh) {wsgi_req->write_errors++; return -1;}
        if (uwsgi_buffer_append(wsgi_req->headers, hh->buf, hh->pos)) goto error;
        uwsgi_buffer_destroy(hh);
	wsgi_req->status = uwsgi_str3_num(status);
        return 0;
error:
        uwsgi_buffer_destroy(hh);
	wsgi_req->write_errors++;
	return -1;
}

//each protocol has its header generator
int uwsgi_response_add_header(struct wsgi_request *wsgi_req, char *key, uint16_t key_len, char *value, uint16_t value_len) {

	if (wsgi_req->headers_sent || wsgi_req->headers_size || wsgi_req->response_size || wsgi_req->write_errors) return -1;

	struct uwsgi_string_list *rh = uwsgi.remove_headers;
	while(rh) {
		if (!uwsgi_strnicmp(key, key_len, rh->value, rh->len)) {
			return 0;
		}
		rh = rh->next;
	}
	rh = wsgi_req->remove_headers;
	while(rh) {
		if (!uwsgi_strnicmp(key, key_len, rh->value, rh->len)) {
			return 0;
		}
		rh = rh->next;
	}

	if (!wsgi_req->headers) {
		wsgi_req->headers = uwsgi_buffer_new(uwsgi.page_size);
		wsgi_req->headers->limit = UMAX16;
	}

	struct uwsgi_buffer *hh = wsgi_req->socket->proto_add_header(wsgi_req, key, key_len, value, value_len);
	if (!hh) { wsgi_req->write_errors++ ; return -1;}
	if (uwsgi_buffer_append(wsgi_req->headers, hh->buf, hh->pos)) goto error;
	wsgi_req->header_cnt++;
	uwsgi_buffer_destroy(hh);
	return 0;
error:
	uwsgi_buffer_destroy(hh);
	wsgi_req->write_errors++;
	return -1;
}

int uwsgi_response_write_headers_do(struct wsgi_request *wsgi_req) {
	if (wsgi_req->headers_sent || !wsgi_req->headers || wsgi_req->response_size || wsgi_req->write_errors) {
		return UWSGI_OK;
	}

	struct uwsgi_string_list *ah = uwsgi.additional_headers;
	while(ah) {
		if (uwsgi_response_add_header(wsgi_req, NULL, 0, ah->value, ah->len)) return -1;
                ah = ah->next;
        }

        ah = wsgi_req->additional_headers;
        while(ah) {
		if (uwsgi_response_add_header(wsgi_req, NULL, 0, ah->value, ah->len)) return -1;
                ah = ah->next;
        }


	if (wsgi_req->socket->proto_fix_headers(wsgi_req)) { wsgi_req->write_errors++ ; return -1;}

	for(;;) {
                int ret = wsgi_req->socket->proto_write_headers(wsgi_req, wsgi_req->headers->buf, wsgi_req->headers->pos);
                if (ret < 0) {
                        if (!uwsgi.ignore_write_errors) {
                                uwsgi_error("uwsgi_response_write_headers_do()");
                        }
			wsgi_req->write_errors++;
                        return -1;
                }
                if (ret == UWSGI_OK) {
                        break;
                }
                ret = uwsgi_wait_write_req(wsgi_req);
                if (ret < 0) { wsgi_req->write_errors++; return -1;}
                if (ret == 0) {
			uwsgi_log("uwsgi_response_write_headers_do() TIMEOUT !!!\n");
			wsgi_req->write_errors++;
			return -1;
		}
        }

        wsgi_req->headers_size += wsgi_req->write_pos;
	// reset for the next write
        wsgi_req->write_pos = 0;
	wsgi_req->headers_sent = 1;

        return UWSGI_OK;
}

// this is the function called by all request plugins to send chunks to the client
int uwsgi_response_write_body_do(struct wsgi_request *wsgi_req, char *buf, size_t len) {

	if (wsgi_req->write_errors) return -1;

	if (!wsgi_req->headers_sent) {
		int ret = uwsgi_response_write_headers_do(wsgi_req);
                if (ret == UWSGI_OK) goto sendbody;
                if (ret == UWSGI_AGAIN) return UWSGI_AGAIN;
		wsgi_req->write_errors++;
                return -1;
	}

sendbody:

	if (len == 0) return UWSGI_OK;

	for(;;) {
		int ret = wsgi_req->socket->proto_write(wsgi_req, buf, len);
		if (ret < 0) {
			if (!uwsgi.ignore_write_errors) {
				uwsgi_error("uwsgi_response_write_body_do()");
			}
			wsgi_req->write_errors++;
			return -1;
		}
		if (ret == UWSGI_OK) {
			break;
		}
		ret = uwsgi_wait_write_req(wsgi_req);			
		if (ret < 0) { wsgi_req->write_errors++; return -1;}
                if (ret == 0) {
                        uwsgi_log("uwsgi_response_write_body_do() TIMEOUT !!!\n");
                        wsgi_req->write_errors++;
                        return -1;
                }
	}

	wsgi_req->response_size += wsgi_req->write_pos;
	// reset for the next write
        wsgi_req->write_pos = 0;

	// now we need to check if the chunk must be stored
	if (wsgi_req->cache_it) {
		if (!wsgi_req->cached_response) {
			wsgi_req->cached_response = uwsgi_buffer_new(len);
		}
		// if we are unable to append the buffer, we just stop caching it
		if (uwsgi_buffer_append(wsgi_req->cached_response, buf, len)) {
			uwsgi_buffer_destroy(wsgi_req->cache_it);
			wsgi_req->cache_it = NULL;
		}
	}

	return UWSGI_OK;	
}

int uwsgi_response_sendfile_do(struct wsgi_request *wsgi_req, int fd, size_t pos, size_t len) {

	int can_close = 1;

	if (fd == wsgi_req->sendfile_fd) can_close = 0;

	if (wsgi_req->write_errors) return -1;

	if (!wsgi_req->headers_sent) {
		int ret = uwsgi_response_write_headers_do(wsgi_req);
		if (ret == UWSGI_OK) goto sendfile;
		if (ret == UWSGI_AGAIN) return UWSGI_AGAIN;
		wsgi_req->write_errors++;
		if (can_close) close(fd);
		return -1;
	}

sendfile:

	if (len == 0) {
		struct stat st;
		if (fstat(fd, &st)) {
			uwsgi_error("fstat()");
			wsgi_req->write_errors++;
			if (can_close) close(fd);
			return -1;
		}
		len = st.st_size;
	}

	if (wsgi_req->socket->can_offload) {
		// of we cannot close the socket (before the app will close it later)
		// let's dup it
		if (!can_close) {
			int tmp_fd = dup(fd);
			if (tmp_fd < 0) {
				uwsgi_error("uwsgi_response_sendfile_do()/dup()");
				wsgi_req->write_errors++;
				return -1;
			}
			fd = tmp_fd;
			can_close = 1;
		}
       		if (!uwsgi_offload_request_sendfile_do(wsgi_req, fd, len)) {
                	wsgi_req->via = UWSGI_VIA_OFFLOAD;
			wsgi_req->response_size += len;
                        return 0;
                }
		wsgi_req->write_errors++;
		if (can_close) close(fd);
		return -1;
	}


        wsgi_req->via = UWSGI_VIA_SENDFILE;

        for(;;) {
                int ret = wsgi_req->socket->proto_sendfile(wsgi_req, fd, pos, len);
                if (ret < 0) {
                        if (!uwsgi.ignore_write_errors) {
                                uwsgi_error("uwsgi_response_sendfile_do()");
                        }
			wsgi_req->write_errors++;
			if (can_close) close(fd);
                        return -1;
                }
                if (ret == UWSGI_OK) {
                        break;
                }
                ret = uwsgi_wait_write_req(wsgi_req);
                if (ret < 0) {
			wsgi_req->write_errors++;
			if (can_close) close(fd);
			return -1;
		}
		if (ret == 0) {
                        uwsgi_log("uwsgi_response_sendfile_do() TIMEOUT !!!\n");
                        wsgi_req->write_errors++;
                        return -1;
                }	
        }

        wsgi_req->response_size += wsgi_req->write_pos;
	// reset for the next write
        wsgi_req->write_pos = 0;
	// close the file descriptor
	if (can_close) close(fd);
        return UWSGI_OK;
}


int uwsgi_simple_wait_write_hook(int fd, int timeout) {
	struct pollfd upoll;
        timeout = timeout * 1000;

        upoll.fd = fd;
        upoll.events = POLLOUT;
        upoll.revents = 0;
        int ret = poll(&upoll, 1, timeout);

        if (ret > 0) {
                if (upoll.revents & POLLOUT) {
                        return 1;
                }
                return -1;
        }
        if (ret < 0) {
                uwsgi_error("uwsgi_simple_wait_write_hook()/poll()");
        }

        return ret;
}
