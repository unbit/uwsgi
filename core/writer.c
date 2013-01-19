// status could be NNN or NNN message
int uwsgi_response_prepare_headers(struct wsgi_request *wsgi_req, char *status, uint16_t status_len) {
}

//each protocol has its header generator
int uwsgi_response_add_header(struct wsgi_request *wsgi_req, char *key, uint16_t key_len, char *value, uint16_t value_len) {

	if (wsgi_req->headers_sent) return -1;

	if (!wsgi_req->headers) {
		wsgi_req->headers = uwsgi_buffer_new(uwsgi.page_size);
		wsgi_req->headers->limit = UMAX16;
	}

	struct uwsgi_buffer *hh = wsgi_req->socket->proto_add_header(wsgi_req, key, key_len, value, value_len);
	if (!hh) return -1;
	if (uwsgi_buffer_append(wsgi_req->headers, hh->buf, hh->pos)) goto error;
	uwsgi_buffer_destroy(hh);
	return 0;
error:
	uwsgi_buffer_destroy(hh);
	return -1;
}

// send the headers in a non blocking-way
int uwsgi_response_commit_headers(struct wsgi_request *wsgi_req) {
	struct uwsgi_buffer *ub = wsgi_req->headers;	
	if (!ub) return UWSGI_OK;

	ssize_t remains = ub->pos - wsgi_req->headers_write_pos;
	if (!remains) return UWSGI_OK;

	// this is special, as it returns -1 on error and OK/AGAIN otherwise
	int ret = wsgi_req->socket->proto_fix_headers(wsgi_req);
	if (len < 0) {
		wsgi_req->write_errors++;	
	}
	if (len == remains) {
		wsgi_req->headers_sent = 1;
		return UWSGI_OK;
	}
}

int uwsgi_response_write_body_do(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	wsgi_req->response_write_body_pos = 0;

	for(;;) {
		int ret = wsgi_req->socket->proto_write(wsgi_req, buf, len);
		if (ret < 0) {
			if (!uwsgi.ignore_write_errors) {
				uwsgi_error("uwsgi_response_write_body_do()");
			}
			return -1;
		}
		if (ret == UWSGI_OK) {
			break;
		}
		ret = uwsgi.wait_write_hook(wsgi_req);			
		if (ret < 0) return -1;
		// callback based hook...
		if (ret == UWSGI_AGAIN) return UWSGI_AGAIN;
	}

	wsgi_req->response_size += wsgi_req->response_write_body_pos;

	return UWSGI_OK;	
}
