/* async fastcgi protocol parser */

#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

#define PROTO_STATUS_RECV_HDR 0
#define PROTO_STATUS_RECV_BODY 1


int uwsgi_proto_fastcgi_parser(struct wsgi_request *wsgi_req) {

	ssize_t len;
	struct fcgi_record *fr;
	uint16_t rs;
	int j;
	uint8_t octet;
	uint32_t keylen, vallen;

	// allocate space for a fastcgi record
	if (!wsgi_req->proto_parser_buf) {
		wsgi_req->proto_parser_buf = uwsgi_malloc(8 + 65536);
	}

	if (wsgi_req->proto_parser_status == PROTO_STATUS_RECV_HDR) {
		len = read(wsgi_req->poll.fd, wsgi_req->proto_parser_buf + wsgi_req->proto_parser_pos, 8 - wsgi_req->proto_parser_pos);
		if (len <= 0) {
			free(wsgi_req->proto_parser_buf);
			uwsgi_error("read()");
			return -1;
		}
		wsgi_req->proto_parser_pos += len;

		if (wsgi_req->proto_parser_pos >= 8) {
			fr = (struct fcgi_record *) wsgi_req->proto_parser_buf;
			rs = ntohs(fr->cl);
#ifdef UWSGI_DEBUG
			uwsgi_log("fastcgi rs %d type %d\n", rs, fr->type);
#endif
			// empty STDIN ?
			if (fr->type == 5 && rs == 0) {
				wsgi_req->proto_parser_status = 0;
				if (wsgi_req->async_post) {
					rewind(wsgi_req->async_post);
					wsgi_req->body_as_file = 1;
				}
				free(wsgi_req->proto_parser_buf);
				return UWSGI_OK;
			}
			wsgi_req->proto_parser_pos = 0;
			if (rs == 0) {
				return UWSGI_AGAIN;
			}
			wsgi_req->proto_parser_status = PROTO_STATUS_RECV_BODY;
		}
		return UWSGI_AGAIN;
	}
	else if (wsgi_req->proto_parser_status == PROTO_STATUS_RECV_BODY) {

		fr = (struct fcgi_record *) wsgi_req->proto_parser_buf;
		rs = ntohs(fr->cl);

		len = read(wsgi_req->poll.fd, wsgi_req->proto_parser_buf + 8 + wsgi_req->proto_parser_pos, (rs + fr->pad) - wsgi_req->proto_parser_pos);
		if (len <= 0) {
			free(wsgi_req->proto_parser_buf);
			uwsgi_error("read()");
			return -1;
		}
		wsgi_req->proto_parser_pos += len;

		if (wsgi_req->proto_parser_pos >= rs + fr->pad) {
#ifdef UWSGI_DEBUG
			uwsgi_log("record parsed = type: %d size: %d padding: %d\n", fr->type, rs, fr->pad);
#endif

			// params
			if (fr->type == 4) {
				for (j = 0; j < rs; j++) {
					octet = ((uint8_t *) wsgi_req->proto_parser_buf)[8 + j];
					if (octet > 127) {
						if (j + 4 >= rs) {
							free(wsgi_req->proto_parser_buf);
							return -1;
						}
						memcpy(&keylen, wsgi_req->proto_parser_buf + 8 + j, 4);
						keylen = ntohl(keylen) ^ 0x80000000;
						j += 4;
					}
					else {
						if (j + 1 >= rs) {
							free(wsgi_req->proto_parser_buf);
							return -1;
						}
						keylen = octet;
						j++;
					}
					octet = ((uint8_t *) wsgi_req->proto_parser_buf)[8 + j];
					if (octet > 127) {
						if (j + 4 > rs) {
							free(wsgi_req->proto_parser_buf);
							return -1;
						}
						memcpy(&vallen, wsgi_req->proto_parser_buf + 8 + j, 4);
						vallen = ntohl(vallen) ^ 0x80000000;
						j += 4;
					}
					else {
						if (j + 1 > rs) {
							free(wsgi_req->proto_parser_buf);
							return -1;
						}
						vallen = octet;
						j++;
					}

					if (j + (keylen + vallen) > rs) {
						free(wsgi_req->proto_parser_buf);
						return -1;
					}
					if (keylen <= 0xffff && vallen <= 0xffff) {
#ifdef UWSGI_DEBUG
						uwsgi_log("keylen %d %.*s vallen %d %.*s\n", keylen, keylen, wsgi_req->proto_parser_buf + 8 + j, vallen, vallen, wsgi_req->proto_parser_buf + 8 + j + keylen);
#endif
						wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, wsgi_req->proto_parser_buf + 8 + j, keylen, wsgi_req->proto_parser_buf + 8 + j + keylen, vallen);
					}
					j += (keylen + vallen) - 1;
				}
			}
			// stdin
			else if (fr->type == 5) {
				if (!wsgi_req->async_post) {
					wsgi_req->async_post = tmpfile();
					if (!wsgi_req->async_post) {
						free(wsgi_req->proto_parser_buf);
						uwsgi_error("tmpfile()");
						return -1;
					}
				}
				if (!fwrite(wsgi_req->proto_parser_buf + 8, rs, 1, wsgi_req->async_post)) {
					free(wsgi_req->proto_parser_buf);
					uwsgi_error("fwrite()");
					return -1;
				}
			}
			wsgi_req->proto_parser_status = PROTO_STATUS_RECV_HDR;
			wsgi_req->proto_parser_pos = 0;
		}
	}

	return UWSGI_AGAIN;
}

ssize_t uwsgi_proto_fastcgi_writev_header(struct wsgi_request * wsgi_req, struct iovec * iovec, size_t iov_len) {
	int i;
	ssize_t len;
	ssize_t ret = 0;

	for (i = 0; i < (int) iov_len; i++) {
		len = uwsgi_proto_fastcgi_write(wsgi_req, iovec[i].iov_base, iovec[i].iov_len);
		if (len <= 0) {
			return len;
		}
		ret += len;
	}

	return ret;
}

ssize_t uwsgi_proto_fastcgi_writev(struct wsgi_request * wsgi_req, struct iovec * iovec, size_t iov_len) {
	return uwsgi_proto_fastcgi_writev_header(wsgi_req, iovec, iov_len);
}

int uwsgi_proto_fastcgi_write(struct wsgi_request * wsgi_req, char *buf, size_t len) {
/*
	struct fcgi_record fr;

	// in fastcgi we need to not send 0 sized frames
	if (!len)
		return UWSGI_OK;

	fr.version = 1;
	fr.type = 6;
	fr.req1 = 0;
	fr.req0 = 1;
	fr.pad = 0;
	fr.reserved = 0;
	fr.cl = htons(len);

	// still trying to send the fcgi header ?
	if (*written < 8) {
		char *ptr = (char *) &fr;
		ssize_t wlen = write(wsgi_req->poll.fd, ptr + *written, 8 - *written);
		if (wlen > 0) {
			*written += wlen;
			if (*written == 8) {
				goto body;
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

	// split response in 64k chunks...
body:
		rlen = write(wsgi_req->poll.fd, &fr, 8);
		if (rlen <= 0) {
			if (!uwsgi.ignore_write_errors) {
				uwsgi_req_error("write()");
			}
			wsgi_req->write_errors++;
			return 0;
		}
		rlen = write(wsgi_req->poll.fd, buf, len);
		if (rlen <= 0) {
			if (!uwsgi.ignore_write_errors) {
				uwsgi_req_error("write()");
			}
			wsgi_req->write_errors++;
			return 0;
		}
		return rlen;	
	}	
	else {
		while(len > 0) {
			chunk_len = UMIN(65535, len);	
			fr.cl = htons(chunk_len);
			rlen = write(wsgi_req->poll.fd, &fr, 8);
			if (rlen != 8) {
                        	if (!uwsgi.ignore_write_errors) {
                                	uwsgi_req_error("write()");
                        	}
                        	wsgi_req->write_errors++;
                        	return 0;
                	}
			rlen = write(wsgi_req->poll.fd, ptr, chunk_len);
			if (rlen <= 0) {
                        	if (!uwsgi.ignore_write_errors) {
                                	uwsgi_req_error("write()");
                        	}
                        	wsgi_req->write_errors++;
                        	return 0;
                	}
			ptr += rlen;
			len -= rlen;
		}
		return ptr-buf;
	}
*/
	return -1;

}

void uwsgi_proto_fastcgi_close(struct wsgi_request *wsgi_req) {

	if (write(wsgi_req->poll.fd, FCGI_END_REQUEST, 24) <= 0) {
		uwsgi_req_error("write()");
	}

	uwsgi_proto_base_close(wsgi_req);
}

int uwsgi_proto_fastcgi_sendfile(struct wsgi_request *wsgi_req, int fd, size_t pos, size_t len) {

/*
	struct fcgi_record fr;
	char buf[65536];
	size_t remains = wsgi_req->sendfile_fd_size - wsgi_req->sendfile_fd_pos;

	wsgi_req->sendfile_fd_chunk = 65536;

	fr.version = 1;
	fr.type = 6;
	fr.req1 = 0;
	fr.req0 = 1;
	fr.pad = 0;
	fr.reserved = 0;

	if (uwsgi.async > 1) {
		fr.cl = htons(UMIN(remains, wsgi_req->sendfile_fd_chunk));
		len = write(wsgi_req->poll.fd, &fr, 8);
		if (len != 8) {
			uwsgi_error("write()");
			return -1;
		}
		len = read(wsgi_req->sendfile_fd, buf, ntohs(fr.cl));
		if (len != (ssize_t) ntohs(fr.cl)) {
			uwsgi_error("read()");
			return -1;
		}
		wsgi_req->sendfile_fd_pos += len;
		return write(wsgi_req->poll.fd, buf, len);
	}

	while (remains) {
		fr.cl = htons(UMIN(remains, wsgi_req->sendfile_fd_chunk));
		len = write(wsgi_req->poll.fd, &fr, 8);
		if (len != 8) {
			uwsgi_error("write()");
			return -1;
		}
		len = read(wsgi_req->sendfile_fd, buf, ntohs(fr.cl));
		if (len != (ssize_t) ntohs(fr.cl)) {
			uwsgi_error("read()");
			return -1;
		}
		wsgi_req->sendfile_fd_pos += len;
		if (write(wsgi_req->poll.fd, buf, len) != len) {
			uwsgi_error("write()");
			return -1;
		}
		remains = wsgi_req->sendfile_fd_size - wsgi_req->sendfile_fd_pos;
	}

	return wsgi_req->sendfile_fd_pos;
*/
	return -1;

}
