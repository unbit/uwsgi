/* async fastcgi protocol parser */

#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

#define FCGI_END_REQUEST "\1\x06\0\1\0\0\0\0\1\3\0\1\0\x08\0\0\0\0\0\0\0\0\0\0"

struct fcgi_record {
	uint8_t version;
        uint8_t type;
        uint8_t req1;
        uint8_t req0;
	uint8_t cl1;
	uint8_t cl0;
        uint8_t pad;
	uint8_t reserved;
} __attribute__ ((__packed__));


// convert fastcgi params to uwsgi key/val
int fastcgi_to_uwsgi(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	size_t j;
	uint8_t octet;
	uint32_t keylen, vallen;
	for (j = 0; j < len; j++) {
        	octet = (uint8_t) buf[j];
                if (octet > 127) {
                	if (j + 4 >= len) return -1;
			keylen = uwsgi_be32(&buf[j]) ^ 0x80000000;
                        j += 4;
		}
		else {
                	if (j+1 >= len) return -1;
			keylen = octet;
			j++;
		}
        	octet = (uint8_t) buf[j];
                if (octet > 127) {
                	if (j + 4 >= len) return -1;
			vallen = uwsgi_be32(&buf[j]) ^ 0x80000000;
                        j += 4;
		}
		else {
                	if (j+1 >= len) return -1;
			vallen = octet;
			j++;
		}

                if (j + (keylen + vallen) > len) {
			return -1;
		}

		if (keylen > 0xffff || vallen > 0xffff) return -1;
		uint16_t pktsize = proto_base_add_uwsgi_var(wsgi_req, buf + j, keylen, buf + j + keylen, vallen);
		if (pktsize == 0) return -1;
                wsgi_req->uh->pktsize += pktsize;
		// -1 here as the for() will increment j again
                j += (keylen + vallen) - 1;
	}

	return 0;
}


/*

	each fastcgi packet is composed by a header and a body
	the parser rebuild a whole packet until it find a 0 PARAMS or a STDIN one

*/

int uwsgi_proto_fastcgi_parser(struct wsgi_request *wsgi_req) {

	// allocate space for a fastcgi record
	if (!wsgi_req->proto_parser_buf) {
		wsgi_req->proto_parser_buf = uwsgi_malloc(uwsgi.buffer_size);
		wsgi_req->proto_parser_buf_size = uwsgi.buffer_size;
	}

	ssize_t len = read(wsgi_req->fd, wsgi_req->proto_parser_buf + wsgi_req->proto_parser_pos,  wsgi_req->proto_parser_buf_size - wsgi_req->proto_parser_pos);
	if (len > 0) {
		goto parse;
	}	
	if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                        return UWSGI_AGAIN;
                }
                uwsgi_error("uwsgi_proto_fastcgi_parser()");
                return -1;
        }
        // mute on 0 len...
        if (wsgi_req->proto_parser_pos > 0) {
                uwsgi_error("uwsgi_proto_fastcgi_parser()");
        }
        return -1;
parse:
	wsgi_req->proto_parser_pos += len;
	// ok let's see what we need to do
	for(;;) {
		if (wsgi_req->proto_parser_pos >= sizeof(struct fcgi_record)) {
			struct fcgi_record *fr = (struct fcgi_record *) wsgi_req->proto_parser_buf;
			uint16_t fcgi_len = uwsgi_be16((char *)&fr->cl1);
			uint32_t fcgi_all_len = sizeof(struct fcgi_record) + fcgi_len + fr->pad;
			uint8_t fcgi_type = fr->type;
			// if STDIN, end of the loop
			if (fcgi_type == 5) {
				wsgi_req->uh->modifier1 = uwsgi.fastcgi_modifier1;
				wsgi_req->uh->modifier2 = uwsgi.fastcgi_modifier2;
				return UWSGI_OK;
			}
			// if we have a full packet, parse it and reset the memory
			if (wsgi_req->proto_parser_pos >= fcgi_all_len) {
				// PARAMS ? (ignore other types)
				if (fcgi_type == 4) {
					if (fastcgi_to_uwsgi(wsgi_req, wsgi_req->proto_parser_buf + sizeof(struct fcgi_record), fcgi_len)) {
						return -1;
					}
				}
				memmove(wsgi_req->proto_parser_buf, wsgi_req->proto_parser_buf + fcgi_all_len, wsgi_req->proto_parser_pos - fcgi_all_len);
				wsgi_req->proto_parser_pos -= fcgi_all_len;
				// end of PARAMS
				if (fcgi_type == 4 && fcgi_len == 0) {
					wsgi_req->uh->modifier1 = uwsgi.fastcgi_modifier1;
					wsgi_req->uh->modifier2 = uwsgi.fastcgi_modifier2;
					return UWSGI_OK;
				}
			}
			else if (fcgi_all_len > wsgi_req->proto_parser_buf_size - wsgi_req->proto_parser_pos) {
				char *tmp_buf = realloc(wsgi_req->proto_parser_buf, wsgi_req->proto_parser_buf_size + fcgi_all_len - (wsgi_req->proto_parser_buf_size - wsgi_req->proto_parser_pos));
				if (!tmp_buf) {
					uwsgi_error("uwsgi_proto_fastcgi_parser()/realloc()");
					return -1;
				}
				wsgi_req->proto_parser_buf = tmp_buf;
				wsgi_req->proto_parser_buf_size += (fcgi_all_len - (wsgi_req->proto_parser_buf_size - wsgi_req->proto_parser_pos));
				break;
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	}
	return UWSGI_AGAIN;

}


ssize_t uwsgi_proto_fastcgi_read_body(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	if (wsgi_req->proto_parser_remains > 0) {
                size_t remains = UMIN(wsgi_req->proto_parser_remains, len);
                memcpy(buf, wsgi_req->proto_parser_remains_buf, remains);
                wsgi_req->proto_parser_remains -= remains;
                wsgi_req->proto_parser_remains_buf += remains;
                return remains;
        }

	ssize_t rlen;

	for(;;) {
                if (wsgi_req->proto_parser_pos >= sizeof(struct fcgi_record)) {
                        struct fcgi_record *fr = (struct fcgi_record *) wsgi_req->proto_parser_buf;
                        uint16_t fcgi_len = uwsgi_be16((char *)&fr->cl1);
			uint32_t fcgi_all_len = sizeof(struct fcgi_record) + fcgi_len + fr->pad;
                        uint8_t fcgi_type = fr->type;
                        // if we have a full packet, parse it and reset the memory
                        if (wsgi_req->proto_parser_pos >= fcgi_all_len) {
                                // STDIN ? (ignore other types)
                                if (fcgi_type == 5) {
					// copy data to the buf
					size_t remains = UMIN(fcgi_len, len);
					memcpy(buf, wsgi_req->proto_parser_buf + sizeof(struct fcgi_record), remains);
					// copy remaining
					wsgi_req->proto_parser_remains = fcgi_len - remains;
					wsgi_req->proto_parser_remains_buf = wsgi_req->proto_parser_buf + sizeof(struct fcgi_record) + remains;
                                	memmove(wsgi_req->proto_parser_buf, wsgi_req->proto_parser_buf + fcgi_all_len, wsgi_req->proto_parser_pos - fcgi_all_len);
                                	wsgi_req->proto_parser_pos -= fcgi_all_len;
					return remains;
				}
                                memmove(wsgi_req->proto_parser_buf, wsgi_req->proto_parser_buf + fcgi_all_len, wsgi_req->proto_parser_pos - fcgi_all_len);
                                wsgi_req->proto_parser_pos -= fcgi_all_len;
                        }
                        else if (fcgi_all_len > wsgi_req->proto_parser_buf_size - wsgi_req->proto_parser_pos) {
                                char *tmp_buf = realloc(wsgi_req->proto_parser_buf, wsgi_req->proto_parser_buf_size + fcgi_all_len - (wsgi_req->proto_parser_buf_size - wsgi_req->proto_parser_pos));
                                if (!tmp_buf) {
                                        uwsgi_error("uwsgi_proto_fastcgi_read_body()/realloc()");
                                        return -1;
                                }
                                wsgi_req->proto_parser_buf = tmp_buf;
                                wsgi_req->proto_parser_buf_size += fcgi_all_len - (wsgi_req->proto_parser_buf_size - wsgi_req->proto_parser_pos);
                        }
			goto gather;
                }
                else {
gather:
			rlen = read(wsgi_req->fd, wsgi_req->proto_parser_buf + wsgi_req->proto_parser_pos,  wsgi_req->proto_parser_buf_size - wsgi_req->proto_parser_pos);
			if (rlen > 0) {
				wsgi_req->proto_parser_pos += rlen;
				continue;
			}
			return rlen;
                }
        }

	return -1;
	
}

// write a STDOUT packet
int uwsgi_proto_fastcgi_write(struct wsgi_request *wsgi_req, char *buf, size_t len) {

	// fastcgi packets are limited to 64k
	if (wsgi_req->proto_parser_status == 0) {
		uint16_t fcgi_len = UMIN(len-wsgi_req->write_pos, 0xffff);
		wsgi_req->proto_parser_status = fcgi_len;
		struct fcgi_record fr;
		fr.version = 1;
		fr.type = 6;
		fr.req1 = 0;
		fr.req0 = 1;
		fr.pad = 0;
		fr.reserved = 0;
		fr.cl0 = (uint8_t) (fcgi_len & 0xff);
		fr.cl1 = (uint8_t) ((fcgi_len >> 8) & 0xff);
		if (uwsgi_write_true_nb(wsgi_req->fd, (char *) &fr, sizeof(struct fcgi_record), uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT])) {
			return -1;
		}
	}

	ssize_t wlen = write(wsgi_req->fd, buf+wsgi_req->write_pos, wsgi_req->proto_parser_status);
        if (wlen > 0) {
                wsgi_req->write_pos += wlen;
		wsgi_req->proto_parser_status -= wlen;
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

void uwsgi_proto_fastcgi_close(struct wsgi_request *wsgi_req) {
	// special case here, we run i nvoid context, so we need to wait directly here
	(void) uwsgi_write_true_nb(wsgi_req->fd, (char *) FCGI_END_REQUEST, sizeof(FCGI_END_REQUEST), uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
	uwsgi_proto_base_close(wsgi_req);
}

int uwsgi_proto_fastcgi_sendfile(struct wsgi_request *wsgi_req, int fd, size_t pos, size_t len) {

	// fastcgi packets are limited to 64k
        if (wsgi_req->proto_parser_status == 0) {
                uint16_t fcgi_len = (uint16_t) UMIN(len-wsgi_req->write_pos, 0xffff);
                wsgi_req->proto_parser_status = fcgi_len;
                struct fcgi_record fr;
                fr.version = 1;
                fr.type = 6;
                fr.req1 = 0;
                fr.req0 = 1;
                fr.pad = 0;
                fr.reserved = 0;
                fr.cl0 = (uint8_t) (fcgi_len & 0xff);
                fr.cl1 = (uint8_t) ((fcgi_len >> 8) & 0xff);
                if (uwsgi_write_true_nb(wsgi_req->fd, (char *) &fr, sizeof(struct fcgi_record), uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT])) {
                        return -1;
                }
        }

	ssize_t wlen = uwsgi_sendfile_do(wsgi_req->fd, fd, pos+wsgi_req->write_pos, wsgi_req->proto_parser_status);
        if (wlen > 0) {
                wsgi_req->write_pos += wlen;
		wsgi_req->proto_parser_status -= wlen;
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
