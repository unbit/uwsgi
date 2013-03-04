#include "uwsgi.h"

/*

        uWSGI websockets functions

	sponsored by 20Tab S.r.l. <info@20tab.com>

*/

extern struct uwsgi_server uwsgi;

static struct uwsgi_buffer *uwsgi_websocket_message(char *msg, size_t len) {
	struct uwsgi_buffer *ub = uwsgi_buffer_new(10 + len);
	if (uwsgi_buffer_u8(ub, 0x81)) goto error;
	if (len < 126) {
		if (uwsgi_buffer_u8(ub, len)) goto error;
	}
	else if (len <= (uint16_t) 0xffff) {
		if (uwsgi_buffer_u8(ub, 126)) goto error;
		if (uwsgi_buffer_u16be(ub, len)) goto error;
	}
	else {
		if (uwsgi_buffer_u8(ub, 127)) goto error;
                if (uwsgi_buffer_u64be(ub, len)) goto error;
	}

	if (uwsgi_buffer_append(ub, msg, len)) goto error;
	return ub;

error:
	uwsgi_buffer_destroy(ub);
	return NULL;
}

static int uwsgi_websockets_ping(struct wsgi_request *wsgi_req) {
        if (uwsgi_response_write_body_do(wsgi_req, uwsgi.websockets_ping->buf, uwsgi.websockets_ping->pos)) {
		return -1;
	}
	wsgi_req->websocket_last_ping = uwsgi_now();
        return 0;
}

static int uwsgi_websockets_pong(struct wsgi_request *wsgi_req) {
        return uwsgi_response_write_body_do(wsgi_req, uwsgi.websockets_pong->buf, uwsgi.websockets_pong->pos);
}

static int uwsgi_websockets_check_pingpong(struct wsgi_request *wsgi_req) {
	time_t now = uwsgi_now();
	// first round
	if (wsgi_req->websocket_last_ping == 0) {
		return uwsgi_websockets_ping(wsgi_req);
	}
	// pong not received ?
	if (wsgi_req->websocket_last_pong < wsgi_req->websocket_last_ping) {
		if (wsgi_req->websocket_last_ping - wsgi_req->websocket_last_pong > uwsgi.websockets_pong_tolerance) {
                                uwsgi_log("[uwsgi-websocket] no PONG received in %d seconds !!!\n", uwsgi.websockets_pong_tolerance);
				return -1;
		}
		return 0;
	}
	// pong received, send anther ping
        if (now - wsgi_req->websocket_last_ping >= uwsgi.websockets_ping_freq) {
                return uwsgi_websockets_ping(wsgi_req);
	}
	return 0;
}

static int uwsgi_websocket_send_do(struct wsgi_request *wsgi_req, char *msg, size_t len) {
	struct uwsgi_buffer *ub = uwsgi_websocket_message(msg, len);
	if (!ub) return -1;

	ssize_t ret = uwsgi_response_write_body_do(wsgi_req, ub->buf, ub->pos);
	uwsgi_buffer_destroy(ub);
	return ret;
	
}

int uwsgi_websocket_send(struct wsgi_request *wsgi_req, char *msg, size_t len) {
	if (wsgi_req->websocket_closed) {
                return -1;
        }
	ssize_t ret = uwsgi_websocket_send_do(wsgi_req, msg, len);
	if (ret < 0) {
		wsgi_req->websocket_closed = 1;
	}
	return ret;
}

static void uwsgi_websocket_parse_header(struct wsgi_request *wsgi_req) {
	uint8_t byte1 = wsgi_req->websocket_buf->buf[0];
	uint8_t byte2 = wsgi_req->websocket_buf->buf[1];
	wsgi_req->websocket_opcode = byte1 & 0xf;
	wsgi_req->websocket_has_mask = byte2 >> 7;
	wsgi_req->websocket_size = byte2 & 0x7f;
}

static struct uwsgi_buffer *uwsgi_websockets_parse(struct wsgi_request *wsgi_req) {
	// de-mask buffer
	uint8_t *ptr = (uint8_t *) (wsgi_req->websocket_buf->buf + (wsgi_req->websocket_pktsize - wsgi_req->websocket_size));
	size_t i;

	if (wsgi_req->websocket_has_mask) {
		uint8_t *mask = ptr-4;
		for(i=0;i<wsgi_req->websocket_size;i++) {
			ptr[i] = ptr[i] ^ mask[i%4];	
		}
	}

	struct uwsgi_buffer *ub = uwsgi_buffer_new(wsgi_req->websocket_size);
	if (uwsgi_buffer_append(ub, (char *) ptr, wsgi_req->websocket_size)) goto error;	
	if (uwsgi_buffer_decapitate(wsgi_req->websocket_buf, wsgi_req->websocket_pktsize)) goto error;
	wsgi_req->websocket_phase = 0;
	wsgi_req->websocket_need = 2;
	return ub;
error:
	uwsgi_buffer_destroy(ub);
	return NULL;
}


static ssize_t uwsgi_websockets_recv_pkt(struct wsgi_request *wsgi_req, int nb) {

	int ret = -1;

	for(;;) {
		ssize_t rlen = wsgi_req->socket->proto_read_body(wsgi_req, wsgi_req->websocket_buf->buf + wsgi_req->websocket_buf->pos, wsgi_req->websocket_buf->len - wsgi_req->websocket_buf->pos);
		if (rlen > 0) return rlen;
		if (rlen == 0) return -1;
		if (rlen < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
				if (nb) {
					if (uwsgi_websockets_check_pingpong(wsgi_req)) {
						return -1;
					}
					return 0;
				}
                                goto wait;
                        }
                        uwsgi_error("uwsgi_websockets_recv_pkt()");
                        return -1;
                }

wait:
                ret = uwsgi.wait_read_hook(wsgi_req->fd, uwsgi.websockets_ping_freq);
                if (ret > 0) {
			rlen = wsgi_req->socket->proto_read_body(wsgi_req, wsgi_req->websocket_buf->buf + wsgi_req->websocket_buf->pos, wsgi_req->websocket_buf->len - wsgi_req->websocket_buf->pos);
			if (rlen > 0) return rlen;
			if (rlen <= 0) return -1;
		}
                if (ret < 0) {
                        uwsgi_error("uwsgi_websockets_recv_pkt()");
			return -1;
                }
		// send unsolicited pong
		if (uwsgi_websockets_check_pingpong(wsgi_req)) {
			return -1;
		}
	}

        return -1;
}


static struct uwsgi_buffer *uwsgi_websocket_recv_do(struct wsgi_request *wsgi_req, int nb) {
	if (!wsgi_req->websocket_buf) {
		// this buffer will be destroyed on connection close
		wsgi_req->websocket_buf = uwsgi_buffer_new(uwsgi.page_size);
		// need 2 byte header
		wsgi_req->websocket_need = 2;
	}

	for(;;) {
		size_t remains = wsgi_req->websocket_buf->pos;
		// i have data;
		if (remains >= wsgi_req->websocket_need) {
			switch(wsgi_req->websocket_phase) {
				// header
				case 0:
					uwsgi_websocket_parse_header(wsgi_req);
					wsgi_req->websocket_pktsize = 2 + (wsgi_req->websocket_has_mask*4);
					if (wsgi_req->websocket_size == 126) {
						wsgi_req->websocket_need += 2;
						wsgi_req->websocket_phase = 1;
						wsgi_req->websocket_pktsize += 2;
					}
					else if (wsgi_req->websocket_size == 127) {
						wsgi_req->websocket_need += 8;
						wsgi_req->websocket_phase = 1;
						wsgi_req->websocket_pktsize += 8;
					}
					else {
						wsgi_req->websocket_phase = 2;
					}
					break;
				// size
				case 1:
					if (wsgi_req->websocket_size == 126) {
						wsgi_req->websocket_size = uwsgi_be16(wsgi_req->websocket_buf->buf+2);
					}
					else if (wsgi_req->websocket_size == 127) {
						wsgi_req->websocket_size = uwsgi_be64(wsgi_req->websocket_buf->buf+2);
					}
					else {
						uwsgi_log("[uwsgi-websocket] BUG error in websocket parser\n");
						return NULL;
					}
					if (wsgi_req->websocket_size > (uwsgi.websockets_max_size*1024)) {
						uwsgi_log("[uwsgi-websocket] invalid packet size received: %llu, max allowed: %llu\n", wsgi_req->websocket_size, uwsgi.websockets_max_size * 1024);
						return NULL;
					}
					wsgi_req->websocket_phase = 2;
					break;
				// mask check
				case 2:
					if (wsgi_req->websocket_has_mask) {
						wsgi_req->websocket_need += 4;
						wsgi_req->websocket_phase = 3;
					}
					else {
						wsgi_req->websocket_need += wsgi_req->websocket_size;
						wsgi_req->websocket_phase = 4;
					}
					break;
				// mask
				case 3:
					wsgi_req->websocket_pktsize += wsgi_req->websocket_size;
					wsgi_req->websocket_need += wsgi_req->websocket_size;
                                        wsgi_req->websocket_phase = 4;
					break;
				// message
				case 4:
					switch (wsgi_req->websocket_opcode) {
						// message
						case 0:
						case 1:
						case 2:
							return uwsgi_websockets_parse(wsgi_req);
						// close
						case 0x8:
							return NULL;
						// ping
						case 0x9:
							if (uwsgi_websockets_pong(wsgi_req)) {
								return NULL;
							}
							break;
						// pong
						case 0xA:
							wsgi_req->websocket_last_pong = uwsgi_now();
							break;
						default:
							break;	
					}
					// reset the status
					wsgi_req->websocket_phase = 0;	
					wsgi_req->websocket_need = 2;	
					// decapitate the buffer
					if (uwsgi_buffer_decapitate(wsgi_req->websocket_buf, wsgi_req->websocket_pktsize)) return NULL;
					break;
				// oops
				default:
					uwsgi_log("[uwsgi-websocket] BUG error in websocket parser\n");
					return NULL;
			}
		}
		// need more data
		else {
			if (uwsgi_buffer_ensure(wsgi_req->websocket_buf, uwsgi.page_size)) return NULL;
			ssize_t len = uwsgi_websockets_recv_pkt(wsgi_req, nb);
			if (len <= 0) {
				if (nb == 1 && len == 0) {
					// return an empty buffer to signal blocking event
					return uwsgi_buffer_new(0);
				}
				return NULL;	
			}
			// update buffer size
			wsgi_req->websocket_buf->pos+=len;
		}
	}

	return NULL;
}

struct uwsgi_buffer *uwsgi_websocket_recv(struct wsgi_request *wsgi_req) {
	if (wsgi_req->websocket_closed) {
		return NULL;
	}
	struct uwsgi_buffer *ub = uwsgi_websocket_recv_do(wsgi_req, 0);
	if (!ub) {
		wsgi_req->websocket_closed = 1;
	}
	return ub;
}

struct uwsgi_buffer *uwsgi_websocket_recv_nb(struct wsgi_request *wsgi_req) {
        if (wsgi_req->websocket_closed) {
                return NULL;
        }
        struct uwsgi_buffer *ub = uwsgi_websocket_recv_do(wsgi_req, 1);
        if (!ub) {
                wsgi_req->websocket_closed = 1;
        }
        return ub;
}



ssize_t uwsgi_websockets_simple_send(struct wsgi_request *wsgi_req, struct uwsgi_buffer *ub) {
	ssize_t len = wsgi_req->socket->proto_write(wsgi_req, ub->buf, ub->pos);
	if (wsgi_req->write_errors > 0) {
		return -1;
	}
	return len;
}

int uwsgi_websocket_handshake(struct wsgi_request *wsgi_req, char *key, uint16_t key_len, char *origin, uint16_t origin_len) {
#ifdef UWSGI_SSL
	char sha1[20];
	if (uwsgi_response_prepare_headers(wsgi_req, "101 Web Socket Protocol Handshake", 33)) return -1;
	if (uwsgi_response_add_header(wsgi_req, "Upgrade", 7, "WebSocket", 9)) return -1;
	if (uwsgi_response_add_header(wsgi_req, "Connection", 10, "Upgrade", 7)) return -1;
        if (origin_len > 0) {
		if (uwsgi_response_add_header(wsgi_req, "Sec-WebSocket-Origin", 20, origin, origin_len)) return -1;
        }
        else {
		if (uwsgi_response_add_header(wsgi_req, "Sec-WebSocket-Origin", 20, "*", 1)) return -1;
        }
	// generate websockets sha1 and encode it to base64
        if (!uwsgi_sha1_2n(key, key_len, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36, sha1)) return -1;
	size_t b64_len = 0;
        char *b64 = uwsgi_base64_encode(sha1, 20, &b64_len);
	if (!b64) return -1;

	if (uwsgi_response_add_header(wsgi_req, "Sec-WebSocket-Accept", 20, b64, b64_len)) {
		free(b64);
		return -1;
	}
	free(b64);

	wsgi_req->websocket_last_pong = uwsgi_now();

	return uwsgi_response_write_headers_do(wsgi_req);
#else
	uwsgi_log("you need to build uWSGI with SSL support to use the websocket handshake api function !!!\n");
	return -1;
#endif
}

void uwsgi_websockets_init() {
        uwsgi.websockets_pong = uwsgi_buffer_new(2);
        uwsgi_buffer_append(uwsgi.websockets_pong, "\x8A\0", 2);
        uwsgi.websockets_ping = uwsgi_buffer_new(2);
        uwsgi_buffer_append(uwsgi.websockets_ping, "\x89\0", 2);
	uwsgi.websockets_ping_freq = 30;
	uwsgi.websockets_pong_tolerance = 3;
	uwsgi.websockets_max_size = 1024;
}
