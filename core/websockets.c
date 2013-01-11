#include "uwsgi.h"

/*

        uWSGI websockets functions

	sponsored by 20Tab S.r.l. <info@20tab.com>

*/

extern struct uwsgi_server uwsgi;

struct uwsgi_buffer *uwsgi_websocket_message(char *msg, size_t len) {
	struct uwsgi_buffer *ub = uwsgi_buffer_new(10 + len);
	if (uwsgi_buffer_u8(ub, 0x81)) goto error;
	if (len < 126) {
		if (uwsgi_buffer_u8(ub, len)) goto error;
	}
	else if (len < (1 << 16)) {
		if (uwsgi_buffer_u8(ub, 126)) goto error;
		if (uwsgi_buffer_u16be(ub, len)) goto error;
	}
	else if (len < ((uint64_t)1 << 63)) {
		if (uwsgi_buffer_u8(ub, 127)) goto error;
                if (uwsgi_buffer_u64be(ub, len)) goto error;
	}
	else {
		goto error;
	}

	if (uwsgi_buffer_append(ub, msg, len)) goto error;
	return ub;

error:
	uwsgi_buffer_destroy(ub);
	return NULL;
}

int uwsgi_websockets_ping(struct wsgi_request *wsgi_req) {
        ssize_t len = uwsgi.websockets_hook_send(wsgi_req, uwsgi.websockets_ping);
        if (len <= 0) {
                return -1;
        }
	wsgi_req->websocket_last_ping = uwsgi_now();
        return 0;
}

int uwsgi_websockets_pong(struct wsgi_request *wsgi_req) {
	time_t now = uwsgi_now();
	if (wsgi_req->websocket_last_ping == 0 ||  
		( wsgi_req->websocket_last_ping > 0 && now - wsgi_req->websocket_last_ping > uwsgi.websockets_ping_freq)) {

		if (uwsgi_websockets_ping(wsgi_req)) return -1;
		return 0;
	}
	// check if last pong arrived in time
	else if (wsgi_req->websocket_last_ping > 0) {
		if (wsgi_req->websocket_last_pong < wsgi_req->websocket_last_ping) {
			if (wsgi_req->websocket_last_ping - wsgi_req->websocket_last_pong >
				uwsgi.websockets_ping_freq) {
				uwsgi_log("[uwsgi-websocket] no PONG received in %d seconds !!!\n", uwsgi.websockets_ping_freq);
				return -1;
			}
		}
	}
        ssize_t len = uwsgi.websockets_hook_send(wsgi_req, uwsgi.websockets_pong);
        if (len <= 0) {
                return -1;
        }
        return 0;
}

ssize_t uwsgi_websocket_send_do(struct wsgi_request *wsgi_req, char *msg, size_t len) {
	struct uwsgi_buffer *ub = uwsgi_websocket_message(msg, len);
	if (!ub) return -1;

	ssize_t ret = uwsgi.websockets_hook_send(wsgi_req, ub);
	uwsgi_buffer_destroy(ub);
	if (ret > 0) {
		wsgi_req->response_size += ret;
	}
	return ret;
	
}

ssize_t uwsgi_websocket_send(struct wsgi_request *wsgi_req, char *msg, size_t len) {
	if (wsgi_req->websocket_closed) {
                return -1;
        }
	ssize_t ret = uwsgi_websocket_send_do(wsgi_req, msg, len);
	if (ret <= 0) {
		wsgi_req->websocket_closed = 1;
	}
	return ret;
}

void uwsgi_websocket_parse_header(struct wsgi_request *wsgi_req) {
	uint8_t byte1 = wsgi_req->websocket_buf->buf[0];
	uint8_t byte2 = wsgi_req->websocket_buf->buf[1];
	wsgi_req->websocket_opcode = byte1 & 0xf;
	wsgi_req->websocket_has_mask = byte2 >> 7;
	wsgi_req->websocket_size = byte2 & 0x7f;
}

struct uwsgi_buffer *uwsgi_websockets_parse(struct wsgi_request *wsgi_req) {
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


struct uwsgi_buffer *uwsgi_websocket_recv_do(struct wsgi_request *wsgi_req) {
	if (!wsgi_req->websocket_buf) {
		// this buffer will be destroyed on connection close
		wsgi_req->websocket_buf = uwsgi_buffer_new(uwsgi.page_size);
		// need 2 byte header
		wsgi_req->websocket_need = 2;
		// set status code
		wsgi_req->status = 101;
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
			ssize_t len = uwsgi.websockets_hook_recv(wsgi_req);
			if (len <= 0) {
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
	struct uwsgi_buffer *ub = uwsgi_websocket_recv_do(wsgi_req);
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

ssize_t uwsgi_websockets_simple_recv(struct wsgi_request *wsgi_req) {
	int fd = wsgi_req->poll.fd;
	int ret = -1;
retry:
	ret = uwsgi_waitfd(fd, uwsgi.websockets_pong_freq);
	if (ret < 0) return -1;

	// send ping
	if (ret == 0) {
		//unsolicited pong
		if (uwsgi_websockets_pong(wsgi_req)) {
                	return -1;
                }
		goto retry;
	}

	ssize_t len = read(fd, wsgi_req->websocket_buf->buf + wsgi_req->websocket_buf->pos, wsgi_req->websocket_buf->len - wsgi_req->websocket_buf->pos);
	if (len <= 0) {
		uwsgi_error("[uwsgi-websocket] uwsgi_websockets_simple_recv()/read()");
	}
	return len;
}

void uwsgi_websockets_init() {
	uwsgi.websockets_hook_send = uwsgi_websockets_simple_send;
        uwsgi.websockets_hook_recv = uwsgi_websockets_simple_recv;
        uwsgi.websockets_pong = uwsgi_buffer_new(2);
        uwsgi_buffer_append(uwsgi.websockets_pong, "\x8A\0", 2);
        uwsgi.websockets_ping = uwsgi_buffer_new(2);
        uwsgi_buffer_append(uwsgi.websockets_ping, "\x89\0", 2);
	uwsgi.websockets_ping_freq = 30;
	uwsgi.websockets_pong_freq = 10;
	uwsgi.websockets_max_size = 1024;
}
