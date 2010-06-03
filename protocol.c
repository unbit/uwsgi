#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

static size_t get_content_length(char *buf, uint16_t size) {
	int i;
	size_t val = 0 ;
	for(i=0;i<size;i++) {
		if (buf[i] >= '0' && buf[i] <= '9') {
			val = (val*10) + (buf[i] - '0') ;
			continue;
		}
		break;
	}

	return val;
}

#ifdef UWSGI_UDP
ssize_t send_udp_message(uint8_t modifier1, char *host, char *message, uint16_t message_size) {

	int fd ;
	struct sockaddr_in udp_addr;
	char *udp_port ;
	ssize_t ret;
	char udpbuff[1024];

	if (message_size + 4 > 1024)
		return -1;

	udp_port = strchr(host, ':');
	if (udp_port == NULL) {
		return -1 ;
	}

	udp_port[0] = 0 ; 

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		uwsgi_error("socket()");
		return -1 ;
	}

	memset(&udp_addr, 0, sizeof(struct sockaddr_in));
	udp_addr.sin_family = AF_INET;
	udp_addr.sin_port = htons(atoi(udp_port));
	udp_addr.sin_addr.s_addr = inet_addr(host);

	udpbuff[0] = modifier1 ;
#ifdef __BIG_ENDIAN__
	message_size = uwsgi_swap16(message_size);
#endif

	memcpy(udpbuff+1, &message_size, 2);

	udpbuff[3] = 0 ;

#ifdef __BIG_ENDIAN__
	message_size = uwsgi_swap16(message_size);
#endif

	memcpy(udpbuff+4, message, message_size);

	ret = sendto(fd, udpbuff, message_size+4, 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr));
	if (ret < 0) {
		uwsgi_error("sendto()");
	}
	close(fd);

	return ret;
	
}
#endif

int uwsgi_enqueue_message(char *host, int port, uint8_t modifier1, uint8_t modifier2, char *message, int size, int timeout) {

	struct pollfd uwsgi_poll;
	struct sockaddr_in uws_addr;
	int cnt;
	struct uwsgi_header uh;

	if (!timeout)
		timeout = 1;

	if (size > 0xFFFF) {
		uwsgi_log( "invalid object (marshalled) size\n");
		return -1;
	}

	uwsgi_poll.fd = socket(AF_INET, SOCK_STREAM, 0);
	if (uwsgi_poll.fd < 0) {
		uwsgi_error("socket()");
		return -1;
	}

	memset(&uws_addr, 0, sizeof(struct sockaddr_in));
	uws_addr.sin_family = AF_INET;
	uws_addr.sin_port = htons(port);
	uws_addr.sin_addr.s_addr = inet_addr(host);

	uwsgi_poll.events = POLLIN;

	if (timed_connect(&uwsgi_poll, (const struct sockaddr *) &uws_addr, sizeof(struct sockaddr_in), timeout)) {
		uwsgi_error("connect()");
		close(uwsgi_poll.fd);
		return -1;
	}

	uh.modifier1 = modifier1;
	uh.pktsize = (uint16_t) size;
	uh.modifier2 = modifier2;

	cnt = write(uwsgi_poll.fd, &uh, 4);
	if (cnt != 4) {
		uwsgi_error("write()");
		close(uwsgi_poll.fd);
		return -1;
	}

	cnt = write(uwsgi_poll.fd, message, size);
	if (cnt != size) {
		uwsgi_error("write()");
		close(uwsgi_poll.fd);
		return -1;
	}

	return uwsgi_poll.fd;
}

PyObject *uwsgi_send_message(const char *host, int port, uint8_t modifier1, uint8_t modifier2, char *message, int size, int timeout) {

	struct pollfd uwsgi_mpoll;
	struct sockaddr_in uws_addr;
	int cnt;
	struct uwsgi_header uh;
	char buffer[0xFFFF];



	if (!timeout)
		timeout = 1;

	if (size > 0xFFFF) {
		uwsgi_log( "invalid object (marshalled) size\n");
		Py_INCREF(Py_None);
		return Py_None;
	}

	uwsgi_mpoll.events = POLLIN;

	uwsgi_mpoll.fd = socket(AF_INET, SOCK_STREAM, 0);
	if (uwsgi_mpoll.fd < 0) {
		uwsgi_error("socket()");
		Py_INCREF(Py_None);
		return Py_None;
	}

	memset(&uws_addr, 0, sizeof(struct sockaddr_in));
	uws_addr.sin_family = AF_INET;
	uws_addr.sin_port = htons(port);
	uws_addr.sin_addr.s_addr = inet_addr(host);

	UWSGI_SET_BLOCKING;

	if (timed_connect(&uwsgi_mpoll, (const struct sockaddr *) &uws_addr, sizeof(struct sockaddr_in), timeout)) {
		uwsgi_error("connect()");
		close(uwsgi_mpoll.fd);
		Py_INCREF(Py_None);
		return Py_None;
	}

	uh.modifier1 = modifier1;
	uh.pktsize = (uint16_t) size;
	uh.modifier2 = modifier2;

	cnt = write(uwsgi_mpoll.fd, &uh, 4);
	if (cnt != 4) {
		uwsgi_error("write()");
		close(uwsgi_mpoll.fd);
		Py_INCREF(Py_None);
		return Py_None;
	}

	cnt = write(uwsgi_mpoll.fd, message, size);
	if (cnt != size) {
		uwsgi_error("write()");
		close(uwsgi_mpoll.fd);
		Py_INCREF(Py_None);
		return Py_None;
	}


	if (!uwsgi_parse_response(&uwsgi_mpoll, timeout, &uh, buffer)) {
		UWSGI_UNSET_BLOCKING;
		Py_INCREF(Py_None);
		return Py_None;
	}

	UWSGI_UNSET_BLOCKING;

	close(uwsgi_mpoll.fd);

	if (uh.modifier1 == UWSGI_MODIFIER_RESPONSE) {
		if (!uh.modifier2) {
			Py_INCREF(Py_None);
			return Py_None;
		}
		else {
			Py_INCREF(Py_True);
			return Py_True;
		}
	}

	return PyMarshal_ReadObjectFromString(buffer, uh.pktsize);
}

int uwsgi_parse_response(struct pollfd *upoll, int timeout, struct uwsgi_header *uh, char *buffer) {
	int rlen, i;

	if (!timeout)
		timeout = 1;
	/* first 4 byte header */
	rlen = poll(upoll, 1, timeout * 1000);
	if (rlen < 0) {
		uwsgi_error("poll()");
		exit(1);
	}
	else if (rlen == 0) {
		uwsgi_log( "timeout. skip request\n");
		close(upoll->fd);
		return 0;
	}
	rlen = read(upoll->fd, uh, 4);
	if (rlen > 0 && rlen < 4) {
		i = rlen;
		while (i < 4) {
			rlen = poll(upoll, 1, timeout * 1000);
			if (rlen < 0) {
				uwsgi_error("poll()");
				exit(1);
			}
			else if (rlen == 0) {
				uwsgi_log( "timeout waiting for header. skip request.\n");
				close(upoll->fd);
				break;
			}
			rlen = read(upoll->fd, (char *) (uh) + i, 4 - i);
			if (rlen <= 0) {
				uwsgi_log( "broken header. skip request.\n");
				close(upoll->fd);
				break;
			}
			i += rlen;
		}
		if (i < 4) {
			return 0;
		}
	}
	else if (rlen <= 0) {
		uwsgi_log( "invalid request header size: %d...skip\n", rlen);
		close(upoll->fd);
		return 0;
	}
	/* big endian ? */
#ifdef __BIG_ENDIAN__
	uh->pktsize = uwsgi_swap16(uh->pktsize);
#endif

	/* check for max buffer size */
	if (uh->pktsize > uwsgi.buffer_size) {
		uwsgi_log( "invalid request block size: %d...skip\n", uh->pktsize);
		close(upoll->fd);
		return 0;
	}

	//uwsgi_log("ready for reading %d bytes\n", wsgi_req.size);

	i = 0;
	while (i < uh->pktsize) {
		rlen = poll(upoll, 1, timeout * 1000);
		if (rlen < 0) {
			uwsgi_error("poll()");
			exit(1);
		}
		else if (rlen == 0) {
			uwsgi_log( "timeout. skip request. (expecting %d bytes, got %d)\n", uh->pktsize, i);
			close(upoll->fd);
			break;
		}
		rlen = read(upoll->fd, buffer + i, uh->pktsize - i);
		if (rlen <= 0) {
			uwsgi_log( "broken vars. skip request.\n");
			close(upoll->fd);
			break;
		}
		i += rlen;
	}


	if (i < uh->pktsize) {
		return 0;
	}

	return 1;
}

int uwsgi_parse_vars(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	char *buffer = wsgi_req->buffer;

	char *ptrbuf, *bufferend;

	uint16_t strsize = 0;

	ptrbuf = buffer;
	bufferend = ptrbuf + wsgi_req->uh.pktsize;

	/* set an HTTP 500 status as default */
	wsgi_req->status = 500;

	while (ptrbuf < bufferend) {
		if (ptrbuf + 2 < bufferend) {
			memcpy(&strsize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
			strsize = uwsgi_swap16(strsize);
#endif
			/* key cannot be null */
                        if (!strsize) {
                                uwsgi_log( "uwsgi key cannot be null. skip this request.\n");
                                return -1;
                        }
			
			ptrbuf += 2;
			if (ptrbuf + strsize < bufferend) {
				// var key
				wsgi_req->hvec[wsgi_req->var_cnt].iov_base = ptrbuf;
				wsgi_req->hvec[wsgi_req->var_cnt].iov_len = strsize;
				ptrbuf += strsize;
				// value can be null (even at the end) so use <=
				if (ptrbuf + 2 <= bufferend) {
					memcpy(&strsize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
					strsize = uwsgi_swap16(strsize);
#endif
					ptrbuf += 2;
					if (ptrbuf + strsize <= bufferend) {
						if (!strncmp("SCRIPT_NAME", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->script_name = ptrbuf;
							wsgi_req->script_name_len = strsize;
						}
						else if (!strncmp("SERVER_PROTOCOL", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->protocol = ptrbuf;
							wsgi_req->protocol_len = strsize;
						}
						else if (!strncmp("REQUEST_URI", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->uri = ptrbuf;
							wsgi_req->uri_len = strsize;
						}
						else if (!strncmp("QUERY_STRING", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->query_string = ptrbuf;
							wsgi_req->query_string_len = strsize;
						}
						else if (!strncmp("REQUEST_METHOD", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->method = ptrbuf;
							wsgi_req->method_len = strsize;
						}
						else if (!strncmp("REMOTE_ADDR", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->remote_addr = ptrbuf;
							wsgi_req->remote_addr_len = strsize;
						}
						else if (!strncmp("REMOTE_USER", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->remote_user = ptrbuf;
							wsgi_req->remote_user_len = strsize;
						}
						else if (!strncmp("UWSGI_SCHEME", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->scheme = ptrbuf;
							wsgi_req->scheme_len = strsize;
						}
						else if (!strncmp("UWSGI_SCRIPT",wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len )) {
							wsgi_req->wsgi_script = ptrbuf;
							wsgi_req->wsgi_script_len = strsize;
						}
						else if (!strncmp("UWSGI_MODULE", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->wsgi_module = ptrbuf;
							wsgi_req->wsgi_module_len = strsize;
						}
						else if (!strncmp("UWSGI_CALLABLE", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->wsgi_callable = ptrbuf;
							wsgi_req->wsgi_callable_len = strsize;
						}
						else if (!strncmp("HTTPS", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->https = ptrbuf;
							wsgi_req->https_len = strsize;
						}
#ifdef UNBIT
						else if (!strncmp("UNBIT_FLAGS", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->unbit_flags = *(unsigned long long *) ptrbuf;
						}
#endif
						else if (!strncmp("CONTENT_LENGTH", wsgi_req->hvec[wsgi_req->var_cnt].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len)) {
							wsgi_req->post_cl = get_content_length(ptrbuf, strsize);
						}
						if (wsgi_req->var_cnt < uwsgi->vec_size - (4 + 1)) {
							wsgi_req->var_cnt++;
						}
						else {
							uwsgi_log( "max vec size reached. skip this header.\n");
							return -1;
						}
						// var value
						wsgi_req->hvec[wsgi_req->var_cnt].iov_base = ptrbuf;
						wsgi_req->hvec[wsgi_req->var_cnt].iov_len = strsize;
						//uwsgi_log("%.*s = %.*s\n", wsgi_req->hvec[wsgi_req->var_cnt-1].iov_len, wsgi_req->hvec[wsgi_req->var_cnt-1].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len, wsgi_req->hvec[wsgi_req->var_cnt].iov_base);
						if (wsgi_req->var_cnt < uwsgi->vec_size - (4 + 1)) {
							wsgi_req->var_cnt++;
						}
						else {
							uwsgi_log( "max vec size reached. skip this header.\n");
							return -1;
						}
						ptrbuf += strsize;
					}
					else {
						return -1;
					}
				}
				else {
					return -1;
				}
			}
		}
		else {
			return -1;
		}
	}


	return 0;
}

int uwsgi_ping_node(int node, struct wsgi_request *wsgi_req) {


	struct pollfd uwsgi_poll;

	struct uwsgi_cluster_node *ucn = &uwsgi.shared->nodes[node];

	if (ucn->name[0] == 0) {
		return 0;
	}

	if (ucn->status == UWSGI_NODE_OK) {
		return 0;
	}

	uwsgi_poll.fd = socket(AF_INET, SOCK_STREAM, 0);
	if (uwsgi_poll.fd < 0) {
		uwsgi_error("socket()");
		return -1;
	}

	if (timed_connect(&uwsgi_poll, (const struct sockaddr *) &ucn->ucn_addr, sizeof(struct sockaddr_in), uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT])) {
		close(uwsgi_poll.fd);
		return -1;
	}

	wsgi_req->uh.modifier1 = UWSGI_MODIFIER_PING;
	wsgi_req->uh.pktsize = 0;
	wsgi_req->uh.modifier2 = 0;
	if (write(uwsgi_poll.fd, wsgi_req, 4) != 4) {
		uwsgi_error("write()");
		return -1;
	}

	uwsgi_poll.events = POLLIN;
	if (!uwsgi_parse_response(&uwsgi_poll, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], (struct uwsgi_header *) wsgi_req, wsgi_req->buffer)) {
		return -1;
	}

	return 0;
}
