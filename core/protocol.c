#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

// this is line uwsgi_str_num but with security checks
static size_t get_content_length(char *buf, uint16_t size) {
        int i;
        size_t val = 0;
        for (i = 0; i < size; i++) {
                if (buf[i] >= '0' && buf[i] <= '9') {
                        val = (val * 10) + (buf[i] - '0');
                        continue;
                }
                break;
        }

        return val;
}



ssize_t send_udp_message(uint8_t modifier1, uint8_t modifier2, char *host, char *message, uint16_t message_size) {

	int fd;
	struct sockaddr_in udp_addr;
	struct sockaddr_un un_addr;
	char *udp_port;
	ssize_t ret;

	struct uwsgi_header *uh;

	if (message) {
		uh = (struct uwsgi_header *) message;
	}
	else {
		uh = (struct uwsgi_header *) uwsgi_malloc(4);
	}

	udp_port = strchr(host, ':');
	if (udp_port) {
		udp_port[0] = 0;

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0) {
			uwsgi_error("socket()");
			return -1;
		}

		memset(&udp_addr, 0, sizeof(struct sockaddr_in));
		udp_addr.sin_family = AF_INET;
		udp_addr.sin_port = htons(atoi(udp_port + 1));
		udp_addr.sin_addr.s_addr = inet_addr(host);
	}
	else {
		fd = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (fd < 0) {
			uwsgi_error("socket()");
			return -1;
		}

		memset(&un_addr, 0, sizeof(struct sockaddr_un));
		un_addr.sun_family = AF_UNIX;
		// use 102 as the magic number
		strncat(un_addr.sun_path, host, 102);

	}

	uh->modifier1 = modifier1;
#ifdef __BIG_ENDIAN__
	uh->pktsize = uwsgi_swap16(message_size);
#else
	uh->pktsize = message_size;
#endif
	uh->modifier2 = modifier2;

	if (udp_port) {
		ret = sendto(fd, (char *) uh, message_size + 4, 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr));
		udp_port[0] = ':';
	}
	else {
		ret = sendto(fd, (char *) uh, message_size + 4, 0, (struct sockaddr *) &un_addr, sizeof(un_addr));
	}
	if (ret < 0) {
		uwsgi_error("sendto()");
	}
	close(fd);

	if ((char *) uh != message) {
		free(uh);
	}

	return ret;

}

int uwsgi_enqueue_message(char *host, int port, uint8_t modifier1, uint8_t modifier2, char *message, int size, int timeout) {

	struct pollfd uwsgi_poll;
	struct sockaddr_in uws_addr;
	int cnt;
	struct uwsgi_header uh;

	if (!timeout)
		timeout = 1;

	if (size > 0xffff) {
		uwsgi_log("invalid object (marshalled) size\n");
		return -1;
	}

#if defined(__linux__) && defined(SOCK_NONBLOCK) && !defined(OBSOLETE_LINUX_KERNEL)
	uwsgi_poll.fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
#else
	uwsgi_poll.fd = socket(AF_INET, SOCK_STREAM, 0);
#endif
	if (uwsgi_poll.fd < 0) {
		uwsgi_error("socket()");
		return -1;
	}

	memset(&uws_addr, 0, sizeof(struct sockaddr_in));
	uws_addr.sin_family = AF_INET;
	uws_addr.sin_port = htons(port);
	uws_addr.sin_addr.s_addr = inet_addr(host);

	uwsgi_poll.events = POLLIN;

	if (timed_connect(&uwsgi_poll, (const struct sockaddr *) &uws_addr, sizeof(struct sockaddr_in), timeout, 0)) {
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



ssize_t uwsgi_send_message(int fd, uint8_t modifier1, uint8_t modifier2, char *message, uint16_t size, int pfd, ssize_t plen, int timeout) {

	ssize_t cnt;
	struct uwsgi_header uh;
	ssize_t ret = 0;
	struct msghdr msg;
	struct iovec iov[1];
	union {
		struct cmsghdr cmsg;
		char control[CMSG_SPACE(sizeof(int))];
	} msg_control;
	struct cmsghdr *cmsg;

	if (!timeout)
		timeout = uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT];

	uh.modifier1 = modifier1;
	uh.pktsize = size;
	uh.modifier2 = modifier2;

	if (pfd >= 0 && plen == -1) {
		// pass the fd
		iov[0].iov_base = &uh;
		iov[0].iov_len = 4;

		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;

		msg.msg_control = &msg_control;
		msg.msg_controllen = sizeof(msg_control);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;

		memcpy(CMSG_DATA(cmsg), &pfd, sizeof(int));

#ifdef UWSGI_DEBUG
		uwsgi_log("passing fd\n");
#endif
		cnt = sendmsg(fd, &msg, 0);
	}
	else {
		cnt = write(fd, &uh, 4);
	}
	if (cnt != 4) {
		uwsgi_error("write()");
		return -1;
	}

	ret += cnt;

	cnt = write(fd, message, size);
	if (cnt != size) {
		uwsgi_error("write()");
		return -1;
	}

	ret += cnt;

	// transfer data from one socket to another
	if (pfd >= 0 && plen > 0) {
		ret = uwsgi_pipe_sized(pfd, fd, plen, timeout);
		if (ret < 0)
			return -1;
	}


	return ret;
}

int uwsgi_read_response(int fd, struct uwsgi_header *uh, int timeout, char **buf) {

	char *ptr = (char *) uh;
	size_t remains = 4;
	int ret = -1;
	int rlen;
	ssize_t len;

	while (remains > 0) {
		rlen = uwsgi_waitfd(fd, timeout);
		if (rlen > 0) {
			len = read(fd, ptr, remains);
			if (len <= 0)
				break;
			remains -= len;
			ptr += len;
			if (remains == 0) {
				ret = uh->modifier2;
				break;
			}
			continue;
		}
		// timed out ?
		else if (ret == 0)
			ret = -2;
		break;
	}

	if (buf && uh->pktsize > 0) {
		if (*buf == NULL)
			*buf = uwsgi_malloc(uh->pktsize);
		remains = uh->pktsize;
		ptr = *buf;
		ret = -1;
		while (remains > 0) {
			rlen = uwsgi_waitfd(fd, timeout);
			if (rlen > 0) {
				len = read(fd, ptr, remains);
				if (len <= 0)
					break;
				remains -= len;
				ptr += len;
				if (remains == 0) {
					ret = uh->modifier2;
					break;
				}
				continue;
			}
			// timed out ?
			else if (ret == 0)
				ret = -2;
			break;
		}
	}

	return ret;
}

int uwsgi_parse_packet(struct wsgi_request *wsgi_req, int timeout) {
	int rlen;
	int status = UWSGI_AGAIN;

	if (!timeout)
		timeout = 1;

	while (status == UWSGI_AGAIN) {
		rlen = poll(&wsgi_req->poll, 1, timeout * 1000);
		if (rlen < 0) {
			uwsgi_error("poll()");
			exit(1);
		}
		else if (rlen == 0) {
			uwsgi_log("timeout. skip request.\n");
			//close(upoll->fd);
			return 0;
		}
		if (wsgi_req->socket) {
			status = wsgi_req->socket->proto(wsgi_req);
		}
		else {
			status = uwsgi_proto_uwsgi_parser(wsgi_req);
		}
		if (status < 0) {
			if (status == -1)
				uwsgi_log_verbose("error parsing request\n");
			else if (status == -2)
				uwsgi_log_verbose("open-close packet (ping/check) received\n");
			//close(upoll->fd);
			return 0;
		}
	}

	return 1;
}

int uwsgi_parse_array(char *buffer, uint16_t size, char **argv, uint16_t argvs[], uint8_t * argc) {

	char *ptrbuf, *bufferend;
	uint16_t strsize = 0;

	uint8_t max = *argc;
	*argc = 0;

	ptrbuf = buffer;
	bufferend = ptrbuf + size;

	while (ptrbuf < bufferend && *argc < max) {
		if (ptrbuf + 2 < bufferend) {
			memcpy(&strsize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
			strsize = uwsgi_swap16(strsize);
#endif

			ptrbuf += 2;
			/* item cannot be null */
			if (!strsize)
				continue;

			if (ptrbuf + strsize <= bufferend) {
				// item
				argv[*argc] = uwsgi_cheap_string(ptrbuf, strsize);
				argvs[*argc] = strsize;
#ifdef UWSGI_DEBUG
				uwsgi_log("arg %s\n", argv[*argc]);
#endif
				ptrbuf += strsize;
				*argc = *argc + 1;
			}
			else {
				uwsgi_log("invalid uwsgi array. skip this var.\n");
				return -1;
			}
		}
		else {
			uwsgi_log("invalid uwsgi array. skip this request.\n");
			return -1;
		}
	}


	return 0;
}

int uwsgi_simple_parse_vars(struct wsgi_request *wsgi_req, char *ptrbuf, char *bufferend) {

	uint16_t strsize;

	while (ptrbuf < bufferend) {
		if (ptrbuf + 2 < bufferend) {
			memcpy(&strsize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
			strsize = uwsgi_swap16(strsize);
#endif
			/* key cannot be null */
			if (!strsize) {
				uwsgi_log("uwsgi key cannot be null. skip this request.\n");
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

						if (wsgi_req->var_cnt < uwsgi.vec_size - (4 + 1)) {
							wsgi_req->var_cnt++;
						}
						else {
							uwsgi_log("max vec size reached. skip this header.\n");
							return -1;
						}
						// var value
						wsgi_req->hvec[wsgi_req->var_cnt].iov_base = ptrbuf;
						wsgi_req->hvec[wsgi_req->var_cnt].iov_len = strsize;

						if (wsgi_req->var_cnt < uwsgi.vec_size - (4 + 1)) {
							wsgi_req->var_cnt++;
						}
						else {
							uwsgi_log("max vec size reached. skip this var.\n");
							return -1;
						}
						ptrbuf += strsize;
					}
					else {
						uwsgi_log("invalid uwsgi request (current strsize: %d). skip.\n", strsize);
						return -1;
					}
				}
				else {
					uwsgi_log("invalid uwsgi request (current strsize: %d). skip.\n", strsize);
					return -1;
				}
			}
		}
	}

	return 0;
}

#define uwsgi_proto_key(x, y) memcmp(x, key, y)

static int uwsgi_proto_check_5(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {

	if (!uwsgi_proto_key("HTTPS", 5)) {
		wsgi_req->https = buf;
		wsgi_req->https_len = len;
		return 0;
	}

	return 0;
}

static int uwsgi_proto_check_9(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {

	if (!uwsgi_proto_key("PATH_INFO", 9)) {
		wsgi_req->path_info = buf;
		wsgi_req->path_info_len = len;
		wsgi_req->path_info_pos = wsgi_req->var_cnt + 1;
#ifdef UWSGI_DEBUG
		uwsgi_debug("PATH_INFO=%.*s\n", wsgi_req->path_info_len, wsgi_req->path_info);
#endif
		return 0;
	}

	if (!uwsgi_proto_key("HTTP_HOST", 9)) {
		wsgi_req->host = buf;
		wsgi_req->host_len = len;
#ifdef UWSGI_DEBUG
		uwsgi_debug("HTTP_HOST=%.*s\n", wsgi_req->host_len, wsgi_req->host);
#endif
		return 0;
	}

	return 0;
}

static int uwsgi_proto_check_10(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {

	if (!uwsgi_proto_key("UWSGI_FILE", 10)) {
		wsgi_req->file = buf;
		wsgi_req->file_len = len;
		wsgi_req->dynamic = 1;
		return 0;
	}

	return 0;
}

static int uwsgi_proto_check_11(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {

	if (!uwsgi_proto_key("SCRIPT_NAME", 11)) {
		wsgi_req->script_name = buf;
		wsgi_req->script_name_len = len;
		wsgi_req->script_name_pos = wsgi_req->var_cnt + 1;
#ifdef UWSGI_DEBUG
		uwsgi_debug("SCRIPT_NAME=%.*s\n", wsgi_req->script_name_len, wsgi_req->script_name);
#endif
		return 0;
	}

	if (!uwsgi_proto_key("REQUEST_URI", 11)) {
		wsgi_req->uri = buf;
		wsgi_req->uri_len = len;
		return 0;
	}

	if (!uwsgi_proto_key("REMOTE_USER", 11)) {
		wsgi_req->remote_user = buf;
		wsgi_req->remote_user_len = len;
		return 0;
	}

	if (wsgi_req->host_len == 0 && !uwsgi_proto_key("SERVER_NAME", 11)) {
		wsgi_req->host = buf;
		wsgi_req->host_len = len;
#ifdef UWSGI_DEBUG
		uwsgi_debug("SERVER_NAME=%.*s\n", wsgi_req->host_len, wsgi_req->host);
#endif
		return 0;
	}

	if (wsgi_req->remote_addr_len == 0 && !uwsgi_proto_key("REMOTE_ADDR", 11)) {
		wsgi_req->remote_addr = buf;
                wsgi_req->remote_addr_len = len;
		return 0;
	}

	if (!uwsgi_proto_key("UWSGI_APPID", 11)) {
		wsgi_req->appid = buf;
		wsgi_req->appid_len = len;
		return 0;
	}

	if (!uwsgi_proto_key("UWSGI_CHDIR", 11)) {
		wsgi_req->chdir = buf;
		wsgi_req->chdir_len = len;
		return 0;
	}

	return 0;
}

static int uwsgi_proto_check_12(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {
	if (!uwsgi_proto_key("QUERY_STRING", 12)) {
		wsgi_req->query_string = buf;
		wsgi_req->query_string_len = len;
		return 0;
	}

	if (!uwsgi_proto_key("CONTENT_TYPE", 12)) {
		wsgi_req->content_type = buf;
		wsgi_req->content_type_len = len;
		return 0;
	}

	if (!uwsgi_proto_key("UWSGI_SCHEME", 12)) {
		wsgi_req->scheme = buf;
		wsgi_req->scheme_len = len;
		return 0;
	}

	if (!uwsgi_proto_key("UWSGI_SCRIPT", 12)) {
		wsgi_req->script = buf;
		wsgi_req->script_len = len;
		wsgi_req->dynamic = 1;
		return 0;
	}

	if (!uwsgi_proto_key("UWSGI_MODULE", 12)) {
		wsgi_req->module = buf;
		wsgi_req->module_len = len;
		wsgi_req->dynamic = 1;
		return 0;
	}

	if (!uwsgi_proto_key("UWSGI_PYHOME", 12)) {
		wsgi_req->pyhome = buf;
		wsgi_req->pyhome_len = len;
		return 0;
	}

	if (!uwsgi_proto_key("UWSGI_SETENV", 12)) {
		char *env_value = memchr(buf, '=', len);
		if (env_value) {
			env_value[0] = 0;
			env_value = uwsgi_concat2n(env_value + 1, len - ((env_value + 1) - buf), "", 0);
			if (setenv(buf, env_value, 1)) {
				uwsgi_error("setenv()");
			}
			free(env_value);
		}
		return 0;
	}
	return 0;
}

static int uwsgi_proto_check_13(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {
	if (!uwsgi_proto_key("DOCUMENT_ROOT", 13)) {
		wsgi_req->document_root = buf;
		wsgi_req->document_root_len = len;
		return 0;
	}
	return 0;
}

static int uwsgi_proto_check_14(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {
	if (!uwsgi_proto_key("REQUEST_METHOD", 14)) {
		wsgi_req->method = buf;
		wsgi_req->method_len = len;
		return 0;
	}

	if (!uwsgi_proto_key("CONTENT_LENGTH", 14)) {
		wsgi_req->post_cl = get_content_length(buf, len);
		if (uwsgi.limit_post) {
			if (wsgi_req->post_cl > uwsgi.limit_post) {
				uwsgi_log("Invalid (too big) CONTENT_LENGTH. skip.\n");
				return -1;
			}
		}
		return 0;
	}

	if (!uwsgi_proto_key("UWSGI_POSTFILE", 14)) {
		char *postfile = uwsgi_concat2n(buf, len, "", 0);
		wsgi_req->async_post = fopen(postfile, "r");
		if (!wsgi_req->async_post) {
			uwsgi_error_open(postfile);
		}
		free(postfile);
		wsgi_req->body_as_file = 1;
		return 0;
	}

	if (!uwsgi_proto_key("UWSGI_CALLABLE", 14)) {
		wsgi_req->callable = buf;
		wsgi_req->callable_len = len;
		wsgi_req->dynamic = 1;
		return 0;
	}

	return 0;
}

static int uwsgi_proto_check_15(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {
	if (!uwsgi_proto_key("SERVER_PROTOCOL", 15)) {
		wsgi_req->protocol = buf;
		wsgi_req->protocol_len = len;
		return 0;
	}

	if (!uwsgi_proto_key("HTTP_USER_AGENT", 15)) {
		wsgi_req->user_agent = buf;
		wsgi_req->user_agent_len = len;
		return 0;
	}

	if (uwsgi.caches > 0 && !uwsgi_proto_key("UWSGI_CACHE_GET", 15)) {
		wsgi_req->cache_get = buf;
		wsgi_req->cache_get_len = len;
		return 0;
	}

	return 0;
}

static int uwsgi_proto_check_18(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {
	if (!uwsgi_proto_key("HTTP_AUTHORIZATION", 18)) {
		wsgi_req->authorization = buf;
		wsgi_req->authorization_len = len;
		return 0;
	}

	if (!uwsgi_proto_key("UWSGI_TOUCH_RELOAD", 18)) {
		wsgi_req->touch_reload = buf;
		wsgi_req->touch_reload_len = len;
		return 0;
	}

	return 0;
}


static int uwsgi_proto_check_20(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {
	if (uwsgi.log_x_forwarded_for && !uwsgi_proto_key("HTTP_X_FORWARDED_FOR", 20)) {
		wsgi_req->remote_addr = buf;
		wsgi_req->remote_addr_len = len;
		return 0;
	}
	return 0;
}

static int uwsgi_proto_check_22(struct wsgi_request *wsgi_req, char *key, char *buf, uint16_t len) {
	if (!uwsgi_proto_key("HTTP_IF_MODIFIED_SINCE", 22)) {
		wsgi_req->if_modified_since = buf;
		wsgi_req->if_modified_since_len = len;
		return 0;
	}
	return 0;
}

void uwsgi_proto_hooks_setup() {
	int i = 0;
	for(i=0;i<UWSGI_PROTO_MAX_CHECK;i++) {
		uwsgi.proto_hooks[i] = NULL;
	}

	uwsgi.proto_hooks[5] = uwsgi_proto_check_5;
	uwsgi.proto_hooks[9] = uwsgi_proto_check_9;
	uwsgi.proto_hooks[10] = uwsgi_proto_check_10;
	uwsgi.proto_hooks[11] = uwsgi_proto_check_11;
	uwsgi.proto_hooks[12] = uwsgi_proto_check_12;
	uwsgi.proto_hooks[13] = uwsgi_proto_check_13;
	uwsgi.proto_hooks[14] = uwsgi_proto_check_14;
	uwsgi.proto_hooks[15] = uwsgi_proto_check_15;
	uwsgi.proto_hooks[18] = uwsgi_proto_check_18;
	uwsgi.proto_hooks[20] = uwsgi_proto_check_20;
	uwsgi.proto_hooks[22] = uwsgi_proto_check_22;
}


int uwsgi_parse_vars(struct wsgi_request *wsgi_req) {

	char *buffer = wsgi_req->buffer;

	char *ptrbuf, *bufferend;

	uint16_t strsize = 0;
	struct uwsgi_dyn_dict *udd;

	ptrbuf = buffer;
	bufferend = ptrbuf + wsgi_req->uh.pktsize;
	int i;
	
	/* set an HTTP 500 status as default */
	wsgi_req->status = 500;

	// skip if already parsed
	if (wsgi_req->parsed)
		return 0;

	// has the protocol already parsed the request ?
	if (wsgi_req->uri_len > 0) {
		wsgi_req->parsed = 1;
		i = uwsgi_simple_parse_vars(wsgi_req, ptrbuf, bufferend);
		if (i == 0)
			goto next;
		return i;
	}

	wsgi_req->parsed = 1;
	wsgi_req->script_name_pos = -1;
	wsgi_req->path_info_pos = -1;

	while (ptrbuf < bufferend) {
		if (ptrbuf + 2 < bufferend) {
			memcpy(&strsize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
			strsize = uwsgi_swap16(strsize);
#endif
			/* key cannot be null */
			if (!strsize) {
				uwsgi_log("uwsgi key cannot be null. skip this var.\n");
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
						if (wsgi_req->hvec[wsgi_req->var_cnt].iov_len > UWSGI_PROTO_MIN_CHECK &&
							wsgi_req->hvec[wsgi_req->var_cnt].iov_len < UWSGI_PROTO_MAX_CHECK &&
								uwsgi.proto_hooks[wsgi_req->hvec[wsgi_req->var_cnt].iov_len]) {
							if (uwsgi.proto_hooks[wsgi_req->hvec[wsgi_req->var_cnt].iov_len](wsgi_req, wsgi_req->hvec[wsgi_req->var_cnt].iov_base, ptrbuf, strsize)) {
								return -1;
							}
						}
						//uwsgi_log("uwsgi %.*s = %.*s\n", wsgi_req->hvec[wsgi_req->var_cnt].iov_len, wsgi_req->hvec[wsgi_req->var_cnt].iov_base, strsize, ptrbuf);

						if (wsgi_req->var_cnt < uwsgi.vec_size - (4 + 1)) {
							wsgi_req->var_cnt++;
						}
						else {
							uwsgi_log("max vec size reached. skip this var.\n");
							return -1;
						}
						// var value
						wsgi_req->hvec[wsgi_req->var_cnt].iov_base = ptrbuf;
						wsgi_req->hvec[wsgi_req->var_cnt].iov_len = strsize;
						//uwsgi_log("%.*s = %.*s\n", wsgi_req->hvec[wsgi_req->var_cnt-1].iov_len, wsgi_req->hvec[wsgi_req->var_cnt-1].iov_base, wsgi_req->hvec[wsgi_req->var_cnt].iov_len, wsgi_req->hvec[wsgi_req->var_cnt].iov_base);
						if (wsgi_req->var_cnt < uwsgi.vec_size - (4 + 1)) {
							wsgi_req->var_cnt++;
						}
						else {
							uwsgi_log("max vec size reached. skip this var.\n");
							return -1;
						}
						ptrbuf += strsize;
					}
					else {
						uwsgi_log("invalid uwsgi request (current strsize: %d). skip.\n", strsize);
						return -1;
					}
				}
				else {
					uwsgi_log("invalid uwsgi request (current strsize: %d). skip.\n", strsize);
					return -1;
				}
			}
		}
		else {
			uwsgi_log("invalid uwsgi request (current strsize: %d). skip.\n", strsize);
			return -1;
		}
	}

next:


	if (uwsgi.post_buffering > 0 && !wsgi_req->body_as_file && !wsgi_req->async_post) {
		// read to disk if post_cl > post_buffering (it will eventually do upload progress...)
		if (wsgi_req->post_cl >= (size_t) uwsgi.post_buffering) {
			if (!uwsgi_read_whole_body(wsgi_req, wsgi_req->post_buffering_buf, uwsgi.post_buffering_bufsize)) {
				wsgi_req->status = -1;
				return -1;
			}
			wsgi_req->body_as_file = 1;
		}
		// on tiny post use memory
		else {
			if (!uwsgi_read_whole_body_in_mem(wsgi_req, wsgi_req->post_buffering_buf)) {
				wsgi_req->status = -1;
				return -1;
			}
		}
	}


	// check if data are available in the local cache
	if (wsgi_req->cache_get_len > 0) {
		uint64_t cache_value_size;
		char *cache_value = uwsgi_cache_get(wsgi_req->cache_get, wsgi_req->cache_get_len, &cache_value_size);
		if (cache_value && cache_value_size > 0) {
			uwsgi_response_write_body_do(wsgi_req, cache_value, cache_value_size);
			wsgi_req->status = -1;
			return -1;
		}
	}

	if (uwsgi.check_cache && wsgi_req->uri_len && wsgi_req->method_len == 3 && wsgi_req->method[0] == 'G' && wsgi_req->method[1] == 'E' && wsgi_req->method[2] == 'T') {

		uint64_t cache_value_size;
		char *cache_value = uwsgi_cache_get(wsgi_req->uri, wsgi_req->uri_len, &cache_value_size);
		if (cache_value && cache_value_size > 0) {
			uwsgi_response_write_body_do(wsgi_req, cache_value, cache_value_size);
			wsgi_req->status = -1;
			return -1;
		}
	}

	if (uwsgi.manage_script_name) {
		if (uwsgi_apps_cnt > 0 && wsgi_req->path_info_len > 1 && wsgi_req->path_info_pos != -1) {
			// starts with 1 as the 0 app is the default (/) one
			int best_found = 0;
			char *orig_path_info = wsgi_req->path_info;
			int orig_path_info_len = wsgi_req->path_info_len;
			// if SCRIPT_NAME is not allocated, add a slot for it
			if (wsgi_req->script_name_pos == -1) {
				if (wsgi_req->var_cnt >= uwsgi.vec_size - (4 + 2)) {
					uwsgi_log("max vec size reached. skip this var.\n");
					return -1;
				}
				wsgi_req->hvec[wsgi_req->var_cnt].iov_base = "SCRIPT_NAME";
				wsgi_req->hvec[wsgi_req->var_cnt].iov_len = 11;
				wsgi_req->var_cnt++;
				wsgi_req->script_name_pos = wsgi_req->var_cnt;
				wsgi_req->hvec[wsgi_req->script_name_pos].iov_base = "";
				wsgi_req->hvec[wsgi_req->script_name_pos].iov_len = 0;
				wsgi_req->var_cnt++;
			}

			for (i = 0; i < uwsgi_apps_cnt; i++) {
				//uwsgi_log("app mountpoint = %.*s\n", uwsgi_apps[i].mountpoint_len, uwsgi_apps[i].mountpoint);
				if (orig_path_info_len >= uwsgi_apps[i].mountpoint_len) {
					if (!uwsgi_startswith(orig_path_info, uwsgi_apps[i].mountpoint, uwsgi_apps[i].mountpoint_len) && uwsgi_apps[i].mountpoint_len > best_found) {
						best_found = uwsgi_apps[i].mountpoint_len;
						wsgi_req->script_name = uwsgi_apps[i].mountpoint;
						wsgi_req->script_name_len = uwsgi_apps[i].mountpoint_len;
						wsgi_req->path_info = orig_path_info + wsgi_req->script_name_len;
						wsgi_req->path_info_len = orig_path_info_len - wsgi_req->script_name_len;

						wsgi_req->hvec[wsgi_req->script_name_pos].iov_base = wsgi_req->script_name;
						wsgi_req->hvec[wsgi_req->script_name_pos].iov_len = wsgi_req->script_name_len;

						wsgi_req->hvec[wsgi_req->path_info_pos].iov_base = wsgi_req->path_info;
						wsgi_req->hvec[wsgi_req->path_info_pos].iov_len = wsgi_req->path_info_len;
#ifdef UWSGI_DEBUG
						uwsgi_log("managed SCRIPT_NAME = %.*s PATH_INFO = %.*s\n", wsgi_req->script_name_len, wsgi_req->script_name, wsgi_req->path_info_len, wsgi_req->path_info);
#endif
					}
				}
			}
		}
	}


	// check for static files

	// skip methods other than GET and HEAD
	if (uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "GET", 3) && uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "HEAD", 4)) {
		return 0;
	}

	// skip extensions
	struct uwsgi_string_list *sse = uwsgi.static_skip_ext;
	while (sse) {
		if (wsgi_req->path_info_len >= sse->len) {
			if (!uwsgi_strncmp(wsgi_req->path_info + (wsgi_req->path_info_len - sse->len), sse->len, sse->value, sse->len)) {
				return 0;
			}
		}
		sse = sse->next;
	}

	// check if a file named uwsgi.check_static+env['PATH_INFO'] exists
	udd = uwsgi.check_static;
	while (udd) {
		// need to build the path ?
		if (udd->value == NULL) {
#ifdef UWSGI_THREADING
			if (uwsgi.threads > 1)
				pthread_mutex_lock(&uwsgi.lock_static);
#endif
			udd->value = uwsgi_malloc(PATH_MAX + 1);
			if (!realpath(udd->key, udd->value)) {
				free(udd->value);
				udd->value = NULL;
			}
#ifdef UWSGI_THREADING
			if (uwsgi.threads > 1)
				pthread_mutex_unlock(&uwsgi.lock_static);
#endif
			if (!udd->value)
				goto nextcs;
			udd->vallen = strlen(udd->value);
		}

		if (!uwsgi_file_serve(wsgi_req, udd->value, udd->vallen, wsgi_req->path_info, wsgi_req->path_info_len, 0)) {
			return -1;
		}
nextcs:
		udd = udd->next;
	}

	// check static-map
	udd = uwsgi.static_maps;
	while (udd) {
#ifdef UWSGI_DEBUG
		uwsgi_log("checking for %.*s <-> %.*s %.*s\n", (int)wsgi_req->path_info_len, wsgi_req->path_info, (int)udd->keylen, udd->key, (int) udd->vallen, udd->value);
#endif
		if (udd->status == 0) {
#ifdef UWSGI_THREADING
			if (uwsgi.threads > 1)
				pthread_mutex_lock(&uwsgi.lock_static);
#endif
			char *real_docroot = uwsgi_malloc(PATH_MAX + 1);
			if (!realpath(udd->value, real_docroot)) {
				free(real_docroot);
				real_docroot = NULL;
				udd->value = NULL;
			}
#ifdef UWSGI_THREADING
			if (uwsgi.threads > 1)
				pthread_mutex_unlock(&uwsgi.lock_static);
#endif
			if (!real_docroot)
				goto nextsm;
			udd->value = real_docroot;
			udd->vallen = strlen(udd->value);
			udd->status = 1 + uwsgi_is_file(real_docroot);
		}

		if (!uwsgi_starts_with(wsgi_req->path_info, wsgi_req->path_info_len, udd->key, udd->keylen)) {
			if (!uwsgi_file_serve(wsgi_req, udd->value, udd->vallen, wsgi_req->path_info + udd->keylen, wsgi_req->path_info_len - udd->keylen, udd->status - 1)) {
				return -1;
			}
		}
nextsm:
		udd = udd->next;
	}

	// check for static_maps in append mode
	udd = uwsgi.static_maps2;
	while (udd) {
#ifdef UWSGI_DEBUG
		uwsgi_log("checking for %.*s <-> %.*s\n", wsgi_req->path_info_len, wsgi_req->path_info, udd->keylen, udd->key);
#endif
		if (udd->status == 0) {
#ifdef UWSGI_THREADING
			if (uwsgi.threads > 1)
				pthread_mutex_lock(&uwsgi.lock_static);
#endif
			char *real_docroot = uwsgi_malloc(PATH_MAX + 1);
			if (!realpath(udd->value, real_docroot)) {
				free(real_docroot);
				real_docroot = NULL;
				udd->value = NULL;
			}
#ifdef UWSGI_THREADING
			if (uwsgi.threads > 1)
				pthread_mutex_unlock(&uwsgi.lock_static);
#endif
			if (!real_docroot)
				goto nextsm2;
			udd->value = real_docroot;
			udd->vallen = strlen(udd->value);
			udd->status = 1 + uwsgi_is_file(real_docroot);
		}

		if (!uwsgi_starts_with(wsgi_req->path_info, wsgi_req->path_info_len, udd->key, udd->keylen)) {
			if (!uwsgi_file_serve(wsgi_req, udd->value, udd->vallen, wsgi_req->path_info, wsgi_req->path_info_len, udd->status - 1)) {
				return -1;
			}
		}
nextsm2:
		udd = udd->next;
	}


	// finally check for docroot
	if (uwsgi.check_static_docroot && wsgi_req->document_root_len > 0) {
		char *real_docroot = uwsgi_expand_path(wsgi_req->document_root, wsgi_req->document_root_len, NULL);
		if (!real_docroot) {
			return -1;
		}
		if (!uwsgi_file_serve(wsgi_req, real_docroot, strlen(real_docroot), wsgi_req->path_info, wsgi_req->path_info_len, 0)) {
			free(real_docroot);
			return -1;
		}
		free(real_docroot);
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

#if defined(__linux__) && defined(SOCK_NONBLOCK) && !defined(OBSOLETE_LINUX_KERNEL)
	uwsgi_poll.fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
#else
	uwsgi_poll.fd = socket(AF_INET, SOCK_STREAM, 0);
#endif
	if (uwsgi_poll.fd < 0) {
		uwsgi_error("socket()");
		return -1;
	}

	if (timed_connect(&uwsgi_poll, (const struct sockaddr *) &ucn->ucn_addr, sizeof(struct sockaddr_in), uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], 0)) {
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
	if (!uwsgi_parse_packet(wsgi_req, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT])) {
		return -1;
	}

	return 0;
}

ssize_t uwsgi_send_empty_pkt(int fd, char *socket_name, uint8_t modifier1, uint8_t modifier2) {

	struct uwsgi_header uh;
	char *port;
	uint16_t s_port;
	struct sockaddr_in uaddr;
	int ret;

	uh.modifier1 = modifier1;
	uh.pktsize = 0;
	uh.modifier2 = modifier2;

	if (socket_name) {
		port = strchr(socket_name, ':');
		if (!port)
			return -1;
		s_port = atoi(port + 1);
		port[0] = 0;
		memset(&uaddr, 0, sizeof(struct sockaddr_in));
		uaddr.sin_family = AF_INET;
		uaddr.sin_addr.s_addr = inet_addr(socket_name);
		uaddr.sin_port = htons(s_port);

		port[0] = ':';

		ret = sendto(fd, &uh, 4, 0, (struct sockaddr *) &uaddr, sizeof(struct sockaddr_in));
	}
	else {
		ret = send(fd, &uh, 4, 0);
	}

	if (ret < 0) {
		uwsgi_error("sendto()");
	}

	return ret;
}

int uwsgi_get_dgram(int fd, struct wsgi_request *wsgi_req) {

	ssize_t rlen;
	struct uwsgi_header *uh;
	static char *buffer = NULL;

	struct sockaddr_in sin;
	socklen_t sin_len = sizeof(struct sockaddr_in);

	if (!buffer) {
		buffer = uwsgi_malloc(uwsgi.buffer_size + 4);
	}


	rlen = recvfrom(fd, buffer, uwsgi.buffer_size + 4, 0, (struct sockaddr *) &sin, &sin_len);

	if (rlen < 0) {
		uwsgi_error("recvfrom");
		return -1;
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("received request from %s\n", inet_ntoa(sin.sin_addr));
#endif

	if (rlen < 4) {
		uwsgi_log("invalid uwsgi packet\n");
		return -1;
	}

	uh = (struct uwsgi_header *) buffer;

	wsgi_req->uh.modifier1 = uh->modifier1;
	/* big endian ? */
#ifdef __BIG_ENDIAN__
	uh->pktsize = uwsgi_swap16(uh->pktsize);
#endif
	wsgi_req->uh.pktsize = uh->pktsize;
	wsgi_req->uh.modifier2 = uh->modifier2;

	if (wsgi_req->uh.pktsize > uwsgi.buffer_size) {
		uwsgi_log("invalid uwsgi packet size, probably you need to increase buffer size\n");
		return -1;
	}

	wsgi_req->buffer = buffer + 4;

#ifdef UWSGI_DEBUG
	uwsgi_log("request received %d %d\n", wsgi_req->uh.modifier1, wsgi_req->uh.modifier2);
#endif

	return 0;

}

int uwsgi_hooked_parse(char *buffer, size_t len, void (*hook) (char *, uint16_t, char *, uint16_t, void *), void *data) {

	char *ptrbuf, *bufferend;
	uint16_t keysize = 0, valsize = 0;
	char *key;

	ptrbuf = buffer;
	bufferend = buffer + len;

	while (ptrbuf < bufferend) {
		if (ptrbuf + 2 >= bufferend)
			return -1;
		memcpy(&keysize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
		keysize = uwsgi_swap16(keysize);
#endif
		/* key cannot be null */
		if (!keysize)
			return -1;

		ptrbuf += 2;
		if (ptrbuf + keysize > bufferend)
			return -1;

		// key
		key = ptrbuf;
		ptrbuf += keysize;
		// value can be null
		if (ptrbuf + 2 > bufferend)
			return -1;

		memcpy(&valsize, ptrbuf, 2);
#ifdef __BIG_ENDIAN__
		valsize = uwsgi_swap16(valsize);
#endif
		ptrbuf += 2;
		if (ptrbuf + valsize > bufferend)
			return -1;

		// now call the hook
		hook(key, keysize, ptrbuf, valsize, data);
		ptrbuf += valsize;
	}

	return 0;

}

int uwsgi_hooked_parse_dict_dgram(int fd, char *buffer, size_t len, uint8_t modifier1, uint8_t modifier2, void (*hook) (char *, uint16_t, char *, uint16_t, void *), void *data) {

	struct uwsgi_header *uh;
	ssize_t rlen;

	struct sockaddr_in sin;
	socklen_t sin_len = sizeof(struct sockaddr_in);

	char *ptrbuf, *bufferend;

	rlen = recvfrom(fd, buffer, len, 0, (struct sockaddr *) &sin, &sin_len);

	if (rlen < 0) {
		uwsgi_error("recvfrom()");
		return -1;
	}


#ifdef UWSGI_DEBUG
	uwsgi_log("RLEN: %ld\n", (long) rlen);
#endif

	// check for valid dict 4(header) 2(non-zero key)+1 2(value)
	if (rlen < (4 + 2 + 1 + 2)) {
#ifdef UWSGI_DEBUG
		uwsgi_log("invalid uwsgi dictionary\n");
#endif
		return -1;
	}

	uwsgi_log("received message from %s\n", inet_ntoa(sin.sin_addr));

	uh = (struct uwsgi_header *) buffer;

	if (uh->modifier1 != modifier1 || uh->modifier2 != modifier2) {
#ifdef UWSGI_DEBUG
		uwsgi_log("invalid uwsgi dictionary received, modifier1: %d modifier2: %d\n", uh->modifier1, uh->modifier2);
#endif
		return -1;
	}

	ptrbuf = buffer + 4;

	/* big endian ? */
#ifdef __BIG_ENDIAN__
	uh->pktsize = uwsgi_swap16(uh->pktsize);
#endif

	if (uh->pktsize > len) {
		uwsgi_log("* WARNING * the uwsgi dictionary received is too big, data will be truncated\n");
		bufferend = ptrbuf + len;
	}
	else {
		bufferend = ptrbuf + uh->pktsize;
	}


#ifdef UWSGI_DEBUG
	uwsgi_log("%p %p %ld\n", ptrbuf, bufferend, bufferend - ptrbuf);
#endif

	uwsgi_hooked_parse(ptrbuf, bufferend - ptrbuf, hook, data);

	return 0;

}

int uwsgi_string_sendto(int fd, uint8_t modifier1, uint8_t modifier2, struct sockaddr *sa, socklen_t sa_len, char *message, size_t len) {

	ssize_t rlen;
	struct uwsgi_header *uh;
	char *upkt = uwsgi_malloc(len + 4);

	uh = (struct uwsgi_header *) upkt;

	uh->modifier1 = modifier1;
	uh->pktsize = len;
#ifdef __BIG_ENDIAN__
	uh->pktsize = uwsgi_swap16(uh->pktsize);
#endif
	uh->modifier2 = modifier2;

	memcpy(upkt + 4, message, len);

	rlen = sendto(fd, upkt, len + 4, 0, sa, sa_len);

	if (rlen < 0) {
		uwsgi_error("sendto()");
	}

	free(upkt);

	return rlen;
}

ssize_t fcgi_send_param(int fd, char *key, uint16_t keylen, char *val, uint16_t vallen) {

	struct fcgi_record fr;
	struct iovec iv[5];

	uint8_t ks1 = 0;
	uint32_t ks4 = 0;

	uint8_t vs1 = 0;
	uint32_t vs4 = 0;

	uint16_t size = keylen + vallen;

	if (keylen > 127) {
		size += 4;
		ks4 = htonl(keylen) | 0x80000000;
		iv[1].iov_base = &ks4;
		iv[1].iov_len = 4;
	}
	else {
		size += 1;
		ks1 = keylen;
		iv[1].iov_base = &ks1;
		iv[1].iov_len = 1;
	}

	if (vallen > 127) {
		size += 4;
		vs4 = htonl(vallen) | 0x80000000;
		iv[2].iov_base = &vs4;
		iv[2].iov_len = 4;
	}
	else {
		size += 1;
		vs1 = vallen;
		iv[2].iov_base = &vs1;
		iv[2].iov_len = 1;
	}

	iv[3].iov_base = key;
	iv[3].iov_len = keylen;
	iv[4].iov_base = val;
	iv[4].iov_len = vallen;

	fr.version = 1;
	fr.type = 4;
	fr.req1 = 0;
	fr.req0 = 1;
	fr.cl8.cl1 = (uint8_t) ((size >> 8) & 0xff);
	fr.cl8.cl0 = (uint8_t) (size & 0xff);
	fr.pad = 0;
	fr.reserved = 0;

	iv[0].iov_base = &fr;
	iv[0].iov_len = 8;

	return writev(fd, iv, 5);

}

ssize_t fcgi_send_record(int fd, uint8_t type, uint16_t size, char *buffer) {

	struct fcgi_record fr;
	struct iovec iv[2];

	fr.version = 1;
	fr.type = type;
	fr.req1 = 0;
	fr.req0 = 1;
	fr.cl8.cl1 = (uint8_t) ((size >> 8) & 0xff);
	fr.cl8.cl0 = (uint8_t) (size & 0xff);
	fr.pad = 0;
	fr.reserved = 0;

	iv[0].iov_base = &fr;
	iv[0].iov_len = 8;

	iv[1].iov_base = buffer;
	iv[1].iov_len = size;

	return writev(fd, iv, 2);

}

uint16_t fcgi_get_record(int fd, char *buf) {

	struct fcgi_record fr;
	uint16_t remains = 8;
	char *ptr = (char *) &fr;
	ssize_t len;

	while (remains) {
		uwsgi_waitfd(fd, -1);
		len = read(fd, ptr, remains);
		if (len <= 0)
			return 0;
		remains -= len;
		ptr += len;
	}

	remains = ntohs(fr.cl) + fr.pad;
	ptr = buf;

	while (remains) {
		uwsgi_waitfd(fd, -1);
		len = read(fd, ptr, remains);
		if (len <= 0)
			return 0;
		remains -= len;
		ptr += len;
	}

	if (fr.type != 6)
		return 0;

	return ntohs(fr.cl);

}

char *uwsgi_simple_message_string(char *socket_name, uint8_t modifier1, uint8_t modifier2, char *what, uint16_t what_len, char *buffer, uint16_t * response_len, int timeout) {

	struct wsgi_request msg_req;

	int fd = uwsgi_connect(socket_name, timeout, 0);

	if (fd < 0) {
		if (response_len)
			*response_len = 0;
		return NULL;
	}

	if (uwsgi_send_message(fd, modifier1, modifier2, what, what_len, -1, 0, timeout) <= 0) {
		close(fd);
		if (response_len)
			*response_len = 0;
		return NULL;
	}

	memset(&msg_req, 0, sizeof(struct wsgi_request));
	msg_req.poll.fd = fd;
	msg_req.poll.events = POLLIN;
	msg_req.buffer = buffer;

	if (buffer) {
		if (!uwsgi_parse_packet(&msg_req, timeout)) {
			close(fd);
			if (response_len)
				*response_len = 0;
			return NULL;
		}

		if (response_len)
			*response_len = msg_req.uh.pktsize;
	}

	close(fd);
	return buffer;
}

int uwsgi_simple_send_string2(char *socket_name, uint8_t modifier1, uint8_t modifier2, char *item1, uint16_t item1_len, char *item2, uint16_t item2_len, int timeout) {

	struct uwsgi_header uh;
	char strsize1[2], strsize2[2];

	struct iovec iov[5];

	int fd = uwsgi_connect(socket_name, timeout, 0);

	if (fd < 0) {
		return -1;
	}

	uh.modifier1 = modifier1;
	uh.pktsize = 2 + item1_len + 2 + item2_len;
	uh.modifier2 = modifier2;

	strsize1[0] = (uint8_t) (item1_len & 0xff);
	strsize1[1] = (uint8_t) ((item1_len >> 8) & 0xff);

	strsize2[0] = (uint8_t) (item2_len & 0xff);
	strsize2[1] = (uint8_t) ((item2_len >> 8) & 0xff);

	iov[0].iov_base = &uh;
	iov[0].iov_len = 4;

	iov[1].iov_base = strsize1;
	iov[1].iov_len = 2;

	iov[2].iov_base = item1;
	iov[2].iov_len = item1_len;

	iov[3].iov_base = strsize2;
	iov[3].iov_len = 2;

	iov[4].iov_base = item2;
	iov[4].iov_len = item2_len;

	if (writev(fd, iov, 5) < 0) {
		uwsgi_error("writev()");
	}

	close(fd);

	return 0;
}

char *uwsgi_req_append(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, char *val, uint16_t vallen) {

	if (wsgi_req->uh.pktsize + (2 + keylen + 2 + vallen) > uwsgi.buffer_size) {
		uwsgi_log("not enough buffer space to add %.*s variable, consider increasing it with the --buffer-size option\n", keylen, key);
		return NULL;
	}

	if (wsgi_req->var_cnt >= uwsgi.vec_size - (4 + 2)) {
        	uwsgi_log("max vec size reached. skip this header.\n");
		return NULL;
	}

	char *ptr = wsgi_req->buffer + wsgi_req->uh.pktsize;

	*ptr++ = (uint8_t) (keylen & 0xff);
	*ptr++ = (uint8_t) ((keylen >> 8) & 0xff);

	memcpy(ptr, key, keylen);
	wsgi_req->hvec[wsgi_req->var_cnt].iov_base = ptr;
        wsgi_req->hvec[wsgi_req->var_cnt].iov_len = keylen;
	wsgi_req->var_cnt++;
	ptr += keylen;

	

	*ptr++ = (uint8_t) (vallen & 0xff);
	*ptr++ = (uint8_t) ((vallen >> 8) & 0xff);

	memcpy(ptr, val, vallen);
	wsgi_req->hvec[wsgi_req->var_cnt].iov_base = ptr;
        wsgi_req->hvec[wsgi_req->var_cnt].iov_len = vallen;
	wsgi_req->var_cnt++;

	wsgi_req->uh.pktsize += (2 + keylen + 2 + vallen);

	return ptr;
}

int uwsgi_simple_send_string(char *socket_name, uint8_t modifier1, uint8_t modifier2, char *item1, uint16_t item1_len, int timeout) {

	struct uwsgi_header uh;
	char strsize1[2];

	struct iovec iov[3];

	int fd = uwsgi_connect(socket_name, timeout, 0);

	if (fd < 0) {
		return -1;
	}

	uh.modifier1 = modifier1;
	uh.pktsize = 2 + item1_len;
	uh.modifier2 = modifier2;

	strsize1[0] = (uint8_t) (item1_len & 0xff);
	strsize1[1] = (uint8_t) ((item1_len >> 8) & 0xff);

	iov[0].iov_base = &uh;
	iov[0].iov_len = 4;

	iov[1].iov_base = strsize1;
	iov[1].iov_len = 2;

	iov[2].iov_base = item1;
	iov[2].iov_len = item1_len;

	if (writev(fd, iov, 3) < 0) {
		uwsgi_error("writev()");
	}

	close(fd);

	return 0;
}
