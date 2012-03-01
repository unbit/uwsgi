/*

   uWSGI http

   requires:

   - async
   - caching
   - pcre (optional)

*/

#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include "../../lib/corerouter.h"

#define MAX_HTTP_VEC 128

#define HTTP_STATUS_FREE 0
#define HTTP_STATUS_CONNECTING 1
#define HTTP_STATUS_RECV 2
#define HTTP_STATUS_RESPONSE 4

#define add_timeout(x) uwsgi_add_rb_timer(uhttp.timeouts, time(NULL)+uhttp.socket_timeout, x)
#define del_timeout(x) rb_erase(&x->timeout->rbt, uhttp.timeouts); free(x->timeout);

struct uwsgi_http {

	int has_sockets;

	int processes;

	int use_cache;
	int use_cluster;
	int nevents;

	int cheap;
	int i_am_cheap;

	int has_subscription_sockets;
	int subscription_regexp;

	char *pattern;
	int pattern_len;

	char *base;
	int base_len;

	char *to;
	int to_len;

	struct uwsgi_string_list *http_vars;

	uint8_t modifier1;
	int load;

	int socket_timeout;

	struct uwsgi_subscribe_slot *subscriptions;

	int manage_expect;

	struct rb_root *timeouts;
} uhttp;

void uwsgi_opt_http(char *opt, char *value, void *foobar) {

	uwsgi_new_gateway_socket(value, "uWSGI http");
	uhttp.has_sockets++;
}

void uwsgi_opt_http_ss(char *opt, char *value, void *foobar) {

        struct uwsgi_gateway_socket *ugs = uwsgi_new_gateway_socket(value, "uWSGI http");
        ugs->subscription = 1;
        uhttp.has_subscription_sockets++;

}

void uwsgi_opt_http_use_pattern(char *opt, char *value, void *foobar) {
	uhttp.pattern = value;
        // optimization
        uhttp.pattern_len = strlen(uhttp.pattern);
}

void uwsgi_opt_http_use_base(char *opt, char *value, void *foobar) {
	uhttp.base = value;
        // optimization
        uhttp.base_len = strlen(uhttp.base);
}

void uwsgi_opt_http_use_to(char *opt, char *value, void *foobar) {
        uhttp.to = value;
        // optimization
	uhttp.to_len = strlen(uhttp.to);
}


struct uwsgi_option http_options[] = {
	{"http", required_argument, 0, "add an http router/server on the specified address", uwsgi_opt_http, NULL, 0},
	{"http-processes", required_argument, 0, "set the number of http processes to spawn", uwsgi_opt_set_int, &uhttp.processes, 0},
	{"http-workers", required_argument, 0, "set the number of http processes to spawn", uwsgi_opt_set_int, &uhttp.processes, 0},
	{"http-var", required_argument, 0, "add a key=value item to the generated uwsgi packet", uwsgi_opt_add_string_list, &uhttp.http_vars, 0},
	{"http-to", required_argument, 0, "forward requests to the specified node", uwsgi_opt_http_use_to, NULL, 0 },
	{"http-modifier1", required_argument, 0, "set uwsgi protocol modifier1", uwsgi_opt_set_int, &uhttp.modifier1, 0},
	{"http-use-cache", no_argument, 0, "use uWSGI cache as key->value virtualhost mapper", uwsgi_opt_true, &uhttp.use_cache, 0},
	{"http-use-pattern", required_argument, 0, "use the specified pattern for mapping requests to unix sockets", uwsgi_opt_http_use_pattern, NULL, 0},
	{"http-use-base", required_argument, 0, "use the specified base for mapping requests to unix sockets", uwsgi_opt_http_use_base, NULL, 0},
	{"http-use-cluster", no_argument, 0, "load balance to nodes subscribed to the cluster", uwsgi_opt_true, &uhttp.use_cluster, 0},
	{"http-events", required_argument, 0, "set the number of concurrent http async events", uwsgi_opt_set_int, &uhttp.nevents, 0},
	{"http-subscription-server", required_argument, 0, "enable the subscription server", uwsgi_opt_http_ss, NULL, 0},
	{"http-subscription-use-regexp", no_argument, 0, "enable regexp usage in subscription system", uwsgi_opt_true, &uhttp.subscription_regexp, 0},
	{"http-timeout", required_argument, 0, "set internal http socket timeout", uwsgi_opt_set_int, &uhttp.socket_timeout, 0},
	{"http-manage-expect", no_argument, 0, "manage the Expect HTTP request header", uwsgi_opt_true, &uhttp.manage_expect, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

extern struct uwsgi_server uwsgi;


void http_manage_subscription(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	struct uwsgi_subscribe_req *usr = (struct uwsgi_subscribe_req *) data;

	if (!uwsgi_strncmp("key", 3, key, keylen)) {
		usr->key = val;
		usr->keylen = vallen;
	}

	else if (!uwsgi_strncmp("auth", 4, key, keylen)) {
		usr->auth = val;
		usr->auth_len = vallen;
	}

	else if (!uwsgi_strncmp("address", 7, key, keylen)) {
		usr->address = val;
		usr->address_len = vallen;
	}

}


struct http_session {

	int fd;
	int instance_fd;
	int status;
	struct uwsgi_header uh;
	uint8_t h_pos;
	uint16_t pos;
	uint16_t parse_pos;
	char *ptr;

	int rnrn;

	char *hostname;
	uint16_t hostname_len;

	char *instance_address;
	uint64_t instance_address_len;

	int instance_failed;

	int pass_fd;

	size_t remains;

	char *port;
	int port_len;

	struct iovec iov[MAX_HTTP_VEC];
	int iov_len;

	char uss[MAX_HTTP_VEC * 2];

	char buffer[UMAX16];
	char path_info[UMAX16];
	uint16_t path_info_len;

	size_t content_length;
	size_t received_body;

	struct uwsgi_subscribe_node *un;

	in_addr_t ip_addr;
	char ip[INET_ADDRSTRLEN];

	struct uwsgi_rb_timer *timeout;
};

static struct uwsgi_rb_timer *reset_timeout(struct http_session *uhttp_session) {

	del_timeout(uhttp_session);
	return add_timeout(uhttp_session);
}

static void close_session(struct http_session **uhttp_table, struct http_session *uhttp_session) {

	close(uhttp_session->fd);
	uhttp_table[uhttp_session->fd] = NULL;
	if (uhttp_session->instance_fd != -1) {
		if (uhttp.subscriptions && (uhttp_session->instance_failed || uhttp_session->status == HTTP_STATUS_CONNECTING)) {
			uwsgi_log("marking %.*s as failed\n", (int) uhttp_session->instance_address_len, uhttp_session->instance_address);
			uwsgi_remove_subscribe_node(&uhttp.subscriptions, uhttp_session->un);
		}
		close(uhttp_session->instance_fd);
		uhttp_table[uhttp_session->instance_fd] = NULL;
	}

	uhttp.load--;
	del_timeout(uhttp_session);
	free(uhttp_session);

}

static void expire_timeouts(struct http_session **uhttp_table) {

	time_t current = time(NULL);
	struct uwsgi_rb_timer *urbt;

	for (;;) {

		urbt = uwsgi_min_rb_timer(uhttp.timeouts);

		if (urbt == NULL)
			return;

		if (urbt->key <= current) {
			close_session(uhttp_table, (struct http_session *) urbt->data);
			uwsgi_log("timeout !!!\n");
			continue;
		}

		break;
	}
}


struct http_session *alloc_uhttp_session() {

	return uwsgi_malloc(sizeof(struct http_session));
}

uint16_t http_add_uwsgi_header(struct http_session *h_session, struct iovec *iov, char *strsize1, char *strsize2, char *hh, uint16_t hhlen, int *c) {

	int i;
	int status = 0;
	char *val = hh;
	uint16_t keylen = 0, vallen = 0;
	int prefix = 0;

	if (*c >= MAX_HTTP_VEC)
		return 0;

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

	if ((*c) + 4 >= MAX_HTTP_VEC)
		return 0;

	if (!uwsgi_strncmp("HOST", 4, hh, keylen)) {
		h_session->hostname = val;
		h_session->hostname_len = vallen;
	}

	if (!uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		h_session->content_length = uwsgi_str_num(val, vallen);
	}

	if (uwsgi_strncmp("CONTENT_TYPE", 12, hh, keylen) && uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		keylen += 5;
		prefix = 1;
		if ((*c) + 5 >= MAX_HTTP_VEC)
			return 0;
	}

	strsize1[0] = (uint8_t) (keylen & 0xff);
	strsize1[1] = (uint8_t) ((keylen >> 8) & 0xff);

	iov[*c].iov_base = strsize1;
	iov[*c].iov_len = 2;
	*c += 1;

	if (prefix) {
		iov[*c].iov_base = "HTTP_";
		iov[*c].iov_len = 5;
		*c += 1;
	}

	iov[*c].iov_base = hh;
	iov[*c].iov_len = keylen - (prefix * 5);
	*c += 1;

	strsize2[0] = (uint8_t) (vallen & 0xff);
	strsize2[1] = (uint8_t) ((vallen >> 8) & 0xff);

	iov[*c].iov_base = strsize2;
	iov[*c].iov_len = 2;
	*c += 1;

	iov[*c].iov_base = val;
	iov[*c].iov_len = vallen;
	*c += 1;

	return 2 + keylen + 2 + vallen;
}


uint16_t http_add_uwsgi_var(struct iovec * iov, char *strsize1, char *strsize2, char *key, uint16_t keylen, char *val, uint16_t vallen, int *c) {

	if ((*c) + 4 >= MAX_HTTP_VEC)
		return 0;

	strsize1[0] = (uint8_t) (keylen & 0xff);
	strsize1[1] = (uint8_t) ((keylen >> 8) & 0xff);

	iov[*c].iov_base = strsize1;
	iov[*c].iov_len = 2;
	*c += 1;

	iov[*c].iov_base = key;
	iov[*c].iov_len = keylen;
	*c += 1;

	strsize2[0] = (uint8_t) (vallen & 0xff);
	strsize2[1] = (uint8_t) ((vallen >> 8) & 0xff);

	iov[*c].iov_base = strsize2;
	iov[*c].iov_len = 2;
	*c += 1;

	iov[*c].iov_base = val;
	iov[*c].iov_len = vallen;
	*c += 1;

	return 2 + keylen + 2 + vallen;
}

int http_parse(struct http_session *h_session) {

	char *ptr = h_session->buffer;
	char *watermark = h_session->ptr;
	char *base = ptr;
	// leave a slot for uwsgi header
	int c = 1;
	char *query_string = NULL;
	char *protocol = NULL; size_t protocol_len = 0;

	// REQUEST_METHOD 
	while (ptr < watermark) {
		if (*ptr == ' ') {
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "REQUEST_METHOD", 14, base, ptr - base, &c);
			ptr++;
			break;
		}
		ptr++;
	}

	// REQUEST_URI / PATH_INFO / QUERY_STRING
	base = ptr;
	while (ptr < watermark) {
		if (*ptr == '?' && !query_string) {
			// PATH_INFO must be url-decoded !!!
			h_session->path_info_len = ptr - base;
			http_url_decode(base, &h_session->path_info_len, h_session->path_info);
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "PATH_INFO", 9, h_session->path_info, h_session->path_info_len, &c);
			query_string = ptr + 1;
		}
		else if (*ptr == ' ') {
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "REQUEST_URI", 11, base, ptr - base, &c);
			if (!query_string) {
				// PATH_INFO must be url-decoded !!!
				h_session->path_info_len = ptr - base;
				http_url_decode(base, &h_session->path_info_len, h_session->path_info);
				h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "PATH_INFO", 9, h_session->path_info, h_session->path_info_len, &c);
				h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "QUERY_STRING", 12, "", 0, &c);
			}
			else {
				h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "QUERY_STRING", 12, query_string, ptr - query_string, &c);
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
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "SERVER_PROTOCOL", 15, base, ptr - base, &c);
			protocol = base; protocol_len = ptr - base;
			ptr += 2;
			break;
		}
		ptr++;
	}

	// SCRIPT_NAME
	h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "SCRIPT_NAME", 11, "", 0, &c);

	// SERVER_NAME
	h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len, &c);
	h_session->hostname = uwsgi.hostname;
	h_session->hostname_len = uwsgi.hostname_len;

	// SERVER_PORT
	h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "SERVER_PORT", 11, h_session->port, h_session->port_len, &c);
	h_session->hostname = uwsgi.hostname;
	h_session->hostname_len = uwsgi.hostname_len;

	// UWSGI_ROUTER
	h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "UWSGI_ROUTER", 12, "http", 4, &c);

	// REMOTE_ADDR
	if (inet_ntop(AF_INET, &h_session->ip_addr, h_session->ip, INET_ADDRSTRLEN)) {
		h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "REMOTE_ADDR", 11, h_session->ip, strlen(h_session->ip), &c);
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
			if (uhttp.manage_expect) {
				if (!uwsgi_strncmp("Expect: 100-continue", 20, base, ptr - base)) {
					if (send(h_session->fd, protocol, protocol_len, 0) == (ssize_t) protocol_len) {
						if (send(h_session->fd, " 100 Continue\r\n\r\n", 17, 0) != 17) { 
							uwsgi_error("send()");
						}
					}
					else {
						uwsgi_error("send()");
					}
				}
			}
			h_session->uh.pktsize += http_add_uwsgi_header(h_session, h_session->iov, h_session->uss + c, h_session->uss + c + 2, base, ptr - base, &c);
			ptr++;
			base = ptr + 1;
		}
		ptr++;
	}

	struct uwsgi_string_list *hv = uhttp.http_vars;
	while(hv) {
		char *equal = strchr(hv->value, '=');
		if (equal) {
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, hv->value, equal - hv->value, equal + 1, strlen(equal + 1), &c);
		}
		hv = hv->next;
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("vec size: %d pkt size: %d load %d\n", c, h_session->uh.pktsize, uhttp.load);
#endif

	return c;

}

void http_loop(int id) {

	int nevents;
	int interesting_fd;
	int new_connection;
	ssize_t len;
	int i, j;

	char *magic_table[0xff];

	char bbuf[UMAX16];

	time_t delta;

	struct uwsgi_rb_timer *min_timeout;
#ifndef __sun__
	struct msghdr msg;
	union {
		struct cmsghdr cmsg;
		char control[CMSG_SPACE(sizeof(int))];
	} msg_control;
	struct cmsghdr *cmsg;
#endif

	union uwsgi_sockaddr uhttp_addr;
	socklen_t uhttp_addr_len = sizeof(struct sockaddr_un);

	struct http_session *uhttp_session;

	struct http_session **uhttp_table;

	int uhttp_queue;

	int soopt;
	socklen_t solen = sizeof(int);

	uhttp_table = uwsgi_malloc(sizeof(struct http_session *) * uwsgi.max_fd);
	for (i = 0; i < (int) uwsgi.max_fd; i++) {
		uhttp_table[i] = NULL;
	}

	void *events = uwsgi_corerouter_setup_event_queue("uWSGI http", id, uhttp.nevents, &uhttp_queue, 0);

	if (uhttp.has_subscription_sockets)
		event_queue_add_fd_read(uhttp_queue, ushared->gateways[id].internal_subscription_pipe[1]);

	if (uhttp.pattern) {
		init_magic_table(magic_table);
	}

	uhttp.timeouts = uwsgi_init_rb_timer();
	if (!uhttp.socket_timeout)
		uhttp.socket_timeout = 30;

	for (;;) {

		min_timeout = uwsgi_min_rb_timer(uhttp.timeouts);
		if (min_timeout == NULL) {
			delta = -1;
		}
		else {
			delta = min_timeout->key - time(NULL);
			if (delta <= 0) {
				expire_timeouts(uhttp_table);
				delta = 0;
			}
		}
		nevents = event_queue_wait_multi(uhttp_queue, delta, events, uhttp.nevents);

		if (nevents == 0) {
			// manage timeout
			expire_timeouts(uhttp_table);
		}

		for (i = 0; i < nevents; i++) {

			interesting_fd = event_queue_interesting_fd(events, i);

			struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
			int taken = 0;
			while (ugs) {

				if (ugs->gateway == &ushared->gateways[id] && interesting_fd == ugs->fd) {
					if (!ugs->subscription) {
						new_connection = accept(ugs->fd, (struct sockaddr *) &uhttp_addr, &uhttp_addr_len);
#ifdef UWSGI_EVENT_USE_PORT
						event_queue_add_fd_read(uhttp_queue, ugs->fd);
#endif
						if (new_connection < 0) {
							taken = 1;
							break;
						}

						uhttp_table[new_connection] = alloc_uhttp_session();
						uhttp_table[new_connection]->fd = new_connection;
						uhttp_table[new_connection]->instance_fd = -1;
						uhttp_table[new_connection]->status = HTTP_STATUS_RECV;
						uhttp_table[new_connection]->h_pos = 0;
						uhttp_table[new_connection]->pos = 0;
						uhttp_table[new_connection]->rnrn = 0;
						uhttp_table[new_connection]->parse_pos = 0;
						uhttp_table[new_connection]->pass_fd = 0;
						uhttp_table[new_connection]->ptr = uhttp_table[new_connection]->buffer;
						uhttp_table[new_connection]->instance_address_len = 0;
						uhttp_table[new_connection]->uh.modifier1 = uhttp.modifier1;
						uhttp_table[new_connection]->uh.pktsize = 0;
						uhttp_table[new_connection]->uh.modifier2 = 0;
						uhttp_table[new_connection]->ip_addr = ((struct sockaddr_in *) &uhttp_addr)->sin_addr.s_addr;
						uhttp_table[new_connection]->instance_failed = 0;

						uhttp_table[new_connection]->content_length = 0;
						uhttp_table[new_connection]->received_body = 0;

						uhttp_table[new_connection]->port = ugs->port;
						uhttp_table[new_connection]->port_len = ugs->port_len;

						uhttp_table[new_connection]->timeout = add_timeout(uhttp_table[new_connection]);

						uhttp.load++;

						event_queue_add_fd_read(uhttp_queue, new_connection);
					}
					else {
						uwsgi_corerouter_manage_subscription("uWSGI http", id, ugs, uhttp_queue, &uhttp.subscriptions,
							uhttp.subscription_regexp, http_manage_subscription, 0, &uhttp.i_am_cheap);
					}

					taken = 1;
					break;

				}

				ugs = ugs->next;
			}

			if (taken)
				continue;

			if (interesting_fd == ushared->gateways[id].internal_subscription_pipe[1]) {
				uwsgi_corerouter_manage_internal_subscription("uWSGI http", uhttp_queue, interesting_fd, &uhttp.subscriptions,
                                        uhttp.subscription_regexp, http_manage_subscription, 0, &uhttp.i_am_cheap);
			} 

			// process already active sessions;

			uhttp_session = uhttp_table[interesting_fd];

			// something is going wrong...
			if (uhttp_session == NULL)
				continue;

			if (event_queue_interesting_fd_has_error(events, i)) {
				close_session(uhttp_table, uhttp_session);
				continue;
			}

			uhttp_session->timeout = reset_timeout(uhttp_session);

			switch (uhttp_session->status) {


			case HTTP_STATUS_RECV:
				len = recv(uhttp_session->fd, uhttp_session->buffer + uhttp_session->h_pos, UMAX16 - uhttp_session->h_pos, 0);
#ifdef UWSGI_EVENT_USE_PORT
				event_queue_add_fd_read(uhttp_queue, uhttp_session->fd);
#endif
				if (len <= 0) {
					if (len < 0)
						uwsgi_error("recv()");
					close_session(uhttp_table, uhttp_session);
					break;
				}


				uhttp_session->h_pos += len;

				for (j = 0; j < len; j++) {
					//uwsgi_log("%d %d %d\n", j, *uhttp_session->ptr, uhttp_session->rnrn);
					if (*uhttp_session->ptr == '\r' && (uhttp_session->rnrn == 0 || uhttp_session->rnrn == 2)) {
						uhttp_session->rnrn++;
					}
					else if (*uhttp_session->ptr == '\r') {
						uhttp_session->rnrn = 1;
					}
					else if (*uhttp_session->ptr == '\n' && uhttp_session->rnrn == 1) {
						uhttp_session->rnrn = 2;
					}
					else if (*uhttp_session->ptr == '\n' && uhttp_session->rnrn == 3) {
						uhttp_session->ptr++;
						uhttp_session->remains = len - (j + 1);
						uhttp_session->iov_len = http_parse(uhttp_session);

						if (uhttp_session->iov_len == 0) {
							close_session(uhttp_table, uhttp_session);
							break;
						}


						if (uhttp.use_cluster) {
							uhttp_session->instance_address = uwsgi_cluster_best_node();
							if (uhttp_session->instance_address) {
								uhttp_session->instance_address_len = strlen(uhttp_session->instance_address);
							}
						}
						else if (uhttp.use_cache) {
							uhttp_session->instance_address = uwsgi_cache_get(uhttp_session->hostname, uhttp_session->hostname_len, &uhttp_session->instance_address_len);
						}
						else if (uhttp.base) {
							uhttp_session->instance_address = uwsgi_concat2n(uhttp.base, uhttp.base_len, uhttp_session->hostname, uhttp_session->hostname_len);
							uhttp_session->instance_address_len = uhttp.base_len + uhttp_session->hostname_len;
						}
						else if (uhttp.pattern) {
							magic_table['s'] = uwsgi_concat2n(uhttp_session->hostname, uhttp_session->hostname_len, "", 0);
							int tmp_addr_len = 0;
							uhttp_session->instance_address = magic_sub(uhttp.pattern, uhttp.pattern_len, &tmp_addr_len, magic_table);
							uhttp_session->instance_address_len = tmp_addr_len;
							free(magic_table['s']);
						}
						else if (uhttp.to) {
							uhttp_session->instance_address = uhttp.to;
							uhttp_session->instance_address_len = uhttp.to_len;
						}
						else if (uhttp.has_subscription_sockets) {
							uhttp_session->un = uwsgi_get_subscribe_node(&uhttp.subscriptions, uhttp_session->hostname, uhttp_session->hostname_len, uhttp.subscription_regexp);
							if (uhttp_session->un && uhttp_session->un->len) {
								uhttp_session->instance_address = uhttp_session->un->name;
								uhttp_session->instance_address_len = uhttp_session->un->len;
							}
						}
						else if (uwsgi.sockets) {
							uhttp_session->instance_address = uwsgi.sockets->name;
							uhttp_session->instance_address_len = strlen(uwsgi.sockets->name);
						}

						if (!uhttp_session->instance_address_len) {
							close_session(uhttp_table, uhttp_session);
							break;
						}



						uhttp_session->pass_fd = is_unix(uhttp_session->instance_address, uhttp_session->instance_address_len);

						uhttp_session->instance_fd = uwsgi_connectn(uhttp_session->instance_address, uhttp_session->instance_address_len, 0, 1);

#ifdef UWSGI_DEBUG
						uwsgi_log("uwsgi backend: %.*s\n", (int) uhttp_session->instance_address_len, uhttp_session->instance_address);
#endif

						if (uhttp.pattern || uhttp.base) {
							free(uhttp_session->instance_address);
						}

						if (uhttp_session->instance_fd < 0) {
							uhttp_session->instance_failed = 1;
							close_session(uhttp_table, uhttp_session);
							break;
						}


						uhttp_session->status = HTTP_STATUS_CONNECTING;
						uhttp_table[uhttp_session->instance_fd] = uhttp_session;
						event_queue_add_fd_write(uhttp_queue, uhttp_session->instance_fd);
						break;
					}
					else {
						uhttp_session->rnrn = 0;
					}
					uhttp_session->ptr++;
				}


				break;


			case HTTP_STATUS_CONNECTING:

				if (interesting_fd == uhttp_session->instance_fd) {

					if (getsockopt(uhttp_session->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&soopt), &solen) < 0) {
						uwsgi_error("getsockopt()");
						uhttp_session->instance_failed = 1;
						close_session(uhttp_table, uhttp_session);
						break;
					}

					if (soopt) {
						uwsgi_log("unable to connect() to uwsgi instance: %s\n", strerror(soopt));
						uhttp_session->instance_failed = 1;
						close_session(uhttp_table, uhttp_session);
						break;
					}

#ifdef __BIG_ENDIAN__
					uhttp_session->uh.pktsize = uwsgi_swap16(uhttp_session->uh.pktsize);
#endif

					uhttp_session->iov[0].iov_base = &uhttp_session->uh;
					uhttp_session->iov[0].iov_len = 4;

					if (uhttp_session->remains > 0) {
						uhttp_session->iov[uhttp_session->iov_len].iov_base = uhttp_session->ptr;
						if (uhttp_session->remains > uhttp_session->content_length) {
							uhttp_session->remains = uhttp_session->content_length;
						}
						uhttp_session->iov[uhttp_session->iov_len].iov_len = uhttp_session->remains;
						uhttp_session->received_body += uhttp_session->remains;
						uhttp_session->iov_len++;
					}


#ifndef __sun__
					// fd passing: PERFORMANCE EXTREME BOOST !!!
					if (uhttp_session->pass_fd && !uhttp_session->remains && !uwsgi.no_fd_passing) {
						msg.msg_name = NULL;
						msg.msg_namelen = 0;
						msg.msg_iov = uhttp_session->iov;
						msg.msg_iovlen = uhttp_session->iov_len;
						msg.msg_flags = 0;
						msg.msg_control = &msg_control;
						msg.msg_controllen = sizeof(msg_control);

						cmsg = CMSG_FIRSTHDR(&msg);
						cmsg->cmsg_len = CMSG_LEN(sizeof(int));
						cmsg->cmsg_level = SOL_SOCKET;
						cmsg->cmsg_type = SCM_RIGHTS;

						memcpy(CMSG_DATA(cmsg), &uhttp_session->fd, sizeof(int));

						if (sendmsg(uhttp_session->instance_fd, &msg, 0) < 0) {
							uwsgi_error("sendmsg()");
						}

						close(uhttp_session->fd);
						close(uhttp_session->instance_fd);
						uhttp_table[uhttp_session->fd] = NULL;
						uhttp_table[uhttp_session->instance_fd] = NULL;
						uhttp.load--;
						del_timeout(uhttp_session);
						free(uhttp_session);
						break;
					}

#endif
#ifdef __sun__
					if (uhttp_session->iov_len > IOV_MAX) {
						int remains = uhttp_session->iov_len;
						int iov_len;
						while (remains) {
							if (remains > IOV_MAX) {
								iov_len = IOV_MAX;
							}
							else {
								iov_len = remains;
							}
							if (writev(uhttp_session->instance_fd, uhttp_session->iov + (uhttp_session->iov_len - remains), iov_len) <= 0) {
								uwsgi_error("writev()");
								close_session(uhttp_table, uhttp_session);
								break;
							}
							remains -= iov_len;
						}
					}
#else
					if (writev(uhttp_session->instance_fd, uhttp_session->iov, uhttp_session->iov_len) <= 0) {
						uwsgi_error("writev()");
						close_session(uhttp_table, uhttp_session);
						break;
					}
#endif

					event_queue_fd_write_to_read(uhttp_queue, uhttp_session->instance_fd);
					uhttp_session->status = HTTP_STATUS_RESPONSE;
				}

				break;

			case HTTP_STATUS_RESPONSE:

				// data from instance
				if (interesting_fd == uhttp_session->instance_fd) {
					len = recv(uhttp_session->instance_fd, bbuf, UMAX16, 0);
#ifdef UWSGI_EVENT_USE_PORT
					event_queue_add_fd_read(uhttp_queue, uhttp_session->instance_fd);
#endif
					if (len <= 0) {
						if (len < 0)
							uwsgi_error("recv()");
						close_session(uhttp_table, uhttp_session);
						break;
					}

					len = send(uhttp_session->fd, bbuf, len, 0);

					if (len <= 0) {
						if (len < 0)
							uwsgi_error("send()");
						close(uhttp_session->fd);
						close(uhttp_session->instance_fd);
						uhttp_table[uhttp_session->fd] = NULL;
						uhttp_table[uhttp_session->instance_fd] = NULL;
						uhttp.load--;
						del_timeout(uhttp_session);
						free(uhttp_session);
						break;
					}
				}
				// body from client
				else if (interesting_fd == uhttp_session->fd) {

					//uwsgi_log("receiving body...\n");
					len = recv(uhttp_session->fd, bbuf, UMAX16, 0);
#ifdef UWSGI_EVENT_USE_PORT
					event_queue_add_fd_read(uhttp_queue, uhttp_session->fd);
#endif
					if (len <= 0) {
						if (len < 0)
							uwsgi_error("recv()");
						close(uhttp_session->fd);
						close(uhttp_session->instance_fd);
						uhttp_table[uhttp_session->fd] = NULL;
						uhttp_table[uhttp_session->instance_fd] = NULL;
						uhttp.load--;
						del_timeout(uhttp_session);
						free(uhttp_session);
						break;
					}


					if (uhttp_session->received_body >= uhttp_session->content_length) {
						break;
					}

					if (len + uhttp_session->received_body > uhttp_session->content_length) {
						len = uhttp_session->content_length - uhttp_session->received_body;
					}

					len = send(uhttp_session->instance_fd, bbuf, len, 0);

					if (len <= 0) {
						if (len < 0)
							uwsgi_error("send()");
						close_session(uhttp_table, uhttp_session);
						break;
					}

					uhttp_session->received_body += len;

				}

				break;



				// fallback to destroy !!!
			default:
				uwsgi_log("default action\n");
				close(uhttp_session->fd);
				uhttp_table[uhttp_session->fd] = NULL;
				if (uhttp_session->instance_fd != -1) {
					close(uhttp_session->instance_fd);
					uhttp_table[uhttp_session->instance_fd] = NULL;
				}
				uhttp.load--;
				del_timeout(uhttp_session);
				free(uhttp_session);
				break;

			}

		}
	}
}

int http_init() {

	int i;

	if (uhttp.has_sockets) {

		if (uhttp.use_cache && !uwsgi.cache_max_items) {
			uwsgi_log("you need to create a uwsgi cache to use the http (add --cache <n>)\n");
			exit(1);
		}

		if (!uhttp.nevents)
			uhttp.nevents = 64;

		if (!uhttp.base && !uhttp.use_cache && !uhttp.to && !uwsgi.sockets && !uhttp.has_subscription_sockets && !uhttp.use_cluster) {
			uwsgi_new_socket(uwsgi_concat2("127.0.0.1:0", ""));
		}

		uwsgi_corerouter_setup_sockets("uWSGI http");	

		if (uhttp.processes < 1)
			uhttp.processes = 1;
		for (i = 0; i < uhttp.processes; i++) {
			if (register_gateway("uWSGI http", http_loop) == NULL) {
				uwsgi_log("unable to register the http gateway\n");
				exit(1);
			}
		}

	}

	return 0;
}


struct uwsgi_plugin http_plugin = {

	.name = "http",
	.options = http_options,
	.init = http_init,
};
