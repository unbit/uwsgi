/*

   uWSGI fastrouter

   requires:

   - async
   - caching
   - pcre (optional)

*/

#include "../../uwsgi.h"

#define LONG_ARGS_FASTROUTER				150001
#define LONG_ARGS_FASTROUTER_EVENTS			150002
#define LONG_ARGS_FASTROUTER_USE_PATTERN		150003
#define LONG_ARGS_FASTROUTER_USE_BASE			150004
#define LONG_ARGS_FASTROUTER_SUBSCRIPTION_SERVER	150005
#define LONG_ARGS_FASTROUTER_TIMEOUT			150006
#define LONG_ARGS_FASTROUTER_SUBSCRIPTION_SLOT		150007
#define LONG_ARGS_FASTROUTER_USE_CODE_STRING		150008
#define LONG_ARGS_FASTROUTER_TOLERANCE			150009
#define LONG_ARGS_FASTROUTER_STATS			150010
#define LONG_ARGS_FASTROUTER_ZERG			150011

#define FASTROUTER_STATUS_FREE 0
#define FASTROUTER_STATUS_CONNECTING 1
#define FASTROUTER_STATUS_RECV_HDR 2
#define FASTROUTER_STATUS_RECV_VARS 3
#define FASTROUTER_STATUS_RESPONSE 4

#define add_timeout(x) uwsgi_add_rb_timer(ufr.timeouts, time(NULL)+ufr.socket_timeout, x)
#define add_check_timeout(x) uwsgi_add_rb_timer(ufr.timeouts, time(NULL)+x, NULL)
#define del_check_timeout(x) rb_erase(&x->rbt, ufr.timeouts);
#define del_timeout(x) rb_erase(&x->timeout->rbt, ufr.timeouts); free(x->timeout);

void fastrouter_send_stats(int);

struct uwsgi_fastrouter_socket {
	char *name;
	int fd;
	char *zerg;
	struct uwsgi_fastrouter_socket *next;
};

struct uwsgi_fastrouter {

        struct uwsgi_fastrouter_socket *sockets;

        int use_cache;
        int nevents;

	int queue;

        int subscription_slot;

        char *pattern;
        int pattern_len;

        char *base;
        int base_len;

	char *stats_server;

        char *subscription_server;
        struct uwsgi_subscribe_slot *subscriptions;
	int subscription_regexp;

        int socket_timeout;

	uint8_t code_string_modifier1;
	char *code_string_code;
	char *code_string_function;

        struct rb_root *timeouts;

	struct uwsgi_rb_timer *subscriptions_check;

	int cheap;
	int i_am_cheap;

	int tolerance;
} ufr;

static void fastrouter_go_cheap(void) {

	uwsgi_log("[uwsgi-fastrouter] no more nodes available. Going cheap...\n");
        struct uwsgi_fastrouter_socket *ufr_sock = ufr.sockets;
        while(ufr_sock) {
        	event_queue_del_fd(ufr.queue, ufr_sock->fd, event_queue_read());
                ufr_sock = ufr_sock->next;
        }
        ufr.i_am_cheap = 1;
}


static struct uwsgi_fastrouter_socket *uwsgi_fastrouter_new_socket(char *name, int fd) {

        struct uwsgi_fastrouter_socket *uwsgi_sock = ufr.sockets, *old_uwsgi_sock;

        if (!uwsgi_sock) {
                ufr.sockets = uwsgi_malloc(sizeof(struct uwsgi_fastrouter_socket));
                uwsgi_sock = ufr.sockets;
        }
        else {
                while(uwsgi_sock) {
                        old_uwsgi_sock = uwsgi_sock;
                        uwsgi_sock = uwsgi_sock->next;
                }

                uwsgi_sock = uwsgi_malloc(sizeof(struct uwsgi_fastrouter_socket));
                old_uwsgi_sock->next = uwsgi_sock;
        }

        memset(uwsgi_sock, 0, sizeof(struct uwsgi_fastrouter_socket));
        uwsgi_sock->name = name;
	if (name) {
		uwsgi_sock->fd = -1;
	}
	else {
		uwsgi_sock->fd = fd;
	}

        return uwsgi_sock;
}



struct option fastrouter_options[] = {
	{"fastrouter", required_argument, 0, LONG_ARGS_FASTROUTER},
	{"fastrouter-zerg", required_argument, 0, LONG_ARGS_FASTROUTER_ZERG},
	{"fastrouter-use-cache", no_argument, &ufr.use_cache, 1},
	{"fastrouter-use-pattern", required_argument, 0, LONG_ARGS_FASTROUTER_USE_PATTERN},
	{"fastrouter-use-base", required_argument, 0, LONG_ARGS_FASTROUTER_USE_BASE},
	{"fastrouter-use-code-string", required_argument, 0, LONG_ARGS_FASTROUTER_USE_CODE_STRING},
	{"fastrouter-events", required_argument, 0, LONG_ARGS_FASTROUTER_EVENTS},
	{"fastrouter-cheap", no_argument, &ufr.cheap, 1},
	{"fastrouter-subscription-server", required_argument, 0, LONG_ARGS_FASTROUTER_SUBSCRIPTION_SERVER},
	{"fastrouter-subscription-slot", required_argument, 0, LONG_ARGS_FASTROUTER_SUBSCRIPTION_SLOT},
	{"fastrouter-subscription-use-regexp", no_argument, &ufr.subscription_regexp, 1},
	{"fastrouter-timeout", required_argument, 0, LONG_ARGS_FASTROUTER_TIMEOUT},
	{"fastrouter-stats", required_argument, 0, LONG_ARGS_FASTROUTER_STATS},
	{"fastrouter-stats-server", required_argument, 0, LONG_ARGS_FASTROUTER_STATS},
	{"fastrouter-ss", required_argument, 0, LONG_ARGS_FASTROUTER_STATS},
	{0, 0, 0, 0},	
};

extern struct uwsgi_server uwsgi;

void fastrouter_manage_subscription(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {
	
	struct uwsgi_subscribe_req *usr = (struct uwsgi_subscribe_req *) data;
	
	if (!uwsgi_strncmp("key", 3, key, keylen)) {
		usr->key = val;
		usr->keylen = vallen;
	}
	else if (!uwsgi_strncmp("address", 7, key, keylen)) {
		usr->address = val;
		usr->address_len = vallen;
	}
	else if (!uwsgi_strncmp("modifier1", 9, key, keylen)) {
		usr->modifier1 = uwsgi_str_num(val, vallen);
	}
	else if (!uwsgi_strncmp("cores", 5, key, keylen)) {
		usr->cores = uwsgi_str_num(val, vallen);
	}
	else if (!uwsgi_strncmp("load", 4, key, keylen)) {
		usr->load = uwsgi_str_num(val, vallen);
	}
}

struct fastrouter_session {

	int fd;
	int instance_fd;
	int status;
	struct uwsgi_header uh;
	uint8_t h_pos;
	uint16_t pos;

	char *hostname;
	uint16_t hostname_len;

	int has_key;

	char *instance_address;
	uint64_t instance_address_len;

	struct uwsgi_subscribe_node *un;
	int pass_fd;

	struct uwsgi_rb_timer *timeout;
	int instance_failed;

	uint8_t modifier1;

	char buffer[0xffff];
};

static void close_session(struct fastrouter_session **fr_table, struct fastrouter_session *fr_session) {

	close(fr_session->fd);
	fr_table[fr_session->fd] = NULL;

		if (ufr.subscriptions && fr_session->un && fr_session->un->len > 0) {
			// decrease reference count
#ifdef UWSGI_DEBUG
			uwsgi_log("[1] node %.*s refcnt: %llu\n", fr_session->un->len, fr_session->un->name, fr_session->un->reference);
#endif
			fr_session->un->reference--;
#ifdef UWSGI_DEBUG
			uwsgi_log("[2] node %.*s refcnt: %llu\n", fr_session->un->len, fr_session->un->name, fr_session->un->reference);
#endif
			if (fr_session->instance_failed || fr_session->status == FASTROUTER_STATUS_CONNECTING) {
				if (fr_session->un->death_mark == 0)
					uwsgi_log("[uwsgi-fastrouter] %.*s => marking %.*s as failed\n", (int) fr_session->hostname_len, fr_session->hostname, (int) fr_session->instance_address_len,fr_session->instance_address);
				fr_session->un->failcnt++;
				fr_session->un->death_mark = 1;
				// check if i can remove the node
				if (fr_session->un->reference == 0) {
                        		uwsgi_remove_subscribe_node(&ufr.subscriptions, fr_session->un);
				}
                                if (ufr.subscriptions == NULL && ufr.cheap && !ufr.i_am_cheap) {
					fastrouter_go_cheap();
                                }

			}
		}

	if (fr_session->instance_fd != -1) {
		close(fr_session->instance_fd);
		fr_table[fr_session->instance_fd] = NULL;
	}
	del_timeout(fr_session); 
	free(fr_session);
}

static struct uwsgi_rb_timer *reset_timeout(struct fastrouter_session *fr_session) {
	del_timeout(fr_session);
	return add_timeout(fr_session);
}

static void expire_timeouts(struct fastrouter_session **fr_table) {

	time_t current = time(NULL);
	struct uwsgi_rb_timer *urbt;

	for(;;) {
		urbt = uwsgi_min_rb_timer(ufr.timeouts);
		if (urbt == NULL) return;

		if (urbt->key <= current) {
			close_session(fr_table, (struct fastrouter_session *)urbt->data);
			continue;
		}

		break;
	}
}

void fr_get_hostname(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	struct fastrouter_session *fr_session = (struct fastrouter_session *) data;

	//uwsgi_log("%.*s = %.*s\n", keylen, key, vallen, val);
	if (!uwsgi_strncmp("SERVER_NAME", 11, key, keylen) && !fr_session->hostname_len) {
		fr_session->hostname = val;
		fr_session->hostname_len = vallen;
		return;
	}

	if (!uwsgi_strncmp("HTTP_HOST", 9, key, keylen) && !fr_session->has_key) {
		fr_session->hostname = val;
		fr_session->hostname_len = vallen;
		return;
	}

	if (!uwsgi_strncmp("UWSGI_FASTROUTER_KEY", 20, key, keylen)) {
		fr_session->has_key = 1;
		fr_session->hostname = val;
		fr_session->hostname_len = vallen;
		return;
	}
}

struct fastrouter_session *alloc_fr_session() {
	
	return uwsgi_malloc(sizeof(struct fastrouter_session));
}

void fastrouter_loop() {

	int nevents;
	int interesting_fd;
	int new_connection;
	ssize_t len;
	int i;

	time_t delta;
	char bbuf[UMAX16];

	char *tcp_port;

	char *tmp_socket_name;
	int tmp_socket_name_len;

	struct uwsgi_subscribe_req usr;

	char *magic_table[0xff];

	struct uwsgi_rb_timer *min_timeout;

	void *events;
	struct msghdr msg;
	union {
                struct cmsghdr cmsg;
                char control [CMSG_SPACE (sizeof (int))];
        } msg_control;
        struct cmsghdr *cmsg;

	struct sockaddr_un fr_addr;
        socklen_t fr_addr_len = sizeof(struct sockaddr_un);
	
	struct fastrouter_session *fr_session;

	struct fastrouter_session *fr_table[2048];

	struct iovec iov[2];

	int soopt;
        socklen_t solen = sizeof(int);

	int ufr_subserver = -1;
	int ufr_stats_server = -1;

	for(i=0;i<2048;i++) {
		fr_table[i] = NULL;
	}

	ufr.queue = event_queue_init();

	struct uwsgi_fastrouter_socket *ufr_sock = ufr.sockets;

	while(ufr_sock) {
		if (ufr_sock->fd > -1) {
			ufr_sock->name = uwsgi_getsockname(ufr_sock->fd);
		}
		else if (ufr_sock->name[0] == '=') {
			int shared_socket = atoi(ufr_sock->name+1);
			if (shared_socket >= 0) {
				ufr_sock->fd = uwsgi_get_shared_socket_fd_by_num(shared_socket);
				if (ufr_sock->fd == -1) {
					uwsgi_log("unable to use shared socket %d\n", shared_socket);
				}
			}
		}
		else {
			tcp_port = strchr(ufr_sock->name, ':');
			if (tcp_port) {
				ufr_sock->fd = bind_to_tcp(ufr_sock->name, uwsgi.listen_queue, tcp_port);
			}
			else {
				ufr_sock->fd = bind_to_unix(ufr_sock->name, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
			}
		}

		if (ufr_sock->zerg) {
			uwsgi_log("uwsgi fastrouter/proxy bound on %s (from zerg server %s)\n", ufr_sock->name, ufr_sock->zerg);
		}
		else {
			uwsgi_log("uwsgi fastrouter/proxy bound on %s\n", ufr_sock->name);
		}

		if (!ufr.cheap) {
			event_queue_add_fd_read(ufr.queue, ufr_sock->fd);
		}
		else {
			uwsgi_log("[uwsgi-fastrouter] cheap mode requested. Waiting for subscriptions...\n");
			ufr.i_am_cheap = 1;
		}
		ufr_sock = ufr_sock->next;
	}


	events = event_queue_alloc(ufr.nevents);

	ufr.timeouts = uwsgi_init_rb_timer();
	if (!ufr.socket_timeout) ufr.socket_timeout = 30;


	if (ufr.subscription_server) {
		ufr_subserver = bind_to_udp(ufr.subscription_server, 0, 0);
		event_queue_add_fd_read(ufr.queue, ufr_subserver);
		if (!ufr.subscription_slot) ufr.subscription_slot = 30;
		// check for node status every 10 seconds
		//ufr.subscriptions_check = add_check_timeout(10);
	}

	if (ufr.stats_server) {
		char *tcp_port = strchr(ufr.stats_server, ':');
                if (tcp_port) {
                        // disable deferred accept for this socket
                        int current_defer_accept = uwsgi.no_defer_accept;
                        uwsgi.no_defer_accept = 1;
                        ufr_stats_server = bind_to_tcp(ufr.stats_server, uwsgi.listen_queue, tcp_port);
                        uwsgi.no_defer_accept = current_defer_accept;
                }
                else {
                        ufr_stats_server = bind_to_unix(ufr.stats_server, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
                }

                event_queue_add_fd_read(ufr.queue, ufr_stats_server);
                uwsgi_log("*** FastRouter stats server enabled on %s fd: %d ***\n", ufr.stats_server, ufr_stats_server);
	}

	if (ufr.pattern) {
		init_magic_table(magic_table);
	}


	for (;;) {

		min_timeout = uwsgi_min_rb_timer(ufr.timeouts);
		if (min_timeout == NULL ) {
			delta = -1;
		}
		else {
			delta = min_timeout->key - time(NULL);
			if (delta <= 0) {
				expire_timeouts(fr_table);
				delta = 0;
			}
		}

		nevents = event_queue_wait_multi(ufr.queue, delta, events, ufr.nevents);

		if (nevents == 0) {
			expire_timeouts(fr_table);
		}

		for (i=0;i<nevents;i++) {

			tmp_socket_name = NULL;
			interesting_fd = event_queue_interesting_fd(events, i);


			int taken = 0;
			struct uwsgi_fastrouter_socket *uwsgi_sock = ufr.sockets;
			while(uwsgi_sock) {
				if (interesting_fd == uwsgi_sock->fd) {
					new_connection = accept(interesting_fd, (struct sockaddr *) &fr_addr, &fr_addr_len);
					if (new_connection < 0) {
						continue;
					}

					fr_table[new_connection] = alloc_fr_session();
					fr_table[new_connection]->fd = new_connection;
					fr_table[new_connection]->instance_fd = -1; 
					fr_table[new_connection]->status = FASTROUTER_STATUS_RECV_HDR;
					fr_table[new_connection]->h_pos = 0;
					fr_table[new_connection]->pos = 0;
					fr_table[new_connection]->un = NULL;
					fr_table[new_connection]->instance_failed = 0;
					fr_table[new_connection]->instance_address_len = 0;
					fr_table[new_connection]->hostname_len = 0;
					fr_table[new_connection]->hostname = NULL;
		
					fr_table[new_connection]->timeout = add_timeout(fr_table[new_connection]);

					event_queue_add_fd_read(ufr.queue, new_connection);
					taken = 1;
					break;
				}
				
				uwsgi_sock = uwsgi_sock->next;
			}	

			if (taken) {
				continue;
			}

			if (interesting_fd == ufr_stats_server) {
                        	fastrouter_send_stats(ufr_stats_server);
			}
			else if (interesting_fd == ufr_subserver) {
				len = recv(ufr_subserver, bbuf, 4096, 0);
#ifdef UWSGI_EVENT_USE_PORT
				event_queue_add_fd_read(ufr.queue, ufr_subserver);
#endif
				if (len > 0) {
					memset(&usr, 0, sizeof(struct uwsgi_subscribe_req));
					uwsgi_hooked_parse(bbuf+4, len-4, fastrouter_manage_subscription, &usr);
					// subscribe request ?
					if (bbuf[3] == 0) {
						if (uwsgi_add_subscribe_node(&ufr.subscriptions, &usr, ufr.subscription_regexp) && ufr.i_am_cheap) {
							struct uwsgi_fastrouter_socket *ufr_sock = ufr.sockets;
                                                	while(ufr_sock) {
                                                		event_queue_add_fd_read(ufr.queue, ufr_sock->fd);
                                                        	ufr_sock = ufr_sock->next;
                                                	}
							ufr.i_am_cheap = 0;
							uwsgi_log("[uwsgi-fastrouter] leaving cheap mode...\n");	
						}
					}
					//unsubscribe 
					else {
						struct uwsgi_subscribe_node *node = uwsgi_get_subscribe_node_by_name(&ufr.subscriptions, usr.key, usr.keylen, usr.address, usr.address_len, ufr.subscription_regexp);	
						if (node && node->len) {
							if (node->death_mark == 0)
								uwsgi_log("[uwsgi-fastrouter] %.*s => marking %.*s as failed\n", (int) usr.keylen, usr.key, (int) usr.address_len, usr.address);
							node->failcnt++;
							node->death_mark = 1;
                                			// check if i can remove the node
                                			if (node->reference == 0) {
                                        			uwsgi_remove_subscribe_node(&ufr.subscriptions, node);
                                			}
                                			if (ufr.subscriptions == NULL && ufr.cheap && !ufr.i_am_cheap) {
								fastrouter_go_cheap();
                                			}
						}
					}	
				}
			}
			else {
				fr_session = fr_table[interesting_fd];

				// something is going wrong...
				if (fr_session == NULL) continue;

				if (event_queue_interesting_fd_has_error(events, i)) {
					close_session(fr_table, fr_session);
					continue;
				}

				fr_session->timeout = reset_timeout(fr_session);

				switch(fr_session->status) {

					case FASTROUTER_STATUS_RECV_HDR:
						len = recv(fr_session->fd, (char *)(&fr_session->uh) + fr_session->h_pos, 4-fr_session->h_pos, 0);
						if (len <= 0) {
							if (len < 0)
								uwsgi_error("recv()");
							close_session(fr_table, fr_session);
							break;
						}
						fr_session->h_pos += len;
						if (fr_session->h_pos == 4) {
#ifdef UWSGI_DEBUG
							uwsgi_log("modifier1: %d pktsize: %d modifier2: %d\n", fr_session->uh.modifier1, fr_session->uh.pktsize, fr_session->uh.modifier2);
#endif
							fr_session->status = FASTROUTER_STATUS_RECV_VARS;
						}
						break;


					case FASTROUTER_STATUS_RECV_VARS:
                                                len = recv(fr_session->fd, fr_session->buffer + fr_session->pos, fr_session->uh.pktsize - fr_session->pos, 0);
                                                if (len <= 0) {
                                                        uwsgi_error("recv()");
							close_session(fr_table, fr_session);
                                                        break;
                                                }
                                                fr_session->pos += len;
                                                if (fr_session->pos == fr_session->uh.pktsize) {
							if (uwsgi_hooked_parse(fr_session->buffer, fr_session->uh.pktsize, fr_get_hostname, (void *) fr_session)) {
								close_session(fr_table, fr_session);
                                                        	break;
							}

							if (fr_session->hostname_len == 0) {
								close_session(fr_table, fr_session);
                                                        	break;
							}

#ifdef UWSGI_DEBUG
							//uwsgi_log("requested domain %.*s\n", fr_session->hostname_len, fr_session->hostname);
#endif
							if (ufr.use_cache) {
								fr_session->instance_address = uwsgi_cache_get(fr_session->hostname, fr_session->hostname_len, &fr_session->instance_address_len);
								char *cs_mod = uwsgi_str_contains(fr_session->instance_address, fr_session->instance_address_len, ',');
                                                                if (cs_mod) {
                                                                	fr_session->modifier1 = uwsgi_str_num(cs_mod+1, (fr_session->instance_address_len - (cs_mod - fr_session->instance_address))-1);
                                                                        fr_session->instance_address_len = (cs_mod - fr_session->instance_address);
                                                                }
							}
							else if (ufr.pattern) {
								magic_table['s'] = uwsgi_concat2n(fr_session->hostname, fr_session->hostname_len, "", 0);	
								tmp_socket_name = magic_sub(ufr.pattern, ufr.pattern_len, &tmp_socket_name_len, magic_table);
								free(magic_table['s']);
								fr_session->instance_address_len = tmp_socket_name_len;
								fr_session->instance_address = tmp_socket_name;
							}
							else if (ufr.subscription_server) {
								fr_session->un = uwsgi_get_subscribe_node(&ufr.subscriptions, fr_session->hostname, fr_session->hostname_len, ufr.subscription_regexp);
								if (fr_session->un && fr_session->un->len) {
									fr_session->instance_address = fr_session->un->name;
									fr_session->instance_address_len = fr_session->un->len;
									fr_session->modifier1 = fr_session->un->modifier1;
								}
								else if (ufr.subscriptions == NULL && ufr.cheap && !ufr.i_am_cheap) {
									fastrouter_go_cheap();
                                				}
							}
							else if (ufr.base) {
								tmp_socket_name = uwsgi_concat2nn(ufr.base, ufr.base_len, fr_session->hostname, fr_session->hostname_len, &tmp_socket_name_len);
								fr_session->instance_address_len = tmp_socket_name_len;
								fr_session->instance_address = tmp_socket_name;
							}
							else if (ufr.code_string_code && ufr.code_string_function) {
								if (uwsgi.p[ufr.code_string_modifier1]->code_string) {
									fr_session->instance_address = uwsgi.p[ufr.code_string_modifier1]->code_string("uwsgi_fastrouter", ufr.code_string_code, ufr.code_string_function, fr_session->hostname, fr_session->hostname_len);
									if (fr_session->instance_address) {
										fr_session->instance_address_len = strlen(fr_session->instance_address);
										char *cs_mod = uwsgi_str_contains(fr_session->instance_address, fr_session->instance_address_len, ',');
										if (cs_mod) {
											fr_session->modifier1 = uwsgi_str_num(cs_mod+1, (fr_session->instance_address_len - (cs_mod - fr_session->instance_address))-1);
											fr_session->instance_address_len = (cs_mod - fr_session->instance_address);
										}
									}
								}
							}

							// no address found
							if (!fr_session->instance_address_len) {
								close_session(fr_table, fr_session);
                                                        	break;
							}


							fr_session->pass_fd = is_unix(fr_session->instance_address, fr_session->instance_address_len);

							fr_session->instance_fd = uwsgi_connectn(fr_session->instance_address, fr_session->instance_address_len, 0, 1);

							if (tmp_socket_name) free(tmp_socket_name);

							if (fr_session->instance_fd < 0) {
								fr_session->instance_failed = 1;
								close_session(fr_table, fr_session);
                                                        	break;
							}


							fr_session->status = FASTROUTER_STATUS_CONNECTING;
							fr_table[fr_session->instance_fd] = fr_session;
							event_queue_add_fd_write(ufr.queue, fr_session->instance_fd);
                                                }
                                                break;



					case FASTROUTER_STATUS_CONNECTING:
						
						if (interesting_fd == fr_session->instance_fd) {

							if (getsockopt(fr_session->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&soopt), &solen) < 0) {
                                                		uwsgi_error("getsockopt()");
								fr_session->instance_failed = 1;
								close_session(fr_table, fr_session);
                                                        	break;
                                        		}

							if (soopt) {
								uwsgi_log("unable to connect() to uwsgi instance: %s\n", strerror(soopt));
								fr_session->instance_failed = 1;
								close_session(fr_table, fr_session);
                                                        	break;
							}

							fr_session->uh.modifier1 = fr_session->modifier1;

							iov[0].iov_base = &fr_session->uh;
							iov[0].iov_len = 4;
							iov[1].iov_base = fr_session->buffer;
							iov[1].iov_len = fr_session->uh.pktsize;

							// increment node requests counter
							if (fr_session->un)
								fr_session->un->requests++;

							// fd passing: PERFORMANCE EXTREME BOOST !!!
							if (fr_session->pass_fd && !uwsgi.no_fd_passing) {
								msg.msg_name    = NULL;
                						msg.msg_namelen = 0;
                						msg.msg_iov     = iov;
                						msg.msg_iovlen  = 2;
                						msg.msg_flags   = 0;
                						msg.msg_control    = &msg_control;
                						msg.msg_controllen = sizeof (msg_control);

                						cmsg = CMSG_FIRSTHDR (&msg);
                						cmsg->cmsg_len   = CMSG_LEN (sizeof (int));
                						cmsg->cmsg_level = SOL_SOCKET;
                						cmsg->cmsg_type  = SCM_RIGHTS;

								memcpy(CMSG_DATA(cmsg), &fr_session->fd, sizeof(int));

                						if (sendmsg(fr_session->instance_fd, &msg, 0) < 0) {
									uwsgi_error("sendmsg()");
								}

								close_session(fr_table, fr_session);	
                                                                break;
							}

							if (writev(fr_session->instance_fd, iov, 2) < 0) {
								uwsgi_error("writev()");
								close_session(fr_table, fr_session);
                                                        	break;
							}

							event_queue_fd_write_to_read(ufr.queue, fr_session->instance_fd);
							fr_session->status = FASTROUTER_STATUS_RESPONSE;
						}

						break;

					case FASTROUTER_STATUS_RESPONSE:
						
						// data from instance
						if (interesting_fd == fr_session->instance_fd) {
							len = recv(fr_session->instance_fd, fr_session->buffer, 0xffff, 0);
							if (len <= 0) {
								if (len < 0) uwsgi_error("recv()");
								close_session(fr_table, fr_session);
                                                        	break;
							}

							len = send(fr_session->fd, fr_session->buffer, len, 0);
							
							if (len <= 0) {
								if (len < 0) uwsgi_error("send()");
								close_session(fr_table, fr_session);
                                                        	break;
							}

							// update transfer statistics
							if (fr_session->un)
								fr_session->un->transferred += len;
						}
						// body from client
						else if (interesting_fd == fr_session->fd) {

							//uwsgi_log("receiving body...\n");
							len = recv(fr_session->fd, fr_session->buffer, 0xffff, 0);
							if (len <= 0) {
								if (len < 0) uwsgi_error("recv()");
								close_session(fr_table, fr_session);
                                                        	break;
							}


							len = send(fr_session->instance_fd, fr_session->buffer, len, 0);
							
							if (len <= 0) {
								if (len < 0) uwsgi_error("send()");
								close_session(fr_table, fr_session);
                                                        	break;
							}
						}

						break;



					// fallback to destroy !!!
					default:
						uwsgi_log("unknown event: closing session\n");
						close_session(fr_table, fr_session);
						break;
					
				}
			}

		}
	}
}

int fastrouter_init() {

	if (ufr.sockets) {

		if (ufr.use_cache && !uwsgi.cache_max_items) {
			uwsgi_log("you need to create a uwsgi cache to use the fastrouter (add --cache <n>)\n");
			exit(1);
		}

		if (!ufr.nevents) ufr.nevents = 64;

		if (ufr.code_string_code && ufr.code_string_function) {
			if (register_fat_gateway("uWSGI fastrouter", fastrouter_loop) == NULL) {
				uwsgi_log("unable to register the fastrouter gateway\n");
				exit(1);
			}
		}
		else {
			if (register_gateway("uWSGI fastrouter", fastrouter_loop) == NULL) {
				uwsgi_log("unable to register the fastrouter gateway\n");
				exit(1);
			}
		}
	}

	return 0;
}
	
int fastrouter_opt(int i, char *optarg) {

	char *cs;
	char *cs_code;
	char *cs_func;
	int zerg_fd;
	int *zerg;
	int j;
	struct uwsgi_fastrouter_socket *fr_sock;

	switch(i) {
		case LONG_ARGS_FASTROUTER:
			uwsgi_fastrouter_new_socket(generate_socket_name(optarg), -1);
			return 1;
		case LONG_ARGS_FASTROUTER_ZERG:
			zerg_fd = uwsgi_connect(optarg, 30, 0);
                	if (zerg_fd < 0) {
                        	uwsgi_log("--- unable to connect to zerg server ---\n");
                        	exit(1);
                	}
                	zerg = uwsgi_attach_fd(zerg_fd, 8, "uwsgi-zerg", 11);
                	if (zerg == NULL) {
                        	uwsgi_log("--- invalid data received from zerg-server ---\n");
                        	exit(1);
                	}
                	close(zerg_fd);
			for(j=0;j<8;j++) {
				if (zerg[j] == -1) break;
				fr_sock = uwsgi_fastrouter_new_socket(NULL, zerg[j]);
				fr_sock->zerg = optarg;
			}
			return 1;
		case LONG_ARGS_FASTROUTER_SUBSCRIPTION_SERVER:
			ufr.subscription_server = optarg;
			return 1;
		case LONG_ARGS_FASTROUTER_STATS:
			ufr.stats_server = optarg;
			return 1;
		case LONG_ARGS_FASTROUTER_EVENTS:
			ufr.nevents = atoi(optarg);
			return 1;
		case LONG_ARGS_FASTROUTER_USE_PATTERN:
			ufr.pattern = optarg;
			// optimization
			ufr.pattern_len = strlen(ufr.pattern);
			return 1;
		case LONG_ARGS_FASTROUTER_USE_BASE:
			ufr.base = optarg;
			// optimization
			ufr.base_len = strlen(ufr.base);
			return 1;
		case LONG_ARGS_FASTROUTER_USE_CODE_STRING:
			cs = uwsgi_str(optarg);
			cs_code = strchr(cs, ':');
			if (!cs_code) {
				uwsgi_log("invalid code_string option\n");
				exit(1);	
			}
			cs_code[0] = 0;
			cs_func = strchr(cs_code+1, ':');
			if (!cs_func) {
				uwsgi_log("invalid code_string option\n");
				exit(1);	
			}
			cs_func[0] = 0;
			ufr.code_string_modifier1 = atoi(cs);
			ufr.code_string_code = cs_code+1;
			ufr.code_string_function = cs_func+1;
			return 1;
		case LONG_ARGS_FASTROUTER_TIMEOUT:
			ufr.socket_timeout = atoi(optarg);
			return -1;
		case LONG_ARGS_FASTROUTER_SUBSCRIPTION_SLOT:
			ufr.subscription_slot = atoi(optarg);
			return 1;
	}
	return 0;
}


struct uwsgi_plugin fastrouter_plugin = {

	.name = "fastrouter",
        .options = fastrouter_options,
        .manage_opt = fastrouter_opt,
        .init = fastrouter_init,
};


#define stats_send_llu(x, y) fprintf(output, x, (long long unsigned int) y)
#define stats_send(x, y) fprintf(output, x, y)

void fastrouter_send_stats(int fd) {

        struct sockaddr_un client_src;
        socklen_t client_src_len = 0;
        int client_fd = accept(fd, (struct sockaddr *) &client_src, &client_src_len);
        if (client_fd < 0) {
                uwsgi_error("accept()");
                return;
        }

        FILE *output = fdopen(client_fd, "w");
        if (!output) {
                uwsgi_error("fdopen()");
                close(client_fd);
                return;
        }

        stats_send("{ \"version\": \"%s\",\n", UWSGI_VERSION);

        fprintf(output,"\"pid\": %d,\n", (int)(getpid()));
        fprintf(output,"\"uid\": %d,\n", (int)(getuid()));
        fprintf(output,"\"gid\": %d,\n", (int)(getgid()));

        char *cwd = uwsgi_get_cwd();
        stats_send("\"cwd\": \"%s\",\n", cwd);
        free(cwd);

        fprintf(output, "\"fastrouter\": [");
	struct uwsgi_fastrouter_socket *uwsgi_sock = ufr.sockets;
        while(uwsgi_sock) {
		if (uwsgi_sock->next) {
			stats_send("\"%s\",", uwsgi_sock->name);
		}
		else {
			stats_send("\"%s\"", uwsgi_sock->name);
		}
		uwsgi_sock = uwsgi_sock->next;
	}
	fprintf(output, "],\n");

	if (ufr.subscription_server) {
		fprintf(output, "\"subscriptions\": [\n");
		struct uwsgi_subscribe_slot *s_slot = ufr.subscriptions;
		while(s_slot) {
			fprintf(output, "\t{ \"key\": \"%.*s\",\n", s_slot->keylen, s_slot->key);
			fprintf(output, "\t\t\"hits\": %llu,\n", (unsigned long long) s_slot->hits);
			fprintf(output, "\t\t\"nodes\": [\n");
			struct uwsgi_subscribe_node *s_node = s_slot->nodes;
			while(s_node) {
				fprintf(output, "\t\t\t{\"name\": \"%.*s\", \"modifier1\": %d, \"modifier2\": %d, \"last_check\": %llu, \"requests\": %llu, \"tx\": %llu, \"cores\": %llu, \"load\": %llu, \"ref\": %llu, \"failcnt\": %llu, \"death_mark\": %d}", s_node->len, s_node->name, s_node->modifier1, s_node->modifier2,
					(unsigned long long) s_node->last_check,  (unsigned long long) s_node->requests, (unsigned long long) s_node->transferred,
					(unsigned long long) s_node->cores, (unsigned long long) s_node->load, (unsigned long long) s_node->reference,
					(unsigned long long) s_node->failcnt, s_node->death_mark);
				if (s_node->next) {
					fprintf(output, ",\n");
				}
				else {
					fprintf(output, "\n");
				}
				s_node = s_node->next;
			}
			fprintf(output, "\t\t]\n");
			if (s_slot->next) {
				fprintf(output, "\t},\n");
			}
			else {
				fprintf(output, "\t}\n");
			}
			s_slot = s_slot->next;
			 // check for loopy optimization
                	if (s_slot == ufr.subscriptions) break;
		}
		fprintf(output, "],\n");
	}

	fprintf(output,"\"cheap\": %d\n", ufr.i_am_cheap);

        fprintf(output,"}\n");
        fclose(output);

}

