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

#define FASTROUTER_STATUS_FREE 0
#define FASTROUTER_STATUS_CONNECTING 1
#define FASTROUTER_STATUS_RECV_HDR 2
#define FASTROUTER_STATUS_RECV_VARS 3
#define FASTROUTER_STATUS_RESPONSE 4

#define add_timeout(x) uwsgi_add_rb_timer(ufr.timeouts, time(NULL)+ufr.socket_timeout, x)
#define del_timeout(x) rb_erase(&x->timeout->rbt, ufr.timeouts); free(x->timeout);

struct uwsgi_fastrouter_socket {
	char *name;
	int fd;
	struct uwsgi_fastrouter_socket *next;
};

struct uwsgi_fastrouter {

        struct uwsgi_fastrouter_socket *sockets;

        int use_cache;
        int nevents;

        int subscription_slot;

        char *pattern;
        int pattern_len;

        char *base;
        int base_len;

        char *subscription_server;
        struct uwsgi_dict *subscription_dict;

        int socket_timeout;

        struct rb_root *timeouts;
} ufr;


static struct uwsgi_fastrouter_socket *uwsgi_fastrouter_new_socket(char *name) {

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

        return uwsgi_sock;
}



struct option fastrouter_options[] = {
	{"fastrouter", required_argument, 0, LONG_ARGS_FASTROUTER},
	{"fastrouter-use-cache", no_argument, &ufr.use_cache, 1},
	{"fastrouter-use-pattern", required_argument, 0, LONG_ARGS_FASTROUTER_USE_PATTERN},
	{"fastrouter-use-base", required_argument, 0, LONG_ARGS_FASTROUTER_USE_BASE},
	{"fastrouter-events", required_argument, 0, LONG_ARGS_FASTROUTER_EVENTS},
	{"fastrouter-subscription-server", required_argument, 0, LONG_ARGS_FASTROUTER_SUBSCRIPTION_SERVER},
	{"fastrouter-subscription-slot", required_argument, 0, LONG_ARGS_FASTROUTER_SUBSCRIPTION_SLOT},
	{"fastrouter-timeout", required_argument, 0, LONG_ARGS_FASTROUTER_TIMEOUT},
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
}

struct fastrouter_session {

	int fd;
	int instance_fd;
	int status;
	struct uwsgi_header uh;
	uint8_t h_pos;
	char buffer[0xffff];
	uint16_t pos;

	char *hostname;
	uint16_t hostname_len;

	int has_key;

	char *instance_address;
	uint64_t instance_address_len;

	struct uwsgi_subscriber_name *un;
	int pass_fd;

	struct uwsgi_rb_timer *timeout;
	int instance_failed;

	uint8_t modifier1;
};

static void close_session(struct fastrouter_session **fr_table, struct fastrouter_session *fr_session) {

	close(fr_session->fd);
	fr_table[fr_session->fd] = NULL;
	if (fr_session->instance_fd != -1) {
		if (ufr.subscription_server && (fr_session->instance_failed || fr_session->status == FASTROUTER_STATUS_CONNECTING)) {
			uwsgi_log("marking %.*s as failed\n", (int) fr_session->instance_address_len,fr_session->instance_address);
			fr_session->un->len = 0;
		}
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
			uwsgi_log("timeout !!!\n");
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

	int fr_queue;
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

	for(i=0;i<2048;i++) {
		fr_table[i] = NULL;
	}

	fr_queue = event_queue_init();

	struct uwsgi_fastrouter_socket *ufr_sock = ufr.sockets;

	while(ufr_sock) {
		if (ufr_sock->name[0] == '=') {
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

		event_queue_add_fd_read(fr_queue, ufr_sock->fd);
		ufr_sock = ufr_sock->next;
	}


	events = event_queue_alloc(ufr.nevents);


	if (ufr.subscription_server) {
		ufr_subserver = bind_to_udp(ufr.subscription_server, 0, 0);
		event_queue_add_fd_read(fr_queue, ufr_subserver);
		if (!ufr.subscription_slot) ufr.subscription_slot = 30;
		ufr.subscription_dict = uwsgi_dict_create(ufr.subscription_slot, 0);
	}

	if (ufr.pattern) {
		init_magic_table(magic_table);
	}

	ufr.timeouts = uwsgi_init_rb_timer();
	if (!ufr.socket_timeout) ufr.socket_timeout = 30;

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

		nevents = event_queue_wait_multi(fr_queue, delta, events, ufr.nevents);

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
					fr_table[new_connection]->instance_failed = 0;
					fr_table[new_connection]->instance_address_len = 0;
		
					fr_table[new_connection]->timeout = add_timeout(fr_table[new_connection]);

					event_queue_add_fd_read(fr_queue, new_connection);
					taken = 1;
					break;
				}
				
				uwsgi_sock = uwsgi_sock->next;
			}	

			if (taken) {
				continue;
			}

			if (interesting_fd == ufr_subserver) {
				len = recv(ufr_subserver, bbuf, 4096, 0);
#ifdef UWSGI_EVENT_USE_PORT
				event_queue_add_fd_read(fr_queue, ufr_subserver);
#endif
				if (len > 0) {
					memset(&usr, 0, sizeof(struct uwsgi_subscribe_req));
					uwsgi_hooked_parse(bbuf+4, len-4, fastrouter_manage_subscription, &usr);
					uwsgi_add_subscriber(ufr.subscription_dict, &usr);
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
							uwsgi_log("requested domain %.*s\n", fr_session->hostname_len, fr_session->hostname);
#endif
							if (ufr.use_cache) {
								fr_session->instance_address = uwsgi_cache_get(fr_session->hostname, fr_session->hostname_len, &fr_session->instance_address_len);
							}
							else if (ufr.pattern) {
								magic_table['s'] = uwsgi_concat2n(fr_session->hostname, fr_session->hostname_len, "", 0);	
								tmp_socket_name = magic_sub(ufr.pattern, ufr.pattern_len, &tmp_socket_name_len, magic_table);
								free(magic_table['s']);
								fr_session->instance_address_len = tmp_socket_name_len;
								fr_session->instance_address = tmp_socket_name;
							}
							else if (ufr.subscription_server) {
								fr_session->un = uwsgi_get_subscriber(ufr.subscription_dict, fr_session->hostname, fr_session->hostname_len);
								if (fr_session->un && fr_session->un->len) {
									fr_session->instance_address = fr_session->un->name;
									fr_session->instance_address_len = fr_session->un->len;
									fr_session->modifier1 = fr_session->un->modifier1;
								}
							}
							else if (ufr.base) {
								tmp_socket_name = uwsgi_concat2nn(ufr.base, ufr.base_len, fr_session->hostname, fr_session->hostname_len, &tmp_socket_name_len);
								fr_session->instance_address_len = tmp_socket_name_len;
								fr_session->instance_address = tmp_socket_name;
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
								if (ufr.subscription_server) {
	                                                        	uwsgi_log("marking %.*s as failed\n", (int) fr_session->instance_address_len,fr_session->instance_address);
	                                                        	fr_session->un->len = 0;
	                                                        }
								close_session(fr_table, fr_session);
                                                        	break;
							}


							fr_session->status = FASTROUTER_STATUS_CONNECTING;
							fr_table[fr_session->instance_fd] = fr_session;
							event_queue_add_fd_write(fr_queue, fr_session->instance_fd);
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

							event_queue_fd_write_to_read(fr_queue, fr_session->instance_fd);
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
						uwsgi_log("default action\n");
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

		if (register_gateway("fastrouter", fastrouter_loop) == NULL) {
			uwsgi_log("unable to register the fastrouter gateway\n");
			exit(1);
		}
	}

	return 0;
}
	
int fastrouter_opt(int i, char *optarg) {

	switch(i) {
		case LONG_ARGS_FASTROUTER:
			uwsgi_fastrouter_new_socket(generate_socket_name(optarg));
			return 1;
		case LONG_ARGS_FASTROUTER_SUBSCRIPTION_SERVER:
			ufr.subscription_server = optarg;
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

