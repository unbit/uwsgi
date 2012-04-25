/*

   uWSGI fastrouter

   requires:

   - async
   - caching
   - pcre (optional)

*/

#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include "../../lib/corerouter.h"


#ifdef UWSGI_SCTP
extern struct uwsgi_fr_sctp_node **uwsgi_fastrouter_sctp_nodes;
extern struct uwsgi_fr_sctp_node **uwsgi_fastrouter_sctp_nodes_current;
#endif

void fastrouter_send_stats(int);

#include "fr.h"

struct uwsgi_fastrouter ufr;

void uwsgi_opt_fastrouter(char *opt, char *value, void *foobar) {
	uwsgi_new_gateway_socket(value, "uWSGI fastrouter");
        ufr.has_sockets++;
}

void uwsgi_opt_fastrouter_use_socket(char *opt, char *value, void *foobar) {
	ufr.use_socket = 1;

	if (value) {
		ufr.socket_num = atoi(value);
	}
}

void uwsgi_opt_fastrouter_zerg(char *opt, char *value, void *foobar) {

	int j;
	int count = 8;
	struct uwsgi_gateway_socket *ugs;

	int zerg_fd = uwsgi_connect(value, 30, 0);
        if (zerg_fd < 0) {
        	uwsgi_log("--- unable to connect to zerg server ---\n");
                exit(1);
        }

	int last_count = count;
        int *zerg = uwsgi_attach_fd(zerg_fd, &count, "uwsgi-zerg", 10);
        if (zerg == NULL) {
		if (last_count != count) {
               		close(zerg_fd);
			zerg_fd = uwsgi_connect(value, 30, 0);
			if (zerg_fd < 0) {
				uwsgi_log("--- unable to connect to zerg server ---\n");
				exit(1);
			}
			zerg = uwsgi_attach_fd(zerg_fd, &count, "uwsgi-zerg", 10);
		}
		else {
               		uwsgi_log("--- invalid data received from zerg-server ---\n");
              		exit(1);
		}
	}

	if (zerg == NULL) {
               	uwsgi_log("--- invalid data received from zerg-server ---\n");
              	exit(1);
	}


	close(zerg_fd);

                        for(j=0;j<count;j++) {
                                if (zerg[j] == -1) break;
                                ugs = uwsgi_new_gateway_socket_from_fd(zerg[j], "uWSGI fastrouter");
                                ugs->zerg = optarg;
                        }
}

void uwsgi_opt_fastrouter_cs(char *opt, char *value, void *foobar) {

	char *cs = uwsgi_str(value);
               char *cs_code = strchr(cs, ':');
                if (!cs_code) {
                        uwsgi_log("invalid code_string option\n");
                        exit(1);
                }
                cs_code[0] = 0;
                char *cs_func = strchr(cs_code + 1, ':');
                if (!cs_func) {
                        uwsgi_log("invalid code_string option\n");
                        exit(1);
                }
                cs_func[0] = 0;
                ufr.code_string_modifier1 = atoi(cs);
                ufr.code_string_code = cs_code + 1;
                ufr.code_string_function = cs_func + 1;
	
}

void uwsgi_opt_fastrouter_ss(char *opt, char *value, void *foobar) {

	struct uwsgi_gateway_socket *ugs = uwsgi_new_gateway_socket(value, "uWSGI fastrouter");
        ugs->subscription = 1;
        ufr.has_subscription_sockets++;

}

void uwsgi_opt_fastrouter_use_base(char *opt, char *value, void *foobar) {
	ufr.base = value;
	ufr.base_len = strlen(ufr.base);
}

void uwsgi_opt_fastrouter_use_pattern(char *opt, char *value, void *foobar) {
	ufr.pattern = value;
	ufr.pattern_len = strlen(ufr.pattern);
}

struct uwsgi_option fastrouter_options[] = {
	{"fastrouter", required_argument, 0, "run the fastrouter on the specified port", uwsgi_opt_fastrouter, NULL, 0},
	{"fastrouter-processes", required_argument, 0, "prefork the specified number of fastrouter processes", uwsgi_opt_set_int, &ufr.processes, 0},
	{"fastrouter-workers", required_argument, 0, "prefork the specified number of fastrouter processes", uwsgi_opt_set_int, &ufr.processes, 0},
	{"fastrouter-zerg", required_argument, 0, "attach the fastrouter to a zerg server", uwsgi_opt_fastrouter_zerg, NULL, 0 },
	{"fastrouter-use-cache", no_argument, 0, "use uWSGI cache as hostname->server mapper for the fastrouter", uwsgi_opt_true, &ufr.use_cache, 0},

	{"fastrouter-use-pattern", required_argument, 0, "use a pattern for fastrouter hostname->server mapping", uwsgi_opt_fastrouter_use_pattern, NULL, 0},
	{"fastrouter-use-base", required_argument, 0, "use a base dir for fastrouter hostname->server mapping", uwsgi_opt_fastrouter_use_base, NULL, 0},

	{"fastrouter-fallback", required_argument, 0, "fallback to the specified node in case of error", uwsgi_opt_add_string_list, &ufr.fallback, 0},

	{"fastrouter-use-code-string", required_argument, 0, "use code string as hostname->server mapper for the fastrouter", uwsgi_opt_fastrouter_cs, NULL, 0},
	{"fastrouter-use-socket", optional_argument, 0, "forward request to the specified uwsgi socket", uwsgi_opt_fastrouter_use_socket, NULL, 0},
	{"fastrouter-to", required_argument, 0, "forward requests to the specified uwsgi server (you can specify it multiple times for load balancing)", uwsgi_opt_add_string_list, &ufr.static_nodes, 0},
	{"fastrouter-gracetime", required_argument, 0, "retry connections to dead static nodes after the specified amount of seconds", uwsgi_opt_set_int, &ufr.static_node_gracetime, 0},
	{"fastrouter-events", required_argument, 0, "set the maximum number of concurrent events", uwsgi_opt_set_int, &ufr.nevents, 0},
	{"fastrouter-quiet", required_argument, 0, "do not report failed connections to instances", uwsgi_opt_true, &ufr.quiet, 0},
	{"fastrouter-cheap", no_argument, 0, "run the fastrouter in cheap mode", uwsgi_opt_true, &ufr.cheap, 0},
	{"fastrouter-subscription-server", required_argument, 0, "run the fastrouter subscription server on the spcified address", uwsgi_opt_fastrouter_ss, NULL, 0},
	{"fastrouter-subscription-slot", required_argument, 0, "*** deprecated ***", uwsgi_opt_deprecated, (void *) "useless thanks to the new implementation", 0},
	{"fastrouter-subscription-use-regexp", no_argument, 0, "enable regexp for subscription system", uwsgi_opt_true, &ufr.subscription_regexp, 0},

#ifdef UWSGI_SCTP
	{"fastrouter-sctp", required_argument, 0, "run the fastrouter SCTP server on the specified address", uwsgi_opt_fastrouter_sctp, NULL, 0},
#endif

	{"fastrouter-timeout", required_argument, 0, "set fastrouter timeout", uwsgi_opt_set_int, &ufr.socket_timeout, 0},
	{"fastrouter-post-buffering", required_argument, 0, "enable fastrouter post buffering", uwsgi_opt_set_64bit, &ufr.post_buffering, 0},
	{"fastrouter-post-buffering-dir", required_argument, 0, "put fastrouter buffered files to the specified directory", uwsgi_opt_set_str, &ufr.pb_base_dir, 0},

	{"fastrouter-stats", required_argument, 0, "run the fastrouter stats server", uwsgi_opt_set_str, &ufr.stats_server, 0},
	{"fastrouter-stats-server", required_argument, 0, "run the fastrouter stats server", uwsgi_opt_set_str, &ufr.stats_server, 0},
	{"fastrouter-ss", required_argument, 0, "run the fastrouter stats server", uwsgi_opt_set_str, &ufr.stats_server, 0},
	{"fastrouter-harakiri", required_argument, 0, "enable fastrouter harakiri", uwsgi_opt_set_int, &ufr.harakiri, 0 },
	{0, 0, 0, 0, 0, 0, 0},
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
	else if (!uwsgi_strncmp("weight", 5, key, keylen)) {
		usr->weight = uwsgi_str_num(val, vallen);
	}
}

static struct uwsgi_rb_timer *reset_timeout(struct fastrouter_session *);

void close_session(struct fastrouter_session *fr_session) {


	if (fr_session->instance_fd != -1) {
#ifdef UWSGI_SCTP
		if (!ufr.fr_table[fr_session->instance_fd]->persistent) {
#endif
			close(fr_session->instance_fd);
			ufr.fr_table[fr_session->instance_fd] = NULL;
#ifdef UWSGI_SCTP
		}
#endif
	}

	if (ufr.subscriptions && fr_session->un && fr_session->un->len > 0) {
        	// decrease reference count
#ifdef UWSGI_DEBUG
               uwsgi_log("[1] node %.*s refcnt: %llu\n", fr_session->un->len, fr_session->un->name, fr_session->un->reference);
#endif
               fr_session->un->reference--;
#ifdef UWSGI_DEBUG
               uwsgi_log("[2] node %.*s refcnt: %llu\n", fr_session->un->len, fr_session->un->name, fr_session->un->reference);
#endif
	}


	if (fr_session->instance_failed) {

		if (fr_session->soopt) {
			if (!ufr.quiet)
				uwsgi_log("unable to connect() to uwsgi instance \"%.*s\": %s\n", (int) fr_session->instance_address_len, fr_session->instance_address, strerror(fr_session->soopt));
		}
		else if (fr_session->timed_out) {
			if (fr_session->instance_address_len > 0) {
				if (fr_session->status == FASTROUTER_STATUS_CONNECTING) {
					if (!ufr.quiet)
						uwsgi_log("unable to connect() to uwsgi instance \"%.*s\": timeout\n", (int) fr_session->instance_address_len, fr_session->instance_address);
				}
				else if (fr_session->status  == FASTROUTER_STATUS_RESPONSE) {
					uwsgi_log("timeout waiting for instance \"%.*s\"\n", (int) fr_session->instance_address_len, fr_session->instance_address);
				}
			}
		}

		// now check for dead nodes
		if (ufr.subscriptions && fr_session->un && fr_session->un->len > 0) {

                        if (fr_session->un->death_mark == 0)
                                uwsgi_log("[uwsgi-fastrouter] %.*s => marking %.*s as failed\n", (int) fr_session->hostname_len, fr_session->hostname, (int) fr_session->instance_address_len, fr_session->instance_address);

                        fr_session->un->failcnt++;
                        fr_session->un->death_mark = 1;
                        // check if i can remove the node
                        if (fr_session->un->reference == 0) {
                                uwsgi_remove_subscribe_node(&ufr.subscriptions, fr_session->un);
                        }
                        if (ufr.subscriptions == NULL && ufr.cheap && !ufr.i_am_cheap && !ufr.fallback) {
                                uwsgi_gateway_go_cheap("uWSGI fastrouter", ufr.queue, &ufr.i_am_cheap);
                        }

        	}
		else if (fr_session->static_node) {
			fr_session->static_node->custom = uwsgi_now();
			uwsgi_log("[uwsgi-fastrouter] %.*s => marking %.*s as failed\n", (int) fr_session->hostname_len, fr_session->hostname, (int) fr_session->instance_address_len, fr_session->instance_address);
		}


		if (fr_session->tmp_socket_name) {
			free(fr_session->tmp_socket_name);
			fr_session->tmp_socket_name = NULL;
		}

		if (ufr.fallback) {
			// ok let's try with the fallback nodes
			if (!fr_session->fallback) {
				fr_session->fallback = ufr.fallback;
			}
			else {
				fr_session->fallback = fr_session->fallback->next;
				if (!fr_session->fallback) goto end;
			}

			fr_session->instance_address = fr_session->fallback->value;
			fr_session->instance_address_len = fr_session->fallback->len;

			// reset error and timeout
			fr_session->timeout = reset_timeout(fr_session);
			fr_session->timed_out = 0;
			fr_session->soopt = 0;

			// reset nodes
			fr_session->un = NULL;
			fr_session->static_node = NULL;

			fr_session->pass_fd = is_unix(fr_session->instance_address, fr_session->instance_address_len);


                	fr_session->instance_fd = uwsgi_connectn(fr_session->instance_address, fr_session->instance_address_len, 0, 1);

                	if (fr_session->instance_fd < 0) {
                		fr_session->instance_failed = 1;
				fr_session->soopt = errno;
                        	close_session(fr_session);
				return;
			}
  
			ufr.fr_table[fr_session->instance_fd] = fr_session;

                	fr_session->status = FASTROUTER_STATUS_CONNECTING;
                	ufr.fr_table[fr_session->instance_fd] = fr_session;
                	event_queue_add_fd_write(ufr.queue, fr_session->instance_fd);
			return;

		}
	}

end:

	if (fr_session->tmp_socket_name) {
		free(fr_session->tmp_socket_name);
	}

	if (fr_session->buf_file)
		fclose(fr_session->buf_file);

	if (fr_session->buf_file_name) {
		if (unlink(fr_session->buf_file_name)) {
			uwsgi_error("unlink()");
		}
		free(fr_session->buf_file_name);
	}

	close(fr_session->fd);
	ufr.fr_table[fr_session->fd] = NULL;

	del_timeout(fr_session);
	free(fr_session);
}

static struct uwsgi_rb_timer *reset_timeout(struct fastrouter_session *fr_session) {
	del_timeout(fr_session);
	return add_timeout(fr_session);
}

static void expire_timeouts() {

	time_t current = time(NULL);
	struct uwsgi_rb_timer *urbt;
	struct fastrouter_session *fr_session;

	for (;;) {
		urbt = uwsgi_min_rb_timer(ufr.timeouts);
		if (urbt == NULL)
			return;

		if (urbt->key <= current) {
			fr_session = (struct fastrouter_session *) urbt->data;
			fr_session->timed_out = 1;
			if (fr_session->retry) {
				fr_session->retry = 0;
				uwsgi_fastrouter_switch_events(fr_session, -1, ufr.magic_table);
				if (fr_session->retry) {
					del_timeout(fr_session);
					fr_session->timeout = add_fake_timeout(fr_session);
				}
				else {
					fr_session->timeout = reset_timeout(fr_session);
				}
			}
			else {
				close_session(fr_session);
			}
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

	if (ufr.post_buffering > 0) {
		if (!uwsgi_strncmp("CONTENT_LENGTH", 14, key, keylen)) {
			fr_session->post_cl = uwsgi_str_num(val, vallen);
			return;
		}
	}
}

struct fastrouter_session *alloc_fr_session() {

	return uwsgi_calloc(sizeof(struct fastrouter_session));
}

void fastrouter_loop(int id) {

	int i;

	ufr.fr_stats_server = -1;

	ufr.fr_table = uwsgi_malloc(sizeof(struct fastrouter_session *) * uwsgi.max_fd);

	for (i = 0; i < (int) uwsgi.max_fd; i++) {
		ufr.fr_table[i] = NULL;
	}

	ufr.i_am_cheap = ufr.cheap;

	void *events = uwsgi_corerouter_setup_event_queue("uWSGI fastrouter", id, ufr.nevents, &ufr.queue, ufr.i_am_cheap);

	if (ufr.has_subscription_sockets)
		event_queue_add_fd_read(ufr.queue, ushared->gateways[id].internal_subscription_pipe[1]);


	if (!ufr.socket_timeout)
		ufr.socket_timeout = 30;

	if (!ufr.static_node_gracetime)
		ufr.static_node_gracetime = 30;

	int i_am_the_first = 1;
	for(i=0;i<id;i++) {
		if (!strcmp(ushared->gateways[i].name, "uWSGI fastrouter")) {
			i_am_the_first = 0;
			break;
		}
	}

	if (ufr.stats_server && i_am_the_first) {
		char *tcp_port = strchr(ufr.stats_server, ':');
		if (tcp_port) {
			// disable deferred accept for this socket
			int current_defer_accept = uwsgi.no_defer_accept;
			uwsgi.no_defer_accept = 1;
			ufr.fr_stats_server = bind_to_tcp(ufr.stats_server, uwsgi.listen_queue, tcp_port);
			uwsgi.no_defer_accept = current_defer_accept;
		}
		else {
			ufr.fr_stats_server = bind_to_unix(ufr.stats_server, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
		}

		event_queue_add_fd_read(ufr.queue, ufr.fr_stats_server);
		uwsgi_log("*** FastRouter stats server enabled on %s fd: %d ***\n", ufr.stats_server, ufr.fr_stats_server);
	}


	if (ufr.use_socket) {
		ufr.to_socket = uwsgi_get_socket_by_num(ufr.socket_num);
		if (ufr.to_socket) {
			// fix socket name_len
			if (ufr.to_socket->name_len == 0 && ufr.to_socket->name) {
				ufr.to_socket->name_len = strlen(ufr.to_socket->name);
			}
		}
	}

	if (!ufr.pb_base_dir) {
		ufr.pb_base_dir = getenv("TMPDIR");
		if (!ufr.pb_base_dir)
			ufr.pb_base_dir = "/tmp";
	}

	int nevents;

	time_t delta;

	struct uwsgi_rb_timer *min_timeout;

	int interesting_fd;
	int new_connection;


	if (ufr.pattern) {
		init_magic_table(ufr.magic_table);
	}

#ifdef UWSGI_SCTP
	uwsgi_fastrouter_sctp_nodes = uwsgi_calloc(sizeof(struct uwsgi_fastrouter_sctp_nodes*));
	uwsgi_fastrouter_sctp_nodes_current = uwsgi_calloc(sizeof(struct uwsgi_fastrouter_sctp_nodes*));
#endif

	struct sockaddr_un fr_addr;
	socklen_t fr_addr_len = sizeof(struct sockaddr_un);

	struct fastrouter_session *fr_session;

	ufr.mapper = uwsgi_fr_map_use_void;

			if (ufr.use_cache) {
                        	ufr.mapper = uwsgi_fr_map_use_cache;
                        }
                        else if (ufr.pattern) {
                                ufr.mapper = uwsgi_fr_map_use_pattern;
                        }
                        else if (ufr.has_subscription_sockets) {
                                ufr.mapper = uwsgi_fr_map_use_subscription;
                        }
                        else if (ufr.base) {
                                ufr.mapper = uwsgi_fr_map_use_base;
                        }
                        else if (ufr.code_string_code && ufr.code_string_function) {
                                ufr.mapper = uwsgi_fr_map_use_cs;
			}
                        else if (ufr.to_socket) {
                                ufr.mapper = uwsgi_fr_map_use_to;
                        }
                        else if (ufr.static_nodes) {
                                ufr.mapper = uwsgi_fr_map_use_static_nodes;
                        }
#ifdef UWSGI_SCTP
                        else if (ufr.has_sctp_sockets > 0) {
                                ufr.mapper = uwsgi_fr_map_use_sctp;
                        }
#endif



	ufr.timeouts = uwsgi_init_rb_timer();

	for (;;) {

		min_timeout = uwsgi_min_rb_timer(ufr.timeouts);
		if (min_timeout == NULL) {
			delta = -1;
		}
		else {
			delta = min_timeout->key - time(NULL);
			if (delta <= 0) {
				expire_timeouts();
				delta = 0;
			}
		}

		if (uwsgi.master_process && ufr.harakiri > 0) {
			ushared->gateways_harakiri[id] = 0;
		}

		nevents = event_queue_wait_multi(ufr.queue, delta, events, ufr.nevents);

		if (uwsgi.master_process && ufr.harakiri > 0) {
			ushared->gateways_harakiri[id] = time(NULL) + ufr.harakiri;
		}

		if (nevents == 0) {
			expire_timeouts();
		}

		for (i = 0; i < nevents; i++) {

			interesting_fd = event_queue_interesting_fd(events, i);

			struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
			int taken = 0;
			while (ugs) {
				if (ugs->gateway == &ushared->gateways[id] && interesting_fd == ugs->fd) {
#ifdef UWSGI_SCTP
					if (!ugs->subscription && !ugs->sctp) {
#else
					if (!ugs->subscription) {
#endif

						new_connection = accept(interesting_fd, (struct sockaddr *) &fr_addr, &fr_addr_len);
						if (new_connection < 0) {
							taken = 1;
							break;
						}

#ifndef __linux__
                                                uwsgi_socket_b(new_connection);
#endif

						ufr.fr_table[new_connection] = alloc_fr_session();
						ufr.fr_table[new_connection]->fd = new_connection;
						ufr.fr_table[new_connection]->instance_fd = -1;
						ufr.fr_table[new_connection]->status = FASTROUTER_STATUS_RECV_HDR;

						ufr.fr_table[new_connection]->timeout = add_timeout(ufr.fr_table[new_connection]);

						event_queue_add_fd_read(ufr.queue, new_connection);
					}
					else if (ugs->subscription) {
						uwsgi_corerouter_manage_subscription("uWSGI fastrouter", id, ugs, ufr.queue, &ufr.subscriptions,
							ufr.subscription_regexp, fastrouter_manage_subscription, ufr.cheap, &ufr.i_am_cheap);
					}
#ifdef UWSGI_SCTP
					else if (ugs->sctp) {
						new_connection = accept(interesting_fd, (struct sockaddr *) &fr_addr, &fr_addr_len);
						if (new_connection < 0) {
                                                        taken = 1;
							break;
						}
						struct uwsgi_fr_sctp_node *sctp_node = uwsgi_fr_sctp_add_node(new_connection);
						snprintf(sctp_node->name, 64, "%s:%d", inet_ntoa(((struct sockaddr_in *)&fr_addr)->sin_addr), ntohs(((struct sockaddr_in *) &fr_addr)->sin_port));
						uwsgi_log("new SCTP peer: %s:%d\n", inet_ntoa(((struct sockaddr_in *)&fr_addr)->sin_addr), ntohs(((struct sockaddr_in *) &fr_addr)->sin_port));

						ufr.fr_table[new_connection] = alloc_fr_session();
                                                ufr.fr_table[new_connection]->instance_fd = new_connection;
                                                ufr.fr_table[new_connection]->fd = -1;
						ufr.fr_table[new_connection]->persistent = 1;
                                                ufr.fr_table[new_connection]->status = FASTROUTER_STATUS_SCTP_NODE_FREE;

						struct sctp_event_subscribe events;
						memset(&events, 0, sizeof(events) );
						events.sctp_data_io_event = 1;
						// check for errors
						setsockopt(new_connection, SOL_SCTP, SCTP_EVENTS, &events, sizeof(events) );

                                                event_queue_add_fd_read(ufr.queue, new_connection);
					}
#endif

					taken = 1;
					break;
				}


				ugs = ugs->next;
			}

			if (taken) {
				continue;
			}

			if (interesting_fd == ushared->gateways[id].internal_subscription_pipe[1]) {
				uwsgi_corerouter_manage_internal_subscription("uWSGI fastrouter", ufr.queue, interesting_fd, &ufr.subscriptions,
					ufr.subscription_regexp, fastrouter_manage_subscription, ufr.cheap, &ufr.i_am_cheap);	
			}
			else if (interesting_fd == ufr.fr_stats_server) {
				fastrouter_send_stats(ufr.fr_stats_server);
			}
			else {
				fr_session = ufr.fr_table[interesting_fd];

				// something is going wrong...
				if (fr_session == NULL)
					continue;

				if (event_queue_interesting_fd_has_error(events, i)) {
#ifdef UWSGI_SCTP
					if (!fr_session->persistent) {
#endif
						close_session(fr_session);
						continue;
#ifdef UWSGI_SCTP
					}
#endif
				}

#ifdef UWSGI_SCTP
				if (!fr_session->persistent) {
#endif
					fr_session->timeout = reset_timeout(fr_session);
#ifdef UWSGI_SCTP
				}
#endif
				
				uwsgi_fastrouter_switch_events(fr_session, interesting_fd, ufr.magic_table);
				

			}
		}
	}

}

int fastrouter_init() {

	int i;

	if (ufr.has_sockets) {

		if (ufr.use_cache && !uwsgi.cache_max_items) {
			uwsgi_log("you need to create a uwsgi cache to use the fastrouter (add --cache <n>)\n");
			exit(1);
		}

		if (!ufr.nevents)
			ufr.nevents = 64;

		uwsgi_corerouter_setup_sockets("uWSGI fastrouter");

		if (ufr.processes < 1)
			ufr.processes = 1;
		if (ufr.cheap) {
			uwsgi_log("starting fastrouter in cheap mode\n");
		}
		for (i = 0; i < ufr.processes; i++) {
			if (register_gateway("uWSGI fastrouter", fastrouter_loop) == NULL) {
				uwsgi_log("unable to register the fastrouter gateway\n");
				exit(1);
			}
		}
	}

	return 0;
}


struct uwsgi_plugin fastrouter_plugin = {

	.name = "fastrouter",
	.options = fastrouter_options,
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

	fprintf(output, "\"pid\": %d,\n", (int) (getpid()));
	fprintf(output, "\"uid\": %d,\n", (int) (getuid()));
	fprintf(output, "\"gid\": %d,\n", (int) (getgid()));

	char *cwd = uwsgi_get_cwd();
	stats_send("\"cwd\": \"%s\",\n", cwd);
	free(cwd);

	fprintf(output, "\"fastrouter\": [");
	struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
	while (ugs) {
		if (!strcmp(ugs->owner, "uWSGI fastrouter")) {
			if (ugs->next) {
				stats_send("\"%s\",", ugs->name);
			}
			else {
				stats_send("\"%s\"", ugs->name);
			}
		}
		ugs = ugs->next;
	}
	fprintf(output, "],\n");

	if (ufr.has_subscription_sockets) {
		fprintf(output, "\"subscriptions\": [\n");
		struct uwsgi_subscribe_slot *s_slot = ufr.subscriptions;
		while (s_slot) {
			fprintf(output, "\t{ \"key\": \"%.*s\",\n", s_slot->keylen, s_slot->key);
			fprintf(output, "\t\t\"hits\": %llu,\n", (unsigned long long) s_slot->hits);
			fprintf(output, "\t\t\"nodes\": [\n");
			struct uwsgi_subscribe_node *s_node = s_slot->nodes;
			while (s_node) {
				fprintf(output, "\t\t\t{\"name\": \"%.*s\", \"modifier1\": %d, \"modifier2\": %d, \"last_check\": %llu, \"requests\": %llu, \"tx\": %llu, \"cores\": %llu, \"load\": %llu, \"weight\": %llu, \"wrr\": %llu, \"ref\": %llu, \"failcnt\": %llu, \"death_mark\": %d}", s_node->len, s_node->name, s_node->modifier1, s_node->modifier2, (unsigned long long) s_node->last_check, (unsigned long long) s_node->requests, (unsigned long long) s_node->transferred, (unsigned long long) s_node->cores, (unsigned long long) s_node->load, (unsigned long long) s_node->weight, (unsigned long long) s_node->wrr, (unsigned long long) s_node->reference, (unsigned long long) s_node->failcnt, s_node->death_mark);
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
			if (s_slot == ufr.subscriptions)
				break;
		}
		fprintf(output, "],\n");
	}

#ifdef UWSGI_SCTP
	if (ufr.has_sctp_sockets > 0) {
		fprintf(output, "\"sctp_nodes\": [\n");
		struct uwsgi_fr_sctp_node *sctp_node = *uwsgi_fastrouter_sctp_nodes;
		while(sctp_node) {
			fprintf(output, "\t{ \"node\": \"%s\", \"requests\": %llu }", sctp_node->name, (unsigned long long) sctp_node->requests);
			if (sctp_node->next == *uwsgi_fastrouter_sctp_nodes) {
				fprintf(output, "\n");
				break;
			}
			sctp_node = sctp_node->next;
			fprintf(output, ",\n");
		}
		fprintf(output, "],\n");
	}
#endif

	fprintf(output, "\"cheap\": %d\n", ufr.i_am_cheap);

	fprintf(output, "}\n");
	fclose(output);

}
