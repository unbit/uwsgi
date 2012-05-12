/*

   uWSGI fastrouter

   requires:

   - async
   - caching
   - pcre (optional)

*/

#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include "cr.h"

void uwsgi_opt_corerouter(char *opt, char *value, void *cr) {
	struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;
        uwsgi_new_gateway_socket(value, ucr->name);
        ucr->has_sockets++;
}

void uwsgi_opt_corerouter_use_socket(char *opt, char *value, void *cr) {
	struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;
        ucr->use_socket = 1;

        if (value) {
                ucr->socket_num = atoi(value);
        }
}

void uwsgi_opt_corerouter_use_base(char *opt, char *value, void *cr) {
	struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;
        ucr->base = value;
        ucr->base_len = strlen(ucr->base);
}

void uwsgi_opt_corerouter_use_pattern(char *opt, char *value, void *cr) {
	struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;
        ucr->pattern = value;
        ucr->pattern_len = strlen(ucr->pattern);
}


void uwsgi_opt_corerouter_zerg(char *opt, char *value, void *cr) {

        int j;
        int count = 8;
        struct uwsgi_gateway_socket *ugs;
	struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;

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
                                ugs = uwsgi_new_gateway_socket_from_fd(zerg[j], ucr->name);
                                ugs->zerg = optarg;
                        }
}


void uwsgi_opt_corerouter_cs(char *opt, char *value, void *cr) {

	struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;

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
                ucr->code_string_modifier1 = atoi(cs);
                ucr->code_string_code = cs_code + 1;
                ucr->code_string_function = cs_func + 1;

}

void uwsgi_opt_corerouter_ss(char *opt, char *value, void *cr) {

	struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;
        struct uwsgi_gateway_socket *ugs = uwsgi_new_gateway_socket(value, ucr->name);
        ugs->subscription = 1;
        ucr->has_subscription_sockets++;

}


void corerouter_send_stats(struct uwsgi_corerouter *);

void corerouter_manage_subscription(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

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

static struct uwsgi_rb_timer *corerouter_reset_timeout(struct uwsgi_corerouter *, struct corerouter_session *);

void corerouter_close_session(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {


	if (cr_session->instance_fd != -1) {
#ifdef UWSGI_SCTP
		if (!ucr->cr_table[cr_session->instance_fd]->persistent) {
#endif
			close(cr_session->instance_fd);
			ucr->cr_table[cr_session->instance_fd] = NULL;
#ifdef UWSGI_SCTP
		}
#endif
	}

	if (ucr->subscriptions && cr_session->un && cr_session->un->len > 0) {
        	// decrease reference count
#ifdef UWSGI_DEBUG
               uwsgi_log("[1] node %.*s refcnt: %llu\n", cr_session->un->len, cr_session->un->name, cr_session->un->reference);
#endif
               cr_session->un->reference--;
#ifdef UWSGI_DEBUG
               uwsgi_log("[2] node %.*s refcnt: %llu\n", cr_session->un->len, cr_session->un->name, cr_session->un->reference);
#endif
	}


	if (cr_session->instance_failed) {

		if (cr_session->soopt) {
			if (!ucr->quiet)
				uwsgi_log("unable to connect() to uwsgi instance \"%.*s\": %s\n", (int) cr_session->instance_address_len, cr_session->instance_address, strerror(cr_session->soopt));
		}
		else if (cr_session->timed_out) {
			if (cr_session->instance_address_len > 0) {
				if (cr_session->status == COREROUTER_STATUS_CONNECTING) {
					if (!ucr->quiet)
						uwsgi_log("unable to connect() to uwsgi instance \"%.*s\": timeout\n", (int) cr_session->instance_address_len, cr_session->instance_address);
				}
				else if (cr_session->status  == COREROUTER_STATUS_RESPONSE) {
					uwsgi_log("timeout waiting for instance \"%.*s\"\n", (int) cr_session->instance_address_len, cr_session->instance_address);
				}
			}
		}

		// now check for dead nodes
		if (ucr->subscriptions && cr_session->un && cr_session->un->len > 0) {

                        if (cr_session->un->death_mark == 0)
                                uwsgi_log("[uwsgi-fastrouter] %.*s => marking %.*s as failed\n", (int) cr_session->hostname_len, cr_session->hostname, (int) cr_session->instance_address_len, cr_session->instance_address);

                        cr_session->un->failcnt++;
                        cr_session->un->death_mark = 1;
                        // check if i can remove the node
                        if (cr_session->un->reference == 0) {
                                uwsgi_remove_subscribe_node(&ucr->subscriptions, cr_session->un);
                        }
                        if (ucr->subscriptions == NULL && ucr->cheap && !ucr->i_am_cheap && !ucr->fallback) {
                                uwsgi_gateway_go_cheap("uWSGI fastrouter", ucr->queue, &ucr->i_am_cheap);
                        }

        	}
		else if (cr_session->static_node) {
			cr_session->static_node->custom = uwsgi_now();
			uwsgi_log("[uwsgi-fastrouter] %.*s => marking %.*s as failed\n", (int) cr_session->hostname_len, cr_session->hostname, (int) cr_session->instance_address_len, cr_session->instance_address);
		}


		if (cr_session->tmp_socket_name) {
			free(cr_session->tmp_socket_name);
			cr_session->tmp_socket_name = NULL;
		}

		if (ucr->fallback) {
			// ok let's try with the fallback nodes
			if (!cr_session->fallback) {
				cr_session->fallback = ucr->fallback;
			}
			else {
				cr_session->fallback = cr_session->fallback->next;
				if (!cr_session->fallback) goto end;
			}

			cr_session->instance_address = cr_session->fallback->value;
			cr_session->instance_address_len = cr_session->fallback->len;

			// reset error and timeout
			cr_session->timeout = corerouter_reset_timeout(ucr, cr_session);
			cr_session->timed_out = 0;
			cr_session->soopt = 0;

			// reset nodes
			cr_session->un = NULL;
			cr_session->static_node = NULL;

			cr_session->pass_fd = is_unix(cr_session->instance_address, cr_session->instance_address_len);


                	cr_session->instance_fd = uwsgi_connectn(cr_session->instance_address, cr_session->instance_address_len, 0, 1);

                	if (cr_session->instance_fd < 0) {
                		cr_session->instance_failed = 1;
				cr_session->soopt = errno;
                        	corerouter_close_session(ucr, cr_session);
				return;
			}
  
			ucr->cr_table[cr_session->instance_fd] = cr_session;

                	cr_session->status = COREROUTER_STATUS_CONNECTING;
                	ucr->cr_table[cr_session->instance_fd] = cr_session;
                	event_queue_add_fd_write(ucr->queue, cr_session->instance_fd);
			return;

		}
	}

end:

	if (cr_session->tmp_socket_name) {
		free(cr_session->tmp_socket_name);
	}

	if (cr_session->buf_file)
		fclose(cr_session->buf_file);

	if (cr_session->buf_file_name) {
		if (unlink(cr_session->buf_file_name)) {
			uwsgi_error("unlink()");
		}
		free(cr_session->buf_file_name);
	}

	close(cr_session->fd);
	ucr->cr_table[cr_session->fd] = NULL;

	cr_del_timeout(ucr, cr_session);
	free(cr_session);
}

static struct uwsgi_rb_timer *corerouter_reset_timeout(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {
	cr_del_timeout(ucr, cr_session);
	return cr_add_timeout(ucr, cr_session);
}

static void corerouter_expire_timeouts(struct uwsgi_corerouter *ucr) {

	time_t current = time(NULL);
	struct uwsgi_rb_timer *urbt;
	struct corerouter_session *cr_session;

	for (;;) {
		urbt = uwsgi_min_rb_timer(ucr->timeouts);
		if (urbt == NULL)
			return;

		if (urbt->key <= current) {
			cr_session = (struct corerouter_session *) urbt->data;
			cr_session->timed_out = 1;
			if (cr_session->retry) {
				cr_session->retry = 0;
				ucr->switch_events(ucr, cr_session, -1);
				if (cr_session->retry) {
					cr_del_timeout(ucr, cr_session);
					cr_session->timeout = cr_add_fake_timeout(ucr, cr_session);
				}
				else {
					cr_session->timeout = corerouter_reset_timeout(ucr, cr_session);
				}
			}
			else {
				corerouter_close_session(ucr, cr_session);
			}
			continue;
		}

		break;
	}
}

struct corerouter_session *corerouter_alloc_session(size_t size) {

	return uwsgi_calloc(size);
}

void uwsgi_corerouter_loop(int id, void *data) {

	int i;

	struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) data;

	ucr->cr_stats_server = -1;

	ucr->cr_table = uwsgi_malloc(sizeof(struct corerouter_session *) * uwsgi.max_fd);

	for (i = 0; i < (int) uwsgi.max_fd; i++) {
		ucr->cr_table[i] = NULL;
	}

	ucr->i_am_cheap = ucr->cheap;

	void *events = uwsgi_corerouter_setup_event_queue(ucr, id);

	if (ucr->has_subscription_sockets)
		event_queue_add_fd_read(ucr->queue, ushared->gateways[id].internal_subscription_pipe[1]);


	if (!ucr->socket_timeout)
		ucr->socket_timeout = 30;

	if (!ucr->static_node_gracetime)
		ucr->static_node_gracetime = 30;

	int i_am_the_first = 1;
	for(i=0;i<id;i++) {
		if (!strcmp(ushared->gateways[i].name, ucr->name)) {
			i_am_the_first = 0;
			break;
		}
	}

	if (ucr->stats_server && i_am_the_first) {
		char *tcp_port = strchr(ucr->stats_server, ':');
		if (tcp_port) {
			// disable deferred accept for this socket
			int current_defer_accept = uwsgi.no_defer_accept;
			uwsgi.no_defer_accept = 1;
			ucr->cr_stats_server = bind_to_tcp(ucr->stats_server, uwsgi.listen_queue, tcp_port);
			uwsgi.no_defer_accept = current_defer_accept;
		}
		else {
			ucr->cr_stats_server = bind_to_unix(ucr->stats_server, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
		}

		event_queue_add_fd_read(ucr->queue, ucr->cr_stats_server);
		uwsgi_log("*** FastRouter stats server enabled on %s fd: %d ***\n", ucr->stats_server, ucr->cr_stats_server);
	}


	if (ucr->use_socket) {
		ucr->to_socket = uwsgi_get_socket_by_num(ucr->socket_num);
		if (ucr->to_socket) {
			// fix socket name_len
			if (ucr->to_socket->name_len == 0 && ucr->to_socket->name) {
				ucr->to_socket->name_len = strlen(ucr->to_socket->name);
			}
		}
	}

	if (!ucr->pb_base_dir) {
		ucr->pb_base_dir = getenv("TMPDIR");
		if (!ucr->pb_base_dir)
			ucr->pb_base_dir = "/tmp";
	}

	int nevents;

	time_t delta;

	struct uwsgi_rb_timer *min_timeout;

	int interesting_fd;
	int new_connection;


	if (ucr->pattern) {
		init_magic_table(ucr->magic_table);
	}

#ifdef UWSGI_SCTP
	uwsgi_fastrouter_sctp_nodes = uwsgi_calloc(sizeof(struct uwsgi_fastrouter_sctp_nodes*));
	uwsgi_fastrouter_sctp_nodes_current = uwsgi_calloc(sizeof(struct uwsgi_fastrouter_sctp_nodes*));
#endif

	union uwsgi_sockaddr cr_addr;
	socklen_t cr_addr_len = sizeof(struct sockaddr_un);

	struct corerouter_session *cr_session;

	ucr->mapper = uwsgi_cr_map_use_void;

			if (ucr->use_cache) {
                        	ucr->mapper = uwsgi_cr_map_use_cache;
                        }
                        else if (ucr->pattern) {
                                ucr->mapper = uwsgi_cr_map_use_pattern;
                        }
                        else if (ucr->has_subscription_sockets) {
                                ucr->mapper = uwsgi_cr_map_use_subscription;
                        }
                        else if (ucr->base) {
                                ucr->mapper = uwsgi_cr_map_use_base;
                        }
                        else if (ucr->code_string_code && ucr->code_string_function) {
                                ucr->mapper = uwsgi_cr_map_use_cs;
			}
                        else if (ucr->to_socket) {
                                ucr->mapper = uwsgi_cr_map_use_to;
                        }
                        else if (ucr->static_nodes) {
                                ucr->mapper = uwsgi_cr_map_use_static_nodes;
                        }
#ifdef UWSGI_SCTP
                        else if (ucr->has_sctp_sockets > 0) {
                                ucr->mapper = uwsgi_cr_map_use_sctp;
                        }
#endif



	ucr->timeouts = uwsgi_init_rb_timer();

	for (;;) {

		min_timeout = uwsgi_min_rb_timer(ucr->timeouts);
		if (min_timeout == NULL) {
			delta = -1;
		}
		else {
			delta = min_timeout->key - time(NULL);
			if (delta <= 0) {
				corerouter_expire_timeouts(ucr);
				delta = 0;
			}
		}

		if (uwsgi.master_process && ucr->harakiri > 0) {
			ushared->gateways_harakiri[id] = 0;
		}

		nevents = event_queue_wait_multi(ucr->queue, delta, events, ucr->nevents);

		if (uwsgi.master_process && ucr->harakiri > 0) {
			ushared->gateways_harakiri[id] = time(NULL) + ucr->harakiri;
		}

		if (nevents == 0) {
			corerouter_expire_timeouts(ucr);
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

						new_connection = accept(interesting_fd, (struct sockaddr *) &cr_addr, &cr_addr_len);
#ifdef UWSGI_EVENT_USE_PORT
                                event_queue_add_fd_read(ucr->queue, interesting_fd);
#endif
						if (new_connection < 0) {
							taken = 1;
							break;
						}

#ifndef __linux__
                                                uwsgi_socket_b(new_connection);
#endif

						ucr->cr_table[new_connection] = corerouter_alloc_session(ucr->session_size);
						ucr->cr_table[new_connection]->fd = new_connection;
						ucr->cr_table[new_connection]->instance_fd = -1;
						ucr->cr_table[new_connection]->status = COREROUTER_STATUS_RECV_HDR;

						ucr->cr_table[new_connection]->timeout = cr_add_timeout(ucr, ucr->cr_table[new_connection]);
						
						ucr->alloc_session(ucr, ugs, ucr->cr_table[new_connection], (struct sockaddr *) &cr_addr, cr_addr_len);

						event_queue_add_fd_read(ucr->queue, new_connection);
					}
					else if (ugs->subscription) {
						uwsgi_corerouter_manage_subscription(ucr, id, ugs);
					}
#ifdef UWSGI_SCTP
					else if (ugs->sctp) {
						new_connection = accept(interesting_fd, (struct sockaddr *) &cr_addr, &cr_addr_len);
#ifdef UWSGI_EVENT_USE_PORT
                                event_queue_add_fd_read(ucr->queue, interesting_fd);
#endif
						if (new_connection < 0) {
                                                        taken = 1;
							break;
						}
						struct uwsgi_fr_sctp_node *sctp_node = uwsgi_fr_sctp_add_node(new_connection);
						snprintf(sctp_node->name, 64, "%s:%d", inet_ntoa(((struct sockaddr_in *)&cr_addr)->sin_addr), ntohs(((struct sockaddr_in *) &cr_addr)->sin_port));
						uwsgi_log("new SCTP peer: %s:%d\n", inet_ntoa(((struct sockaddr_in *)&cr_addr)->sin_addr), ntohs(((struct sockaddr_in *) &cr_addr)->sin_port));

						ucr->cr_table[new_connection] = alloc_cr_session();
                                                ucr->cr_table[new_connection]->instance_fd = new_connection;
                                                ucr->cr_table[new_connection]->fd = -1;
						ucr->cr_table[new_connection]->persistent = 1;
                                                ucr->cr_table[new_connection]->status = FASTROUTER_STATUS_SCTP_NODE_FREE;

						struct sctp_event_subscribe events;
						memset(&events, 0, sizeof(events) );
						events.sctp_data_io_event = 1;
						// check for errors
						setsockopt(new_connection, SOL_SCTP, SCTP_EVENTS, &events, sizeof(events) );

                                                event_queue_add_fd_read(ucr->queue, new_connection);
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
				uwsgi_corerouter_manage_internal_subscription(ucr, interesting_fd);
			}
			else if (interesting_fd == ucr->cr_stats_server) {
				corerouter_send_stats(ucr);
			}
			else {
				cr_session = ucr->cr_table[interesting_fd];

				// something is going wrong...
				if (cr_session == NULL)
					continue;

				if (event_queue_interesting_fd_has_error(events, i)) {
#ifdef UWSGI_SCTP
					if (!cr_session->persistent) {
#endif
						corerouter_close_session(ucr, cr_session);
						continue;
#ifdef UWSGI_SCTP
					}
#endif
				}

#ifdef UWSGI_SCTP
				if (!cr_session->persistent) {
#endif
					cr_session->timeout = corerouter_reset_timeout(ucr, cr_session);
#ifdef UWSGI_SCTP
				}
#endif
				
				// mplementation specific cycle;
				ucr->switch_events(ucr, cr_session, interesting_fd);
				

			}
		}
	}

}

int uwsgi_corerouter_init(struct uwsgi_corerouter *ucr) {

	int i;

	if (ucr->has_sockets) {

		if (ucr->use_cache && !uwsgi.cache_max_items) {
			uwsgi_log("you need to create a uwsgi cache to use the %s (add --cache <n>)\n", ucr->name);
			exit(1);
		}

		if (!ucr->nevents)
			ucr->nevents = 64;

		uwsgi_corerouter_setup_sockets(ucr);

		if (ucr->processes < 1)
			ucr->processes = 1;
		if (ucr->cheap) {
			uwsgi_log("starting %s in cheap mode\n", ucr->name);
		}
		for (i = 0; i < ucr->processes; i++) {
			if (register_gateway(ucr->name, uwsgi_corerouter_loop, ucr) == NULL) {
				uwsgi_log("unable to register the %s gateway\n", ucr->name);
				exit(1);
			}
		}
	}

	return 0;
}


struct uwsgi_plugin corerouter_plugin = {

	.name = "courerouter",
};


#define stats_send_llu(x, y) fprintf(output, x, (long long unsigned int) y)
#define stats_send(x, y) fprintf(output, x, y)

void corerouter_send_stats(struct uwsgi_corerouter *ucr) {

	struct sockaddr_un client_src;
	socklen_t client_src_len = 0;
	int client_fd = accept(ucr->cr_stats_server, (struct sockaddr *) &client_src, &client_src_len);
#ifdef UWSGI_EVENT_USE_PORT
        event_queue_add_fd_read(ucr->queue, ucr->cr_stats_server);
#endif
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

	fprintf(output, "\"%s\": [", ucr->short_name);
	struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
	while (ugs) {
		if (!strcmp(ugs->owner, ucr->name)) {
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

	if (ucr->has_subscription_sockets) {
		fprintf(output, "\"subscriptions\": [\n");
		struct uwsgi_subscribe_slot *s_slot = ucr->subscriptions;
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
			if (s_slot == ucr->subscriptions)
				break;
		}
		fprintf(output, "],\n");
	}

#ifdef UWSGI_SCTP
	if (ucr->has_sctp_sockets > 0) {
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

	fprintf(output, "\"cheap\": %d\n", ucr->i_am_cheap);

	fprintf(output, "}\n");
	fclose(output);

}
