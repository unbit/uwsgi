/*

common functions for various routers (fastrouter, http...)

*/
static void uwsgi_corerouter_setup_sockets(char *gw_id) {

	struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
	while (ugs) {
		if (!strcmp(gw_id, ugs->owner)) {
			if (!ugs->subscription) {
				ugs->port = strchr(ugs->name, ':');
				if (ugs->fd == -1) {
					if (ugs->port) {
						ugs->fd = bind_to_tcp(ugs->name, uwsgi.listen_queue, ugs->port);
					}
					else {
						ugs->fd = bind_to_unix(ugs->name, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
					}
				}
				// put socket in non-blocking mode
				uwsgi_socket_nb(ugs->fd);
				ugs->port++;
				ugs->port_len = strlen(ugs->port);
				uwsgi_log("%s bound on %s fd %d\n", gw_id, ugs->name, ugs->fd);
			}
			else {
				if (ugs->fd == -1) {
					ugs->fd = bind_to_udp(ugs->name, 0, 0);
				}
				uwsgi_log("%s subscription server bound on %s fd %d\n", gw_id, ugs->name, ugs->fd);
			}
		}
		ugs = ugs->next;
	}

}

static void *uwsgi_corerouter_setup_event_queue(char *gw_id, int id, int nevents, int *efd, int cheap) {

	*efd = event_queue_init();

	struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
	while (ugs) {
		if (!strcmp(gw_id, ugs->owner)) {
			if (!cheap || ugs->subscription) {
				event_queue_add_fd_read(*efd, ugs->fd);
			}
			ugs->gateway = &uwsgi.gateways[id];
		}
		ugs = ugs->next;
	}

	return event_queue_alloc(nevents);
}

static void __attribute__ ((unused)) uwsgi_corerouter_go_cheap(char *gw_id, int queue, int *i_am_cheap) {

	uwsgi_log("[%s pid %d] no more nodes available. Going cheap...\n", gw_id, (int) uwsgi.mypid);
	struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
	while (ugs) {
		if (!strcmp(ugs->owner, gw_id) && !ugs->subscription) {
			event_queue_del_fd(queue, ugs->fd, event_queue_read());
		}
		ugs = ugs->next;
	}
	*i_am_cheap = 1;
}

static void __attribute__ ((unused)) uwsgi_corerouter_manage_subscription(char *gw_id, int id, struct uwsgi_gateway_socket *ugs, int queue, struct uwsgi_subscribe_slot **subscriptions, int regexp, void (*parse_hook) (char *, uint16_t, char *, uint16_t, void *), int cheap, int *i_am_cheap) {

	int i;
	struct uwsgi_subscribe_req usr;
	char bbuf[4096];

	ssize_t len = recv(ugs->fd, bbuf, 4096, 0);
#ifdef UWSGI_EVENT_USE_PORT
	event_queue_add_fd_read(queue, ugs->fd);
#endif
	if (len > 0) {
		memset(&usr, 0, sizeof(struct uwsgi_subscribe_req));
		uwsgi_hooked_parse(bbuf + 4, len - 4, parse_hook, &usr);

		// subscribe request ?
		if (bbuf[3] == 0) {
			if (uwsgi_add_subscribe_node(subscriptions, &usr, regexp) && *i_am_cheap) {
				struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
				while (ugs) {
					if (!strcmp(ugs->owner, gw_id) && !ugs->subscription) {
						event_queue_add_fd_read(queue, ugs->fd);
					}
					ugs = ugs->next;
				}
				*i_am_cheap = 0;
				uwsgi_log("[%s pid %d] leaving cheap mode...\n", gw_id, (int) uwsgi.mypid);
			}
		}
		//unsubscribe 
		else {
			struct uwsgi_subscribe_node *node = uwsgi_get_subscribe_node_by_name(subscriptions, usr.key, usr.keylen, usr.address, usr.address_len, regexp);
			if (node && node->len) {
				if (node->death_mark == 0)
					uwsgi_log("[%s pid %d] %.*s => marking %.*s as failed\n", gw_id, (int) uwsgi.mypid, (int) usr.keylen, usr.key, (int) usr.address_len, usr.address);
				node->failcnt++;
				node->death_mark = 1;
				// check if i can remove the node
				if (node->reference == 0) {
					uwsgi_remove_subscribe_node(subscriptions, node);
				}
				if (*subscriptions == NULL && cheap && !*i_am_cheap) {
					uwsgi_corerouter_go_cheap(gw_id, queue, i_am_cheap);
				}
			}
		}

		// propagate the subscription to other nodes
		for (i = 0; i < uwsgi.gateways_cnt; i++) {
			if (i == id)
				continue;
			if (!strcmp(uwsgi.gateways[i].name, gw_id)) {
				if (send(uwsgi.gateways[i].internal_subscription_pipe[0], bbuf, len, 0) != len) {
					uwsgi_error("send()");
				}
			}
		}
	}

}

static void __attribute__ ((unused)) uwsgi_corerouter_manage_internal_subscription(char *gw_id, int queue, int fd, struct uwsgi_subscribe_slot **subscriptions, int regexp, void (*parse_hook) (char *, uint16_t, char *, uint16_t, void *), int cheap, int *i_am_cheap) {


	struct uwsgi_subscribe_req usr;
	char bbuf[4096];

	ssize_t len = recv(fd, bbuf, 4096, 0);
#ifdef UWSGI_EVENT_USE_PORT
	event_queue_add_fd_read(queue, fd);
#endif
	if (len > 0) {
		memset(&usr, 0, sizeof(struct uwsgi_subscribe_req));
		uwsgi_hooked_parse(bbuf + 4, len - 4, parse_hook, &usr);

		// subscribe request ?
		if (bbuf[3] == 0) {
			if (uwsgi_add_subscribe_node(subscriptions, &usr, regexp) && *i_am_cheap) {
				struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
				while (ugs) {
					if (!strcmp(ugs->owner, gw_id) && !ugs->subscription) {
						event_queue_add_fd_read(queue, ugs->fd);
					}
					ugs = ugs->next;
				}
				*i_am_cheap = 0;
				uwsgi_log("[%s pid %d] leaving cheap mode...\n", gw_id, (int) uwsgi.mypid);
			}
		}
		//unsubscribe 
		else {
			struct uwsgi_subscribe_node *node = uwsgi_get_subscribe_node_by_name(subscriptions, usr.key, usr.keylen, usr.address, usr.address_len, regexp);
			if (node && node->len) {
				if (node->death_mark == 0)
					uwsgi_log("[%s] %.*s => marking %.*s as failed\n", gw_id, (int) usr.keylen, usr.key, (int) usr.address_len, usr.address);
				node->failcnt++;
				node->death_mark = 1;
				// check if i can remove the node
				if (node->reference == 0) {
					uwsgi_remove_subscribe_node(subscriptions, node);
				}
				if (*subscriptions == NULL && cheap && !*i_am_cheap) {
					uwsgi_corerouter_go_cheap(gw_id, queue, i_am_cheap);
				}
			}
		}
	}

}
