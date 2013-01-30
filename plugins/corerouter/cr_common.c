/*

common functions for various routers (fastrouter, http...)

*/

#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include "cr.h"

void uwsgi_corerouter_setup_sockets(struct uwsgi_corerouter *ucr) {

	struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
	while (ugs) {
		if (!strcmp(ucr->name, ugs->owner)) {
			if (!ugs->subscription) {
				if (ugs->name[0] == '=') {
					int shared_socket = atoi(ugs->name + 1);
					if (shared_socket >= 0) {
						ugs->fd = uwsgi_get_shared_socket_fd_by_num(shared_socket);
						ugs->shared = 1;
						if (ugs->fd == -1) {
							uwsgi_log("unable to use shared socket %d\n", shared_socket);
							exit(1);
						}
						ugs->name = uwsgi_getsockname(ugs->fd);
					}
				}
				else if (!uwsgi_startswith("fd://", ugs->name, 5)) {
					int fd_socket = atoi(ugs->name + 5);
					if (fd_socket >= 0) {
						ugs->fd = fd_socket;
						ugs->name = uwsgi_getsockname(ugs->fd);
						if (!ugs->name) {
							uwsgi_log("unable to use file descriptor %d as socket\n", fd_socket);
							exit(1);
						}
					}
				}
				else {
					ugs->port = strchr(ugs->name, ':');
					int current_defer_accept = uwsgi.no_defer_accept;
					if (ugs->no_defer) {
                        			uwsgi.no_defer_accept = 1;
					}
					if (ugs->fd == -1) {
						if (ugs->port) {
							ugs->fd = bind_to_tcp(ugs->name, uwsgi.listen_queue, ugs->port);
							ugs->port++;
							ugs->port_len = strlen(ugs->port);
						}
						else {
							ugs->fd = bind_to_unix(ugs->name, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
						}
					}
					if (ugs->no_defer) {
                        			uwsgi.no_defer_accept = current_defer_accept;
					}
				}
				// put socket in non-blocking mode
				uwsgi_socket_nb(ugs->fd);
				uwsgi_log("%s bound on %s fd %d\n", ucr->name, ugs->name, ugs->fd);
			}
			else if (ugs->subscription) {
				if (ugs->fd == -1) {
					if (strchr(ugs->name, ':')) {
#ifdef UWSGI_UDP
						ugs->fd = bind_to_udp(ugs->name, 0, 0);
#else
						uwsgi_log("uWSGI has been built without UDP support !!!\n");
						exit(1);
#endif
					}
					else {
						ugs->fd = bind_to_unix_dgram(ugs->name);
					}
					uwsgi_socket_nb(ugs->fd);
				}
				uwsgi_log("%s subscription server bound on %s fd %d\n", ucr->name, ugs->name, ugs->fd);
			}
		}
		ugs = ugs->next;
	}

}

void *uwsgi_corerouter_setup_event_queue(struct uwsgi_corerouter *ucr, int id) {

	ucr->queue = event_queue_init();

	struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
	while (ugs) {
		if (!strcmp(ucr->name, ugs->owner)) {
			if (!ucr->cheap || ugs->subscription) {
				event_queue_add_fd_read(ucr->queue, ugs->fd);
			}
			ugs->gateway = &ushared->gateways[id];
		}
		ugs = ugs->next;
	}

	return event_queue_alloc(ucr->nevents);
}

void uwsgi_corerouter_manage_subscription(struct uwsgi_corerouter *ucr, int id, struct uwsgi_gateway_socket *ugs) {

	int i;
	struct uwsgi_subscribe_req usr;
	char bbuf[4096];

	ssize_t len = recv(ugs->fd, bbuf, 4096, 0);
	if (len > 0) {
		memset(&usr, 0, sizeof(struct uwsgi_subscribe_req));
		uwsgi_hooked_parse(bbuf + 4, len - 4, corerouter_manage_subscription, &usr);
		if (usr.sign_len > 0) {
			// calc the base size
			usr.base = bbuf + 4;
			usr.base_len = len - 4 - (2 + 4 + 2 + usr.sign_len);
		}

		// subscribe request ?
		if (bbuf[3] == 0) {
			if (uwsgi_add_subscribe_node(ucr->subscriptions, &usr) && ucr->i_am_cheap) {
				struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
				while (ugs) {
					if (!strcmp(ugs->owner, ucr->name) && !ugs->subscription) {
						event_queue_add_fd_read(ucr->queue, ugs->fd);
					}
					ugs = ugs->next;
				}
				ucr->i_am_cheap = 0;
				uwsgi_log("[%s pid %d] leaving cheap mode...\n", ucr->name, (int) uwsgi.mypid);
			}
		}
		//unsubscribe 
		else {
			struct uwsgi_subscribe_node *node = uwsgi_get_subscribe_node_by_name(ucr->subscriptions, usr.key, usr.keylen, usr.address, usr.address_len);
			if (node && node->len) {
#ifdef UWSGI_SSL
				if (uwsgi.subscriptions_sign_check_dir) {
					if (usr.sign_len == 0 || usr.base_len == 0)
						return;
					if (usr.unix_check <= node->unix_check)
						return;
					if (!uwsgi_subscription_sign_check(node->slot, &usr)) {
						return;
					}
				}
#endif
				if (node->death_mark == 0)
					uwsgi_log("[%s pid %d] %.*s => marking %.*s as failed\n", ucr->name, (int) uwsgi.mypid, (int) usr.keylen, usr.key, (int) usr.address_len, usr.address);
				node->failcnt++;
				node->death_mark = 1;
				// check if i can remove the node
				if (node->reference == 0) {
					uwsgi_remove_subscribe_node(ucr->subscriptions, node);
				}
				if (ucr->cheap && !ucr->i_am_cheap && uwsgi_no_subscriptions(ucr->subscriptions)) {
					uwsgi_gateway_go_cheap(ucr->name, ucr->queue, &ucr->i_am_cheap);
				}
			}
		}

		// propagate the subscription to other nodes
		for (i = 0; i < ushared->gateways_cnt; i++) {
			if (i == id)
				continue;
			if (!strcmp(ushared->gateways[i].name, ucr->name)) {
				if (send(ushared->gateways[i].internal_subscription_pipe[0], bbuf, len, 0) != len) {
					uwsgi_error("send()");
				}
			}
		}
	}

}

void uwsgi_corerouter_manage_internal_subscription(struct uwsgi_corerouter *ucr, int fd) {


	struct uwsgi_subscribe_req usr;
	char bbuf[4096];

	ssize_t len = recv(fd, bbuf, 4096, 0);
	if (len > 0) {
		memset(&usr, 0, sizeof(struct uwsgi_subscribe_req));
		uwsgi_hooked_parse(bbuf + 4, len - 4, corerouter_manage_subscription, &usr);

		// subscribe request ?
		if (bbuf[3] == 0) {
			if (uwsgi_add_subscribe_node(ucr->subscriptions, &usr) && ucr->i_am_cheap) {
				struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
				while (ugs) {
					if (!strcmp(ugs->owner, ucr->name) && !ugs->subscription) {
						event_queue_add_fd_read(ucr->queue, ugs->fd);
					}
					ugs = ugs->next;
				}
				ucr->i_am_cheap = 0;
				uwsgi_log("[%s pid %d] leaving cheap mode...\n", ucr->name, (int) uwsgi.mypid);
			}
		}
		//unsubscribe 
		else {
			struct uwsgi_subscribe_node *node = uwsgi_get_subscribe_node_by_name(ucr->subscriptions, usr.key, usr.keylen, usr.address, usr.address_len);
			if (node && node->len) {
				if (node->death_mark == 0)
					uwsgi_log("[%s pid %d] %.*s => marking %.*s as failed\n", ucr->name, (int) uwsgi.mypid, (int) usr.keylen, usr.key, (int) usr.address_len, usr.address);
				node->failcnt++;
				node->death_mark = 1;
				// check if i can remove the node
				if (node->reference == 0) {
					uwsgi_remove_subscribe_node(ucr->subscriptions, node);
				}
				if (ucr->cheap && !ucr->i_am_cheap && uwsgi_no_subscriptions(ucr->subscriptions)) {
					uwsgi_gateway_go_cheap(ucr->name, ucr->queue, &ucr->i_am_cheap);
				}
			}
		}
	}

}
