/*

common functions for various routers (fastrouter, http...)

*/

#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include "cr.h"

ssize_t uwsgi_cr_simple_recv(struct uwsgi_corerouter *uc, struct corerouter_session *cs, char *buf, size_t len) {
        ssize_t ret = recv(cs->fd, buf, len, 0);
        if (ret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                        errno = EINPROGRESS;
                        return -1;
                }
                uwsgi_error("recv()");
        }
        return ret;
}

ssize_t uwsgi_cr_simple_instance_recv(struct uwsgi_corerouter *uc, struct corerouter_session *cs, char *buf, size_t len) {
        ssize_t ret = recv(cs->instance_fd, buf, len, 0);
        if (ret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                        errno = EINPROGRESS;
                        return -1;
                }
                uwsgi_error("recv()");
        }
        return ret;
}


ssize_t uwsgi_cr_simple_send(struct uwsgi_corerouter *uc, struct corerouter_session *cs, char *buf, size_t len) {
        ssize_t ret = -1;
        char *tmp_buf;
	off_t pos = 0;

	size_t partial_len = len;
	off_t partial_pos = 0;

        if (cs->write_queue_len > 0) {
                ret = send(cs->fd, cs->write_queue, cs->write_queue_len, 0);
                if (ret > 0) {
                        cs->write_queue_len-=ret;
			pos = ret;
                        if (cs->write_queue_len == 0) {
                                free(cs->write_queue);
                                cs->write_queue = NULL;
                                if (cs->fd_state) {
                                        event_queue_fd_write_to_read(uc->queue, cs->fd);
                                        cs->fd_state = 0;
                                }
                                goto next;
                        }
                        goto blocking;
                }
                else if (ret == 0) {
                        return 0;
                }
                else {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                                goto blocking;
                        }
                        uwsgi_error("send()");
                        return -1;
                }
        }

next:
	if (len == 0) goto end;

        ret = send(cs->fd, buf, len, 0);
        if (ret > 0) {
                if ((size_t)ret == len) return len;
		partial_len-=ret;
		partial_pos = ret;
                goto blocking;
        }

        if (ret == 0) {
                return 0;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                goto blocking;
        }
        uwsgi_error("send()");
        return -1;

end:
	if (cs->write_queue_close) {
		return 0;
	}
	return ret;

blocking:
        // wait for write
        if (!cs->fd_state) {
                event_queue_fd_read_to_write(uc->queue, cs->fd);
                cs->fd_state = 1;
        }
        // add new datas to the buffer
	tmp_buf = malloc(cs->write_queue_len+partial_len);
        if (!tmp_buf) {
                uwsgi_error("malloc()");
                return -1;
        }
	if (cs->write_queue_len>0) {
        	memcpy(tmp_buf, cs->write_queue+pos, cs->write_queue_len);
		free(cs->write_queue);
	}
        memcpy(tmp_buf+cs->write_queue_len, buf+partial_pos, partial_len);
	cs->write_queue = tmp_buf;
        cs->write_queue_len+=partial_len;
        errno = EINPROGRESS;
        return -1;
}

ssize_t uwsgi_cr_simple_instance_send(struct uwsgi_corerouter *uc, struct corerouter_session *cs, char *buf, size_t len) {
        ssize_t ret;
        char *tmp_buf;
	off_t pos = 0;

	size_t partial_len = len;
        off_t partial_pos = 0;

        if (cs->instance_write_queue_len > 0) {
                ret = send(cs->instance_fd, cs->instance_write_queue, cs->instance_write_queue_len, 0);
                if (ret > 0) {
                        cs->instance_write_queue_len-=ret;
                        pos=ret;
                        if (cs->instance_write_queue_len == 0) {
                                free(cs->instance_write_queue);
                                cs->instance_write_queue = NULL;
                                if (cs->instance_fd_state) {
                                        event_queue_fd_write_to_read(uc->queue, cs->instance_fd);
                                        cs->instance_fd_state = 0;
                                }
                                goto next;
                        }
                        goto blocking;
                }
                else if (ret == 0) {
                        return 0;
                }
                else {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                                goto blocking;
                        }
                        uwsgi_error("send()");
                        return -1;
                }
        }

next:
        ret = send(cs->instance_fd, buf, len, 0);
        if (ret > 0) {
                if ((size_t)ret == len) return len;
		partial_len-=ret;
                partial_pos = ret;
                goto blocking;
        }

        if (ret == 0) {
                return 0;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                goto blocking;
        }
        uwsgi_error("send()");
        return -1;

blocking:
        // wait for write
        if (!cs->instance_fd_state) {
                event_queue_fd_read_to_write(uc->queue, cs->instance_fd);
                cs->instance_fd_state = 1;
        }
	// add new datas to the buffer
        tmp_buf = malloc(cs->instance_write_queue_len+partial_len);
        if (!tmp_buf) {
                uwsgi_error("malloc()");
                return -1;
        }
        if (cs->instance_write_queue_len>0) {
                memcpy(tmp_buf, cs->instance_write_queue+pos, cs->instance_write_queue_len);
		free(cs->instance_write_queue);
        }
        memcpy(tmp_buf+cs->instance_write_queue_len, buf+partial_pos, partial_len);
        cs->instance_write_queue = tmp_buf;
        cs->instance_write_queue_len+=partial_len;
        errno = EINPROGRESS;
        return -1;
}



void uwsgi_corerouter_setup_sockets(struct uwsgi_corerouter *ucr) {

	struct uwsgi_gateway_socket *ugs = uwsgi.gateway_sockets;
	while (ugs) {
		if (!strcmp(ucr->name, ugs->owner)) {
			if (!ugs->subscription) {
				if (ugs->name[0] == '=') {
					int shared_socket = atoi(ugs->name+1);
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
				else if (!uwsgi_startswith("fd://", ugs->name, 5 )) {
					int fd_socket = atoi(ugs->name+5);
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
#ifdef UWSGI_EVENT_USE_PORT
	event_queue_add_fd_read(ucr->queue, ugs->fd);
#endif
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
					if (usr.sign_len == 0 || usr.base_len == 0) return;
					if (usr.unix_check <= node->unix_check) return ;
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
#ifdef UWSGI_EVENT_USE_PORT
	event_queue_add_fd_read(ucr->queue, fd);
#endif
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
