#include "common.h"

extern struct uwsgi_server uwsgi;
struct uwsgi_tuntap utt;

/*

	The tuntap router is a non-blocking highly optimized ip router
	translating from tuntap device to socket streams.

	It is meant as a replacement for the currently available networking namespaces
	approaches. Compared to veth or macvlan it is really simple and allows total control
	over the routing subsystem (in addition to a simple customizable firewalling engine)

	Generally you spawn the tuntap router in the Emperor instance

	[uwsgi]
	master = true
	emperor = /etc/uwsgi
	emperor-use-clone = fs,uts,ipc,pid,net
	tuntap-router = emperor0 /tmp/tuntap.socket
	exec-as-root = ifconfig emperor0 192.168.0.1 netmask 255.255.255.0 up
	exec-as-root = iptables -t nat -F
	exec-as-root = iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.0/24 -j MASQUERADE
	exec-as-root = echo 1 > /proc/sys/net/ipv4/ip_forward

	vassals will run in new namespaces in which they create a tuntap device attached to
	the tuntap router. UNIX sockets are the only way to connect to the tuntap router
	after jailing.

	Firewalling is based on 2 chains (in and out), and each rule is formed by 3 parameters: <action> <src> <dst>
	The firewall is applied to traffic from the clients to the tuntap device (out) and the opposite (in)


	The first matching rule stop the chain, if no rule applies, the policy is "allow"

	the following rules allows access from vassals to the internet, but block
	vassals intercommunication

	--tuntap-router-firewall-out = allow 192.168.0.0/24 192.168.0.1
	--tuntap-router-firewall-out = deny 192.168.0.0/24 192.168.0.0/24
	--tuntap-router-firewall-out = allow 192.168.0.0/24 0.0.0.0
	--tuntap-router-firewall-out = deny
	--tuntap-router-firewall-in = allow 192.168.0.1 192.168.0.0/24
	--tuntap-router-firewall-in = deny 192.168.0.0/24 192.168.0.0/24
	--tuntap-router-firewall-in = allow 0.0.0.0 192.168.0.0/24
	--tuntap-router-firewall-in = deny

	Author: Roberto De Ioris

	TODO:

	- some form of security to disallow raw access to the tuntap router unix socket
	- stats server
	- port to other platforms ?

*/

static struct uwsgi_option uwsgi_tuntap_options[] = {
	{"tuntap-router", required_argument, 0, "run the tuntap router (syntax: <device> <socket> [stats] [gateway])", uwsgi_opt_add_string_list, &utt.routers, 0},
	{"tuntap-device", required_argument, 0, "add a tuntap device to the instance (syntax: <device>[ <socket>])", uwsgi_opt_add_string_list, &utt.devices, 0},
	{"tuntap-use-credentials", optional_argument, 0, "enable check of SCM_CREDENTIALS for tuntap client/server", uwsgi_opt_set_str, &utt.use_credentials, 0},
	{"tuntap-router-firewall-in", required_argument, 0, "add a firewall rule to the tuntap router (syntax: <action> <src/mask> <dst/mask>)", uwsgi_tuntap_opt_firewall, &utt.fw_in, 0},
	{"tuntap-router-firewall-out", required_argument, 0, "add a firewall rule to the tuntap router (syntax: <action> <src/mask> <dst/mask>)", uwsgi_tuntap_opt_firewall, &utt.fw_out, 0},
	{"tuntap-router-route", required_argument, 0, "add a routing rule to the tuntap router (syntax: <src/mask> <dst/mask> <gateway>)", uwsgi_tuntap_opt_route, &utt.routes, 0},
	{"tuntap-router-stats", required_argument, 0, "run the tuntap router stats server", uwsgi_opt_set_str, &utt.stats_server, 0},
	{"tuntap-device-rule", required_argument, 0, "add a tuntap device rule (syntax: <direction> <src/mask> <dst/mask> <action> [target])", uwsgi_opt_add_string_list, &utt.device_rules, 0},
	{NULL, 0, 0, NULL, NULL, NULL, 0},
};

static void *uwsgi_tuntap_loop(void *arg) {

	// block signals on this thread
	sigset_t smask;
	sigfillset(&smask);
#ifndef UWSGI_DEBUG
	sigdelset(&smask, SIGSEGV);
#endif
	pthread_sigmask(SIG_BLOCK, &smask, NULL);

	struct uwsgi_tuntap_router *uttr = (struct uwsgi_tuntap_router *) arg;

	uwsgi_socket_nb(uttr->fd);

	if (!utt.buffer_size)
		utt.buffer_size = 8192;
	uttr->buf = uwsgi_malloc(utt.buffer_size);
	uttr->write_buf = uwsgi_malloc(utt.buffer_size);

	uttr->queue = event_queue_init();

	if (event_queue_add_fd_read(uttr->queue, uttr->fd)) {
		exit(1);
	}
	if (event_queue_add_fd_read(uttr->queue, uttr->server_fd)) {
		exit(1);
	}

	uwsgi_socket_nb(uttr->server_fd);

	struct uwsgi_tuntap_peer *uttp = uwsgi_tuntap_peer_create(uttr, uttr->server_fd, 0);

	for (;;) {
		int interesting_fd = -1;
		int ret = event_queue_wait(uttr->queue, -1, &interesting_fd);

		if (ret <= 0)
			continue;

		if (interesting_fd == uttr->fd) {
			if (uttr->wait_for_write) {
				uwsgi_tuntap_enqueue(uttr);
				continue;
			}
			ssize_t rlen = read(uttr->fd, uttr->buf, utt.buffer_size);
			if (rlen <= 0) {
				uwsgi_error("uwsgi_tuntap_loop()/read()");
				exit(1);
			}

			// check for full write buffer
                        if (uttp->write_buf_pktsize + 4 + rlen > utt.buffer_size) {
                        	uttp->dropped++;
                                continue;
                        }

			uint16_t pktsize = rlen;
			char *ptr = uttp->write_buf + uttp->write_buf_pktsize;
			memcpy(ptr + 4, uttr->buf, rlen);
			ptr[0] = 0;
			ptr[1] = (uint8_t) (pktsize & 0xff);
			ptr[2] = (uint8_t) ((pktsize >> 8) & 0xff);
			ptr[3] = 0;
			uttp->write_buf_pktsize+= pktsize+4;
			if (uwsgi_tuntap_peer_enqueue(uttr, uttp)) {
				uwsgi_log_verbose("tuntap server disconnected...\n");
				exit(1);
			}
			continue;
		}


		if (interesting_fd == uttr->server_fd) {
			// read from the client
			if (!uttp->wait_for_write) {
				if (uwsgi_tuntap_peer_dequeue(uttr, uttp, 0)) {
					uwsgi_log_verbose("tuntap server disconnected...\n");
					exit(1);
				}
			}
			else {
				// something is wrong (the tuntap device is blocked)
				if (uttr->wait_for_write) {
					continue;
				}

				// write to the client
				if (uwsgi_tuntap_peer_enqueue(uttr, uttp)) {
					uwsgi_log_verbose("tuntap server disconnected...\n");
					exit(1);
				}
			}
		}
	}

		return NULL;
}

static void uwsgi_tuntap_client() {

	if (!utt.devices) return;

	struct uwsgi_string_list *usl;
	uwsgi_foreach(usl, utt.devices) {
		char *space = strchr(usl->value, ' ');
		if (space) {
			*space = 0;
			struct uwsgi_tuntap_router *uttr = uwsgi_calloc(sizeof(struct uwsgi_tuntap_router));
			uttr->fd = uwsgi_tuntap_device(usl->value);

			uttr->server_fd = uwsgi_connect(space+1, 30, 0);
        		if (uttr->server_fd < 0) {
                		uwsgi_error("uwsgi_tuntap_client()/uwsgi_connect()");
                		exit(1);
        		}
			*space = ' ';

			pthread_t t;
			pthread_create(&t, NULL, uwsgi_tuntap_loop, uttr);
		}
		else {
			if (uwsgi_tuntap_device(usl->value) < 0) {
				// foo
			}
		}
	}
}

void tuntaprouter_send_stats(struct uwsgi_tuntap_router *);

void uwsgi_tuntap_router_loop(int id, void *arg) {
	int i;

	struct uwsgi_tuntap_router *uttr = (struct uwsgi_tuntap_router *) arg;
	uttr->buf = uwsgi_malloc(utt.buffer_size);
	uttr->write_buf = uwsgi_malloc(utt.buffer_size);
	uttr->queue = event_queue_init();

	uttr->stats_server_fd = -1;
	uttr->gateway_fd = -1;

	void *events = event_queue_alloc(64);
	if (event_queue_add_fd_read(uttr->queue, uttr->server_fd))
		exit(1);
	if (event_queue_add_fd_read(uttr->queue, uttr->fd))
		exit(1);

	char *stats_server = utt.stats_server;
	if (uttr->stats_server) stats_server = uttr->stats_server;
	if (stats_server) {
                char *tcp_port = strchr(stats_server, ':');
                if (tcp_port) {
                        // disable deferred accept for this socket
                        int current_defer_accept = uwsgi.no_defer_accept;
                        uwsgi.no_defer_accept = 1;
                        uttr->stats_server_fd = bind_to_tcp(stats_server, uwsgi.listen_queue, tcp_port);
                        uwsgi.no_defer_accept = current_defer_accept;
                }
                else {
                        uttr->stats_server_fd = bind_to_unix(stats_server, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
                }

                if (event_queue_add_fd_read(uttr->queue, uttr->stats_server_fd)) exit(1);
                uwsgi_log("*** tuntap stats server enabled on %s fd: %d ***\n", stats_server, uttr->stats_server_fd);
		uwsgi_socket_nb(uttr->stats_server_fd);
        }

	if (uttr->gateway) {
		uttr->gateway_fd = bind_to_udp(uttr->gateway, 0, 0);	
		if (uttr->gateway_fd < 0) exit(1);
                if (event_queue_add_fd_read(uttr->queue, uttr->gateway_fd)) exit(1);
		uwsgi_log("*** tuntap gateway address enabled on %s\n", uttr->gateway);
		uttr->gateway_buf = uwsgi_malloc(utt.buffer_size);
		uwsgi_socket_nb(uttr->gateway_fd);
	}

	for (;;) {
		int nevents = event_queue_wait_multi(uttr->queue, -1, events, 64);
		for (i = 0; i < nevents; i++) {
			int interesting_fd = event_queue_interesting_fd(events, i);
			if (interesting_fd == uttr->fd) {
				// if writing, continue enqueuing
				if (uttr->wait_for_write) {
					uwsgi_tuntap_enqueue(uttr);
					continue;
				}
				ssize_t rlen = read(uttr->fd, uttr->buf, utt.buffer_size);
				if (rlen <= 0) {
					uwsgi_error("uwsgi_tuntap_router_loop()/read()");
					exit(1);
				}
				if (rlen < 20) continue;

				if (uwsgi_tuntap_firewall_check(utt.fw_in, uttr->buf, rlen)) continue;


				uint32_t *dst_ip = (uint32_t *) & uttr->buf[16];
				struct uwsgi_tuntap_peer *uttp = uwsgi_tuntap_peer_get_by_addr(uttr, *dst_ip);
				if (!uttp)
					continue;

				if (uwsgi_tuntap_peer_rules_check(uttr, uttp, uttr->buf, rlen, 0)) continue;

				// check for full write buffer
				if (uttp->write_buf_pktsize + 4 + rlen > utt.buffer_size) {
					uttp->dropped++;
					continue;
				}

				uint16_t pktsize = rlen;
                        	char *ptr = uttp->write_buf + uttp->write_buf_pktsize;
                        	memcpy(ptr + 4, uttr->buf, rlen);
                        	ptr[0] = 0;
                        	ptr[1] = (uint8_t) (pktsize & 0xff);
                        	ptr[2] = (uint8_t) ((pktsize >> 8) & 0xff);
                        	ptr[3] = 0;
                        	uttp->write_buf_pktsize+= pktsize+4;
				if (uwsgi_tuntap_peer_enqueue(uttr, uttp)) {
					uwsgi_tuntap_peer_destroy(uttr, uttp);
				}
				continue;
			}

			if (interesting_fd == uttr->server_fd) {
				int client_fd = uwsgi_accept(uttr->server_fd);
				if (client_fd < 0) {
					uwsgi_error("uwsgi_tuntap_server_loop()/accept()");
					continue;
				}
				if (utt.use_credentials) {
					if (uwsgi_socket_passcred(client_fd)) {
						close(client_fd);
						continue;
					}
				}
				struct uwsgi_tuntap_peer *uttp = uwsgi_tuntap_peer_create(uttr, client_fd, 1);
				if (event_queue_add_fd_read(uttr->queue, uttp->fd)) {
					uwsgi_tuntap_peer_destroy(uttr, uttp);
				}
				continue;
			}

			if (uttr->stats_server_fd > -1 && interesting_fd == uttr->stats_server_fd) {
				tuntaprouter_send_stats(uttr);
				continue;
			}

			if (uttr->gateway_fd > -1 && interesting_fd == uttr->gateway_fd) {
				ssize_t rlen = read(uttr->gateway_fd, uttr->gateway_buf, utt.buffer_size);	
				if (rlen <= 0) {
                                        uwsgi_error("uwsgi_tuntap_router_loop()/read()");
					continue;
                                }
				if (rlen < 20) continue;
				if (uwsgi_tuntap_firewall_check(utt.fw_in, uttr->gateway_buf, rlen)) continue;
				uint32_t *dst_ip = (uint32_t *) & uttr->gateway_buf[16];
                                struct uwsgi_tuntap_peer *uttp = uwsgi_tuntap_peer_get_by_addr(uttr, *dst_ip);
                                if (!uttp)
                                        continue;

                                // check for full write buffer
                                if (uttp->write_buf_pktsize + 4 + rlen > utt.buffer_size) {
                                        uttp->dropped++;
                                        continue;
                                }

                                uint16_t pktsize = rlen;
                                char *ptr = uttp->write_buf + uttp->write_buf_pktsize;
                                memcpy(ptr + 4, uttr->gateway_buf, rlen);
                                ptr[0] = 0;
                                ptr[1] = (uint8_t) (pktsize & 0xff);
                                ptr[2] = (uint8_t) ((pktsize >> 8) & 0xff);
                                ptr[3] = 0;
                                uttp->write_buf_pktsize+= pktsize+4;
                                if (uwsgi_tuntap_peer_enqueue(uttr, uttp)) {
                                        uwsgi_tuntap_peer_destroy(uttr, uttp);
                                }
                                continue;
			}

			struct uwsgi_tuntap_peer *uttp = uttr->peers_head;
			while (uttp) {
				if (interesting_fd == uttp->fd) {
					// read from the client
					if (event_queue_interesting_fd_is_read(events, i)) {
						if (utt.use_credentials) {
							if (uttp->addr == 0) {
								if (!uttp->sent_credentials) {
									if (uwsgi_recv_cred(uttp->fd, "uwsgi-tuntap", 12, &uttp->pid, &uttp->uid, &uttp->gid)) {
										uwsgi_tuntap_peer_destroy(uttr, uttp);
										break;
									}
									if (utt.addr_by_credentials) {
										uttp->addr = utt.addr_by_credentials(uttp->pid, uttp->uid, uttp->gid);
										if (!uttp->addr) {
											uwsgi_tuntap_peer_destroy(uttr, uttp);
											break;
										}
										if (uwsgi_tuntap_register_addr(uttr, uttp)) {
											uwsgi_tuntap_peer_destroy(uttr, uttp);
											break;
										}
									}
									uttp->sent_credentials = 1;
									break;
								}
								else {
									// if credentials are sent and a function is available, destroy the peer (if addr is 0)
									if (utt.addr_by_credentials) {
										uwsgi_tuntap_peer_destroy(uttr, uttp);
										break;
									}
								}
							}
						}

						if (uwsgi_tuntap_peer_dequeue(uttr, uttp, 1)) {
							uwsgi_tuntap_peer_destroy(uttr, uttp);
							break;
						}
					}

					if (event_queue_interesting_fd_is_write(events, i)) {
						// something is wrong (the tuntap device is blocked)
						if (uttr->wait_for_write)
							break;

						// write to the client
						if (uwsgi_tuntap_peer_enqueue(uttr, uttp)) {
							uwsgi_tuntap_peer_destroy(uttr, uttp);
							break;
						}
					}
					break;
				}
				uttp = uttp->next;
			}
		}
	}
}

static void uwsgi_tuntap_router() {

	if (!utt.routers) return;

	if (!utt.buffer_size)
		utt.buffer_size = 8192;

	if (utt.use_credentials) {
		if (utt.use_credentials[0] != 0 && strcmp(utt.use_credentials, "true")) {
			utt.addr_by_credentials = (uint32_t (*)(pid_t, uid_t, gid_t)) dlsym(RTLD_DEFAULT, utt.use_credentials);
			if (!utt.addr_by_credentials) {
				uwsgi_log("[uwsgi-tuntap] unable to find symbol %s\n", utt.use_credentials);
				exit(1);
			}
		}
	}

	struct uwsgi_string_list *usl;
	uwsgi_foreach(usl, utt.routers) {
		size_t rlen = 0;
		char **args = uwsgi_split_quoted(usl->value, usl->len, " \t", &rlen);
		if (rlen < 2) {
			uwsgi_log("invalid tuntap router syntax, must be <device> <socket> [stats] [gateway]\n");
			exit(1);
		}

		struct uwsgi_tuntap_router *uttr = uwsgi_calloc(sizeof(struct uwsgi_tuntap_router));

		uttr->server_fd = bind_to_unix(args[1], uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);

		uttr->fd = uwsgi_tuntap_device(args[0]);

		if (rlen > 2) uttr->stats_server = args[2];
		if (rlen > 3) uttr->gateway = args[3];

		if (register_gateway("uWSGI tuntap router", uwsgi_tuntap_router_loop, uttr) == NULL) {
			uwsgi_log("unable to register the tuntap server gateway\n");
			exit(1);
		}
	}
}

void tuntaprouter_send_stats(struct uwsgi_tuntap_router *uttr) {

        struct sockaddr_un client_src;
        socklen_t client_src_len = 0;

        int client_fd = accept(uttr->stats_server_fd, (struct sockaddr *) &client_src, &client_src_len);
        if (client_fd < 0) {
                uwsgi_error("tuntaprouter_send_stats()/accept()");
                return;
        }

        if (uwsgi.stats_http) {
                if (uwsgi_send_http_stats(client_fd)) {
                        close(client_fd);
                        return;
                }
        }

        struct uwsgi_stats *us = uwsgi_stats_new(8192);

        if (uwsgi_stats_keyval_comma(us, "version", UWSGI_VERSION)) goto end;
        if (uwsgi_stats_keylong_comma(us, "pid", (unsigned long long) getpid())) goto end;
        if (uwsgi_stats_keylong_comma(us, "uid", (unsigned long long) getuid())) goto end;
        if (uwsgi_stats_keylong_comma(us, "gid", (unsigned long long) getgid())) goto end;

        char *cwd = uwsgi_get_cwd();
        if (uwsgi_stats_keyval_comma(us, "cwd", cwd)) goto end0;

	if (uwsgi_stats_key(us , "peers")) goto end0;
                if (uwsgi_stats_list_open(us)) goto end0;
	struct uwsgi_tuntap_peer *uttp = uttr->peers_head;
	
        while (uttp) {
                if (uwsgi_stats_object_open(us)) goto end0;
		if (uwsgi_stats_keyval_comma(us, "addr", uttp->ip)) goto end0;
		if (uwsgi_stats_keylong_comma(us, "addr_32", uttp->addr)) goto end0;
		if (uwsgi_stats_keylong_comma(us, "uid", uttp->uid)) goto end0;
		if (uwsgi_stats_keylong_comma(us, "gid", uttp->gid)) goto end0;
		if (uwsgi_stats_keylong_comma(us, "pid", uttp->pid)) goto end0;
		if (uwsgi_stats_keylong_comma(us, "tx", uttp->tx)) goto end0;
		if (uwsgi_stats_keylong_comma(us, "rx", uttp->rx)) goto end0;
		if (uwsgi_stats_keylong(us, "dropped", uttp->dropped)) goto end0;
		if (uwsgi_stats_object_close(us)) goto end0;
                uttp = uttp->next;
		if (uttp) {
			if (uwsgi_stats_comma(us)) goto end0;
		}
        }

        if (uwsgi_stats_list_close(us)) goto end0;

	if (uwsgi_stats_object_close(us)) goto end0;	

        size_t remains = us->pos;
        off_t pos = 0;
        while(remains > 0) {
                int ret = uwsgi_waitfd_write(client_fd, uwsgi.socket_timeout);
                if (ret <= 0) {
                        goto end0;
                }
                ssize_t res = write(client_fd, us->base + pos, remains);
                if (res <= 0) {
                        if (res < 0) {
                                uwsgi_error("tuntaprouter_send_stats()/write()");
                        }
                        goto end0;
                }
                pos += res;
                remains -= res;
        }

end0:
        free(cwd);
end:
        free(us->base);
        free(us);
        close(client_fd);
}


struct uwsgi_plugin tuntap_plugin = {
	.name = "tuntap",
	.options = uwsgi_tuntap_options,
	.post_jail = uwsgi_tuntap_client,
	.jail = uwsgi_tuntap_router,
};
