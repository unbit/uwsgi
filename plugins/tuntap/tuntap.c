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
	- multiple devices
	- stats server

*/

static struct uwsgi_option uwsgi_tuntap_options[] = {
	{"tuntap-router", required_argument, 0, "run the tuntap router (syntax: <device> <socket>)", uwsgi_opt_set_str, &utt.addr, 0},
	{"tuntap-device", required_argument, 0, "add a tuntap device to the instance (syntax: <device>[ <socket>])", uwsgi_opt_set_str, &utt.device, 0},
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

	int fd = utt.fd;

	uwsgi_socket_nb(fd);

	if (!utt.buffer_size)
		utt.buffer_size = 8192;
	utt.buf = uwsgi_malloc(utt.buffer_size);
	utt.write_buf = uwsgi_malloc(utt.buffer_size);

	utt.queue = event_queue_init();

	event_queue_add_fd_read(utt.queue, fd);
	int server_fd = uwsgi_connect("/tmp/tuntap.socket", 30, 0);
	if (event_queue_add_fd_read(utt.queue, server_fd)) {
		// retry;
	}

	struct uwsgi_tuntap_peer *uttp = uwsgi_tuntap_peer_create(server_fd);

	for (;;) {
		int interesting_fd = -1;
		int ret = event_queue_wait(utt.queue, -1, &interesting_fd);

		if (ret <= 0)
			continue;

		if (interesting_fd == fd) {
			if (utt.wait_for_write) {
				uwsgi_tuntap_enqueue();
				continue;
			}
			ssize_t rlen = read(fd, utt.buf, utt.buffer_size);
			if (rlen <= 0) {
				uwsgi_error("uwsgi_tuntap_loop()/read()");
				exit(1);
			}
			uint16_t pktsize = rlen;
			char *ptr = uttp->write_buf + uttp->write_buf_pktsize;
			memcpy(ptr + 4, utt.buf, rlen);
			ptr[0] = 0;
			ptr[1] = (uint8_t) (pktsize & 0xff);
			ptr[2] = (uint8_t) ((pktsize >> 8) & 0xff);
			ptr[3] = 0;
			uttp->write_buf_pktsize+= pktsize+4;
			if (uwsgi_tuntap_peer_enqueue(uttp)) {
				uwsgi_log("server disconnected...\n");
				exit(1);
			}
			continue;
		}


		if (interesting_fd == server_fd) {
			// read from the client
			if (!uttp->wait_for_write) {
				if (uwsgi_tuntap_peer_dequeue(uttp)) {
					uwsgi_log("server disconnected...\n");
					exit(1);
				}
			}
			else {
				// something is wrong (the tuntap device is blocked)
				if (utt.wait_for_write)
					continue;

				// write to the client
				if (uwsgi_tuntap_peer_enqueue(uttp)) {
					uwsgi_log("server disconnected...\n");
					exit(1);
				}
			}
		}
	}

		return NULL;
}

static void uwsgi_tuntap_client() {

	if (!utt.device) return;


	utt.fd = uwsgi_tuntap_device(utt.device);

	pthread_t t;
	pthread_create(&t, NULL, uwsgi_tuntap_loop, NULL);
}

void uwsgi_tuntap_router_loop(int id, void *foobar) {
	int i;
	utt.buf = uwsgi_malloc(utt.buffer_size);
	utt.write_buf = uwsgi_malloc(utt.buffer_size);
	utt.queue = event_queue_init();
	void *events = event_queue_alloc(64);
	if (event_queue_add_fd_read(utt.queue, utt.server_fd))
		exit(1);
	if (event_queue_add_fd_read(utt.queue, utt.fd))
		exit(1);
	for (;;) {
		int nevents = event_queue_wait_multi(utt.queue, -1, events, 64);
		for (i = 0; i < nevents; i++) {
			int interesting_fd = event_queue_interesting_fd(events, i);
			if (interesting_fd == utt.fd) {
				// if writing, continue enqueuing
				if (utt.wait_for_write) {
					uwsgi_tuntap_enqueue();
					continue;
				}
				ssize_t rlen = read(utt.fd, utt.buf, utt.buffer_size);
				if (rlen <= 0) {
					uwsgi_error("uwsgi_tuntap_router_loop()/read()");
					exit(1);
				}

				if (uwsgi_tuntap_firewall_check(utt.fw_in, utt.buf, rlen)) continue;

				uint32_t *dst_ip = (uint32_t *) & utt.buf[16];
				struct uwsgi_tuntap_peer *uttp = uwsgi_tuntap_peer_get_by_addr(*dst_ip);
				if (!uttp)
					continue;

				// check for full write buffer
				if (uttp->write_buf_pktsize + 4 + rlen > utt.buffer_size) continue;

				uint16_t pktsize = rlen;
                        	char *ptr = uttp->write_buf + uttp->write_buf_pktsize;
                        	memcpy(ptr + 4, utt.buf, rlen);
                        	ptr[0] = 0;
                        	ptr[1] = (uint8_t) (pktsize & 0xff);
                        	ptr[2] = (uint8_t) ((pktsize >> 8) & 0xff);
                        	ptr[3] = 0;
                        	uttp->write_buf_pktsize+= pktsize+4;
				if (uwsgi_tuntap_peer_enqueue(uttp)) {
					uwsgi_tuntap_peer_destroy(uttp);
				}
				continue;
			}

			if (interesting_fd == utt.server_fd) {
				int client_fd = uwsgi_accept(utt.server_fd);
				if (client_fd < 0) {
					uwsgi_error("uwsgi_tuntap_server_loop()/accept()");
					continue;
				}
				struct uwsgi_tuntap_peer *uttp = uwsgi_tuntap_peer_create(client_fd);
				if (event_queue_add_fd_read(utt.queue, uttp->fd)) {
					uwsgi_tuntap_peer_destroy(uttp);
				}
				continue;
			}

			struct uwsgi_tuntap_peer *uttp = utt.peers_head;
			while (uttp) {
				if (interesting_fd == uttp->fd) {
					// read from the client
					if (!uttp->wait_for_write) {
						if (uwsgi_tuntap_peer_dequeue(uttp)) {
							struct uwsgi_tuntap_peer *tmp_uttp = uttp;
							uttp = uttp->next;
							uwsgi_tuntap_peer_destroy(tmp_uttp);
							continue;
						}
					}
					else {
						// something is wrong (the tuntap device is blocked)
						if (utt.wait_for_write)
							break;

						// write to the client
						if (uwsgi_tuntap_peer_enqueue(uttp)) {
							struct uwsgi_tuntap_peer *tmp_uttp = uttp;
							uttp = uttp->next;
							uwsgi_tuntap_peer_destroy(tmp_uttp);
							continue;
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

	if (!utt.addr) return;

	if (!utt.buffer_size)
		utt.buffer_size = 8192;

	char *space = strchr(utt.addr, ' ');
	if (!space) {
		uwsgi_log("invalid tuntap router syntax, must be <device> <socket>\n");
		exit(1);
	}

	utt.server_fd = bind_to_unix(space+1, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);

	*space = 0 ;
	utt.fd = uwsgi_tuntap_device(utt.addr);
	*space = ' ';

	if (register_gateway("uWSGI tuntap router", uwsgi_tuntap_router_loop, NULL) == NULL) {
		uwsgi_log("unable to register the tuntap server gateway\n");
		exit(1);
	}
}

struct uwsgi_plugin tuntap_plugin = {
	.name = "tuntap",
	.options = uwsgi_tuntap_options,
	.post_jail = uwsgi_tuntap_client,
	.jail = uwsgi_tuntap_router,
};
