#include <uwsgi.h>
#include <linux/if_tun.h>

extern struct uwsgi_server uwsgi;

#define UWSGI_TUNTAP_DEVICE "/dev/net/tun"

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

	Firewalling it is based on 2 chains (in and out), and each rule is formed by 3 parameters: <action> <src> <dst>
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

	some form of security to disallow raw access to the tuntap router unix socket

*/

/*

	a peer is a client connected to the router. It has 2 queue, one for read
	and one for write. The write queue can be filled up. If the write queue is full, packets are dropped.

*/
struct uwsgi_tuntap_peer {
	int fd;
	uint32_t addr;
	int wait_for_write;
	int blocked_read;
	size_t written;
	char header[4];
	uint8_t header_pos;
	char *buf;
	uint16_t buf_pktsize;
	uint16_t buf_pos;
	char *write_buf;
	uint16_t write_buf_pktsize;
	uint16_t write_buf_pos;
	struct uwsgi_tuntap_peer *prev;
	struct uwsgi_tuntap_peer *next;
};

struct uwsgi_tuntap_firewall_rule {
	uint8_t action;
	uint32_t src;
	uint32_t src_mask;
	uint32_t dst;
	uint32_t dst_mask;
	struct uwsgi_tuntap_firewall_rule *next;
};

struct uwsgi_tuntap {
	char *addr;
	char *device;
	int fd;
	int server_fd;
	int queue;
	uint16_t buffer_size;
	char *buf;
	char *write_buf;
	uint16_t write_pktsize;
	uint16_t write_pos;
	int wait_for_write;
	struct uwsgi_tuntap_peer *peers_head;
	struct uwsgi_tuntap_peer *peers_tail;
	struct uwsgi_tuntap_firewall_rule *fw_in;
	struct uwsgi_tuntap_firewall_rule *fw_out;
} utt;

static struct uwsgi_option uwsgi_tuntap_options[] = {
	{"tuntap-router", required_argument, 0, "run the tuntap router (syntax: <device> <socket>)", uwsgi_opt_set_str, &utt.addr, 0},
	{"tuntap-device", required_argument, 0, "add a tuntap device to the instance (syntax: <device>[ <socket>])", uwsgi_opt_set_str, &utt.device, 0},
	{NULL, 0, 0, NULL, NULL, NULL, 0},
};

// create a new peer
static struct uwsgi_tuntap_peer *uwsgi_tuntap_peer_create(int fd) {

	struct uwsgi_tuntap_peer *uttp = uwsgi_calloc(sizeof(struct uwsgi_tuntap_peer));
	uttp->fd = fd;
	uttp->buf = uwsgi_malloc(utt.buffer_size + 4);
	uttp->write_buf = uwsgi_malloc(utt.buffer_size + 4);

	if (utt.peers_tail) {
		utt.peers_tail->next = uttp;
		uttp->prev = utt.peers_tail;
		utt.peers_tail = uttp;
	}
	else {
		utt.peers_head = uttp;
		utt.peers_tail = uttp;
	}

	return uttp;
}

// destroy a peer
static void uwsgi_tuntap_peer_destroy(struct uwsgi_tuntap_peer *uttp) {
	struct uwsgi_tuntap_peer *prev = uttp->prev;
	struct uwsgi_tuntap_peer *next = uttp->next;

	if (prev) {
		prev->next = next;
	}

	if (next) {
		next->prev = prev;
	}

	if (uttp == utt.peers_head) {
		utt.peers_head = next;
	}

	if (uttp == utt.peers_tail) {
		utt.peers_tail = prev;
	}

	free(uttp->buf);
	free(uttp);
}


// get a peer by addr
static struct uwsgi_tuntap_peer *uwsgi_tuntap_peer_get_by_addr(uint32_t addr) {
	struct uwsgi_tuntap_peer *uttp = utt.peers_head;
	while (uttp) {
		if (uttp->addr == addr)
			return uttp;
		uttp = uttp->next;
	}

	return NULL;
}

// block all reading peers
static void uwsgi_tuntap_block_reads() {
	struct uwsgi_tuntap_peer *uttp = utt.peers_head;
	while (uttp) {
		if (!uttp->wait_for_write) {
			if (!uttp->blocked_read) {
				if (event_queue_del_fd(utt.queue, uttp->fd, event_queue_read())) {
					struct uwsgi_tuntap_peer *tmp_uttp = uttp;
					uttp = uttp->next;
					uwsgi_tuntap_peer_destroy(tmp_uttp);
					continue;
				}
				uttp->blocked_read = 1;
			}
		}
		uttp = uttp->next;
	}
}

//unblock all reading peers
static void uwsgi_tuntap_unblock_reads() {
	struct uwsgi_tuntap_peer *uttp = utt.peers_head;
	while (uttp) {
		if (uttp->blocked_read) {
			if (event_queue_add_fd_read(utt.queue, uttp->fd)) {
				struct uwsgi_tuntap_peer *tmp_uttp = uttp;
				uttp = uttp->next;
				uwsgi_tuntap_peer_destroy(tmp_uttp);
				continue;
			}
			uttp->blocked_read = 0;
		}
		uttp = uttp->next;
	}
}

// enqueue a packet in the tuntap device
static void uwsgi_tuntap_enqueue() {
	ssize_t rlen = write(utt.fd, utt.write_buf + utt.write_pos, utt.write_pktsize - utt.write_pos);
	// error on the tuntap device, destroy !!!
	if (rlen == 0) {
		uwsgi_error("uwsgi_tuntap_enqueue()/write()");
		exit(1);
	}

	if (rlen < 0) {
		if (uwsgi_is_again())
			goto retry;
		uwsgi_error("uwsgi_tuntap_enqueue()/write()");
		exit(1);
	}

	utt.write_pos += rlen;
	if (utt.write_pos >= utt.write_pktsize) {
		utt.write_pos = 0;
		if (utt.wait_for_write) {
			if (event_queue_fd_write_to_read(utt.queue, utt.fd)) {
				uwsgi_error("uwsgi_tuntap_enqueue()/event_queue_fd_read_to_write()");
				exit(1);
			}
			utt.wait_for_write = 0;
		}
		uwsgi_tuntap_unblock_reads();
		return;
	}

retry:
	if (!utt.wait_for_write) {
		uwsgi_tuntap_block_reads();
		if (event_queue_fd_read_to_write(utt.queue, utt.fd)) {
			uwsgi_error("uwsgi_tuntap_enqueue()/event_queue_fd_read_to_write()");
			exit(1);
		}
		utt.wait_for_write = 1;
	}
}

// receive a packet from the client
static int uwsgi_tuntap_peer_dequeue(struct uwsgi_tuntap_peer *uttp) {
	// get body
	if (uttp->header_pos >= 4) {
		ssize_t rlen = read(uttp->fd, uttp->buf + uttp->buf_pos, uttp->buf_pktsize - uttp->buf_pos);
		if (rlen == 0)
			return -1;
		if (rlen < 0) {
			if (uwsgi_is_again())
				return 0;
			uwsgi_error("uwsgi_tuntap_peer_dequeue()/read()");
			return -1;
		}
		uttp->buf_pos += rlen;
		// a whole pkt has been received
		if (uttp->buf_pos >= uttp->buf_pktsize) {
			// if there is no associated address store the source
			if (!uttp->addr) {
				uint32_t *src_ip = (uint32_t *) & uttp->buf[12];
				uttp->addr = *src_ip;
				// drop invalid ip addresses
				if (!uttp->addr)
					return -1;
				char ip[INET_ADDRSTRLEN + 1];
				memset(ip, 0, INET_ADDRSTRLEN + 1);
				if (!inet_ntop(AF_INET, &uttp->addr, ip, INET_ADDRSTRLEN)) {
					uwsgi_error("inet_ntop()");
					return -1;
				}
				uwsgi_log("[tuntap-router] registered new peer %s (fd: %d)\n", ip, uttp->fd);
			}
			memcpy(utt.write_buf, uttp->buf, uttp->buf_pktsize);
			utt.write_pktsize = uttp->buf_pktsize;
			uttp->header_pos = 0;
			uttp->buf_pos = 0;
			uwsgi_tuntap_enqueue();
		}
		return 0;
	}
	ssize_t rlen = read(uttp->fd, uttp->header + uttp->header_pos, 4 - uttp->header_pos);
	if (rlen == 0)
		return -1;
	if (rlen < 0) {
		if (uwsgi_is_again())
			return 0;
		uwsgi_error("uwsgi_tuntap_peer_dequeue()/read()");
		return -1;
	}
	uttp->header_pos += rlen;
	if (uttp->header_pos >= 4) {
		uint16_t *pktsize = (uint16_t *) &uttp->header[1];
		uttp->buf_pktsize = *pktsize;
	}
	return 0;
}

// enqueue a packet to the client
static int uwsgi_tuntap_peer_enqueue(struct uwsgi_tuntap_peer *uttp) {

	ssize_t rlen = write(uttp->fd, uttp->write_buf + uttp->written, uttp->write_buf_pktsize - uttp->written);
	if (rlen == 0) {
		uwsgi_error("uwsgi_tuntap_peer_enqueue()/write()");
		return -1;
	}

	if (rlen < 0) {
		if (uwsgi_is_again())
			goto retry;
		uwsgi_error("uwsgi_tuntap_peer_enqueue()/write()");
		return -1;
	}

	uttp->written += rlen;
	if (uttp->written >= uttp->write_buf_pktsize) {
		uttp->written = 0;
		uttp->write_buf_pktsize = 0;
		if (uttp->wait_for_write) {
			// if the write ends while we are writing to the tuntap, block the reads
			if (utt.wait_for_write) {
				uttp->blocked_read = 1;
			}
			else {
				if (event_queue_fd_write_to_read(utt.queue, uttp->fd)) {
					uwsgi_error("uwsgi_tuntap_peer_enqueue()/event_queue_fd_write_to_read()");
					return -1;
				}
			}
			utt.wait_for_write = 0;
		}
		return 0;
	}

	memmove(uttp->write_buf, uttp->write_buf + rlen, uttp->write_buf_pktsize - rlen);
	uttp->write_buf_pktsize -= rlen;

retry:
	if (!uttp->wait_for_write) {
		if (event_queue_fd_read_to_write(utt.queue, uttp->fd)) {
			uwsgi_error("uwsgi_tuntap_peer_enqueue()/event_queue_fd_read_to_write()");
			return -1;
		}
		uttp->wait_for_write = 1;
	}

	return 0;
}


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

	struct ifreq ifr;
	utt.fd = open(UWSGI_TUNTAP_DEVICE, O_RDWR);
	if (utt.fd < 0) {
		uwsgi_error_open(UWSGI_TUNTAP_DEVICE);
		exit(1);
	}

	memset(&ifr, 0, sizeof(struct ifreq));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, utt.device, IFNAMSIZ);

	if (ioctl(utt.fd, TUNSETIFF, (void *) &ifr) < 0) {
		uwsgi_error("uwsgi_tuntap_init()/ioctl()");
		exit(1);
	}

	uwsgi_log("initialized tuntap device %s\n", ifr.ifr_name);

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
				uint32_t *dst_ip = (uint32_t *) & utt.buf[16];
				struct uwsgi_tuntap_peer *uttp = uwsgi_tuntap_peer_get_by_addr(*dst_ip);
				if (!uttp)
					continue;
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

	struct ifreq ifr;
	utt.fd = open(UWSGI_TUNTAP_DEVICE, O_RDWR);
	if (utt.fd < 0) {
		uwsgi_error_open(UWSGI_TUNTAP_DEVICE);
		exit(1);
	}

	memset(&ifr, 0, sizeof(struct ifreq));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	*space = 0 ;
	strncpy(ifr.ifr_name, utt.addr, IFNAMSIZ);
	*space = ' ';

	if (ioctl(utt.fd, TUNSETIFF, (void *) &ifr) < 0) {
		uwsgi_error("uwsgi_tuntap_server()/ioctl()");
		exit(1);
	}

	uwsgi_log("initialized tuntap device %s\n", ifr.ifr_name);
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
