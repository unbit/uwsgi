#include "common.h"

extern struct uwsgi_tuntap utt;

// create a new peer
struct uwsgi_tuntap_peer *uwsgi_tuntap_peer_create(struct uwsgi_tuntap_router *uttr, int fd) {

	struct uwsgi_tuntap_peer *uttp = uwsgi_calloc(sizeof(struct uwsgi_tuntap_peer));
	uttp->fd = fd;
	// leave space fot he uwsgi header
	uttp->buf = uwsgi_malloc(utt.buffer_size + 4);
	uttp->write_buf = uwsgi_malloc(utt.buffer_size);

	if (uttr->peers_tail) {
		uttr->peers_tail->next = uttp;
		uttp->prev = uttr->peers_tail;
		uttr->peers_tail = uttp;
	}
	else {
		uttr->peers_head = uttp;
		uttr->peers_tail = uttp;
	}

	return uttp;
}

// destroy a peer
void uwsgi_tuntap_peer_destroy(struct uwsgi_tuntap_router *uttr, struct uwsgi_tuntap_peer *uttp) {
	struct uwsgi_tuntap_peer *prev = uttp->prev;
	struct uwsgi_tuntap_peer *next = uttp->next;

	if (prev) {
		prev->next = next;
	}

	if (next) {
		next->prev = prev;
	}

	if (uttp == uttr->peers_head) {
		uttr->peers_head = next;
	}

	if (uttp == uttr->peers_tail) {
		uttr->peers_tail = prev;
	}

	free(uttp->buf);
	free(uttp->write_buf);
	close(uttp->fd);
	free(uttp);
}


// get a peer by addr
struct uwsgi_tuntap_peer *uwsgi_tuntap_peer_get_by_addr(struct uwsgi_tuntap_router *uttr, uint32_t addr) {
	struct uwsgi_tuntap_peer *uttp = uttr->peers_head;
	while (uttp) {
		if (uttp->addr == addr)
			return uttp;
		uttp = uttp->next;
	}

	return NULL;
}

// block all reading peers
void uwsgi_tuntap_block_reads(struct uwsgi_tuntap_router *uttr) {
	struct uwsgi_tuntap_peer *uttp = uttr->peers_head;
	while (uttp) {
		if (!uttp->blocked_read) {
			if (!uttp->wait_for_write) {
				if (event_queue_del_fd(uttr->queue, uttp->fd, event_queue_read())) {
					struct uwsgi_tuntap_peer *tmp_uttp = uttp;
					uttp = uttp->next;
					uwsgi_tuntap_peer_destroy(uttr, tmp_uttp);
					continue;
				}
			}
			else {
				if (event_queue_fd_readwrite_to_write(uttr->queue, uttp->fd)) {
                                        struct uwsgi_tuntap_peer *tmp_uttp = uttp;
                                        uttp = uttp->next;
                                        uwsgi_tuntap_peer_destroy(uttr, tmp_uttp);
                                        continue;
                                }
			}
			uttp->blocked_read = 1;
		}
		uttp = uttp->next;
	}
}

//unblock all reading peers
void uwsgi_tuntap_unblock_reads(struct uwsgi_tuntap_router *uttr) {
	struct uwsgi_tuntap_peer *uttp = uttr->peers_head;
	while (uttp) {
		if (uttp->blocked_read) {
			if (!uttp->wait_for_write) {
				if (event_queue_add_fd_read(uttr->queue, uttp->fd)) {
					struct uwsgi_tuntap_peer *tmp_uttp = uttp;
					uttp = uttp->next;
					uwsgi_tuntap_peer_destroy(uttr, tmp_uttp);
					continue;
				}
			}
			else {
				if (event_queue_fd_write_to_readwrite(uttr->queue, uttp->fd)) {
					struct uwsgi_tuntap_peer *tmp_uttp = uttp;
					uttp = uttp->next;
					uwsgi_tuntap_peer_destroy(uttr, tmp_uttp);
					continue;
				}
			}
			uttp->blocked_read = 0;
		}
		uttp = uttp->next;
	}
}

// enqueue a packet in the tuntap device
void uwsgi_tuntap_enqueue(struct uwsgi_tuntap_router *uttr) {
	ssize_t rlen = write(uttr->fd, uttr->write_buf + uttr->write_pos, uttr->write_pktsize - uttr->write_pos);
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

	uttr->write_pos += rlen;
	if (uttr->write_pos >= uttr->write_pktsize) {
		uttr->write_pos = 0;
		if (uttr->wait_for_write) {
			if (event_queue_fd_write_to_read(uttr->queue, uttr->fd)) {
				uwsgi_error("uwsgi_tuntap_enqueue()/event_queue_fd_read_to_write()");
				exit(1);
			}
			uttr->wait_for_write = 0;
		}
		uwsgi_tuntap_unblock_reads(uttr);
		return;
	}

retry:
	if (!uttr->wait_for_write) {
		uwsgi_tuntap_block_reads(uttr);
		if (event_queue_fd_read_to_write(uttr->queue, uttr->fd)) {
			uwsgi_error("uwsgi_tuntap_enqueue()/event_queue_fd_read_to_write()");
			exit(1);
		}
		uttr->wait_for_write = 1;
	}
}

// receive a packet from the client
int uwsgi_tuntap_peer_dequeue(struct uwsgi_tuntap_router *uttr, struct uwsgi_tuntap_peer *uttp) {
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
		uttp->rx += rlen;
		// a whole pkt has been received
		if (uttp->buf_pos >= uttp->buf_pktsize) {

			uttp->header_pos = 0;
			uttp->buf_pos = 0;

			if (uwsgi_tuntap_firewall_check(utt.fw_out, uttp->buf, uttp->buf_pktsize)) return 0;

			// if there is no associated address store the source
			if (!uttp->addr) {
				uint32_t *src_ip = (uint32_t *) & uttp->buf[12];
				uttp->addr = *src_ip;
				// drop invalid ip addresses
				if (!uttp->addr)
					return -1;

				struct uwsgi_tuntap_peer *tmp_uttp = uwsgi_tuntap_peer_get_by_addr(uttr, uttp->addr);
				char ip[INET_ADDRSTRLEN + 1];
				memset(ip, 0, INET_ADDRSTRLEN + 1);
				if (!inet_ntop(AF_INET, &uttp->addr, ip, INET_ADDRSTRLEN)) {
					uwsgi_error("inet_ntop()");
					return -1;
				}
				if (uttp != tmp_uttp) {
					uwsgi_log("[tuntap-router] detected ip collision for %s\n", ip);
					uwsgi_tuntap_peer_destroy(uttr, tmp_uttp);
				}
				uwsgi_log("[tuntap-router] registered new peer %s (fd: %d)\n", ip, uttp->fd);
			}

			memcpy(uttr->write_buf, uttp->buf, uttp->buf_pktsize);
			uttr->write_pktsize = uttp->buf_pktsize;
			uwsgi_tuntap_enqueue(uttr);
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
		uttp->rx += 4;
	}
	return 0;
}

// enqueue a packet to the client
int uwsgi_tuntap_peer_enqueue(struct uwsgi_tuntap_router *uttr, struct uwsgi_tuntap_peer *uttp) {

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
	uttp->tx += rlen;
	if (uttp->written >= uttp->write_buf_pktsize) {
		uttp->written = 0;
		uttp->write_buf_pktsize = 0;
		if (uttp->wait_for_write) {
			// if the write ends while we are writing to the tuntap, block the reads
			if (uttr->wait_for_write) {
				uttp->blocked_read = 1;
				if (event_queue_del_fd(uttr->queue, uttp->fd, event_queue_write())) {
					uwsgi_error("uwsgi_tuntap_peer_enqueue()/event_queue_del_fd()");
					return -1;
				}
			}
			else {
				if (event_queue_fd_readwrite_to_read(uttr->queue, uttp->fd)) {
					uwsgi_error("uwsgi_tuntap_peer_enqueue()/event_queue_fd_write_to_read()");
					return -1;
				}
			}
			uttp->wait_for_write = 0;
		}
		return 0;
	}

	memmove(uttp->write_buf, uttp->write_buf + rlen, uttp->write_buf_pktsize - rlen);
	uttp->write_buf_pktsize -= rlen;

retry:
	if (!uttp->wait_for_write) {
		if (event_queue_fd_read_to_readwrite(uttr->queue, uttp->fd)) {
			uwsgi_error("uwsgi_tuntap_peer_enqueue()/event_queue_fd_read_to_write()");
			return -1;
		}
		uttp->wait_for_write = 1;
	}

	return 0;
}

int uwsgi_tuntap_device(char *name) {
	struct ifreq ifr;
        int fd = open(UWSGI_TUNTAP_DEVICE, O_RDWR);
        if (fd < 0) {
                uwsgi_error_open(UWSGI_TUNTAP_DEVICE);
                exit(1);
        }

        memset(&ifr, 0, sizeof(struct ifreq));

        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, name, IFNAMSIZ);

        if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
                uwsgi_error("uwsgi_tuntap_device()/ioctl()");
                exit(1);
        }

	uwsgi_log("initialized tuntap device %s (fd: %d)\n", ifr.ifr_name, fd);

	return fd;
}

