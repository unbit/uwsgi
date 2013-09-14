#include <uwsgi.h>

#ifdef __linux__
#include <linux/if_tun.h>
#define UWSGI_TUNTAP_DEVICE "/dev/net/tun"
#endif

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
	// counters
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
};

struct uwsgi_tuntap_firewall_rule {
        uint8_t action;
        uint32_t src;
        uint32_t src_mask;
        uint32_t dst;
        uint32_t dst_mask;
        struct uwsgi_tuntap_firewall_rule *next;
};

struct uwsgi_tuntap_router {
	int fd;
        int server_fd;
        int queue;
	char *buf;
        char *write_buf;
        struct uwsgi_tuntap_peer *peers_head;
        struct uwsgi_tuntap_peer *peers_tail;
        uint16_t write_pktsize;
        uint16_t write_pos;
        int wait_for_write;
};

struct uwsgi_tuntap {
        struct uwsgi_string_list *routers;
        struct uwsgi_string_list *devices;
        uint16_t buffer_size;
        struct uwsgi_tuntap_firewall_rule *fw_in;
        struct uwsgi_tuntap_firewall_rule *fw_out;
};

int uwsgi_tuntap_peer_dequeue(struct uwsgi_tuntap_router *, struct uwsgi_tuntap_peer *);
int uwsgi_tuntap_peer_enqueue(struct uwsgi_tuntap_router *, struct uwsgi_tuntap_peer *);
void uwsgi_tuntap_enqueue(struct uwsgi_tuntap_router *);

int uwsgi_tuntap_firewall_check(struct uwsgi_tuntap_firewall_rule *, char *, uint16_t);

struct uwsgi_tuntap_peer *uwsgi_tuntap_peer_create(struct uwsgi_tuntap_router *, int);
struct uwsgi_tuntap_peer *uwsgi_tuntap_peer_get_by_addr(struct uwsgi_tuntap_router *,uint32_t);
void uwsgi_tuntap_peer_destroy(struct uwsgi_tuntap_router *, struct uwsgi_tuntap_peer *);

int uwsgi_tuntap_device(char *);

void uwsgi_tuntap_opt_firewall(char *, char *, void *);
