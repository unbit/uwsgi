#define COREROUTER_STATUS_FREE 0
#define COREROUTER_STATUS_CONNECTING 1
#define COREROUTER_STATUS_RECV_HDR 2
#define COREROUTER_STATUS_RESPONSE 3

#define cr_add_timeout(u, x) uwsgi_add_rb_timer(u->timeouts, time(NULL)+u->socket_timeout, x)
#define cr_add_fake_timeout(u, x) uwsgi_add_rb_timer(u->timeouts, time(NULL)+1, x)
#define cr_add_check_timeout(x) uwsgi_add_rb_timer(timeouts, time(NULL)+x, NULL)
#define cr_del_check_timeout(x) rb_erase(&x->rbt, timeouts);
#define cr_del_timeout(u, x) rb_erase(&x->timeout->rbt, u->timeouts); free(x->timeout);

struct corerouter_session;

struct uwsgi_corerouter {

	char *name;
	char *short_name;
	size_t session_size;

	void (*alloc_session)(struct uwsgi_corerouter *, struct uwsgi_gateway_socket *, struct corerouter_session *, struct sockaddr *, socklen_t);
	int (*mapper)(struct uwsgi_corerouter *, struct corerouter_session *);
	void (*switch_events)(struct uwsgi_corerouter *, struct corerouter_session *, int);

        int has_sockets;
	int has_backends;
        int has_subscription_sockets;
#ifdef UWSGI_SCTP
        int has_sctp_sockets;
#endif

        int processes;
        int quiet;

        struct rb_root *timeouts;

        int use_cache;
        int nevents;

	char *magic_table[256];

        int queue;

        char *pattern;
        int pattern_len;

        char *base;
        int base_len;

        size_t post_buffering;
        char *pb_base_dir;

        struct uwsgi_string_list *static_nodes;
        struct uwsgi_string_list *current_static_node;
        int static_node_gracetime;

        char *stats_server;
        int cr_stats_server;

        int use_socket;
        int socket_num;
        struct uwsgi_socket *to_socket;

	int use_cluster;

        struct uwsgi_subscribe_slot *subscriptions;
        int subscription_regexp;

        struct uwsgi_string_list *fallback;

        int socket_timeout;

        uint8_t code_string_modifier1;
        char *code_string_code;
        char *code_string_function;


        struct uwsgi_rb_timer *subscriptions_check;

        int cheap;
        int i_am_cheap;

        int tolerance;
        int harakiri;

        struct corerouter_session **cr_table;

};

#ifdef UWSGI_SCTP
struct uwsgi_fr_sctp_node {

        int fd;
	char name[64];
        uint64_t requests;
        struct uwsgi_fr_sctp_node *prev;
        struct uwsgi_fr_sctp_node *next;
};

struct uwsgi_fr_sctp_node *uwsgi_fr_sctp_add_node(int);
void uwsgi_fr_sctp_del_node(int);
void uwsgi_opt_fastrouter_sctp(char *, char *, void *);

#endif

struct corerouter_session {

        int fd;
        int instance_fd;
        int status;
        uint8_t h_pos;
        uint16_t pos;

	struct uwsgi_gateway_socket *ugs;

        char *hostname;
        uint16_t hostname_len;

        int has_key;
        int retry;
#ifdef UWSGI_SCTP
        int persistent;
#endif

        char *instance_address;
        uint64_t instance_address_len;

        struct uwsgi_subscribe_node *un;
        struct uwsgi_string_list *static_node;
        int pass_fd;
        int soopt;
        int timed_out;

        struct uwsgi_rb_timer *timeout;
        int instance_failed;

        size_t post_cl;
        size_t post_remains;

        struct uwsgi_string_list *fallback;

        char *buf_file_name;
        FILE *buf_file;

        uint8_t modifier1;
        uint8_t modifier2;

        char *tmp_socket_name;

	struct sockaddr_un addr;
        socklen_t addr_len;

	void (*close)(struct uwsgi_corerouter *, struct corerouter_session *);
};

void uwsgi_opt_corerouter(char *, char *, void *);
void uwsgi_opt_corerouter_use_socket(char *, char *, void *);
void uwsgi_opt_corerouter_use_base(char *, char *, void *);
void uwsgi_opt_corerouter_use_pattern(char *, char *, void *);
void uwsgi_opt_corerouter_zerg(char *, char *, void *);
void uwsgi_opt_corerouter_cs(char *, char *, void *);
void uwsgi_opt_corerouter_ss(char *, char *, void *);

void corerouter_manage_subscription(char *, uint16_t, char *, uint16_t, void *);

void *uwsgi_corerouter_setup_event_queue(struct uwsgi_corerouter *, int);
void uwsgi_corerouter_manage_subscription(struct uwsgi_corerouter *, int id, struct uwsgi_gateway_socket *);
void uwsgi_corerouter_manage_internal_subscription(struct uwsgi_corerouter *, int);
void uwsgi_corerouter_setup_sockets(struct uwsgi_corerouter *);

int uwsgi_corerouter_init(struct uwsgi_corerouter *);

struct corerouter_session *corerouter_alloc_session(struct uwsgi_corerouter *, struct uwsgi_gateway_socket *, int, struct sockaddr *, socklen_t);
void corerouter_close_session(struct uwsgi_corerouter *, struct corerouter_session *);

int uwsgi_cr_map_use_void(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_cache(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_pattern(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_cluster(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_subscription(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_base(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_cs(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_to(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_static_nodes(struct uwsgi_corerouter *, struct corerouter_session *);

int uwsgi_courerouter_has_has_backends(struct uwsgi_corerouter *);
#ifdef UWSGI_SCTP
int uwsgi_cr_map_use_sctp(struct fastrouter_session *, char **);
#endif
