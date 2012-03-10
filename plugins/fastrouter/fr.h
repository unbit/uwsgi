#define FASTROUTER_STATUS_FREE 0
#define FASTROUTER_STATUS_CONNECTING 1
#define FASTROUTER_STATUS_RECV_HDR 2
#define FASTROUTER_STATUS_RECV_VARS 3
#define FASTROUTER_STATUS_RESPONSE 4
#define FASTROUTER_STATUS_BUFFERING 5

#ifdef UWSGI_SCTP
#define FASTROUTER_STATUS_SCTP_NODE_FREE 6
#define FASTROUTER_STATUS_SCTP_RESPONSE 7
#endif

#define add_timeout(x) uwsgi_add_rb_timer(ufr.timeouts, time(NULL)+ufr.socket_timeout, x)
#define add_fake_timeout(x) uwsgi_add_rb_timer(ufr.timeouts, time(NULL)+1, x)
#define add_check_timeout(x) uwsgi_add_rb_timer(timeouts, time(NULL)+x, NULL)
#define del_check_timeout(x) rb_erase(&x->rbt, timeouts);
#define del_timeout(x) rb_erase(&x->timeout->rbt, ufr.timeouts); free(x->timeout);

struct fastrouter_session;

struct uwsgi_fastrouter {

	int (*mapper)(struct fastrouter_session *, char **);

        int has_sockets;
        int has_subscription_sockets;
#ifdef UWSGI_SCTP
        int has_sctp_sockets;
#endif

        int processes;
        int quiet;

        struct rb_root *timeouts;

        int use_cache;
        int nevents;

	char *magic_table[0xff];

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
        int fr_stats_server;

        int use_socket;
        int socket_num;
        struct uwsgi_socket *to_socket;

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

        struct fastrouter_session **fr_table;

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

struct fastrouter_session {

        int fd;
        int instance_fd;
        int status;
        struct uwsgi_header uh;
        uint8_t h_pos;
        uint16_t pos;

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

        char buffer[0xffff];
};


void uwsgi_fastrouter_switch_events(struct fastrouter_session *, int intersting_fd, char **);
void close_session(struct fastrouter_session *);
void fr_get_hostname(char *, uint16_t, char *, uint16_t, void *);

int uwsgi_fr_map_use_void(struct fastrouter_session *, char **);
int uwsgi_fr_map_use_cache(struct fastrouter_session *, char **);
int uwsgi_fr_map_use_pattern(struct fastrouter_session *, char **);
int uwsgi_fr_map_use_subscription(struct fastrouter_session *, char **);
int uwsgi_fr_map_use_base(struct fastrouter_session *, char **);
int uwsgi_fr_map_use_cs(struct fastrouter_session *, char **);
int uwsgi_fr_map_use_to(struct fastrouter_session *, char **);
int uwsgi_fr_map_use_static_nodes(struct fastrouter_session *, char **);
#ifdef UWSGI_SCTP
int uwsgi_fr_map_use_sctp(struct fastrouter_session *, char **);
#endif
