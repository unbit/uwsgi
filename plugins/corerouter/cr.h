#define COREROUTER_STATUS_FREE 0
#define COREROUTER_STATUS_CONNECTING 1
#define COREROUTER_STATUS_RECV_HDR 2
#define COREROUTER_STATUS_RESPONSE 3

#define cr_add_timeout(u, x) uwsgi_add_rb_timer(u->timeouts, time(NULL)+u->socket_timeout, x)
#define cr_add_fake_timeout(u, x) uwsgi_add_rb_timer(u->timeouts, time(NULL)+1, x)
#define cr_add_check_timeout(x) uwsgi_add_rb_timer(timeouts, time(NULL)+x, NULL)
#define cr_del_check_timeout(x) rb_erase(&x->rbt, timeouts);
#define cr_del_timeout(u, x) rb_erase(&x->timeout->rbt, u->timeouts); free(x->timeout);

#define cr_try_again if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {\
                     	errno = EINPROGRESS;\
                     	return -1;\
                     }


struct corerouter_session;

struct uwsgi_corerouter {

	char *name;
	char *short_name;
	size_t session_size;

	void (*alloc_session)(struct uwsgi_corerouter *, struct uwsgi_gateway_socket *, struct corerouter_session *, struct sockaddr *, socklen_t);
	int (*mapper)(struct uwsgi_corerouter *, struct corerouter_session *);

        int has_sockets;
	int has_backends;
        int has_subscription_sockets;

        int processes;
        int quiet;

        struct rb_root *timeouts;

        int use_cache;
        int nevents;

	int max_retries;

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

        struct uwsgi_subscribe_slot **subscriptions;

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

struct corerouter_session {

        int fd;
        int instance_fd;

	// corerouter related to this session
	struct uwsgi_corerouter *corerouter;
	// gateway socket related to this session
	struct uwsgi_gateway_socket *ugs;

	// parsed hostname
        char *hostname;
        uint16_t hostname_len;

        int has_key;
        int connecting;

        char *instance_address;
        uint64_t instance_address_len;

        struct uwsgi_subscribe_node *un;
        struct uwsgi_string_list *static_node;
        int soopt;
        int timed_out;

        struct uwsgi_rb_timer *timeout;
        int instance_failed;

	// check content_length
        size_t post_cl;
        size_t post_remains;

        struct uwsgi_string_list *fallback;

        char *buf_file_name;
        FILE *buf_file;

        char *tmp_socket_name;

	// store the client address
	struct sockaddr_un addr;
        socklen_t addr_len;

	// async hooks:
	// the session is watiting for this fd
	ssize_t (*event_hook_read)(struct corerouter_session *);
	ssize_t (*event_hook_write)(struct corerouter_session *);
	ssize_t (*event_hook_instance_read)(struct corerouter_session *);
	ssize_t (*event_hook_instance_write)(struct corerouter_session *);

	void (*close)(struct corerouter_session *);
	int (*retry)(struct uwsgi_corerouter *, struct corerouter_session *);
	size_t retries;

	struct uwsgi_buffer *buffer;
        size_t buffer_len;
	off_t buffer_pos;

	struct uwsgi_header uh;
	
	uint8_t modifier1;
	uint8_t modifier2;
};

void uwsgi_opt_corerouter(char *, char *, void *);
void uwsgi_opt_undeferred_corerouter(char *, char *, void *);
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
int uwsgi_cr_map_use_subscription_dotsplit(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_base(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_cs(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_to(struct uwsgi_corerouter *, struct corerouter_session *);
int uwsgi_cr_map_use_static_nodes(struct uwsgi_corerouter *, struct corerouter_session *);

int uwsgi_corerouter_has_backends(struct uwsgi_corerouter *);

int uwsgi_cr_hook_read(struct corerouter_session *, ssize_t (*)(struct corerouter_session *));
int uwsgi_cr_hook_write(struct corerouter_session *, ssize_t (*)(struct corerouter_session *));
int uwsgi_cr_hook_instance_read(struct corerouter_session *, ssize_t (*)(struct corerouter_session *));
int uwsgi_cr_hook_instance_write(struct corerouter_session *, ssize_t (*)(struct corerouter_session *));
