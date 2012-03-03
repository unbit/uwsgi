struct uwsgi_fastrouter {

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
        uint64_t requests;
        struct uwsgi_fr_sctp_node *prev;
        struct uwsgi_fr_sctp_node *next;
};

struct uwsgi_fr_sctp_node *uwsgi_fr_sctp_add_node(int);
void uwsgi_opt_fastrouter_sctp(char *, char *, void *);
#endif
