/* uWSGI */

/* indent -i8 -br -brs -brf -l0 -npsl -nip -npcs -npsl -di1 */

#define UWSGI_VERSION	"0.9.7-dev"

#define UWSGI_LOGBASE "[- uWSGI -"

#define uwsgi_error(x)  uwsgi_log("%s: %s [%s line %d]\n", x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_debug(x, ...) uwsgi_log("[uWSGI DEBUG] " x, __VA_ARGS__);

#define wsgi_req_time ((wsgi_req->end_of_request.tv_sec * 1000000 + wsgi_req->end_of_request.tv_usec) - (wsgi_req->start_of_request.tv_sec * 1000000 + wsgi_req->start_of_request.tv_usec))/1000

#define ushared uwsgi.shared

#define MAX_APPS 64
#define MAX_GENERIC_PLUGINS 64
#define MAX_RPC 64

#ifndef UWSGI_LOAD_EMBEDDED_PLUGINS
#define UWSGI_LOAD_EMBEDDED_PLUGINS
#endif

#ifndef UWSGI_DECLARE_EMBEDDED_PLUGINS
#define UWSGI_DECLARE_EMBEDDED_PLUGINS
#endif

#define UDEP(pname) extern struct uwsgi_plugin pname##_plugin;

#define ULEP(pname)\
	if (pname##_plugin.request) {\
		uwsgi.p[pname##_plugin.modifier1] = &pname##_plugin;\
	}\
	else {\
		if (uwsgi.gp_cnt >= MAX_GENERIC_PLUGINS) {\
			uwsgi_log("you have embedded too much generic plugins !!!\n");\
			exit(1);\
		}\
		uwsgi.gp[uwsgi.gp_cnt] = &pname##_plugin;\
		uwsgi.gp_cnt++;\
	}\


#define fill_plugin_table(x, up)\
	if (up->request) {\
		uwsgi.p[x] = up;\
	}\
	else {\
		if (uwsgi.gp_cnt >= MAX_GENERIC_PLUGINS) {\
			uwsgi_log("you have embedded to much generic plugins !!!\n");\
			exit(1);\
		}\
		uwsgi.gp[uwsgi.gp_cnt] = up;\
		uwsgi.gp_cnt++;\
	}\




#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <unistd.h>


#include <ifaddrs.h>

#include <dirent.h>

#include <pwd.h>
#include <grp.h>


#include <sys/utsname.h>

#ifdef __linux
#include <sys/prctl.h>
#include <linux/limits.h>
#include <sys/mount.h>
extern int pivot_root(const char * new_root, const char * put_old);
#else
#include <limits.h>
#endif

#ifdef UWSGI_SCTP
#include <netinet/sctp.h>
#endif

#ifndef UWSGI_PLUGIN_BASE
#define UWSGI_PLUGIN_BASE ""
#endif

#ifdef UWSGI_ROUTING
#include <pcre.h>
#endif

#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/file.h>

#include <stdint.h>

#include <sys/wait.h>

#ifdef __APPLE__
#define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_4
#endif

#include <dlfcn.h>

#include <poll.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <fcntl.h>
#include <pthread.h>

#include <sys/resource.h>

#include <getopt.h>

#ifdef __APPLE__
#include <libkern/OSAtomic.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#endif

#ifdef UNBIT
#include "unbit.h"
#endif

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif
#ifdef __sun__
#define WAIT_ANY (-1)
#include <sys/filio.h>
#define PRIO_MAX  20
#endif

#ifdef __HAIKU__
#define WAIT_ANY (-1)
#endif

#define MAX_PYARGV 10

#include <sys/ioctl.h>

#ifdef __linux__
#include <sys/sendfile.h>
#include <sys/epoll.h>
#elif defined(__sun__)
#include <sys/sendfile.h>
#include <sys/devpoll.h>
#elif defined(__HAIKU__)
#else
#include <sys/event.h>
#endif

#ifdef __HAIKU__
#include <kernel/OS.h>
#endif

#undef _XOPEN_SOURCE

/* this value are taken from nginx */
#if defined(__APPLE__) || defined(__freebsd__)
#define UWSGI_LISTEN_QUEUE -1
#else
#define UWSGI_LISTEN_QUEUE 511
#endif

#define UWSGI_CACHE_MAX_KEY_SIZE 4071

// maintain alignment here !!!
struct uwsgi_cache_item {

	// size of the key
	uint16_t	keysize;
	// djb hash of the key
	uint32_t	djbhash;
	// size of the value (max 64KB)
	uint16_t	valsize;
	// 64bit expiration (0 for immortal)
	uint64_t	expires;
	// 64bit hits
	uint64_t	hits;
	// mark the end of the table
	char		used;
	// key chracters follows...
	char		key[UWSGI_CACHE_MAX_KEY_SIZE];
} __attribute__((__packed__));

struct uwsgi_opt {
	char *key;
	char *value;
};

#define MAX_CLUSTER_NODES	100

#define UWSGI_NODE_OK		0
#define UWSGI_NODE_FAILED	1

#define LONG_ARGS_PIDFILE		17001
#define LONG_ARGS_CHROOT		17002
#define LONG_ARGS_GID			17003
#define LONG_ARGS_UID			17004
#define LONG_ARGS_CHECK_INTERVAL	17007
#define LONG_ARGS_LIMIT_AS		17009
#define LONG_ARGS_UDP			17010
#define LONG_ARGS_WSGI_FILE             17011
#define LONG_ARGS_ERLANG		17012
#define LONG_ARGS_ERLANG_COOKIE		17013
#define LONG_ARGS_BINARY_PATH		17014
#define LONG_ARGS_PROXY			17015
#define LONG_ARGS_PROXY_NODE		17016
#define LONG_ARGS_PROXY_MAX_CONNECTIONS	17017
#define LONG_ARGS_VERSION		17018
#define LONG_ARGS_SNMP			17019
#define LONG_ARGS_SNMP_COMMUNITY	17020
#define LONG_ARGS_ASYNC			17021
#define LONG_ARGS_UGREEN_PAGES		17022
#define LONG_ARGS_FILE_CONFIG		17023
#define LONG_ARGS_MULTICAST		17024
#define LONG_ARGS_LOGTO			17025
#define LONG_ARGS_PRIO			17026
#define LONG_ARGS_POST_BUFFERING	17027
#define LONG_ARGS_POST_BUFFERING_SIZE	17028
#define LONG_ARGS_LIMIT_POST		17029
#define LONG_ARGS_HTTP			17030
#define LONG_ARGS_MODE			17031
#define LONG_ARGS_CHDIR			17032
#define LONG_ARGS_ENV			17033
#define LONG_ARGS_CHDIR2		17034
#define LONG_ARGS_INI			17035
#define LONG_ARGS_LDAP_SCHEMA		17036
#define LONG_ARGS_LDAP			17037
#define LONG_ARGS_LDAP_SCHEMA_LDIF	17038
#define LONG_ARGS_PING			17039
#define LONG_ARGS_PING_TIMEOUT		17040
#define LONG_ARGS_INI_PASTE		17041
#define LONG_ARGS_CALLABLE		17042
#define LONG_ARGS_HTTP_VAR		17043
#define LONG_ARGS_NO_DEFAULT_APP	17044
#define LONG_ARGS_EVAL_CONFIG		17045
#define LONG_ARGS_CGROUP		17046
#define LONG_ARGS_CGROUP_OPT		17047
#define LONG_ARGS_LOG_ZERO		17048
#define LONG_ARGS_LOG_SLOW		17049
#define LONG_ARGS_LOG_4xx		17050
#define LONG_ARGS_LOG_5xx		17051
#define LONG_ARGS_LOG_BIG		17052
#define LONG_ARGS_MOUNT			17053
#define LONG_ARGS_THREADS		17054
#define LONG_ARGS_LOG_SENDFILE		17055
#define LONG_ARGS_HTTP_MODIFIER1	17056
#define LONG_ARGS_PLUGINS		17057
#define LONG_ARGS_LOOP			17058
#define LONG_ARGS_VHOSTHOST		17059
#define LONG_ARGS_UPLOAD_PROGRESS	17060
#define LONG_ARGS_REMAP_MODIFIER	17061
#define LONG_ARGS_CLUSTER		17062
#define LONG_ARGS_CLUSTER_RELOAD	17063
#define LONG_ARGS_CLUSTER_LOG		17064
#define LONG_ARGS_CACHE			17065
#define LONG_ARGS_NS			17066



#define UWSGI_OK	0
#define UWSGI_AGAIN	1
#define UWSGI_ACCEPTING	2
#define UWSGI_PAUSED	3

#define UWSGI_CLEAR_STATUS		uwsgi.workers[uwsgi.mywid].status = 0

#define UWSGI_STATUS_IN_REQUEST		1 << 0
#define UWSGI_IS_IN_REQUEST		uwsgi.workers[uwsgi.mywid].status & UWSGI_STATUS_IN_REQUEST
#define UWSGI_SET_IN_REQUEST		uwsgi.workers[uwsgi.mywid].status |= UWSGI_STATUS_IN_REQUEST
#define UWSGI_UNSET_IN_REQUEST		uwsgi.workers[uwsgi.mywid].status ^= UWSGI_STATUS_IN_REQUEST

#define UWSGI_STATUS_BLOCKING		1 << 1
#define UWSGI_IS_BLOCKING		uwsgi.workers[uwsgi.mywid].status & UWSGI_STATUS_BLOCKING
#define UWSGI_SET_BLOCKING		uwsgi.workers[uwsgi.mywid].status |= UWSGI_STATUS_BLOCKING
#define UWSGI_UNSET_BLOCKING		uwsgi.workers[uwsgi.mywid].status ^= UWSGI_STATUS_BLOCKING

#define UWSGI_STATUS_LOCKING		1 << 2
#define UWSGI_IS_LOCKING		uwsgi.workers[uwsgi.mywid].status & UWSGI_STATUS_LOCKING
#define UWSGI_SET_LOCKING		uwsgi.workers[uwsgi.mywid].status |= UWSGI_STATUS_LOCKING
#define UWSGI_UNSET_LOCKING		uwsgi.workers[uwsgi.mywid].status ^= UWSGI_STATUS_LOCKING

#define UWSGI_STATUS_ERLANGING		1 << 3
#define UWSGI_IS_ERLANGING		uwsgi.workers[uwsgi.mywid].status & UWSGI_STATUS_ERLANGING
#define UWSGI_SET_ERLANGING		uwsgi.workers[uwsgi.mywid].status |= UWSGI_STATUS_ERLANGING
#define UWSGI_UNSET_ERLANGING		uwsgi.workers[uwsgi.mywid].status ^= UWSGI_STATUS_ERLANGING

#ifdef __linux__
#include <endian.h>
#elif __sun__
#include <sys/byteorder.h>
#ifdef _BIG_ENDIAN
#define __BIG_ENDIAN__ 1
#endif
#elif __APPLE__
#include <libkern/OSByteOrder.h>
#elif defined(__HAIKU__)
#else
#include <machine/endian.h>
#endif

#define UWSGI_OPTION_LOGGING		0
#define UWSGI_OPTION_MAX_REQUESTS	1
#define UWSGI_OPTION_SOCKET_TIMEOUT	2
#define UWSGI_OPTION_MEMORY_DEBUG	3
#define UWSGI_OPTION_MASTER_INTERVAL	4
#define UWSGI_OPTION_HARAKIRI		5
#define UWSGI_OPTION_CGI_MODE		6
#define UWSGI_OPTION_THREADS		7
#define UWSGI_OPTION_REAPER		8
#define UWSGI_OPTION_LOG_ZERO		9
#define UWSGI_OPTION_LOG_SLOW		10
#define UWSGI_OPTION_LOG_4xx		11
#define UWSGI_OPTION_LOG_5xx		12
#define UWSGI_OPTION_LOG_BIG		13
#define UWSGI_OPTION_LOG_SENDFILE	14

#define UWSGI_MODIFIER_ADMIN_REQUEST		10
#define UWSGI_MODIFIER_SPOOL_REQUEST		17
#define UWSGI_MODIFIER_EVAL			22
#define UWSGI_MODIFIER_FASTFUNC			26
#define UWSGI_MODIFIER_MANAGE_PATH_INFO		30
#define UWSGI_MODIFIER_MESSAGE			31
#define UWSGI_MODIFIER_MESSAGE_ARRAY		32
#define UWSGI_MODIFIER_MESSAGE_MARSHAL		33
#define UWSGI_MODIFIER_MULTICAST_ANNOUNCE	73
#define UWSGI_MODIFIER_MULTICAST		74
#define UWSGI_MODIFIER_PING			100

#define UWSGI_MODIFIER_RESPONSE		255

#define NL_SIZE 2
#define H_SEP_SIZE 2

#define UWSGI_RELOAD_CODE 17
#define UWSGI_END_CODE 30

#define MAX_VARS 64
#define MAX_LOOPS 60

struct uwsgi_loop {
	char           *name;
	void            (*loop) (void);
};

struct uwsgi_socket {
	int             fd;
	char           *name;
	int             family;
	int             bound;
	int		arg;
	void           *ctx;
};

struct wsgi_request;
struct uwsgi_server;

struct uwsgi_plugin {

        const char     *name;
        uint8_t         modifier1;
        void           *data;
        int             (*init) (void);
        void            (*post_fork) (void);
        struct option  *options;
        const char     *short_options;
        int             (*manage_opt) (int, char *);
        void            (*enable_threads) (void);
        void            (*init_thread) (int);
        int             (*request) (struct wsgi_request *);
        void            (*after_request) (struct wsgi_request *);
        void            (*init_apps) (void);
        int             (*manage_udp) (char *, int, char *, int);
        int             (*manage_xml) (char *, char *);
        void            (*suspend) (struct wsgi_request *);
        void            (*resume) (struct wsgi_request *);

        int             (*magic) (char *, char *);

	void*		(*encode_string)(char *);
	char*		(*decode_string)(void *);
	int		(*signal_handler)(uint8_t, void *, char *, uint8_t);

	uint16_t	(*rpc)(void *, uint8_t, char **, char *);

};


struct uwsgi_app {

	uint8_t         modifier1;

	char           *mountpoint;
	int             mountpoint_len;

	void           *interpreter;
	              //PyObject * pymain_dict;
	              //PyObject * wsgi_dict;
	void           *callable;


#ifdef UWSGI_ASYNC
	void          **args;
	void          **environ;
#else
	void           *args;
	void           *environ;
#endif

	void           *sendfile;

#ifdef UWSGI_ASYNC
	void           *eventfd_read;
	void           *eventfd_write;
#endif

	void           *(*request_subhandler) (struct wsgi_request *, struct uwsgi_app *);
	int             (*response_subhandler) (struct wsgi_request *);

	int             argc;
	int             requests;
	char           *chdir;

};


#ifdef UWSGI_ROUTING
struct uwsgi_route {

	const char     *mountpoint;
	const char     *callbase;

	pcre           *pattern;
	pcre_extra     *pattern_extra;
	pcre           *method;
	pcre_extra     *method_extra;

	const char     *call;

	int             modifier1;
	int             modifier2;

	void           *callable;
	void           *callable_args;
	int             args;

	void            (*action) (struct wsgi_request *, struct uwsgi_route *);
};
#endif

struct __attribute__ ((packed)) uwsgi_header {
	uint8_t         modifier1;
	uint16_t        pktsize;
	uint8_t         modifier2;
};


struct wsgi_request {
	struct uwsgi_header uh;
	              //temporary attr

	int             app_id;

	struct pollfd   poll;

	              //this is big enough to contain sockaddr_in
	struct sockaddr_un c_addr;
	int             c_len;

	              //iovec
	struct iovec   *hvec;

	struct timeval  start_of_request;
	struct timeval  end_of_request;

	char           *uri;
	uint16_t        uri_len;
	char           *remote_addr;
	uint16_t        remote_addr_len;
	char           *remote_user;
	uint16_t        remote_user_len;
	char           *query_string;
	uint16_t        query_string_len;
	char           *protocol;
	uint16_t        protocol_len;
	char           *method;
	uint16_t        method_len;
	char           *scheme;
	uint16_t        scheme_len;
	char           *https;
	uint16_t        https_len;
	char           *script_name;
	uint16_t        script_name_len;

	char           *host;
	uint16_t        host_len;

	char           *path_info;
	uint16_t        path_info_len;

	char           *script;
	uint16_t        script_len;
	char           *module;
	uint16_t        module_len;
	char           *callable;
	uint16_t        callable_len;
	char           *pyhome;
	uint16_t        pyhome_len;

	char           *file;
	uint16_t        file_len;

	char           *paste;
	uint16_t        paste_len;

	char           *chdir;
	uint16_t        chdir_len;

	int             fd_closed;

	int             sendfile_fd;
	size_t          sendfile_fd_chunk;
	size_t          sendfile_fd_size;
	off_t           sendfile_fd_pos;
	void           *sendfile_obj;

	uint16_t        var_cnt;
	uint16_t        header_cnt;

	int             status;
	size_t          response_size;
	ssize_t          headers_size;

	int             async_id;
	int             async_status;
	int             async_waiting_fd;
	int             async_waiting_fd_type;
	int             async_waiting_fd_monitored;

	int             switches;

	time_t          async_timeout;
	int             async_timeout_expired;

	void           *async_app;
	void           *async_result;
	void           *async_placeholder;
	void           *async_args;
	void           *async_environ;
	void           *async_post;
	void           *async_sendfile;

	int             async_plagued;

	int            *ovector;
	size_t          post_cl;
	char           *post_buffering_buf;
	uint64_t        post_buffering_read;

	//for generic use
	off_t buf_pos;

	char           *buffer;

	off_t frame_pos;
	int frame_len;

	int leave_open;
};

#define LOADER_DYN		0
#define LOADER_UWSGI		1
#define LOADER_FILE		2
#define LOADER_PASTE		3
#define LOADER_EVAL		4
#define LOADER_CALLABLE		5
#define LOADER_STRING_CALLABLE	6
#define LOADER_MOUNT		7

#define LOADER_MAX		8

struct uwsgi_fmon {
	char filename[0xff];
	int fd;
	int id;
	int registered;
	uint8_t sig;
};

struct uwsgi_timer {
	char svalue[0xff];
	int value;
	int fd;
	int id;
	int registered;
	uint8_t sig;
};

struct uwsgi_server {


	char		hostname[256];
	int		no_initial_output;
	int             has_threads;
	int             apps_cnt;
	int             default_app;

	int option_index;
	struct option *long_options;
	struct uwsgi_opt **exported_opts;
	int exported_opts_cnt;
	//base for all the requests(even on async mode)
	struct wsgi_request **wsgi_requests;
	struct wsgi_request *wsgi_req;

	char *remap_modifier;

	char           *chroot;
	gid_t           gid;
	uid_t           uid;

	char           *mode;

#ifdef UWSGI_HTTP
	char           *http;
	char           *http_server_name;
	char           *http_server_port;
	int             http_only;
	int             http_fd;
	char           *http_vars[64];
	int             http_vars_cnt;
	uint8_t         http_modifier1;
#endif

	int             ignore_script_name;
	int             manage_script_name;
	int             no_default_app;
	int             logdate;

#ifdef UWSGI_PROXY
	int             proxyfd;
	char           *proxy_socket_name;
	int		proxy_add_me;
#endif

	char           *logfile;

	int             vhost;
	int             vhost_host;

	struct iovec  **async_hvec;
	char          **async_buf;
	char          **async_post_buf;

#ifdef UWSGI_ROUTING
	int           **async_ovector;
#endif

	struct rlimit   rl;
	size_t          limit_post;
	int             prio;

	int             grunt;

	char           *binary_path;

	int             is_a_reload;


#ifdef UWSGI_UDP
	char           *udp_socket;
#endif

#ifdef UWSGI_MULTICAST
	char           *multicast_group;
#endif

#ifdef UWSGI_SPOOLER
	char           *spool_dir;
#endif

#ifdef UWSGI_ERLANG
	char           *erlang_node;
	char           *erlang_cookie;
#endif

#ifdef UWSGI_NAGIOS
	int             nagios;
#endif

#ifdef UWSGI_SNMP
	int             snmp;
	char           *snmp_community;
#endif


	int             to_heaven;
	int             to_hell;

	int             buffer_size;

	int             post_buffering;
	int             post_buffering_harakiri;
	int             post_buffering_bufsize;

	int             master_process;
	int		master_queue;

	int             no_defer_accept;

	int             page_size;

	char           *pidfile;

	int             numproc;
	int             async;
	int             async_running;
	int             async_queue;
	int             async_nevents;

#ifdef __linux__
	struct epoll_event *async_events;
#elif defined(__sun__)
	struct pollfd  *async_events;
#else
	struct kevent  *async_events;
#endif

	int             max_vars;
	int             vec_size;

	char           *sharedarea;
	void           *sharedareamutex;
	int             sharedareasize;

	/* the list of workers */
	struct uwsgi_worker *workers;

	pid_t           mypid;
	int             mywid;

	struct timeval  start_tv;

	int             abstract_socket;
	int             chmod_socket;
	mode_t          chmod_socket_value;
	int             listen_queue;

#ifdef UWSGI_XML
	char           *xml_config;
#endif

	char           *file_config;


#ifdef UWSGI_ROUTING
#ifndef MAX_UWSGI_ROUTES
#define MAX_UWSGI_ROUTES 64
#endif
	int             routing;
	int             nroutes;
	struct uwsgi_route routes[MAX_UWSGI_ROUTES];
#endif

#ifdef UWSGI_YAML
	char		*yaml;
#endif

#ifdef UWSGI_INI
	char           *ini;
#endif

	int             single_interpreter;

	struct uwsgi_shared *shared;

	struct uwsgi_app apps[MAX_APPS];

#ifdef UWSGI_ERLANG
	int             erlang_nodes;
	int             erlangfd;
#endif

	int             no_orphans;

	char           *chdir2;
	int             catch_exceptions;

	int             vacuum;
	int             no_server;

#ifdef UWSGI_LDAP
	char           *ldap;
#endif

	int             xml_round2;

	char           *cwd;

	int             log_slow_requests;
	int             log_zero_headers;
	int             log_empty_body;
	int             log_high_memory;

#ifdef __linux__
	char           *cgroup;
	char           *cgroup_opt[64];
	int             cgroup_opt_cnt;
	char		*ns;
#endif

	int             sockets_cnt;
	struct uwsgi_socket sockets[8];
	// leave a slot for no-orphan mode
	struct pollfd   sockets_poll[9];

	time_t          respawn_delta;

	char           *mounts[MAX_APPS];
	int             mounts_cnt;

	int             cores;
	int             threads;

	//this key old the u_request structure per core / thread
	pthread_key_t tur_key;


	struct wsgi_request *(*current_wsgi_req) (void);

	// usedby suspend/resume loops
	void (*schedule_to_main) (struct wsgi_request *);

	int close_on_exec;

	char           *loop;
	struct uwsgi_loop loops[MAX_LOOPS];
	int             loops_cnt;

	struct uwsgi_plugin *p[0xFF];
	struct uwsgi_plugin *gp[MAX_GENERIC_PLUGINS];
	int gp_cnt;

	char *upload_progress;

	char *cluster;
	int cluster_fd;
	struct sockaddr_in mc_cluster_addr;

	uint32_t 	cache_max_items;
	struct uwsgi_cache_item	*cache_items;
	void		*cache;

	void *cache_lock;
	void *user_lock;
	void *signal_table_lock;
	void *fmon_table_lock;
	void *timer_table_lock;
	void *rpc_table_lock;

};

struct uwsgi_rpc {
	char name[0xff];
	void *func;
	uint8_t args;
	uint8_t modifier1;
};

struct uwsgi_lb_group {
	char name[101];
	int kind;
};

#define KIND_NULL 0
#define KIND_WORKER 1
#define KIND_EVENT 2
#define KIND_SPOOLER 3
#define KIND_ERLANG 4
#define KIND_PROXY 5
#define KIND_MASTER 6

struct uwsgi_signal_entry {
	uint8_t kind;
	uint8_t modifier1;
	uint8_t	payload_size;
	void *handler;
	char payload[0xff];
};

struct uwsgi_lb_node {

	char            name[101];
	int		group;
	uint64_t	hits;
	time_t          last_choosen;
	
};

#define CLUSTER_NODE_STATIC	0
#define CLUSTER_NODE_DYNAMIC	1

struct uwsgi_cluster_node {
	char            name[101];

	char		nodename[0xff];

	struct sockaddr_in ucn_addr;

	int		type;

	int             workers;
	int             connections;
	int             status;

	time_t          last_seen;
	int             errors;

	time_t          last_choosen;

	int             requests;
	
};

#ifdef UWSGI_SNMP
struct uwsgi_snmp_custom_value {
	uint8_t         type;
	uint64_t        val;
};

struct uwsgi_snmp_server_value {
	uint8_t         type;
	uint64_t       *val;
};
#endif

struct uwsgi_shared {

	//vga 80 x25 specific !
	char            warning_message[81];

	uint32_t        options[0xFF];

	struct uwsgi_cluster_node nodes[MAX_CLUSTER_NODES];

	off_t           logsize;

#ifdef UWSGI_SPOOLER
	pid_t           spooler_pid;
	int             spooler_frequency;
#endif

#ifdef UWSGI_PROXY
	pid_t           proxy_pid;
#endif

#ifdef UWSGI_SNMP
	char            snmp_community[72 + 1];
	struct uwsgi_snmp_server_value snmp_gvalue[100];
	struct uwsgi_snmp_custom_value snmp_value[100];

#define SNMP_COUNTER32 0x41
#define SNMP_GAUGE 0x42
#define SNMP_COUNTER64 0x46

#endif

	uint16_t	cache_first_available_item;
	uint16_t	cache_first_available_item_tmp;


	int		worker_signal_pipe[2];
	struct uwsgi_signal_entry signal_table[0xff];

	struct uwsgi_fmon files_monitored[64];
	int files_monitored_cnt;

	struct uwsgi_timer timers[64];
	int timers_cnt;

	struct uwsgi_rpc rpc_table[MAX_RPC];
	int rpc_count;
};

struct uwsgi_core {

	int             id;
	int             worker_id;

	time_t          harakiri;

	uint64_t        requests;
	uint64_t        failed_requests;

	              //multiple ts per - core are needed only with multiple_interpreter + threads
	void           *ts[MAX_APPS];

};

struct uwsgi_worker {
	int             id;
	pid_t           pid;
	uint64_t        status;

	time_t          last_spawn;
	uint64_t        respawn_count;

	uint64_t        requests;
	uint64_t        failed_requests;

	time_t          harakiri;

	uint64_t        vsz_size;
	uint64_t        rss_size;

	double          running_time;
	double          last_running_time;

	int             manage_next_request;

	struct uwsgi_core **cores;

};

char           *uwsgi_get_cwd(void);

void            warn_pipe(void);
void            what_i_am_doing(void);
void            goodbye_cruel_world(void);
void            gracefully_kill(void);
void            reap_them_all(void);
void            kill_them_all(void);
void            grace_them_all(void);
void            reload_me(void);
void            end_me(void);
int             bind_to_unix(char *, int, int, int);
int             bind_to_tcp(char *, int, char *);
int             bind_to_udp(char *, int);
int             timed_connect(struct pollfd *, const struct sockaddr *, int, int, int);
int             uwsgi_connect(char *, int, int);
int             connect_to_tcp(char *, int, int, int);
int             connect_to_unix(char *, int, int);
#ifdef UWSGI_SCTP
int             bind_to_sctp(char *, int, char *);
#endif

void            daemonize(char *);
void            logto(char *);

void            log_request(struct wsgi_request *);
void            get_memusage(void);
void            harakiri(void);

void            stats(void);

#ifdef UWSGI_XML
void            uwsgi_xml_config(struct wsgi_request *, int);
#endif

void            internal_server_error(int, char *);

#ifdef UWSGI_SNMP
void            manage_snmp(int, uint8_t *, int, struct sockaddr_in *);
void            snmp_init(void);
#endif

#ifdef UWSGI_SPOOLER
int             spool_request(char *, int, char *, int);
void            spooler(void);
pid_t           spooler_start(void);
#endif

void            set_harakiri(int);
void            inc_harakiri(int);

#ifdef __BIG_ENDIAN__
uint16_t        uwsgi_swap16(uint16_t);
uint32_t        uwsgi_swap32(uint32_t);
uint64_t        uwsgi_swap64(uint64_t);
#endif

#ifdef UWSGI_UDP
ssize_t         send_udp_message(uint8_t, char *, char *, uint16_t);
#endif

int             uwsgi_parse_response(struct pollfd *, int, struct uwsgi_header *, char *);
int             uwsgi_parse_vars(struct wsgi_request *);

int             uwsgi_enqueue_message(char *, int, uint8_t, uint8_t, char *, int, int);

#ifdef UWSGI_ERLANG

#include <erl_interface.h>
#include <ei.h>

int             init_erlang(char *, char *);
void            erlang_loop(struct wsgi_request *);

#endif

void            manage_opt(int, char *);

#ifdef UWSGI_PROXY
void            uwsgi_proxy(int);
pid_t           proxy_start(int);
#endif

void            uwsgi_cluster_add_node(struct uwsgi_cluster_node *, int);
void            uwsgi_cluster_simple_add_node(char *, int, int);
int             uwsgi_ping_node(int, struct wsgi_request *);

struct http_status_codes {
	const char      key[3];
	const char     *message;
	int             message_size;
};

#ifdef UWSGI_ASYNC
struct wsgi_request *async_loop(void);
struct wsgi_request *find_first_available_wsgi_req(void);
struct wsgi_request *find_first_accepting_wsgi_req(void);
struct wsgi_request *find_wsgi_req_by_fd(int, int);
struct wsgi_request *find_wsgi_req_by_id(int);

#ifdef __clang__
struct wsgi_request *next_wsgi_req(struct wsgi_request *);
#else
inline struct wsgi_request *next_wsgi_req(struct wsgi_request *);
#endif


int             async_add(int, int, int);
int             async_mod(int, int, int);
int             async_wait(int, void *, int, int, int);
int             async_del(int, int, int);
int             async_queue_init(int);

int             async_get_timeout(void);
void            async_set_timeout(struct wsgi_request *, time_t);
void            async_expire_timeouts(void);
void            async_write_all(char *, size_t);
void            async_unpause_all(void);

#ifdef __linux__
#define ASYNC_FD data.fd
#define ASYNC_EV events
#define ASYNC_IN EPOLLIN
#define ASYNC_OUT EPOLLOUT
#define ASYNC_IS_IN ASYNC_EV & ASYNC_IN
#define ASYNC_IS_OUT ASYNC_EV & ASYNC_OUT
#elif defined(__sun__)
#define ASYNC_FD fd
#define ASYNC_EV revents
#define ASYNC_IN POLLIN
#define ASYNC_OUT POLLOUT
#define ASYNC_IS_IN ASYNC_EV & ASYNC_IN
#define ASYNC_IS_OUT ASYNC_EV & ASYNC_OUT
#else
#define ASYNC_FD ident
#define ASYNC_EV filter
#define ASYNC_IN EVFILT_READ
#define ASYNC_OUT EVFILT_WRITE
#define ASYNC_IS_IN ASYNC_EV == ASYNC_IN
#define ASYNC_IS_OUT ASYNC_EV == ASYNC_OUT
#endif

#endif

void            uwsgi_as_root(void);

#ifdef UWSGI_NAGIOS
void            nagios(void);
#endif

void            uwsgi_close_request(struct wsgi_request *);

void            wsgi_req_setup(struct wsgi_request *, int);
int             wsgi_req_recv(struct wsgi_request *);
int             wsgi_req_accept(struct wsgi_request *);
int             wsgi_req_simple_accept(struct wsgi_request *, int);

#ifdef UWSGI_STACKLESS
#ifdef __clang__
struct wsgi_request *current_wsgi_req(void);
#else
inline struct wsgi_request *current_wsgi_req(void);
#endif
#else
#define current_wsgi_req() (*uwsgi.current_wsgi_req)()
#endif

void            sanitize_args(void);

void            env_to_arg(char *, char *);
void            parse_sys_envs(char **);

void            uwsgi_log(const char *,...);
void            uwsgi_log_verbose(const char *,...);


int             uwsgi_load_plugin(int, char *, char *, int);
void            embed_plugins(void);


void            http_loop(void);

int             unconfigured_hook(struct wsgi_request *);

#ifdef UWSGI_INI
void            uwsgi_ini_config(char *);
#endif

#ifdef UWSGI_YAML
void            uwsgi_yaml_config(char *);
#endif


#ifdef UWSGI_LDAP
void            uwsgi_ldap_schema_dump(void);
void            uwsgi_ldap_schema_dump_ldif(void);
void            uwsgi_ldap_config(void);
#endif

#ifdef __clang__
int             uwsgi_strncmp(char *, int, char *, int);
int             uwsgi_startswith(char *, char *, int);
#else
inline int      uwsgi_strncmp(char *, int, char *, int);
inline int      uwsgi_startswith(char *, char *, int);
#endif


char           *uwsgi_concat(int,...);
char           *uwsgi_concatn(int,...);
char           *uwsgi_concat2(char *, char *);
char           *uwsgi_concat2n(char *, int, char *, int);
char           *uwsgi_concat3(char *, char *, char *);
char           *uwsgi_concat3n(char *, int, char *, int, char *, int);
char           *uwsgi_concat4(char *, char *, char *, char *);
char           *uwsgi_concat4n(char *, int, char *, int, char *, int, char *, int);


int             uwsgi_get_app_id(char *, int);
char           *uwsgi_strncopy(char *, int);

void            master_loop(char **, char **);


int             find_worker_id(pid_t);


void           *simple_loop(void *);
void            complex_loop(void);

int             count_options(struct option *);

#ifdef UWSGI_SENDFILE
ssize_t         uwsgi_do_sendfile(int, int, size_t, size_t, off_t *, int);
#endif

struct wsgi_request *simple_current_wsgi_req(void);
struct wsgi_request *threaded_current_wsgi_req(void);

void            build_options(void);

int             uwsgi_read_whole_body(struct wsgi_request *, char *, size_t);

ssize_t         uwsgi_sendfile(struct wsgi_request *);

void            uwsgi_register_loop(char *, void *);
void           *uwsgi_get_loop(char *);

void add_exported_option(int, char *);

ssize_t uwsgi_send_empty_pkt(int , char *, uint8_t , uint8_t);

int uwsgi_waitfd(int, int);

int uwsgi_hooked_parse_dict_dgram(int, char *, size_t, uint8_t, uint8_t, void (*)(char *, uint16_t, char *, uint16_t, void*), void *);
int uwsgi_hooked_parse(char *, size_t, void (*)(char *, uint16_t, char *, uint16_t, void *), void *);
void manage_string_opt(char *, uint16_t, char*, uint16_t, void *);

int uwsgi_get_dgram(int, struct wsgi_request *);

int uwsgi_cluster_join(char *);

int uwsgi_string_sendto(int, uint8_t, uint8_t, struct sockaddr *, socklen_t, char *, size_t);

void uwsgi_stdin_sendto(char *, uint8_t, uint8_t);

int uwsgi_cluster_add_me(void);

char *generate_socket_name(char *);

#define UMIN(a,b) ((a)>(b)?(b):(a))

ssize_t uwsgi_send_message(int, uint8_t, uint8_t, char *, uint16_t, int, size_t, int);

char *uwsgi_cluster_best_node(void);

int uwsgi_cache_set(char *, uint16_t, char *, uint16_t, uint64_t);
int uwsgi_cache_del(char *, uint16_t);
char *uwsgi_cache_get(char *, uint16_t, uint16_t *);
uint32_t uwsgi_cache_exists(char *, uint16_t);

void uwsgi_lock_init(void *);
void uwsgi_lock(void *);
void uwsgi_unlock(void *);

inline void *uwsgi_malloc(size_t);


int event_queue_init(void);
int event_queue_add_fd_read(int, int);
int event_queue_wait(int, int, int *);

int event_queue_add_timer(int, int *, int);
struct uwsgi_timer *event_queue_ack_timer(int);

int event_queue_add_file_monitor(int, char *, int *);
struct uwsgi_fmon *event_queue_ack_file_monitor(int, int);


void *uwsgi_mmap_shared_lock(void);

void uwsgi_register_signal(uint8_t, uint8_t, void *, uint8_t, char *, uint8_t);
void uwsgi_register_file_monitor(uint8_t, char *, uint8_t, void *, uint8_t);
void uwsgi_register_timer(uint8_t, int, uint8_t, void *, uint8_t);
int uwsgi_signal_handler(uint8_t);

void uwsgi_route_signal(uint8_t);

int uwsgi_start(void *);

int uwsgi_register_rpc(char *, uint8_t, uint8_t, void *);
uint16_t uwsgi_rpc(char *, uint8_t, char **, char *);
