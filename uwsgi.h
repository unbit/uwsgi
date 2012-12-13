/* uWSGI */

/* indent -i8 -br -brs -brf -l0 -npsl -nip -npcs -npsl -di1 -il0 */

#ifdef __cplusplus
extern "C" {
#endif

#define UMAX16	65536

#define UMAX64_STR "18446744073709551616"

#define uwsgi_error(x)  uwsgi_log("%s: %s [%s line %d]\n", x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_error_realpath(x)  uwsgi_log("realpath() of %s failed: %s [%s line %d]\n", x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_log_safe(x)  if (uwsgi.original_log_fd != 2) dup2(uwsgi.original_log_fd, 2) ; uwsgi_log(x);
#define uwsgi_error_safe(x)  if (uwsgi.original_log_fd != 2) dup2(uwsgi.original_log_fd, 2) ; uwsgi_log("%s: %s [%s line %d]\n", x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_log_initial if (!uwsgi.no_initial_output) uwsgi_log
#ifdef UWSGI_ALARM
#define uwsgi_log_alarm(x, ...) uwsgi_log("[uwsgi-alarm" x, __VA_ARGS__)
#endif
#define uwsgi_fatal_error(x) uwsgi_error(x); exit(1);
#define uwsgi_error_open(x)  uwsgi_log("open(\"%s\"): %s [%s line %d]\n", x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_req_error(x)  if (wsgi_req->uri_len > 0 && wsgi_req->method_len > 0 && wsgi_req->remote_addr_len > 0) uwsgi_log_verbose("%s: %s [%s line %d] during %.*s %.*s (%.*s)\n", x, strerror(errno), __FILE__, __LINE__,\
				wsgi_req->method_len, wsgi_req->method, wsgi_req->uri_len, wsgi_req->uri, wsgi_req->remote_addr_len, wsgi_req->remote_addr); else uwsgi_log_verbose("%s %s [%s line %d] \n",x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_debug(x, ...) uwsgi_log("[uWSGI DEBUG] " x, __VA_ARGS__);
#define uwsgi_rawlog(x) if (write(2, x, strlen(x)) != strlen(x)) uwsgi_error("write()")
#define uwsgi_str(x) uwsgi_concat2(x, (char *)"")

#define uwsgi_notify(x) if (uwsgi.notify) uwsgi.notify(x)
#define uwsgi_notify_ready() uwsgi.shared->ready = 1 ; if (uwsgi.notify_ready) uwsgi.notify_ready()

#define uwsgi_apps uwsgi.workers[uwsgi.mywid].apps
#define uwsgi_apps_cnt uwsgi.workers[uwsgi.mywid].apps_cnt

#define wsgi_req_time ((wsgi_req->end_of_request-wsgi_req->start_of_request)/1000)

#define thunder_lock if (uwsgi.threads > 1 && !uwsgi.is_et) {pthread_mutex_lock(&uwsgi.thunder_mutex);}
#define thunder_unlock if (uwsgi.threads > 1 && !uwsgi.is_et) {pthread_mutex_unlock(&uwsgi.thunder_mutex);}

#define uwsgi_check_scheme(file) (!uwsgi_startswith(file, "emperor://", 10) || !uwsgi_startswith(file, "http://", 7) || !uwsgi_startswith(file, "data://", 7) || !uwsgi_startswith(file, "sym://", 6) || !uwsgi_startswith(file, "fd://", 5) || !uwsgi_startswith(file, "exec://", 7) || !uwsgi_startswith(file, "section://", 10))

#define ushared uwsgi.shared

#define UWSGI_OPT_IMMEDIATE		(1 << 0)
#define UWSGI_OPT_MASTER		(1 << 1)
#define UWSGI_OPT_LOG_MASTER		(1 << 2)
#define UWSGI_OPT_THREADS		(1 << 3)
#define UWSGI_OPT_CHEAPER		(1 << 4)
#define UWSGI_OPT_VHOST			(1 << 5)
#define UWSGI_OPT_MEMORY		(1 << 6)
#define UWSGI_OPT_PROCNAME		(1 << 7)
#define UWSGI_OPT_LAZY			(1 << 8)
#define UWSGI_OPT_NO_INITIAL		(1 << 9)
#define UWSGI_OPT_NO_SERVER		(1 << 10)
#define UWSGI_OPT_POST_BUFFERING	(1 << 11)
#define UWSGI_OPT_CLUSTER		(1 << 12)
#define UWSGI_OPT_MIME			(1 << 13)

#define MAX_GENERIC_PLUGINS 64
#define MAX_RPC 64
#define MAX_GATEWAYS 64
#define MAX_TIMERS 64
#define MAX_PROBES 64
#define MAX_CRONS 64

#ifndef UWSGI_LOAD_EMBEDDED_PLUGINS
#define UWSGI_LOAD_EMBEDDED_PLUGINS
#endif

#ifndef UWSGI_DECLARE_EMBEDDED_PLUGINS
#define UWSGI_DECLARE_EMBEDDED_PLUGINS
#endif

#ifdef UWSGI_EMBED_CONFIG
extern char UWSGI_EMBED_CONFIG;
extern char UWSGI_EMBED_CONFIG_END;
#endif

#define UDEP(pname) extern struct uwsgi_plugin pname##_plugin;

#define ULEP(pname)\
	if (pname##_plugin.request) {\
		uwsgi.p[pname##_plugin.modifier1] = &pname##_plugin;\
		if (uwsgi.p[pname##_plugin.modifier1]->on_load)\
			uwsgi.p[pname##_plugin.modifier1]->on_load();\
	}\
	else {\
		if (uwsgi.gp_cnt >= MAX_GENERIC_PLUGINS) {\
			uwsgi_log("you have embedded too much generic plugins !!!\n");\
			exit(1);\
		}\
		uwsgi.gp[uwsgi.gp_cnt] = &pname##_plugin;\
		if (uwsgi.gp[uwsgi.gp_cnt]->on_load)\
			uwsgi.gp[uwsgi.gp_cnt]->on_load();\
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



#ifndef __need_IOV_MAX 
#define __need_IOV_MAX 
#endif 


#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <math.h>

#include <sys/types.h>
#ifdef __linux__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif
#endif
#include <sys/socket.h>
#ifdef __linux__
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN   0x20000000
#endif
#endif
#undef _GNU_SOURCE
#include <netinet/in.h>

#include <termios.h>

#ifdef UWSGI_UUID
#include <uuid/uuid.h>
#endif

#ifdef __sun__
#define _XPG4_2
#define __EXTENSIONS__
#endif

#include <string.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#ifdef __linux__
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif
#endif
#include <netdb.h>

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/cpuset.h>
#endif

#include <sys/ipc.h>
#include <sys/sem.h>

#include <stdarg.h>
#include <errno.h>
#ifndef __USE_ISOC99
#define __USE_ISOC99
#endif
#include <ctype.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef UWSGI_HAS_IFADDRS
#include <ifaddrs.h>
#endif


#include <pwd.h>
#include <grp.h>


#include <sys/utsname.h>


#ifdef __linux__


#include <sched.h>
#include <sys/prctl.h>
#include <linux/limits.h>
#include <sys/mount.h>
#ifdef UWSGI_PTRACE
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>
#endif
extern int pivot_root(const char *new_root, const char *put_old);
#endif

#include <limits.h>

#include <dirent.h>

#ifndef UWSGI_PLUGIN_BASE
#define UWSGI_PLUGIN_BASE ""
#endif

#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/file.h>

#include <stdint.h>

#include <sys/wait.h>

#ifdef __APPLE__
#define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_4
#include <mach-o/dyld.h>
#endif

#include <dlfcn.h>

#include <poll.h>
#include <sys/uio.h>
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

#ifdef UWSGI_CAP
#include <sys/capability.h>
#endif

#ifdef __HAIKU__
#include <kernel/OS.h>
#endif

#undef _XOPEN_SOURCE
#ifdef __sun__
#undef __EXTENSIONS__
#endif

#ifdef UWSGI_ZEROMQ
#include <zmq.h>
#endif

#define UWSGI_CACHE_MAX_KEY_SIZE 2048
#define UWSGI_CACHE_FLAG_UNGETTABLE	0x0001
#define UWSGI_CACHE_FLAG_UPDATE		0x0002
#define UWSGI_CACHE_FLAG_LOCAL		0x0004
#define UWSGI_CACHE_FLAG_ABSEXPIRE	0x0008

#define uwsgi_cache_update_start(x, y, z) uwsgi_cache_set(x, y, "", 0, CACHE_FLAG_UNGETTABLE)

#ifdef UWSGI_SSL
#include "openssl/conf.h"
#include "openssl/ssl.h"
#include <openssl/err.h>
#endif


struct uwsgi_buffer {
	char *buf;
	off_t pos;
	size_t len;
	size_t limit;
};

struct uwsgi_string_list {

	char *value;
	size_t len;
	uint64_t custom;
	uint64_t custom2;
	void *custom_ptr;
	struct uwsgi_string_list *next;
};

struct uwsgi_custom_option {

	char *name;
	char *value;
	int has_args;
	struct uwsgi_custom_option *next;
};

struct uwsgi_lock_item {
	char *id;
	void *lock_ptr;
	int rw;
	pid_t pid;
	int can_deadlock;
	struct uwsgi_lock_item *next;
};


struct uwsgi_lock_ops {
	struct uwsgi_lock_item* (*lock_init)(char *);
	pid_t (*lock_check)(struct uwsgi_lock_item *);
	void (*lock)(struct uwsgi_lock_item *);
	void (*unlock)(struct uwsgi_lock_item *);

	struct uwsgi_lock_item * (*rwlock_init)(char *);
	pid_t (*rwlock_check)(struct uwsgi_lock_item *);
	void (*rlock)(struct uwsgi_lock_item *);
	void (*wlock)(struct uwsgi_lock_item *);
	void (*rwunlock)(struct uwsgi_lock_item *);
};

#define uwsgi_lock_init(x) uwsgi.lock_ops.lock_init(x)
#define uwsgi_lock_check(x) uwsgi.lock_ops.lock_check(x)
#define uwsgi_lock(x) uwsgi.lock_ops.lock(x)
#define uwsgi_unlock(x) uwsgi.lock_ops.unlock(x)

#define uwsgi_rwlock_init(x) uwsgi.lock_ops.rwlock_init(x)
#define uwsgi_rwlock_check(x) uwsgi.lock_ops.rwlock_check(x)
#define uwsgi_rlock(x) uwsgi.lock_ops.rlock(x)
#define uwsgi_wlock(x) uwsgi.lock_ops.wlock(x)
#define uwsgi_rwunlock(x) uwsgi.lock_ops.rwunlock(x)

#ifdef UWSGI_PCRE
#include <pcre.h>
#endif

#ifdef UWSGI_MATHEVAL
#include <matheval.h>
#endif

struct uwsgi_dyn_dict {

	char *key;
	int keylen;
	char *value;
	int vallen;

	uint64_t hits;
	int status;

#ifdef UWSGI_PCRE
	pcre *pattern;
        pcre_extra *pattern_extra;
#endif

	struct uwsgi_dyn_dict *prev;
	struct uwsgi_dyn_dict *next;
};

#ifdef UWSGI_PCRE
struct uwsgi_regexp_list {

	pcre *pattern;
        pcre_extra *pattern_extra;

        uint64_t custom;
	char *custom_str;
	void *custom_ptr;
        struct uwsgi_regexp_list *next;
};
#endif


union uwsgi_sockaddr {
	struct sockaddr sa;
	struct sockaddr_in sa_in;
	struct sockaddr_un sa_un;
#ifdef UWSGI_IPV6
	struct sockaddr_in6 sa_in6;
#endif
};

union uwsgi_sockaddr_ptr {
	struct sockaddr *sa;
	struct sockaddr_in *sa_in;
	struct sockaddr_un *sa_un;
#ifdef UWSGI_IPV6
	struct sockaddr_in6 *sa_in6;
#endif
};

// Gateways are processes (managed by the master) that extends the
// server core features
// -- Gateways can prefork or spawn threads --

struct uwsgi_gateway {

	char *name;
	char *fullname;
	void (*loop) (int, void *);
	pid_t pid;
	int num;
	int use_signals;

	int internal_subscription_pipe[2];
	uint64_t respawns;
	
	void *data;
};

struct uwsgi_gateway_socket {

        char *name;
	size_t name_len;
        int fd;
        char *zerg;

	char *port;
	int port_len;

	int no_defer;

	void *data;
	// this requires UDP
	int subscription;
	int shared;

	char *owner;
	struct uwsgi_gateway *gateway;

        struct uwsgi_gateway_socket *next;

	// could be useful for ssl
	void *ctx;
	// could be useful ofr plugins
	int mode;
	
};



// Daemons are external processes maintained by the master

struct uwsgi_daemon {
	char *command;
	pid_t pid;
	uint64_t respawns;
	time_t born;
	time_t last_spawn;
	int status;
	int registered;


	char *pidfile;
	int daemonize;

	// this is incremented every time a pidfile is not found
	uint64_t pidfile_checks;
	// frequency of pidfile checks (default 10 secs)
	int freq;

	struct uwsgi_daemon *next;
};

struct uwsgi_logger {
	char *name;
	char *id;
	ssize_t (*func)(struct uwsgi_logger *, char *, size_t);
	int configured;
	int fd;
	void *data;
	union uwsgi_sockaddr addr;
	socklen_t addr_len;
	int count;
	struct msghdr msg;
	// used by choosen logger
	char *arg;
	struct uwsgi_logger *next;
};

#ifdef UWSGI_SSL
struct uwsgi_legion {
        char *legion;
        uint16_t legion_len;
        uint64_t valor;
        char *addr;
        time_t lord;
	time_t last_seen_lord;
	char *name;
	uint16_t name_len;
	pid_t pid;
        int socket;
	EVP_CIPHER_CTX *encrypt_ctx;
	EVP_CIPHER_CTX *decrypt_ctx;
        struct uwsgi_string_list *nodes;
        struct uwsgi_string_list *lord_hooks;
        struct uwsgi_string_list *unlord_hooks;
        struct uwsgi_string_list *setup_hooks;
        struct uwsgi_string_list *death_hooks;
        struct uwsgi_legion *next;
};

struct uwsgi_legion_action {
        char *name;
        int (*func)(struct uwsgi_legion *, char *);
        struct uwsgi_legion_action *next;
};
#endif

struct uwsgi_queue_header {
	uint64_t pos;
	uint64_t pull_pos;
};

struct uwsgi_queue_item {
	uint64_t size;
	time_t ts;
};

// maintain alignment here !!!
struct uwsgi_cache_item {
	// unused
	uint16_t flags;
	// size of the key
	uint16_t keysize;
	// djb hash of the key
	uint32_t djbhash;
	// size of the value (64bit)
	uint64_t valsize;
	// 64bit expiration (0 for immortal)
	uint64_t expires;
	// 64bit hits
	uint64_t hits;
	// previous same-hash item
	uint64_t prev;
	// next same-hash item
	uint64_t next;
	// key chracters follows...
	char key[UWSGI_CACHE_MAX_KEY_SIZE];
} __attribute__ ((__packed__));

struct uwsgi_option {
	char *name;
	int type;
	int shortcut;
	char *help;
	void (*func)(char *, char *, void *);
	void *data;
	uint64_t flags;
};

struct uwsgi_opt {
	char *key;
	char *value;
	int configured;
};

#define MAX_CLUSTER_NODES	100

#define UWSGI_NODE_OK		0
#define UWSGI_NODE_FAILED	1

#define UWSGI_OK	0
#define UWSGI_AGAIN	1
#define UWSGI_ACCEPTING	2
#define UWSGI_PAUSED	3

#ifdef __linux__
#include <endian.h>
#elif defined(__sun__)
#include <sys/byteorder.h>
#ifdef _BIG_ENDIAN
#define __BIG_ENDIAN__ 1
#endif
#elif defined(__APPLE__)
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
#define UWSGI_OPTION_BACKLOG_STATUS	15
#define UWSGI_OPTION_BACKLOG_ERRORS	16
#define UWSGI_OPTION_SPOOLER_HARAKIRI   17
#define UWSGI_OPTION_MULE_HARAKIRI	18

#define UWSGI_SPOOLER_EXTERNAL	1

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
#define UWSGI_EXILE_CODE 26
#define UWSGI_FAILED_APP_CODE 22
#define UWSGI_DE_HIJACKED_CODE 173
#define UWSGI_EXCEPTION_CODE 5
#define UWSGI_QUIET_CODE 29

#define MAX_VARS 64

struct uwsgi_loop {
	char *name;
	void (*loop) (void);
	struct uwsgi_loop *next;
};

struct wsgi_request;

struct uwsgi_socket {
	int fd;
	char *name;
	int name_len;
	int family;
	int bound;
	int arg;
	void *ctx;

	int queue;
	int no_defer;

	int auto_port;
	// true if connection must be initialized for each core
	int per_core;

	char *proto_name;

	int (*proto) (struct wsgi_request *);
	int (*proto_accept) (struct wsgi_request *, int);
	 ssize_t(*proto_write) (struct wsgi_request *, char *, size_t);
	 ssize_t(*proto_writev) (struct wsgi_request *, struct iovec *, size_t);
	 ssize_t(*proto_write_header) (struct wsgi_request *, char *, size_t);
	 ssize_t(*proto_writev_header) (struct wsgi_request *, struct iovec *, size_t);
	 ssize_t(*proto_sendfile) (struct wsgi_request *);
	 ssize_t(*proto_read_body) (struct wsgi_request *, char *, size_t);
	void (*proto_close) (struct wsgi_request *);
	void (*proto_thread_fixup) (struct uwsgi_socket *, int);
	int edge_trigger;

	int *retry;

	int can_offload;

	// this is a special map for having socket->thread mapping
	int *fd_threads;

#ifdef UWSGI_UUID
	char uuid[37];
#endif

	// currently used by zeromq handlers
	void *pub;
	void *pull;
	pthread_key_t key;

	pthread_mutex_t lock;

	char *receiver;

	int disabled;
	int recv_flag;

	struct uwsgi_socket *next;
	int lazy;
	int shared;
	int from_shared;
};

struct uwsgi_server;

struct uwsgi_plugin {

	const char *name;
	const char *alias;
	uint8_t modifier1;
	void *data;
	void (*on_load) (void);
	int (*init) (void);
	void (*post_init) (void);
	void (*post_fork) (void);
	struct uwsgi_option *options;
	void (*enable_threads) (void);
	void (*init_thread) (int);
	int (*request) (struct wsgi_request *);
	void (*after_request) (struct wsgi_request *);
	void (*preinit_apps) (void);
	void (*init_apps) (void);
	void (*postinit_apps) (void);
	void (*fixup) (void);
	void (*master_fixup) (int);
	void (*master_cycle) (void);
	int (*mount_app) (char *, char *);
	int (*manage_udp) (char *, int, char *, int);
	void (*suspend) (struct wsgi_request *);
	void (*resume) (struct wsgi_request *);

	void (*harakiri) (int);

	void (*hijack_worker) (void);
	void (*spooler_init) (void);
	void (*atexit) (void);

	int (*magic) (char *, char *);

	void *(*encode_string) (char *);
	char *(*decode_string) (void *);
	int (*signal_handler) (uint8_t, void *);
	char *(*code_string) (char *, char *, char *, char *, uint16_t);

	int (*spooler) (char *, char *, uint16_t, char *, size_t);

	uint16_t(*rpc) (void *, uint8_t, char **, uint16_t *, char *);

	void (*jail) (int (*)(void *), char **);
	void (*before_privileges_drop)(void);

	int (*mule)(char *);
	int (*mule_msg)(char *, size_t);

	void (*master_cleanup) (void);

};

#ifdef UWSGI_PCRE
int uwsgi_regexp_build(char *, pcre **, pcre_extra **);
int uwsgi_regexp_match(pcre *, pcre_extra *, char *, int);
int uwsgi_regexp_match_ovec(pcre *, pcre_extra *, char *, int, int *, int);
int uwsgi_regexp_ovector(pcre *, pcre_extra *);
char *uwsgi_regexp_apply_ovec(char *, int, char *, int, int *, int);
#endif



struct uwsgi_app {

	uint8_t modifier1;

	char mountpoint[0xff];
	int mountpoint_len;

	void *interpreter;
	void *callable;

#ifdef UWSGI_ASYNC
	void **args;
	void **environ;
#else
	void *args;
	void *environ;
#endif

	void *sendfile;
	void *input;
	void *error;
	void *stream;
	void *responder0;
	void *responder1;
	void *responder2;

#ifdef UWSGI_ASYNC
	void *eventfd_read;
	void *eventfd_write;
#endif

	void *(*request_subhandler) (struct wsgi_request *, struct uwsgi_app *);
	int (*response_subhandler) (struct wsgi_request *);

	int argc;
	uint64_t requests;
	uint64_t exceptions;

	char chdir[0xff];
	char touch_reload[0xff];

	time_t touch_reload_mtime;

	void *gateway_version;
        void *uwsgi_version;
        void *uwsgi_node;

	time_t started_at;
	time_t startup_time;

	uint64_t avg_response_time;
};

struct uwsgi_spooler {

	char dir[PATH_MAX];
	pid_t pid;
	uint64_t respawned;
	uint64_t tasks;
	struct uwsgi_lock_item *lock;
	time_t harakiri;

	int mode;

	int running;

	int signal_pipe[2];

	struct uwsgi_spooler *next;
};

#ifdef UWSGI_ROUTING

#define UWSGI_ROUTE_NEXT 0
#define UWSGI_ROUTE_CONTINUE 1
#define UWSGI_ROUTE_BREAK 2

struct uwsgi_route {

	pcre *pattern;
	pcre_extra *pattern_extra;
	int ovn;
	int *ovector;

	size_t subject;
	size_t subject_len;

	int (*func)(struct wsgi_request *, struct uwsgi_route *);

	void *data;
	size_t data_len;

	void *data2;
	size_t data2_len;

	void *data3;
	size_t data3_len;

	// 64bit value for custom usage
	uint64_t custom;

	// true ifthis is the last rule of this kind
	int is_last;

	struct uwsgi_route *next;

};

struct uwsgi_router {

	char *name;
	int (*func)(struct uwsgi_route *, char *);
	struct uwsgi_router *next;

};

#endif

#ifdef UWSGI_ALARM
struct uwsgi_alarm;
struct uwsgi_alarm_instance {
	char *name;
	char *arg;
	void *data_ptr;
	uint8_t data8;
	uint16_t data16;
	uint32_t data32;
	uint64_t data64;

	time_t last_run;

	char *last_msg;
	size_t last_msg_size;

	struct uwsgi_alarm *alarm;
	struct uwsgi_alarm_instance *next;
};

struct uwsgi_alarm {
	char *name;
	void (*init)(struct uwsgi_alarm_instance *);
	void (*func)(struct uwsgi_alarm_instance *, char *, size_t);
	struct uwsgi_alarm *next;
};

struct uwsgi_alarm_ll {
	struct uwsgi_alarm_instance *alarm;
	struct uwsgi_alarm_ll *next;
};

struct uwsgi_alarm_log {
	pcre *pattern;
        pcre_extra *pattern_extra;
	int negate;
	struct uwsgi_alarm_ll *alarms;
	struct uwsgi_alarm_log *next;
};
#endif

struct __attribute__ ((packed)) uwsgi_header {
	uint8_t modifier1;
	uint16_t pktsize;
	uint8_t modifier2;
};

struct uwsgi_async_fd {
	int fd;
	int event;
	struct uwsgi_async_fd *prev;
	struct uwsgi_async_fd *next;
};

struct uwsgi_logvar {
	char key[256];
	uint8_t keylen;
	char val[256];
	uint8_t vallen;
	struct uwsgi_logvar *next;
};


struct wsgi_request {
	struct uwsgi_header uh;
	//temporary attr

	int app_id;
	int dynamic;
	int parsed;

	char *appid;
	uint16_t appid_len;

	struct pollfd poll;

	//this is big enough to contain sockaddr_in
	struct sockaddr_un c_addr;
	int c_len;

	//iovec
	struct iovec *hvec;

	uint64_t start_of_request;
	uint64_t start_of_request_in_sec;
	uint64_t end_of_request;

	char *uri;
	uint16_t uri_len;
	char *remote_addr;
	uint16_t remote_addr_len;
	char *remote_user;
	uint16_t remote_user_len;
	char *query_string;
	uint16_t query_string_len;
	char *protocol;
	uint16_t protocol_len;
	char *method;
	uint16_t method_len;
	char *scheme;
	uint16_t scheme_len;
	char *https;
	uint16_t https_len;
	char *script_name;
	uint16_t script_name_len;

	char *host;
	uint16_t host_len;

	char *content_type;
	uint16_t content_type_len;

	char *document_root;
	uint16_t document_root_len;

	char *path_info;
	uint16_t path_info_len;
	int path_info_pos;

	char *authorization;
	uint16_t authorization_len;

	char *script;
	uint16_t script_len;
	char *module;
	uint16_t module_len;
	char *callable;
	uint16_t callable_len;
	char *pyhome;
	uint16_t pyhome_len;

	char *file;
	uint16_t file_len;

	char *paste;
	uint16_t paste_len;

	char *chdir;
	uint16_t chdir_len;

	char *touch_reload;
	uint16_t touch_reload_len;

	char *cache_get;
	uint16_t cache_get_len;

	char *if_modified_since;
	uint16_t if_modified_since_len;

	int fd_closed;

	int sendfile_fd;
	size_t sendfile_fd_chunk;
	size_t sendfile_fd_size;
	off_t sendfile_fd_pos;
	void *sendfile_obj;

	uint16_t var_cnt;
	uint16_t header_cnt;

	int do_not_log;

	int do_not_add_to_async_queue;

	int status;
	void *status_header;
	void *headers;
	void *gc_tracker;
	size_t response_size;
	ssize_t headers_size;

	int async_id;
	int async_status;

	int switches;

	int async_timed_out;
	int async_ready_fd;
	int async_last_ready_fd;
	struct uwsgi_rb_timer *async_timeout;
	struct uwsgi_async_fd *waiting_fds;

	void *async_app;
	void *async_result;
	void *async_placeholder;
	void *async_args;
	void *async_environ;
	void *async_post;
	void *async_input;
	void *async_sendfile;

	int async_force_again;

	int async_plagued;

	int suspended;
	int write_errors;

	int *ovector;
	size_t post_cl;
	off_t post_pos;
	char *post_buffering_buf;
	uint64_t post_buffering_read;

	// current socket mapped to request
	struct uwsgi_socket *socket;

	// check if headers are already sent
	int headers_sent;
	int headers_hvec;

	int body_as_file;
	//for generic use
	size_t buf_pos;

	uint64_t proto_parser_pos;
	int proto_parser_status;
	void *proto_parser_buf;

	char *buffer;

	off_t frame_pos;
	int frame_len;

	int log_this;

	int sigwait;
	int signal_received;

	struct uwsgi_logvar *logvars;

	uint16_t stream_id;

	struct msghdr msg;
	union {
		struct cmsghdr cmsg;
		// should be enough...
		char control[64];
	} msg_control;


};

struct uwsgi_fmon {
	char filename[0xff];
	int fd;
	int id;
	int registered;
	uint8_t sig;
};

struct uwsgi_timer {
	int value;
	int fd;
	int id;
	int registered;
	uint8_t sig;
};

struct uwsgi_signal_rb_timer {
	int value;
	int registered;
	int iterations;
	int iterations_done;
	uint8_t sig;
	struct uwsgi_rb_timer *uwsgi_rb_timer;
};

struct uwsgi_signal_probe {
	
	int (*func)(int, struct uwsgi_signal_probe *);
	char args[1024];

	int fd;
	int state;
	int bad;
	int last_event;
	void *data;
	uint64_t cycles;

	int timeout;
	int freq;

	int registered;
	uint8_t sig;
};

struct uwsgi_probe {

	char *name;
	int (*func)(int, struct uwsgi_signal_probe *);

	struct uwsgi_probe *next;
};

struct uwsgi_cheaper_algo {

	char *name;
	int (*func)(void);
	struct uwsgi_cheaper_algo *next;
};

struct uwsgi_emperor_scanner;

struct uwsgi_imperial_monitor {
        char *scheme;
        void (*init)(struct uwsgi_emperor_scanner *);
        void (*func)(struct uwsgi_emperor_scanner  *);
        struct uwsgi_imperial_monitor *next;
};

struct uwsgi_clock {
	char *name;
	time_t (*seconds)(void);
	uint64_t (*microseconds)(void);
	struct uwsgi_clock *next;
};

struct uwsgi_subscribe_slot;
struct uwsgi_stats_pusher;
struct uwsgi_stats_pusher_instance;

struct uwsgi_server {


	// store the machine hostname
	char hostname[256];
	int hostname_len;

	char **orig_argv;
	char **argv;
	int argc;
	int max_procname;
	int auto_procname;
	char **environ;
	char *procname_prefix;
	char *procname_append;
	char *procname_master;
	char *procname;

	char *requested_clock;
	struct uwsgi_clock *clocks;
	struct uwsgi_clock *clock;

	// quiet startup
	int no_initial_output;

	struct uwsgi_string_list *get_list;

	// enable threads
	int has_threads;
	int no_threads_wait;

	// default app id
	int default_app;

	char *logto2;
	char *logformat;
	int logformat_strftime;
	int logformat_vectors;
	struct uwsgi_logchunk *logchunks;
	void (*logit)(struct wsgi_request *);
	struct iovec **logvectors;

	// autoload plugins
	int autoload;
	struct uwsgi_string_list *plugins_dir;
	struct uwsgi_string_list *blacklist;
	struct uwsgi_string_list *whitelist;

	int snapshot;

	// enable auto-snapshotting
	int auto_snapshot;
	pid_t restore_snapshot;


	int respawn_workers;
	unsigned int reloads;

	// leave master running as root
	int master_as_root;
	// kill the stack on SIGTERM (instead of brutal reloading)
	int die_on_term;

	// disable fd passing on unix socket
	int no_fd_passing;

	// store the current time
	time_t current_time;

	uint64_t master_cycles;

	int reuse_port;
	int tcp_fast_open;
	int tcp_fast_open_client;

	// enable lazy mode
	int lazy;
	// enable lazy-apps mode
	int lazy_apps;
	// enable cheap mode
	int cheap;
	// enable cheaper mode
	int cheaper;
	char *requested_cheaper_algo;
	struct uwsgi_cheaper_algo *cheaper_algos;
	int (*cheaper_algo)(void);
	int cheaper_step;
	uint64_t cheaper_overload;
	// minimal number of running workers in cheaper mode
	int cheaper_count;
	int cheaper_initial;
	// enable idle mode
	int idle;
	
	// destroy the stack when idle
	int die_on_idle;

	// store the screen session
	char *screen_session;

	// true if run under the emperor
	int has_emperor;
	int emperor_fd;
	int emperor_queue;
	int emperor_tyrant;
	int emperor_fd_config;
	int early_emperor;
        int emperor_throttle;
        int emperor_freq;
        int emperor_max_throttle;
	int emperor_magic_exec;
	int emperor_heartbeat;
	time_t next_heartbeat;
	int heartbeat;
	struct uwsgi_string_list *emperor;
	struct uwsgi_imperial_monitor *emperor_monitors;
	char *emperor_absolute_dir;
	char *emperor_pidfile;
	pid_t emperor_pid;
	int	emperor_broodlord;
	int	emperor_broodlord_count;
	char *emperor_stats;
	int 	emperor_stats_fd;
	struct uwsgi_string_list *vassals_templates;
	// true if loyal to the emperor
	int loyal;

	// emperor hook (still in development)
	char *vassals_start_hook;
	char *vassals_stop_hook;

	struct uwsgi_string_list *additional_headers;

	// maximum time to wait after a reload
	time_t master_mercy;

	// set cpu affinity
	int cpu_affinity;

	int reload_mercy;
	// map reloads to death
	int exit_on_reload;

	// store options
	int dirty_config;
	int option_index;
	int (*logic_opt)(char *, char *);
	char *logic_opt_arg;
	char *logic_opt_data;
	int logic_opt_running;
	int logic_opt_cycles;
	struct uwsgi_option *options;
	struct option *long_options;
	char *short_options;
	struct uwsgi_opt **exported_opts;
	int exported_opts_cnt;
	struct uwsgi_custom_option *custom_options;

	// dump the whole set of options
	int dump_options;
	// show ini representation of the current config
	int show_config;

	// list loaded features
	int cheaper_algo_list;
#ifdef UWSGI_ROUTING
	int router_list;
#endif
	int imperial_monitor_list;
	int plugins_list;
	int loggers_list;
	int loop_list;
	int clock_list;
#ifdef UWSGI_ALARM
	int alarms_list;
#endif

	struct wsgi_request *wsgi_req;

	char *remap_modifier;

	// enable zerg mode
	int *zerg;
	char *zerg_server;
	struct uwsgi_string_list *zerg_node;
	int zerg_fallback;
	int zerg_server_fd;

	// security
	char *chroot;
	gid_t gid;
	uid_t uid;
	char *uidname;
	char *gidname;
	int no_initgroups;

#ifdef UWSGI_CAP
	cap_value_t *cap;
	int cap_count;
#endif

#ifdef __linux__
	int unshare;
#endif

	int ignore_sigpipe;
	int ignore_write_errors;
	int write_errors_tolerance;
	int write_errors_exception_only;
	int disable_write_exception;

	// still working on it
	char *profiler;

	// the weight of the instance, used by various cluster/lb components
	uint64_t weight;
	int auto_weight;

	// mostly useless
	char *mode;

	// binary path the worker image
	char *worker_exec;

	// this must be UN-shared
	struct uwsgi_gateway_socket *gateway_sockets;


	int ignore_script_name;
	int manage_script_name;
	int reload_on_exception;
	int catch_exceptions;
	struct uwsgi_string_list *reload_on_exception_type;
	struct uwsgi_string_list *reload_on_exception_value;
	struct uwsgi_string_list *reload_on_exception_repr;


	int no_default_app;
	// exit if no-app is loaded
	int need_app;

	int forkbomb_delay;

	int logdate;
	int log_micros;
	char *log_strftime;
	int log_x_forwarded_for;

	int honour_stdin;
	struct termios termios;
	int restore_tc;

	// route all of the logs to the master process
	int log_master;
	char *log_master_buf;
	size_t log_master_bufsize;

	int log_reopen;
	int log_truncate;
	off_t log_maxsize;
	char *log_backupname;

	int original_log_fd;

	// static file serving
	int file_serve_mode;
	int build_mime_dict;

	struct uwsgi_string_list *mime_file;

	struct uwsgi_probe *probes;

	struct uwsgi_string_list *exec_pre_jail;
	struct uwsgi_string_list *exec_post_jail;
	struct uwsgi_string_list *exec_in_jail;
	struct uwsgi_string_list *exec_as_root;
	struct uwsgi_string_list *exec_as_user;
	struct uwsgi_string_list *exec_as_user_atexit;
	struct uwsgi_string_list *exec_pre_app;

	char *privileged_binary_patch;
	char *unprivileged_binary_patch;
	char *privileged_binary_patch_arg;
	char *unprivileged_binary_patch_arg;

	struct uwsgi_logger *loggers;
	struct uwsgi_logger *choosen_logger;
	struct uwsgi_string_list *requested_logger;

#ifdef UWSGI_PCRE
	int pcre_jit;
	struct uwsgi_regexp_list *log_drain_rules;
	struct uwsgi_regexp_list *log_filter_rules;
	struct uwsgi_regexp_list *log_route;
#endif

#ifdef UWSGI_ALARM
	int alarm_freq;
	struct uwsgi_string_list *alarm_list;
	struct uwsgi_string_list *alarm_logs_list;
	struct uwsgi_alarm *alarms;
	struct uwsgi_alarm_instance *alarm_instances;
	struct uwsgi_alarm_log *alarm_logs;
#endif

	int threaded_logger;
	pthread_mutex_t threaded_logger_lock;

	struct uwsgi_daemon *daemons;
	int daemons_cnt;

#ifdef UWSGI_SSL
	char *subscriptions_sign_check_dir;
	int subscriptions_sign_check_tolerance;
	const EVP_MD *subscriptions_sign_check_md;	
#endif

	struct uwsgi_dyn_dict *static_maps;
	struct uwsgi_dyn_dict *static_maps2;
	struct uwsgi_dyn_dict *check_static;
	struct uwsgi_dyn_dict *mimetypes;
	struct uwsgi_string_list *static_skip_ext;
	struct uwsgi_string_list *static_index;

	struct uwsgi_dyn_dict *static_expires_type;
	struct uwsgi_dyn_dict *static_expires_type_mtime;

	struct uwsgi_dyn_dict *static_expires;
	struct uwsgi_dyn_dict *static_expires_mtime;

	struct uwsgi_dyn_dict *static_expires_uri;
	struct uwsgi_dyn_dict *static_expires_uri_mtime;

	struct uwsgi_dyn_dict *static_expires_path_info;
	struct uwsgi_dyn_dict *static_expires_path_info_mtime;

	int offload_threads;
	int offload_threads_events;
	struct uwsgi_thread **offload_thread;

	int check_static_docroot;

	char *daemonize;
	char *daemonize2;
	int do_not_change_umask;
	char *logfile;
	int logfile_chown;

	// enable vhost mode
	int vhost;
	int vhost_host;

	// async commodity
	struct wsgi_request **async_waiting_fd_table;
	struct wsgi_request **async_proto_fd_table;
	struct uwsgi_async_request *async_runqueue;
	struct uwsgi_async_request *async_runqueue_last;
	int async_runqueue_cnt;

	struct rb_root *rb_async_timeouts;

	int async_queue_unused_ptr;
	struct wsgi_request **async_queue_unused;


	// store rlimit
	struct rlimit rl;
	struct rlimit rl_nproc;
	size_t limit_post;

	// set process priority
	int prio;

	// funny reload systems
	int force_get_memusage;
	rlim_t reload_on_as;
	rlim_t reload_on_rss;
	rlim_t evil_reload_on_as;
	rlim_t evil_reload_on_rss;

	struct uwsgi_string_list *touch_reload;
	struct uwsgi_string_list *touch_logrotate;
	struct uwsgi_string_list *touch_logreopen;

	int propagate_touch;

	// enable grunt mode
	int grunt;

	// store the binary path
	char *binary_path;

	int is_a_reload;


#ifdef UWSGI_UDP
	char *udp_socket;
#endif

#ifdef UWSGI_MULTICAST
	int multicast_ttl;
	int multicast_loop;
	char *multicast_group;
#endif

#ifdef UWSGI_SPOOLER
	struct uwsgi_spooler *spoolers;
	int spooler_numproc;
	struct uwsgi_spooler *i_am_a_spooler;
	char *spooler_chdir;
	int spooler_max_tasks;
	int spooler_ordered;
	int spooler_quiet;
#endif

#ifdef UWSGI_SNMP
	int snmp;
	char *snmp_addr;
	char *snmp_community;
	struct uwsgi_lock_item *snmp_lock;
#endif


	int to_heaven;
	int to_hell;
	int to_outworld;

	int cleaning;

	int marked_workers;
	int ready_to_die;
	int ready_to_reload;

	int lazy_respawned;

	int buffer_size;
	int signal_bufsize;

	// post buffering
	size_t post_buffering;
	int post_buffering_harakiri;
	size_t post_buffering_bufsize;

	int master_process;
	int master_queue;

	// mainly iseful for broodlord mode
	int vassal_sos_backlog;

	int no_defer_accept;
	int so_keepalive;
	int so_send_timeout;

	int page_size;
	int cpus;

	char *pidfile;
	char *pidfile2;

	char *flock2;
	char *flock_wait2;

	int backtrace_depth;

	int harakiri_verbose;
	int harakiri_no_arh;

	char *magic_table[256];

	int numproc;
	int async;
	int async_running;
	int async_queue;
	int async_nevents;

	int max_vars;
	int vec_size;

	// shared area
	char *sharedarea;
	uint64_t sharedareasize;

#ifdef UWSGI_THREADING
	// avoid thundering herd in threaded modes
	pthread_mutex_t six_feet_under_lock;
	pthread_mutex_t lock_static;
#endif


	/* the list of workers */
	struct uwsgi_worker *workers;
	int max_apps;

	/* the list of mules */
	struct uwsgi_string_list *mules_patches;
	struct uwsgi_mule *mules;
	struct uwsgi_string_list *farms_list;
	struct uwsgi_farm *farms;

	pid_t mypid;
	int mywid;

	int muleid;
	int mules_cnt;
	int farms_cnt;

	rlim_t requested_max_fd;
	rlim_t max_fd;

	struct timeval start_tv;

	int abstract_socket;
#ifdef __linux__
	int freebind;
#endif

	int chmod_socket;
	char *chown_socket;
	mode_t chmod_socket_value;
	mode_t chmod_logfile_value;
	int listen_queue;

	char *file_config;

#ifdef UWSGI_ROUTING
	struct uwsgi_router *routers;
	struct uwsgi_route *routes;
#endif

	int single_interpreter;

	struct uwsgi_shared *shared;


	int no_orphans;
	int skip_zero;

	char *chdir;
	char *chdir2;

	int vacuum;
	int no_server;
	int command_mode;

	int xml_round2;

	char *cwd;

	// conditional logging
	int log_slow_requests;
	int log_zero_headers;
	int log_empty_body;
	int log_high_memory;

#ifdef __linux__
	struct uwsgi_string_list *cgroup;
	struct uwsgi_string_list *cgroup_opt;
	char *ns;
	char *ns_net;
	struct uwsgi_string_list *ns_keep_mount;
#endif

	char *protocol;

	int signal_socket;
	int my_signal_socket;

#ifdef UWSGI_ZEROMQ
	int zeromq;
	void *zmq_context;
#endif
	struct uwsgi_socket *sockets;
	struct uwsgi_socket *shared_sockets;
	int is_et;

	struct uwsgi_string_list *map_socket;

	struct uwsgi_cron *crons;

	time_t respawn_delta;

	struct uwsgi_string_list *mounts;

	int cores;

	int threads;
	pthread_attr_t threads_attr;
	size_t threads_stacksize;

	//this key old the u_request structure per core / thread
	pthread_key_t tur_key;


	struct wsgi_request *(*current_wsgi_req) (void);

	void (*notify) (char *);
	void (*notify_ready) (void);
	int notification_fd;
	void *notification_object;

	// usedby suspend/resume loops
	void (*schedule_to_main) (struct wsgi_request *);
	void (*schedule_to_req) (void);

	void (*gbcw_hook)(void);

	int close_on_exec;

	char *loop;
	struct uwsgi_loop *loops;

	struct uwsgi_plugin *p[256];
	struct uwsgi_plugin *gp[MAX_GENERIC_PLUGINS];
	int gp_cnt;

	char *allowed_modifiers;

	char *upload_progress;

	char *cluster;
	int cluster_nodes;
	int cluster_fd;
	struct sockaddr_in mc_cluster_addr;

	struct uwsgi_lock_item *registered_locks;
	struct uwsgi_lock_ops lock_ops;
	char *lock_engine;
	char *ftok;
	char *lock_id;
	size_t lock_size;
	size_t rwlock_size;

	int check_cache;

	uint32_t cache_max_items;
	uint64_t *cache_hashtable;
	uint64_t *cache_unused_stack;
	uint64_t cache_blocksize;
	struct uwsgi_cache_item *cache_items;
	void *cache;
	char *cache_store;
	size_t cache_filesize;
	int cache_store_sync;
	int cache_no_expire;
	int cache_expire_freq;
	int cache_report_freed_items;

	struct uwsgi_string_list *cache_udp_server;
	struct uwsgi_string_list *cache_udp_node;
	int cache_udp_node_socket;

	char *cache_server;
	int cache_server_threads;
	int cache_server_fd;
	pthread_mutex_t cache_server_lock;

	// the stats server
	char *stats;
	int stats_fd;
	int stats_http;
	int stats_minified;
	struct uwsgi_string_list *requested_stats_pushers;
	struct uwsgi_stats_pusher *stats_pushers;
	struct uwsgi_stats_pusher_instance *stats_pusher_instances;
	int stats_pusher_default_freq;

	uint64_t queue_size;
	uint64_t queue_blocksize;
	void *queue;
	struct uwsgi_queue_header *queue_header;
	char *queue_store;
	size_t queue_filesize;
	int queue_store_sync;

	pthread_mutex_t thunder_mutex;

	int locks;

	struct uwsgi_lock_item *cache_lock;
	struct uwsgi_lock_item *queue_lock;
	struct uwsgi_lock_item **user_lock;
	struct uwsgi_lock_item *signal_table_lock;
	struct uwsgi_lock_item *fmon_table_lock;
	struct uwsgi_lock_item *timer_table_lock;
	struct uwsgi_lock_item *probe_table_lock;
	struct uwsgi_lock_item *rb_timer_table_lock;
	struct uwsgi_lock_item *cron_table_lock;
	struct uwsgi_lock_item *rpc_table_lock;
        struct uwsgi_lock_item *sa_lock;

	// subscription client
	int subscribe_freq;
	int subscription_tolerance;
	int unsubscribe_on_graceful_reload;
	struct uwsgi_string_list *subscriptions;

	struct uwsgi_subscribe_node * (*subscription_algo)(struct uwsgi_subscribe_slot *, struct uwsgi_subscribe_node *);
	int subscription_dotsplit;

	int never_swap;

#ifdef UWSGI_SSL
	int ssl_initialized;
	int ssl_verbose;
	int ssl_sessions_use_cache;
	int ssl_sessions_timeout;
#ifdef UWSGI_PCRE
	struct uwsgi_regexp_list *sni_regexp;
#endif
	struct uwsgi_string_list *sni;
#endif

#ifdef UWSGI_SSL
	struct uwsgi_legion *legions;
	struct uwsgi_legion_action *legion_actions;
	int legion_queue;
	int legion_freq;
	int legion_tolerance;
#endif

#ifdef __linux__
#ifdef MADV_MERGEABLE
	int linux_ksm;
	int ksm_buffer_size;
	char *ksm_mappings_last;
	char *ksm_mappings_current;
	size_t ksm_mappings_last_size;
	size_t ksm_mappings_current_size;
#endif
#endif

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


struct uwsgi_signal_entry {
	int wid;
	uint8_t modifier1;
	char receiver[64];
	void *handler;
};

struct uwsgi_lb_node {

	char name[101];
	int group;
	uint64_t hits;
	time_t last_choosen;

};

#define CLUSTER_NODE_STATIC	0
#define CLUSTER_NODE_DYNAMIC	1

struct uwsgi_cluster_node {
	char name[101];

	char nodename[0xff];

	struct sockaddr_in ucn_addr;

	int type;

	int workers;
	int connections;
	int status;

	time_t last_seen;
	int errors;

	time_t last_choosen;

	int requests;

};

#ifdef UWSGI_SNMP
struct uwsgi_snmp_custom_value {
	uint8_t type;
	uint64_t val;
};

int uwsgi_setup_snmp(void);

struct uwsgi_snmp_server_value {
	uint8_t type;
	uint64_t *val;
};
#endif

struct uwsgi_cron {

	int minute;
	int hour;
	int day;
	int month;
	int week;

	time_t last_job;
	uint8_t sig;

	char *command;

	struct uwsgi_cron *next;
};

struct uwsgi_shared {

	//vga 80 x25 specific !
	char warning_message[81];

	uint32_t options[256];

	struct uwsgi_cluster_node nodes[MAX_CLUSTER_NODES];

	off_t logsize;

#ifdef UWSGI_SNMP
	char snmp_community[72 + 1];
	struct uwsgi_snmp_server_value snmp_gvalue[100];
	struct uwsgi_snmp_custom_value snmp_value[100];

#define SNMP_COUNTER32 0x41
#define SNMP_GAUGE 0x42
#define SNMP_COUNTER64 0x46

#endif

	uint64_t cache_first_available_item;
	uint64_t cache_unused_stack_ptr;
	uint64_t cache_hits;
	uint64_t cache_miss;
	uint64_t cache_items;
	uint64_t cache_full;


	int worker_signal_pipe[2];
#ifdef UWSGI_SPOOLER
	int spooler_frequency;
	int spooler_signal_pipe[2];
#endif
	int mule_signal_pipe[2];
	int mule_queue_pipe[2];

	struct uwsgi_signal_entry signal_table[256];

	struct uwsgi_fmon files_monitored[64];
	int files_monitored_cnt;

	struct uwsgi_signal_probe probes[MAX_PROBES];
	int probes_cnt;

	struct uwsgi_timer timers[MAX_TIMERS];
	int timers_cnt;

	struct uwsgi_signal_rb_timer rb_timers[MAX_TIMERS];
	int rb_timers_cnt;

	struct uwsgi_rpc rpc_table[MAX_RPC];
	int rpc_count;

	int worker_log_pipe[2];

#ifdef __linux__
	struct tcp_info ti;
#endif
	uint64_t load;
	struct uwsgi_cron cron[MAX_CRONS];
	int cron_cnt;

	// gateways
	struct uwsgi_gateway gateways[MAX_GATEWAYS];
	int gateways_cnt;
	time_t gateways_harakiri[MAX_GATEWAYS];

	int ready;
};

struct uwsgi_core {

	//time_t harakiri;

	uint64_t        requests;
	uint64_t	failed_requests;
	uint64_t        static_requests;
	uint64_t        routed_requests;
	uint64_t        offloaded_requests;

#ifdef UWSGI_THREADING
	pthread_t thread_id;
#endif

	int offload_rr;

	// one ts-perapp
	void **ts;

	int in_request;

	char *buffer;
	struct iovec *hvec;
	char *post_buf;

	struct wsgi_request req;
};

struct uwsgi_snapshot {
	char *name;
	pid_t pid;
	time_t timestamp;
};

struct uwsgi_worker {
	int id;
	pid_t pid;

	pid_t snapshot;
	uint64_t status;

	time_t last_spawn;
	uint64_t respawn_count;

	uint64_t requests;
	uint64_t delta_requests;
	uint64_t failed_requests;

	time_t harakiri;
	time_t user_harakiri;
	uint64_t harakiri_count;
	int pending_harakiri;

	uint64_t vsz_size;
	uint64_t rss_size;

	uint64_t running_time;

	int manage_next_request;

	uint64_t exceptions;

	int destroy;
	
	int apps_cnt;
	struct uwsgi_app *apps;

	uint64_t tx;

	int hijacked;
	uint64_t hijacked_count;
	int busy;
	int cheaped;
	int suspended;
        int sig;
	uint8_t signum;

	// signals managed by this worker
        uint64_t signals;

	int signal_pipe[2];

	uint64_t avg_response_time;

	struct uwsgi_core *cores;

	char name[0xff];
	char snapshot_name[0xff];
};


struct uwsgi_mule {
	int id;
	pid_t pid;

	int signal_pipe[2];
	int queue_pipe[2];

	time_t last_spawn;
	uint64_t respawn_count;

	char *patch;

	// signals managed by this mule
	uint64_t signals;
	int sig;
        uint8_t signum;

	time_t harakiri;

	char name[0xff];
};

struct uwsgi_mule_farm {
	struct uwsgi_mule *mule;
	struct uwsgi_mule_farm *next;
};

struct uwsgi_farm {
	int id;
	char name[0xff];

	int signal_pipe[2];
	int queue_pipe[2];

	struct uwsgi_mule_farm *mules;

};



char *uwsgi_get_cwd(void);

void warn_pipe(void);
void what_i_am_doing(void);
void goodbye_cruel_world(void);
void gracefully_kill(int);
void reap_them_all(int);
void kill_them_all(int);
void grace_them_all(int);
void end_me(int);
int bind_to_unix(char *, int, int, int);
int bind_to_tcp(char *, int, char *);
#ifdef UWSGI_IPV6
int bind_to_tcp6(char *, int, char *);
#endif
int bind_to_udp(char *, int, int);
int bind_to_unix_dgram(char *);
int timed_connect(struct pollfd *, const struct sockaddr *, int, int, int);
int uwsgi_connect(char *, int, int);
int uwsgi_connectn(char *, uint16_t, int, int);
int connect_to_tcp(char *, int, int, int);
int connect_to_unix(char *, int, int);

void daemonize(char *);
void logto(char *);

void log_request(struct wsgi_request *);
void get_memusage(uint64_t *, uint64_t *);
void harakiri(void);

void stats(int);

#ifdef UWSGI_XML
void uwsgi_xml_config(char *, struct wsgi_request *, char *[]);
#endif

void internal_server_error(struct wsgi_request *, char *);

#ifdef UWSGI_SNMP
void manage_snmp(int, uint8_t *, int, struct sockaddr_in *);
void snmp_init(void);
#endif

#ifdef UWSGI_SPOOLER
int spool_request(struct uwsgi_spooler *uspool, char *, int, int, char *, int, char *, time_t, char *, size_t);
void spooler(struct uwsgi_spooler *);
pid_t spooler_start(struct uwsgi_spooler *);
#endif

void set_harakiri(int);
void set_user_harakiri(int);
void set_mule_harakiri(int);
void set_spooler_harakiri(int);
void inc_harakiri(int);

#ifdef __BIG_ENDIAN__
uint16_t uwsgi_swap16(uint16_t);
uint32_t uwsgi_swap32(uint32_t);
uint64_t uwsgi_swap64(uint64_t);
#endif

ssize_t send_udp_message(uint8_t, uint8_t, char *, char *, uint16_t);

int uwsgi_parse_packet(struct wsgi_request *, int);
int uwsgi_parse_vars(struct wsgi_request *);

int uwsgi_enqueue_message(char *, int, uint8_t, uint8_t, char *, int, int);

void manage_opt(int, char *);

void uwsgi_cluster_add_node(struct uwsgi_cluster_node *, int);
int uwsgi_ping_node(int, struct wsgi_request *);

struct http_status_codes {
	const char key[3];
	const char *message;
	int message_size;
};

#ifdef UWSGI_ASYNC
void uwsgi_async_init(void);
void async_loop();
struct wsgi_request *find_first_available_wsgi_req(void);
struct wsgi_request *find_first_accepting_wsgi_req(void);
struct wsgi_request *find_wsgi_req_by_fd(int);
struct wsgi_request *find_wsgi_req_by_id(int);

void async_add_fd_write(struct wsgi_request *, int, int);
void async_add_fd_read(struct wsgi_request *, int, int);

struct wsgi_request *next_wsgi_req(struct wsgi_request *);


void async_add_timeout(struct wsgi_request *, int);
void async_expire_timeouts(void);


#endif

void uwsgi_as_root(void);

#ifdef UWSGI_NAGIOS
void nagios(void);
#endif

void uwsgi_close_request(struct wsgi_request *);

void wsgi_req_setup(struct wsgi_request *, int, struct uwsgi_socket *);
int wsgi_req_recv(struct wsgi_request *);
int wsgi_req_async_recv(struct wsgi_request *);
int wsgi_req_accept(int, struct wsgi_request *);
int wsgi_req_simple_accept(struct wsgi_request *, int);

#define current_wsgi_req() (*uwsgi.current_wsgi_req)()

void sanitize_args(void);

void env_to_arg(char *, char *);
void parse_sys_envs(char **);

void uwsgi_log(const char *, ...);
void uwsgi_log_verbose(const char *, ...);


void *uwsgi_load_plugin(int, char *, char *);

int unconfigured_hook(struct wsgi_request *);

#ifdef UWSGI_INI
void uwsgi_ini_config(char *, char *[]);
#endif

#ifdef UWSGI_YAML
void uwsgi_yaml_config(char *, char *[]);
#endif

#ifdef UWSGI_JSON
void uwsgi_json_config(char *, char *[]);
#endif

#ifdef UWSGI_SQLITE3
void uwsgi_sqlite3_config(char *, char *[]);
#endif


#ifdef UWSGI_LDAP
void uwsgi_opt_ldap_dump(char *, char *, void *);
void uwsgi_opt_ldap_dump_ldif(char *, char *, void *);
void uwsgi_ldap_config(char *);
#endif

int uwsgi_strncmp(char *, int, char *, int);
int uwsgi_startswith(char *, char *, int);


char *uwsgi_concat(int, ...);
char *uwsgi_concatn(int, ...);
char *uwsgi_concat2(char *, char *);
char *uwsgi_concat2n(char *, int, char *, int);
char *uwsgi_concat2nn(char *, int, char *, int, int *);
char *uwsgi_concat3(char *, char *, char *);
char *uwsgi_concat3n(char *, int, char *, int, char *, int);
char *uwsgi_concat4(char *, char *, char *, char *);
char *uwsgi_concat4n(char *, int, char *, int, char *, int, char *, int);


int uwsgi_get_app_id(char *, int, int);
char *uwsgi_strncopy(char *, int);

int master_loop(char **, char **);


int find_worker_id(pid_t);


void simple_loop();
void *simple_loop_run(void *);

int uwsgi_count_options(struct uwsgi_option *);

ssize_t uwsgi_do_sendfile(int, int, size_t, size_t, off_t *, int);

struct wsgi_request *simple_current_wsgi_req(void);
struct wsgi_request *threaded_current_wsgi_req(void);

void build_options(void);

int uwsgi_read_whole_body(struct wsgi_request *, char *, size_t);
int uwsgi_read_whole_body_in_mem(struct wsgi_request *, char *);

ssize_t uwsgi_sendfile(struct wsgi_request *);

void uwsgi_register_loop(char *, void (*)(void));
void *uwsgi_get_loop(char *);

void add_exported_option(char *, char *, int);

ssize_t uwsgi_send_empty_pkt(int, char *, uint8_t, uint8_t);

int uwsgi_waitfd_event(int, int, int);
#define uwsgi_waitfd(a, b) uwsgi_waitfd_event(a, b, POLLIN)
#define uwsgi_waitfd_write(a, b) uwsgi_waitfd_event(a, b, POLLOUT)

int uwsgi_hooked_parse_dict_dgram(int, char *, size_t, uint8_t, uint8_t, void (*)(char *, uint16_t, char *, uint16_t, void *), void *);
int uwsgi_hooked_parse(char *, size_t, void (*)(char *, uint16_t, char *, uint16_t, void *), void *);

int uwsgi_get_dgram(int, struct wsgi_request *);

int uwsgi_cluster_join(char *);

int uwsgi_string_sendto(int, uint8_t, uint8_t, struct sockaddr *, socklen_t, char *, size_t);

void uwsgi_stdin_sendto(char *, uint8_t, uint8_t);

int uwsgi_cluster_add_me(void);

char *generate_socket_name(char *);

#define UMIN(a,b) ((a)>(b)?(b):(a))
#define UMAX(a,b) ((a)<(b)?(b):(a))

ssize_t uwsgi_send_message(int, uint8_t, uint8_t, char *, uint16_t, int, ssize_t, int);

char *uwsgi_cluster_best_node(void);

int uwsgi_cache_set(char *, uint16_t, char *, uint64_t, uint64_t, uint16_t);
int uwsgi_cache_del(char *, uint16_t, uint64_t, uint16_t);
char *uwsgi_cache_get(char *, uint16_t, uint64_t *);
uint32_t uwsgi_cache_exists(char *, uint16_t);


void *uwsgi_malloc(size_t);
void *uwsgi_calloc(size_t);


int event_queue_init(void);
void *event_queue_alloc(int);
int event_queue_add_fd_read(int, int);
int event_queue_add_fd_write(int, int);
int event_queue_del_fd(int, int, int);
int event_queue_wait(int, int, int *);
int event_queue_wait_multi(int, int, void *, int);
int event_queue_interesting_fd(void *, int);
int event_queue_interesting_fd_has_error(void *, int);
int event_queue_fd_write_to_read(int, int);
int event_queue_fd_read_to_write(int, int);
int event_queue_fd_readwrite_to_read(int, int);
int event_queue_fd_readwrite_to_write(int, int);
int event_queue_fd_read_to_readwrite(int, int);
int event_queue_fd_write_to_readwrite(int, int);
int event_queue_interesting_fd_is_read(void *, int);
int event_queue_interesting_fd_is_write(void *, int);

int event_queue_add_timer(int, int *, int);
struct uwsgi_timer *event_queue_ack_timer(int);

int event_queue_add_file_monitor(int, char *, int *);
struct uwsgi_fmon *event_queue_ack_file_monitor(int, int);


int uwsgi_register_signal(uint8_t, char *, void *, uint8_t);
int uwsgi_add_file_monitor(uint8_t, char *);
int uwsgi_add_timer(uint8_t, int);
int uwsgi_signal_add_rb_timer(uint8_t, int, int);
int uwsgi_signal_handler(uint8_t);

void uwsgi_route_signal(uint8_t);

int uwsgi_start(void *);

int uwsgi_register_rpc(char *, uint8_t, uint8_t, void *);
uint16_t uwsgi_rpc(char *, uint8_t, char **, uint16_t *, char *);
char *uwsgi_do_rpc(char *, char *, uint8_t, char **, uint16_t *, uint16_t *);

char *uwsgi_cheap_string(char *, int);

int uwsgi_parse_array(char *, uint16_t, char **, uint16_t *, uint8_t *);


struct uwsgi_gateway *register_gateway(char *, void (*)(int, void *), void *);
void gateway_respawn(int);

void uwsgi_gateway_go_cheap(char *, int, int *);

char *uwsgi_open_and_read(char *, int *, int, char *[]);
char *uwsgi_get_last_char(char *, char);

struct uwsgi_twobytes {
	uint8_t cl1;
	uint8_t cl0;
} __attribute__ ((__packed__));

struct fcgi_record {
	uint8_t version;
	uint8_t type;
	uint8_t req1;
	uint8_t req0;
	union {
		uint16_t cl;
		struct uwsgi_twobytes cl8;
	};
	uint8_t pad;
	uint8_t reserved;
} __attribute__ ((__packed__));

#define FCGI_BEGIN_REQUEST "\0\1\0\0\0\0\0\0"
#define FCGI_END_REQUEST "\1\x06\0\1\0\0\0\0\1\3\0\1\0\x08\0\0\0\0\0\0\0\0\0\0"
ssize_t fcgi_send_record(int, uint8_t, uint16_t, char *);
ssize_t fcgi_send_param(int, char *, uint16_t, char *, uint16_t);
uint16_t fcgi_get_record(int, char *);

void uwsgi_spawn_daemon(struct uwsgi_daemon *);
void uwsgi_detach_daemons();

void emperor_loop(void);
char *uwsgi_num2str(int);

char *magic_sub(char *, int, int *, char *[]);
void init_magic_table(char *[]);

char *uwsgi_simple_message_string(char *, uint8_t, uint8_t, char *, uint16_t, char *, uint16_t *, int);
int uwsgi_simple_send_string2(char *, uint8_t, uint8_t, char *, uint16_t, char *, uint16_t, int);
int uwsgi_simple_send_string(char *, uint8_t, uint8_t, char *, uint16_t, int);
char *uwsgi_req_append(struct wsgi_request *, char *, uint16_t, char *, uint16_t);

int is_unix(char *, int);
int is_a_number(char *);

char *uwsgi_resolve_ip(char *);

void uwsgi_init_queue(void);
void uwsgi_init_cache(void);
char *uwsgi_queue_get(uint64_t, uint64_t *);
char *uwsgi_queue_pull(uint64_t *);
int uwsgi_queue_push(char *, uint64_t);
char *uwsgi_queue_pop(uint64_t *);
int uwsgi_queue_set(uint64_t, char *, uint64_t);

/*
// maintain alignment here !!!
struct uwsgi_dict_item {
	// size of the value (64bit)
	uint64_t valsize;
	// 64bit hits
	uint64_t hits;
	// previous same-hash item
	uint64_t prev;
	// next same-hash item
	uint64_t next;
	// djb hash of the key
	uint32_t djbhash;
	// size of the key
	uint16_t keysize;
	// key chracters follows...
	char key[UWSGI_CACHE_MAX_KEY_SIZE];
} __attribute__ ((__packed__));

struct uwsgi_dict {
	uint64_t blocksize;
	uint64_t max_items;

	uint64_t *hashtable;
	uint64_t *unused_stack;


	uint64_t first_available_item;
	uint64_t unused_stack_ptr;

	void *data;
	void *lock;

	uint64_t count;

	struct uwsgi_dict_item *items;
};
*/


struct uwsgi_subscribe_req {
	char *key;
	uint16_t keylen;

	char *address;
	uint16_t address_len;

	char *auth;
	uint16_t auth_len;

	uint8_t modifier1;
	uint8_t modifier2;

	uint64_t cores;
	uint64_t load;
	uint64_t weight;
	char *sign;
	uint16_t sign_len;

	time_t unix_check;

	char *base;
	uint16_t base_len;
};

#ifndef _NO_UWSGI_RB

/*

  *** uWSGI, stripped down version of Linux rbtree ***


  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

*/

struct rb_node
{
        unsigned long  rb_parent_color;
#define RB_RED          0
#define RB_BLACK        1
        struct rb_node *rb_right;
        struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
    /* The alignment might seem pointless, but allegedly CRIS needs it */

struct rb_root
{
        struct rb_node *rb_node;
};

#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_color(r)   ((r)->rb_parent_color & 1)
#define rb_is_red(r)   (!rb_color(r))
#define rb_is_black(r) rb_color(r)
#define rb_set_red(r)  do { (r)->rb_parent_color &= ~1; } while (0)
#define rb_set_black(r)  do { (r)->rb_parent_color |= 1; } while (0)

void rb_insert_color(struct rb_node *, struct rb_root *);
void rb_erase(struct rb_node *, struct rb_root *);

void rb_link_node(struct rb_node *, struct rb_node *,
                                struct rb_node **);

struct uwsgi_rb_timer {

	struct rb_node rbt;

	time_t key;
	void *data;
};

struct rb_root *uwsgi_init_rb_timer(void);
struct uwsgi_rb_timer *uwsgi_add_rb_timer(struct rb_root *, time_t, void *);
struct uwsgi_rb_timer *uwsgi_min_rb_timer(struct rb_root *);

#endif

void uwsgi_nuclear_blast();

void uwsgi_unix_signal(int, void (*)(int));

char *uwsgi_get_exported_opt(char *);

int uwsgi_signal_add_cron(uint8_t, int, int, int, int, int);

char *uwsgi_get_optname_by_index(int);

int uwsgi_list_has_num(char *, int);

int uwsgi_list_has_str(char *, char *);

void uwsgi_cache_fix(void);

struct uwsgi_async_request {

	struct wsgi_request *wsgi_req;
	struct uwsgi_async_request *prev;
	struct uwsgi_async_request *next;
};

int event_queue_read(void);
int event_queue_write(void);

void uwsgi_help(char *opt, char *val, void *);

int uwsgi_str2_num(char *);
int uwsgi_str3_num(char *);
int uwsgi_str4_num(char *);

#ifdef __linux__
void linux_namespace_start(void *);
void linux_namespace_jail(void);
int uwsgi_netlink_veth(char *, char *);
int uwsgi_netlink_veth_attach(char *, pid_t);
int uwsgi_netlink_ifup(char *);
int uwsgi_netlink_ip(char *, char *, int);
int uwsgi_netlink_gw(char *, char *);
int uwsgi_netlink_rt(char *, char *, int, char *);
int uwsgi_netlink_del(char *);
#endif


int uwsgi_amqp_consume_queue(int, char *, char *, char *, char *, char *, char *);
char *uwsgi_amqp_consume(int, uint64_t *, char **);

int uwsgi_file_serve(struct wsgi_request *, char *, uint16_t, char *, uint16_t, int);
int uwsgi_starts_with(char *, int, char *, int);

#ifdef __sun__
time_t timegm(struct tm *);
#endif



size_t uwsgi_str_num(char *, int);


int uwsgi_proto_uwsgi_parser(struct wsgi_request *);
ssize_t uwsgi_proto_uwsgi_writev_header(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_uwsgi_writev(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_uwsgi_write(struct wsgi_request *, char *, size_t);
ssize_t uwsgi_proto_uwsgi_write_header(struct wsgi_request *, char *, size_t);

int uwsgi_proto_http_parser(struct wsgi_request *);

int uwsgi_proto_fastcgi_parser(struct wsgi_request *);
ssize_t uwsgi_proto_fastcgi_writev_header(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_fastcgi_writev(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_fastcgi_write(struct wsgi_request *, char *, size_t);
ssize_t uwsgi_proto_fastcgi_write_header(struct wsgi_request *, char *, size_t);
ssize_t uwsgi_proto_fastcgi_sendfile(struct wsgi_request *);
void uwsgi_proto_fastcgi_close(struct wsgi_request *);


int uwsgi_proto_base_accept(struct wsgi_request *, int);
void uwsgi_proto_base_close(struct wsgi_request *);
uint16_t proto_base_add_uwsgi_header(struct wsgi_request *, char *, uint16_t, char *, uint16_t);
uint16_t proto_base_add_uwsgi_var(struct wsgi_request *, char *, uint16_t, char *, uint16_t);

#ifdef UWSGI_ZEROMQ
void uwsgi_proto_zeromq_setup(struct uwsgi_socket *);
ssize_t uwsgi_zeromq_logger(struct uwsgi_logger *, char *, size_t len);
int uwsgi_proto_zeromq_accept(struct wsgi_request *, int);
void uwsgi_proto_zeromq_close(struct wsgi_request *);
ssize_t uwsgi_proto_zeromq_writev_header(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_zeromq_writev(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_zeromq_write(struct wsgi_request *, char *, size_t);
ssize_t uwsgi_proto_zeromq_write_header(struct wsgi_request *, char *, size_t);
ssize_t uwsgi_proto_zeromq_sendfile(struct wsgi_request *);
int uwsgi_proto_zeromq_parser(struct wsgi_request *);
void *uwsgi_zeromq_init(void);
void uwsgi_zeromq_init_sockets(void);
#endif

int uwsgi_num2str2(int, char *);


void uwsgi_add_socket_from_fd(struct uwsgi_socket *, int);


char *uwsgi_split3(char *, size_t, char, char **, size_t *, char **, size_t *, char **, size_t *);
char *uwsgi_split4(char *, size_t, char, char **, size_t *, char **, size_t *, char **, size_t *, char **, size_t *);
char *uwsgi_netstring(char *, size_t, char **, size_t *);

int uwsgi_get_socket_num(struct uwsgi_socket *);
struct uwsgi_socket *uwsgi_new_socket(char *);
struct uwsgi_socket *uwsgi_new_shared_socket(char *);
struct uwsgi_socket *uwsgi_del_socket(struct uwsgi_socket *);

void uwsgi_close_all_sockets(void);

struct uwsgi_string_list *uwsgi_string_new_list(struct uwsgi_string_list **, char *);
#ifdef UWSGI_PCRE
struct uwsgi_regexp_list *uwsgi_regexp_custom_new_list(struct uwsgi_regexp_list **, char *, char *);
#define uwsgi_regexp_new_list(x, y) uwsgi_regexp_custom_new_list(x, y, NULL);
#endif

void uwsgi_string_del_list(struct uwsgi_string_list **, struct uwsgi_string_list *);

void uwsgi_init_all_apps(void);
void uwsgi_init_worker_mount_apps(void);
void uwsgi_socket_nb(int);
void uwsgi_socket_b(int);

void uwsgi_destroy_request(struct wsgi_request *);

void uwsgi_systemd_init(char *);

void uwsgi_sig_pause(void);

void uwsgi_ignition(void);

void master_check_cluster_nodes(void);
int uwsgi_respawn_worker(int);

socklen_t socket_to_in_addr(char *, char *, int, struct sockaddr_in *);
socklen_t socket_to_un_addr(char *, struct sockaddr_un *);
#ifdef UWSGI_IPV6
socklen_t socket_to_in_addr6(char *, char *, int, struct sockaddr_in6 *);
#endif

int uwsgi_get_shared_socket_fd_by_num(int);
struct uwsgi_socket *uwsgi_get_shared_socket_by_num(int);

struct uwsgi_socket *uwsgi_get_socket_by_num(int);

int uwsgi_get_shared_socket_num(struct uwsgi_socket *);

#ifdef __linux__
void uwsgi_set_cgroup(void);
long uwsgi_num_from_file(char *);
#endif

void uwsgi_add_sockets_to_queue(int, int);
void uwsgi_del_sockets_from_queue(int);

int uwsgi_run_command_and_wait(char *, char *);

void uwsgi_manage_signal_cron(time_t);
pid_t uwsgi_run_command(char *, int *, int);

void uwsgi_manage_command_cron(time_t);

int *uwsgi_attach_fd(int, int *, char *, size_t);

int uwsgi_count_sockets(struct uwsgi_socket *);
int uwsgi_file_exists(char *);

int uwsgi_signal_registered(uint8_t);

int uwsgi_endswith(char *, char *);

int uwsgi_cache_server(char *, int);

void uwsgi_chown(char *, char *);

char *uwsgi_get_binary_path(char *);

char *uwsgi_lower(char *, size_t);
int uwsgi_num2str2n(int, char *, int);
void create_logpipe(void);

char *uwsgi_str_contains(char *, int, char);

int uwsgi_simple_parse_vars(struct wsgi_request *, char *, char *);

void uwsgi_build_mime_dict(char *);
struct uwsgi_dyn_dict *uwsgi_dyn_dict_new(struct uwsgi_dyn_dict **, char *, int, char *, int);
void uwsgi_dyn_dict_del(struct uwsgi_dyn_dict *);


void uwsgi_apply_config_pass(char symbol, char*(*)(char *) );

void uwsgi_mule(int);

char *uwsgi_string_get_list(struct uwsgi_string_list **, int, size_t *);

void uwsgi_fixup_fds(int, int, struct uwsgi_gateway *);

void uwsgi_set_processname(char *);

void http_url_decode(char *, uint16_t *, char *);

pid_t uwsgi_fork(char *);

struct uwsgi_mule *get_mule_by_id(int);
struct uwsgi_mule_farm *uwsgi_mule_farm_new(struct uwsgi_mule_farm **, struct uwsgi_mule *);

int uwsgi_farm_has_mule(struct uwsgi_farm *, int);
struct uwsgi_farm *get_farm_by_name(char *);


struct uwsgi_subscribe_node {

        char name[0xff];
        uint16_t len;
        uint8_t modifier1;
        uint8_t modifier2;

        time_t last_check;

	uint64_t requests;
	uint64_t transferred;

	int death_mark;
	uint64_t reference;
	uint64_t cores;
	uint64_t load;
	uint64_t failcnt;

	uint64_t weight;
	uint64_t wrr;

	time_t unix_check;

	struct uwsgi_subscribe_slot *slot;

        struct uwsgi_subscribe_node *next;
};

struct uwsgi_subscribe_slot {

        char key[0xff];
        uint16_t keylen;

	uint32_t hash;

        uint64_t hits;

#ifdef UWSGI_SSL
	EVP_PKEY *sign_public_key;
	EVP_MD_CTX *sign_ctx;
#endif


        struct uwsgi_subscribe_node *nodes;

        struct uwsgi_subscribe_slot *prev;
        struct uwsgi_subscribe_slot *next;
};

void mule_send_msg(int, char *, size_t);

void create_signal_pipe(int *);
struct uwsgi_subscribe_slot *uwsgi_get_subscribe_slot(struct uwsgi_subscribe_slot **, char *, uint16_t);
struct uwsgi_subscribe_node *uwsgi_get_subscribe_node_by_name(struct uwsgi_subscribe_slot **, char *, uint16_t, char *, uint16_t);
struct uwsgi_subscribe_node *uwsgi_get_subscribe_node(struct uwsgi_subscribe_slot **, char *, uint16_t);
int uwsgi_remove_subscribe_node(struct uwsgi_subscribe_slot **, struct uwsgi_subscribe_node *);
struct uwsgi_subscribe_node *uwsgi_add_subscribe_node(struct uwsgi_subscribe_slot **, struct uwsgi_subscribe_req *);

ssize_t uwsgi_mule_get_msg(int, int, char *, size_t, int);

int uwsgi_signal_wait(int);
struct uwsgi_app *uwsgi_add_app(int, uint8_t, char *, int, void *, void *);
int uwsgi_signal_send(int, uint8_t);
int uwsgi_remote_signal_send(char *, uint8_t); 

void uwsgi_configure();
void cluster_setup(void);
void manage_cluster_announce(char *, uint16_t, char *, uint16_t, void *);

int uwsgi_read_response(int, struct uwsgi_header *, int, char **);
char *uwsgi_simple_file_read(char *);

void uwsgi_send_subscription(char *, char *, size_t , uint8_t, uint8_t , uint8_t, char *, char *);

void uwsgi_subscribe(char *, uint8_t);

struct uwsgi_probe *uwsgi_probe_register(struct uwsgi_probe **, char *, int (*)(int, struct uwsgi_signal_probe *));
int uwsgi_add_probe(uint8_t sig, char *, char *, int, int);

int uwsgi_is_bad_connection(int);
int uwsgi_long2str2n(unsigned long long, char *, int);

#ifdef __linux__
void uwsgi_build_unshare(char *);
#ifdef MADV_MERGEABLE
void uwsgi_linux_ksm_map(void);
#endif
#endif

#ifdef UWSGI_CAP
void uwsgi_build_cap(char *);
#endif

void uwsgi_register_logger(char *, ssize_t (*func)(struct uwsgi_logger *, char *, size_t));
void uwsgi_append_logger(struct uwsgi_logger *);
struct uwsgi_logger *uwsgi_get_logger(char *);
struct uwsgi_logger *uwsgi_get_logger_from_id(char *);

char *uwsgi_getsockname(int);
char *uwsgi_get_var(struct wsgi_request *, char *, uint16_t, uint16_t *);

struct uwsgi_gateway_socket *uwsgi_new_gateway_socket(char *, char *);
struct uwsgi_gateway_socket *uwsgi_new_gateway_socket_from_fd(int, char *);

void escape_shell_arg(char *, size_t, char *);

void *uwsgi_malloc_shared(size_t);
void *uwsgi_calloc_shared(size_t);

struct uwsgi_spooler *uwsgi_new_spooler(char *);

struct uwsgi_spooler *uwsgi_get_spooler_by_name(char *);

int uwsgi_zerg_attach(char *);

int uwsgi_manage_opt(char *, char *);

void uwsgi_opt_print(char *, char *, void *);
void uwsgi_opt_true(char *, char *, void *);
void uwsgi_opt_set_str(char *, char *, void *);
void uwsgi_opt_set_logger(char *, char *, void *);
void uwsgi_opt_set_str_spaced(char *, char *, void *);
void uwsgi_opt_add_string_list(char *, char *, void *);
void uwsgi_opt_add_string_list_custom(char *, char *, void *);
void uwsgi_opt_add_dyn_dict(char *, char *, void *);
#ifdef UWSGI_PCRE
void uwsgi_opt_pcre_jit(char *, char *, void *);
void uwsgi_opt_add_regexp_dyn_dict(char *, char *, void *);
void uwsgi_opt_add_regexp_list(char *, char *, void *);
void uwsgi_opt_add_regexp_custom_list(char *, char *, void *);
#endif
void uwsgi_opt_set_int(char *, char *, void *);
void uwsgi_opt_set_rawint(char *, char *, void *);
void uwsgi_opt_set_64bit(char *, char *, void *);
void uwsgi_opt_set_megabytes(char *, char *, void *);
void uwsgi_opt_set_dyn(char *, char *, void *);
void uwsgi_opt_dyn_true(char *, char *, void *);
void uwsgi_opt_dyn_false(char *, char *, void *);
void uwsgi_opt_set_placeholder(char *, char *, void *);
void uwsgi_opt_add_shared_socket(char *, char *, void *);
void uwsgi_opt_add_socket(char *, char *, void *);
void uwsgi_opt_add_lazy_socket(char *, char *, void *);
void uwsgi_opt_add_cron(char *, char *, void *);
void uwsgi_opt_load_plugin(char *, char *, void *);
void uwsgi_opt_load_dl(char *, char *, void *);
void uwsgi_opt_load(char *, char *, void *);
void uwsgi_opt_cluster_log(char *, char *, void *);
void uwsgi_opt_cluster_reload(char *, char *, void *);

#ifdef UWSGI_SSL
void uwsgi_opt_sni(char *, char *, void *);
#endif

void uwsgi_opt_flock(char *, char *, void *);
void uwsgi_opt_flock_wait(char *, char *, void *);
#ifdef UWSGI_INI
void uwsgi_opt_load_ini(char *, char *, void *);
#endif
#ifdef UWSGI_XML
void uwsgi_opt_load_xml(char *, char *, void *);
#endif
#ifdef UWSGI_YAML
void uwsgi_opt_load_yml(char *, char *, void *);
#endif
#ifdef UWSGI_SQLITE3
void uwsgi_opt_load_sqlite3(char *, char *, void *);
#endif
#ifdef UWSGI_JSON
void uwsgi_opt_load_json(char *, char *, void *);
#endif
#ifdef UWSGI_LDAP
void uwsgi_opt_load_ldap(char *, char *, void *);
#endif

void uwsgi_opt_set_umask(char *, char *, void *);
void uwsgi_opt_add_spooler(char *, char *, void *);
void uwsgi_opt_add_daemon(char *, char *, void *);
void uwsgi_opt_set_uid(char *, char *, void *);
void uwsgi_opt_set_gid(char *, char *, void *);
void uwsgi_opt_set_env(char *, char *, void *);
void uwsgi_opt_unset_env(char *, char *, void *);
void uwsgi_opt_pidfile_signal(char *, char *, void *);

void uwsgi_opt_check_static(char *, char *, void *);
void uwsgi_opt_fileserve_mode(char *, char *, void *);
void uwsgi_opt_static_map(char *, char *, void *);

void uwsgi_opt_add_mule(char *, char *, void *);
void uwsgi_opt_add_mules(char *, char *, void *);
void uwsgi_opt_add_farm(char *, char *, void *);

void uwsgi_opt_signal(char *, char *, void *);

void uwsgi_opt_snmp(char *, char *, void *);
void uwsgi_opt_snmp_community(char *, char *, void *);

void uwsgi_opt_logfile_chmod(char *, char *, void *);

void uwsgi_opt_log_date(char *, char *, void *);
void uwsgi_opt_chmod_socket(char *, char *, void *);

void uwsgi_opt_max_vars(char *, char *, void *);
void uwsgi_opt_deprecated(char *, char *, void *);

void uwsgi_opt_noop(char *, char *, void *);

void uwsgi_opt_logic(char *, char *, void *);
int uwsgi_logic_opt_for(char *, char *);
int uwsgi_logic_opt_if_env(char *, char *);
int uwsgi_logic_opt_if_not_env(char *, char *);
int uwsgi_logic_opt_if_opt(char *, char *);
int uwsgi_logic_opt_if_not_opt(char *, char *);
int uwsgi_logic_opt_if_exists(char *, char *);
int uwsgi_logic_opt_if_not_exists(char *, char *);
int uwsgi_logic_opt_if_file(char *, char *);
int uwsgi_logic_opt_if_not_file(char *, char *);
int uwsgi_logic_opt_if_dir(char *, char *);
int uwsgi_logic_opt_if_not_dir(char *, char *);
int uwsgi_logic_opt_if_reload(char *, char *);
int uwsgi_logic_opt_if_not_reload(char *, char *);


#ifdef UWSGI_CAP
void uwsgi_opt_set_cap(char *, char *, void *);
#endif
#ifdef __linux__
void uwsgi_opt_set_unshare(char *, char *, void *);
#endif

char *uwsgi_tmpname(char *, char *);

#ifdef UWSGI_ROUTING
struct uwsgi_router *uwsgi_register_router(char *, int (*)(struct uwsgi_route *, char *));
void uwsgi_opt_add_route(char *, char *, void *);
int uwsgi_apply_routes(struct wsgi_request *);
int uwsgi_apply_routes_fast(struct wsgi_request *, char *, int);
#endif

void uwsgi_reload(char **);

char *uwsgi_chomp(char *);
int uwsgi_file_to_string_list(char *, struct uwsgi_string_list **);
void uwsgi_backtrace(int);
void uwsgi_check_logrotate(void);
char *uwsgi_check_touches(struct uwsgi_string_list *);

void uwsgi_manage_zerg(int, int, int *);

time_t uwsgi_now(void);

int uwsgi_calc_cheaper(void);
int uwsgi_cheaper_algo_spare(void);
int uwsgi_cheaper_algo_backlog(void);
int uwsgi_cheaper_algo_backlog2(void);

int uwsgi_master_log(void);
void uwsgi_flush_logs(void);

void uwsgi_register_cheaper_algo(char *, int(*) (void));

void uwsgi_setup_locking(void);
int uwsgi_fcntl_lock(int);
int uwsgi_fcntl_is_locked(int);

void uwsgi_emulate_cow_for_apps(int);

char *uwsgi_read_fd(int, int *, int);

void uwsgi_setup_post_buffering(void);

struct uwsgi_lock_item *uwsgi_lock_ipcsem_init(char *);

void uwsgi_write_pidfile(char *);
int uwsgi_manage_exception(char *, char *, char *);

void uwsgi_protected_close(int);
ssize_t uwsgi_protected_read(int, void *, size_t);
int uwsgi_socket_uniq(struct uwsgi_socket *, struct uwsgi_socket *);
int uwsgi_socket_is_already_bound(char *name);

char *uwsgi_expand_path(char *, int, char *);
int uwsgi_try_autoload(char *);

uint64_t uwsgi_micros(void);
int uwsgi_is_file(char *);
int uwsgi_is_link(char *);

void uwsgi_receive_signal(int, char *, int);
void uwsgi_exec_atexit(void);

struct uwsgi_stats {
	char *base;
	off_t pos;
	size_t tabs;
	size_t chunk;
	size_t size;
	int minified;
};

struct uwsgi_stats_pusher_instance;

struct uwsgi_stats_pusher {
	char *name;
	void (*func)(struct uwsgi_stats_pusher_instance *, char *, size_t);
	struct uwsgi_stats_pusher *next;
};

struct uwsgi_stats_pusher_instance {
	struct uwsgi_stats_pusher *pusher;
	char *arg;
	void *data;
	int configured;
	int freq;
	time_t last_run;
	struct uwsgi_stats_pusher_instance *next;
};

struct uwsgi_thread;
void uwsgi_stats_pusher_loop(struct uwsgi_thread *);
void uwsgi_stats_pusher_file(struct uwsgi_stats_pusher_instance *, char *, size_t);
void uwsgi_stats_pusher_socket(struct uwsgi_stats_pusher_instance *, char *, size_t);

void uwsgi_stats_pusher_setup(void);
void uwsgi_send_stats(int, struct uwsgi_stats * (*func)(void));
struct uwsgi_stats *uwsgi_master_generate_stats(void);
void uwsgi_register_stats_pusher(char *, void(*) (struct uwsgi_stats_pusher_instance *, char *, size_t));

struct uwsgi_stats *uwsgi_stats_new(size_t);
int uwsgi_stats_symbol(struct uwsgi_stats *, char);
int uwsgi_stats_comma(struct uwsgi_stats *);
int uwsgi_stats_object_open(struct uwsgi_stats *);
int uwsgi_stats_object_close(struct uwsgi_stats *);
int uwsgi_stats_list_open(struct uwsgi_stats *);
int uwsgi_stats_list_close(struct uwsgi_stats *);
int uwsgi_stats_keyval(struct uwsgi_stats *, char *, char *);
int uwsgi_stats_keyval_comma(struct uwsgi_stats *, char *, char *);
int uwsgi_stats_keyvalnum(struct uwsgi_stats *, char *, char *, unsigned long long);
int uwsgi_stats_keyvalnum_comma(struct uwsgi_stats *, char *, char *, unsigned long long);
int uwsgi_stats_keyvaln(struct uwsgi_stats *, char *, char *, int);
int uwsgi_stats_keyvaln_comma(struct uwsgi_stats *, char *, char *, int);
int uwsgi_stats_key(struct uwsgi_stats *, char *);
int uwsgi_stats_keylong(struct uwsgi_stats *, char *, unsigned long long);
int uwsgi_stats_keylong_comma(struct uwsgi_stats *, char *, unsigned long long);
int uwsgi_stats_str(struct uwsgi_stats *, char *);

char *uwsgi_substitute(char *, char *, char *);

void manage_cluster_message(char *, int);
void uwsgi_opt_add_custom_option(char *, char *, void *);
void uwsgi_opt_cflags(char *, char *, void *);
void uwsgi_opt_connect_and_read(char *, char *, void *);
void uwsgi_opt_extract(char *, char *, void *);

struct uwsgi_string_list *uwsgi_string_list_has_item(struct uwsgi_string_list *, char *, size_t);

void trigger_harakiri(int);

void uwsgi_setup_systemd();
void uwsgi_setup_upstart();
void uwsgi_setup_zerg();
void uwsgi_setup_inherited_sockets();

#ifdef UWSGI_SSL
void uwsgi_ssl_init(void);
SSL_CTX *uwsgi_ssl_new_server_context(char *, char *, char *, char *, char *);
char *uwsgi_rsa_sign(char *, char *, size_t, unsigned int *);
char *uwsgi_sanitize_cert_filename(char *, char *, uint16_t);
void uwsgi_opt_scd(char *, char *, void *);
int uwsgi_subscription_sign_check(struct uwsgi_subscribe_slot *, struct uwsgi_subscribe_req *);
#endif

void uwsgi_opt_ssa(char *, char *, void *);

uint32_t djb33x_hash(char *, int);
int uwsgi_no_subscriptions(struct uwsgi_subscribe_slot **);
void uwsgi_deadlock_check(pid_t);

char *uwsgi_setup_clusterbuf(size_t *);

struct uwsgi_logchunk {
	char *ptr;
	size_t len;
	int vec;
	long pos;
	long pos_len;
	int type;
	int free;
	ssize_t (*func)(struct wsgi_request *, char **);
	struct uwsgi_logchunk *next;
};

void uwsgi_build_log_format(char *);

void uwsgi_add_logchunk(int, int, char *, size_t);

void uwsgi_logit_simple(struct wsgi_request *);
void uwsgi_logit_lf(struct wsgi_request *);
void uwsgi_logit_lf_strftime(struct wsgi_request *);

struct uwsgi_logvar *uwsgi_logvar_get(struct wsgi_request *, char *, uint8_t);
void uwsgi_logvar_add(struct wsgi_request *, char *, uint8_t, char *, uint8_t);

// scanners are instances of 'imperial_monitor'
struct uwsgi_emperor_scanner {
        char *arg;
	int fd;
	void *data;
	void (*event_func)(struct uwsgi_emperor_scanner *);
        struct uwsgi_imperial_monitor *monitor;
        struct uwsgi_emperor_scanner *next;
};



void uwsgi_register_imperial_monitor(char *, void (*)(struct uwsgi_emperor_scanner *), void (*)(struct uwsgi_emperor_scanner *));
int uwsgi_emperor_is_valid(char *);

// an instance (called vassal) is a uWSGI stack running
// it is identified by the name of its config file
// a vassal is 'loyal' as soon as it manages a request
struct uwsgi_instance {
        struct uwsgi_instance *ui_prev;
        struct uwsgi_instance *ui_next;

        char name[0xff];
        pid_t pid;

        int status;
        time_t born;
        time_t last_mod;
        time_t last_loyal;

	time_t last_run;
	time_t first_run;

        time_t last_heartbeat;

        uint64_t respawns;
        int use_config;

        int pipe[2];
        int pipe_config[2];

        char *config;
        uint32_t config_len;

        int loyal;

        int zerg;

	struct uwsgi_emperor_scanner *scanner;

        uid_t uid;
        gid_t gid;
};

struct uwsgi_instance *emperor_get_by_fd(int);
struct uwsgi_instance *emperor_get(char *);
void emperor_stop(struct uwsgi_instance *);
void emperor_respawn(struct uwsgi_instance *, time_t);
void emperor_add(struct uwsgi_emperor_scanner *, char *, time_t, char *, uint32_t, uid_t, gid_t);

void uwsgi_exec_command_with_args(char *);

void uwsgi_imperial_monitor_glob_init(struct uwsgi_emperor_scanner *);
void uwsgi_imperial_monitor_directory_init(struct uwsgi_emperor_scanner *);
void uwsgi_imperial_monitor_directory(struct uwsgi_emperor_scanner *);
void uwsgi_imperial_monitor_glob(struct uwsgi_emperor_scanner *);

void uwsgi_register_clock(struct uwsgi_clock *);
void uwsgi_set_clock(char *name);

void uwsgi_init_default(void);
void uwsgi_setup_reload(void);
void uwsgi_autoload_plugins_by_name(char *);
void uwsgi_commandline_config(void);

void uwsgi_setup_log(void);
void uwsgi_setup_log_master(void);

void uwsgi_setup_shared_sockets(void);

void uwsgi_setup_mules_and_farms(void);

void uwsgi_setup_workers(void);
void uwsgi_map_sockets(void);

void uwsgi_set_cpu_affinity(void);

void uwsgi_emperor_start(void);

void uwsgi_bind_sockets(void);
void uwsgi_set_sockets_protocols(void);

struct uwsgi_buffer *uwsgi_buffer_new(size_t);
int uwsgi_buffer_append(struct uwsgi_buffer *, char *, size_t);
int uwsgi_buffer_fix(struct uwsgi_buffer *, size_t);
int uwsgi_buffer_ensure(struct uwsgi_buffer *, size_t);
void uwsgi_buffer_destroy(struct uwsgi_buffer *);
int uwsgi_buffer_u16le(struct uwsgi_buffer *, uint16_t);
int uwsgi_buffer_num64(struct uwsgi_buffer *, int64_t);
int uwsgi_buffer_append_keyval(struct uwsgi_buffer *, char *, uint16_t, char *, uint64_t);
int uwsgi_buffer_append_keynum(struct uwsgi_buffer *, char *, uint16_t, int64_t);

void uwsgi_httpize_var(char *, size_t);
struct uwsgi_buffer *uwsgi_to_http(struct wsgi_request *, char *, uint16_t, char *, uint16_t);

ssize_t uwsgi_pipe(int, int, int);
ssize_t uwsgi_pipe_sized(int, int, size_t, int);

int uwsgi_buffer_send(struct uwsgi_buffer *, int);
void uwsgi_master_cleanup_hooks(void);

pid_t uwsgi_daemonize2();

void uwsgi_emperor_simple_do(struct uwsgi_emperor_scanner *, char *, char *, time_t, uid_t, gid_t);

#if defined(__linux__)
#define UWSGI_ELF
char *uwsgi_elf_section(char *, char *, size_t *);
#endif

#ifdef UWSGI_ALARM
void uwsgi_alarm_log_check(char *, size_t);
void uwsgi_alarm_run(struct uwsgi_alarm_instance *, char *, size_t);
void uwsgi_alarm_log_run(struct uwsgi_alarm_log *, char *, size_t);
void uwsgi_register_alarm(char *, void (*)(struct uwsgi_alarm_instance *), void (*)(struct uwsgi_alarm_instance *, char *, size_t));
void uwsgi_register_embedded_alarms();
void uwsgi_alarms_init();
#endif

struct uwsgi_thread {
	pthread_t tid;
	pthread_attr_t tattr;
	int pipe[2];
	int queue;
	ssize_t rlen;
	void *data;
	char *buf;
	off_t pos;
	size_t len;
	uint64_t custom0;
	uint64_t custom1;
	uint64_t custom2;
	uint64_t custom3;
	// linked list for offloaded requests
        struct uwsgi_offload_request *offload_requests_head;
        struct uwsgi_offload_request *offload_requests_tail;
	void (*func)(struct uwsgi_thread *);
};
struct uwsgi_thread *uwsgi_thread_new(void (*)(struct uwsgi_thread *));

struct uwsgi_offload_request {
	// the request socket
        int s;
	// the peer
        int fd;

	// internal state
	int status;

        off_t pos;
	char *buf;
	off_t buf_pos;

	size_t to_write;
        size_t len;
        size_t written;

	// a uwsgi_buffer (will be destroyed at the end of the task)
	struct uwsgi_buffer *ubuf;

	int (*func)(struct uwsgi_thread *, struct uwsgi_offload_request *, int);

	struct uwsgi_offload_request *prev;
	struct uwsgi_offload_request *next;
};

struct uwsgi_thread *uwsgi_offload_thread_start(void);
int uwsgi_offload_request_sendfile_do(struct wsgi_request *, char *, size_t);
int uwsgi_offload_request_net_do(struct wsgi_request *, char *, struct uwsgi_buffer *);

void uwsgi_subscription_set_algo(char *);
struct uwsgi_subscribe_slot **uwsgi_subscription_init_ht(void);

int uwsgi_check_pidfile(char *);
void uwsgi_daemons_spawn_all();

int uwsgi_daemon_check_pid_death(pid_t);
int uwsgi_daemon_check_pid_reload(pid_t);
void uwsgi_daemons_smart_check();

void uwsgi_setup_thread_req(long, struct wsgi_request *);
void uwsgi_loop_cores_run(void *(*)(void *));

#ifdef UWSGI_MATHEVAL
double uwsgi_matheval(char *);
char *uwsgi_matheval_str(char *);
#endif

int uwsgi_kvlist_parse(char *, size_t, char, char, ...);
int uwsgi_send_http_stats(int);

void uwsgi_simple_response_write(struct wsgi_request *, char *, size_t);
void uwsgi_simple_response_write_header(struct wsgi_request *, char *, size_t);
void uwsgi_simple_set_status(struct wsgi_request *, int status);
void uwsgi_simple_inc_headers(struct wsgi_request *);
ssize_t uwsgi_simple_request_read(struct wsgi_request *, char *, size_t);
int uwsgi_plugin_modifier1(char *);

int uwsgi_cache_enabled(void);
void uwsgi_cache_wlock(void);
void uwsgi_cache_rlock(void);
void uwsgi_cache_rwunlock(void);

void *cache_sweeper_loop(void *);
void *cache_udp_server_loop(void *);

void uwsgi_user_lock(int);
void uwsgi_user_unlock(int);

void simple_loop_run_int(int);

char *uwsgi_strip(char *);

#ifdef UWSGI_SSL
void uwsgi_opt_legion(char *, char *, void *);
void uwsgi_opt_legion_node(char *, char *, void *);
void uwsgi_opt_legion_hook(char *, char *, void *);
void uwsgi_legion_add(struct uwsgi_legion *);
char *uwsgi_ssl_rand(size_t);
void uwsgi_start_legions(void);
int uwsgi_legion_announce(struct uwsgi_legion *);
struct uwsgi_legion_action *uwsgi_legion_action_get(char *);
void uwsgi_legion_action_register(char *, int (*)(struct uwsgi_legion *, char *));
int uwsgi_legion_action_call(char *, struct uwsgi_legion *, struct uwsgi_string_list *);
void uwsgi_legion_atexit(void);
#endif

struct uwsgi_option *uwsgi_opt_get(char *);
int uwsgi_valid_fd(int);
void uwsgi_close_all_fds(void);

void uwsgi_check_emperor(void);
#ifdef UWSGI_AS_SHARED_LIBRARY
int uwsgi_init(int, char **, char **);
#endif

#ifdef __cplusplus
}
#endif

