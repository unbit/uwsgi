/* uWSGI */

/* indent -i8 -br -brs -brf -l0 -npsl -nip -npcs -npsl -di1 */

#ifdef __cplusplus
extern "C" {
#endif

#define UMAX16	65536

#define UMAX64_STR "18446744073709551616"

#define uwsgi_error(x)  uwsgi_log("%s: %s [%s line %d]\n", x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_log_safe(x)  if (uwsgi.original_log_fd != 2) dup2(uwsgi.original_log_fd, 2) ; uwsgi_log(x);
#define uwsgi_error_safe(x)  if (uwsgi.original_log_fd != 2) dup2(uwsgi.original_log_fd, 2) ; uwsgi_log("%s: %s [%s line %d]\n", x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_log_initial if (!uwsgi.no_initial_output) uwsgi_log
#define uwsgi_fatal_error(x) uwsgi_error(x); exit(1);
#define uwsgi_error_open(x)  uwsgi_log("open(\"%s\"): %s [%s line %d]\n", x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_req_error(x)  if (wsgi_req->uri_len > 0 && wsgi_req->method_len > 0 && wsgi_req->remote_addr_len > 0) uwsgi_log_verbose("%s: %s [%s line %d] during %.*s %.*s (%.*s)\n", x, strerror(errno), __FILE__, __LINE__,\
				wsgi_req->method_len, wsgi_req->method, wsgi_req->uri_len, wsgi_req->uri, wsgi_req->remote_addr_len, wsgi_req->remote_addr); else uwsgi_log_verbose("%s %s [%s line %d] \n",x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_debug(x, ...) uwsgi_log("[uWSGI DEBUG] " x, __VA_ARGS__);
#define uwsgi_rawlog(x) if (write(2, x, strlen(x)) != strlen(x)) uwsgi_error("write()")
#define uwsgi_str(x) uwsgi_concat2(x, "")

#define uwsgi_notify(x) if (uwsgi.notify) uwsgi.notify(x)
#define uwsgi_notify_ready() if (uwsgi.notify_ready) uwsgi.notify_ready()

#define uwsgi_apps uwsgi.workers[uwsgi.mywid].apps
#define uwsgi_apps_cnt uwsgi.workers[uwsgi.mywid].apps_cnt

#define wsgi_req_time ((wsgi_req->end_of_request.tv_sec * 1000000 + wsgi_req->end_of_request.tv_usec) - (wsgi_req->start_of_request.tv_sec * 1000000 + wsgi_req->start_of_request.tv_usec))/1000

#define thunder_lock if (uwsgi.threads > 1) {pthread_mutex_lock(&uwsgi.thunder_mutex);}
#define thunder_unlock if (uwsgi.threads > 1) {pthread_mutex_unlock(&uwsgi.thunder_mutex);}

#define uwsgi_check_scheme(file) (!uwsgi_startswith(file, "http://", 7) || !uwsgi_startswith(file, "data://", 7) || !uwsgi_startswith(file, "sym://", 6) || !uwsgi_startswith(file, "fd://", 5))

#define ushared uwsgi.shared

#define MAX_APPS 64
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

#ifdef __clang__
#define inline
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




#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <math.h>
#include <netinet/in.h>

#ifdef UWSGI_UUID
#include <uuid/uuid.h>
#endif

#ifdef __sun__
#define _XPG4_2
#define __EXTENSIONS__
#endif

#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netdb.h>

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif

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
#ifndef __USE_GNU
#define __USE_GNU
#endif

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

#ifdef UWSGI_SCTP
#include <netinet/sctp.h>
#endif

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

/* this value are taken from nginx */
#if defined(__APPLE__) || defined(__freebsd__)
#define UWSGI_LISTEN_QUEUE -1
#else
#define UWSGI_LISTEN_QUEUE 511
#endif

#define UWSGI_CACHE_MAX_KEY_SIZE 2048
#define UWSGI_CACHE_FLAG_UNGETTABLE	0x0001
#define UWSGI_CACHE_FLAG_UPDATE		0x0002

#define uwsgi_cache_update_start(x, y, z) uwsgi_cache_set(x, y, "", 0, CACHE_FLAG_UNGETTABLE)


struct uwsgi_help_item {

	char *key;
	char *value;
};

struct uwsgi_config_template {
	char *filename;
	int applied;
	struct uwsgi_config_template *next;
};

struct uwsgi_string_list {

	char *value;
	size_t len;
	uint64_t custom;
	struct uwsgi_string_list *next;
};

struct uwsgi_dyn_dict {

	char *key;
	int keylen;
	char *value;
	int vallen;

	uint64_t hits;
	int status;

	struct uwsgi_dyn_dict *prev;
	struct uwsgi_dyn_dict *next;
};


union uwsgi_sockaddr {
	struct sockaddr sa;
	struct sockaddr_in sa_in;
	struct sockaddr_un sa_un;
};

union uwsgi_sockaddr_ptr {
	struct sockaddr *sa;
	struct sockaddr_in *sa_in;
	struct sockaddr_un *sa_un;
};

// Gateways are processes (managed by the master) that extends the
// server core features
// -- Gateways can prefork or spawn threads --

struct uwsgi_gateway {

	char *name;
	void (*loop) (void);
	pid_t pid;
	int num;
	int use_signals;
	uint64_t respawns;
};


// Daemons are external processes maintained by the master

struct uwsgi_daemon {
	char *command;
	char *tmp_command;
	pid_t pid;
	uint64_t respawns;
	time_t born;
	time_t last_spawn;
	int status;
	int registered;
	//int pipe[2];

	struct uwsgi_daemon *next;
};

struct uwsgi_logger {
	char *name;
	ssize_t (*func)(struct uwsgi_logger *, char *, size_t);
	int configured;
	int fd;
	void *data;
	union uwsgi_sockaddr addr;
	socklen_t addr_len;
	int count;
	struct msghdr msg;
	struct uwsgi_logger *next;
};

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

struct uwsgi_opt {
	char *key;
	char *value;
	int configured;
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
#define LONG_ARGS_LINUX_NS		17066
#define LONG_ARGS_LOG_DATE		17067
#define LONG_ARGS_LOG_SYSLOG		17068
#define LONG_ARGS_LOG_MASTER		17069
#define LONG_ARGS_CHECK_STATIC		17070
#define LONG_ARGS_WORKER_EXEC		17071
#define LONG_ARGS_EMPEROR		17072
#define LONG_ARGS_PRINT			17073
#define LONG_ARGS_CACHE_BLOCKSIZE	17074
#define LONG_ARGS_QUEUE			17075
#define LONG_ARGS_QUEUE_BLOCKSIZE	17076
#define LONG_ARGS_ATTACH_DAEMON		17077
#define LONG_ARGS_SUBSCRIBE_TO		17078
#define LONG_ARGS_CLUSTER_NODES		17079
#define LONG_ARGS_RELOAD_MERCY		17080
#define LONG_ARGS_ALLOWED_MODIFIERS	17081
#define LONG_ARGS_LINUX_NS_NET		17082
#define LONG_ARGS_CPU_AFFINITY		17083
#define LONG_ARGS_CACHE_STORE		17084
#define LONG_ARGS_CACHE_STORE_SYNC	17085
#define LONG_ARGS_QUEUE_STORE		17086
#define LONG_ARGS_QUEUE_STORE_SYNC	17087
#define LONG_ARGS_PIDFILE2		17088
#define LONG_ARGS_MAP_SOCKET		17089
#define LONG_ARGS_SHARED_SOCKET		17090
#define LONG_ARGS_STATIC_MAP		17091
#define LONG_ARGS_FILE_SERVE_MODE	17092
#define LONG_ARGS_RELOAD_ON_AS		17093
#define LONG_ARGS_RELOAD_ON_RSS		17094
#define LONG_ARGS_TOUCH_RELOAD		17095
#define LONG_ARGS_EMPEROR_AMQP_VHOST	17096
#define LONG_ARGS_EMPEROR_AMQP_USERNAME	17097
#define LONG_ARGS_EMPEROR_AMQP_PASSWORD	17098
#define LONG_ARGS_PROTOCOL		17099
#define LONG_ARGS_ZEROMQ		17100
#define LONG_ARGS_INHERIT		17101
#define LONG_ARGS_VASSALS_INHERIT	17102
#define LONG_ARGS_SOCKET_PROTOCOL	17103
#define LONG_ARGS_LOG_ZEROMQ		17104
#define LONG_ARGS_PROFILER		17105
#define LONG_ARGS_SQLITE3		17106
#define LONG_ARGS_AUTO_SNAPSHOT		17107
#define LONG_ARGS_LOG_SOCKET		17108
#define LONG_ARGS_ADD_HEADER		17109
#define LONG_ARGS_IDLE			17120
#define LONG_ARGS_VASSALS_START_HOOK	17121
#define LONG_ARGS_VASSALS_STOP_HOOK	17122
#define LONG_ARGS_CRON			17123
#define LONG_ARGS_ZERG			17124
#define LONG_ARGS_ZERG_SERVER		17125
#define LONG_ARGS_LOGTO2		17126
#define LONG_ARGS_VASSAL_SOS_BACKLOG	17127
#define LONG_ARGS_EMPEROR_BROODLORD	17128
#define LONG_ARGS_CACHE_SERVER		17129
#define LONG_ARGS_CACHE_SERVER_THREADS	17130
#define LONG_ARGS_CHOWN_SOCKET		17131
#define LONG_ARGS_HTTP_SOCKET		17132
#define LONG_ARGS_FASTCGI_SOCKET	17133
#define LONG_ARGS_THREADS_STACKSIZE	17134
#define LONG_ARGS_EMPEROR_THROTTLE	17135
#define LONG_ARGS_STOP			17136
#define LONG_ARGS_RELOAD		17137
#define LONG_ARGS_REGEXP_MOUNT		17138
#define LONG_ARGS_MIMEFILE		17139
#define LONG_ARGS_CHEAPER		17140
#define LONG_ARGS_CAP			17141
#define LONG_ARGS_STATS			17142
#define LONG_ARGS_MULE			17143
#define LONG_ARGS_LOG_MAXSIZE		17144
#define LONG_ARGS_LOG_BACKUPNAME	17145
#define LONG_ARGS_EVIL_RELOAD_ON_AS	17146
#define LONG_ARGS_EVIL_RELOAD_ON_RSS	17147
#define LONG_ARGS_SPOOLER_HARAKIRI	17148
#define LONG_ARGS_MULE_HARAKIRI		17149
#define LONG_ARGS_EMPEROR_STATS		17150
#define LONG_ARGS_SPOOLER_CHDIR		17151
#define LONG_ARGS_LOCKS			17152
#define LONG_ARGS_PROCNAME_PREFIX	17153
#define LONG_ARGS_PROCNAME_APPEND	17154
#define LONG_ARGS_PROCNAME		17155
#define LONG_ARGS_PROCNAME_MASTER	17156
#define LONG_ARGS_FARM			17157
#define LONG_ARGS_MULES			17158
#define LONG_ARGS_PROCNAME_PREFIX_SP	17159
#define LONG_ARGS_UMASK			17160
#define LONG_ARGS_PAUSE			17161
#define LONG_ARGS_SIGNAL_BUFSIZE	17162
#define LONG_ARGS_SIGNAL		17163
#define LONG_ARGS_KSM			17164
#define LONG_ARGS_LOGFILE_CHMOD		17165
#define LONG_ARGS_SUBSCRIBE_FREQ	17166
#define LONG_ARGS_SUBSCR_TOLERANCE	17167
#define LONG_ARGS_UNSHARE		17168
#define LONG_ARGS_EXEC_AS_ROOT		17169
#define LONG_ARGS_EXEC_AS_USER		17170
#define LONG_ARGS_STATIC_SKIP_EXT	17171
#define LONG_ARGS_LOGGER		17172
#define LONG_ARGS_STATIC_INDEX		17173
#define LONG_ARGS_CHEAPER_STEP		17174


#define UWSGI_OK	0
#define UWSGI_AGAIN	1
#define UWSGI_ACCEPTING	2
#define UWSGI_PAUSED	3

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
#define UWSGI_OPTION_BACKLOG_STATUS	15
#define UWSGI_OPTION_BACKLOG_ERRORS	16
#define UWSGI_OPTION_SPOOLER_HARAKIRI   17
#define UWSGI_OPTION_MULE_HARAKIRI	18

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

#define MAX_VARS 64
#define MAX_LOOPS 60

struct uwsgi_loop {
	char *name;
	void (*loop) (void);
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

	int auto_port;

	char *proto_name;

	int (*proto) (struct wsgi_request *);
	int (*proto_accept) (struct wsgi_request *, int);
	 ssize_t(*proto_write) (struct wsgi_request *, char *, size_t);
	 ssize_t(*proto_writev) (struct wsgi_request *, struct iovec *, size_t);
	 ssize_t(*proto_write_header) (struct wsgi_request *, char *, size_t);
	 ssize_t(*proto_writev_header) (struct wsgi_request *, struct iovec *, size_t);
	 ssize_t(*proto_sendfile) (struct wsgi_request *);
	void (*proto_close) (struct wsgi_request *);
	int edge_trigger;

	int disabled;

	struct uwsgi_socket *next;
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
	struct option *options;
	const char *short_options;
	int (*manage_opt) (int, char *);
	void (*enable_threads) (void);
	void (*init_thread) (int);
	int (*request) (struct wsgi_request *);
	void (*after_request) (struct wsgi_request *);
	void (*init_apps) (void);
	void (*preinit_apps) (void);
	void (*fixup) (void);
	void (*master_fixup) (int);
	void (*master_cycle) (void);
	int (*mount_app) (char *, char *, int);
	int (*manage_udp) (char *, int, char *, int);
	int (*manage_xml) (char *, char *);
	void (*suspend) (struct wsgi_request *);
	void (*resume) (struct wsgi_request *);

	void (*hijack_worker) (void);
	void (*spooler_init) (void);

	int (*magic) (char *, char *);

	void *(*encode_string) (char *);
	char *(*decode_string) (void *);
	int (*signal_handler) (uint8_t, void *);
	char *(*code_string) (char *, char *, char *, char *, uint16_t);

	int (*spooler) (char *, char *, uint16_t, char *, size_t);

	uint16_t(*rpc) (void *, uint8_t, char **, uint16_t *, char *);

	void (*jail) (int (*)(void *), char **);

	int (*mule)(char *);
	int (*mule_msg)(char *, size_t);
	struct uwsgi_help_item *help;

};

#ifdef UWSGI_PCRE
#include <pcre.h>
int uwsgi_regexp_build(char *re, pcre **pattern, pcre_extra **pattern_extra);
int uwsgi_regexp_match(pcre *pattern, pcre_extra *pattern_extra, char *subject, int length);
#endif



struct uwsgi_app {

	uint8_t modifier1;

	char *mountpoint;
	int mountpoint_len;

#ifdef UWSGI_PCRE
	pcre *pattern;
        pcre_extra *pattern_extra;
#endif
	
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

#ifdef UWSGI_ASYNC
	void *eventfd_read;
	void *eventfd_write;
#endif

	void *(*request_subhandler) (struct wsgi_request *, struct uwsgi_app *);
	int (*response_subhandler) (struct wsgi_request *);

	int argc;
	uint64_t requests;
	uint64_t exceptions;
	char *chdir;

	char *touch_reload;
	time_t touch_reload_mtime;

	void *gateway_version;
        void *uwsgi_version;
        void *uwsgi_node;

	uint64_t avg_response_time;
};


#ifdef UWSGI_ROUTING
struct uwsgi_route {

	const char *mountpoint;
	const char *callbase;

	pcre *pattern;
	pcre_extra *pattern_extra;
	pcre *method;
	pcre_extra *method_extra;

	const char *call;

	int modifier1;
	int modifier2;

	void *callable;
	void *callable_args;
	int args;

	void (*action) (struct wsgi_request *, struct uwsgi_route *);
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


struct wsgi_request {
	struct uwsgi_header uh;
	//temporary attr

	int app_id;
	int dynamic;

	char *appid;
	uint16_t appid_len;

	struct pollfd poll;

	//this is big enough to contain sockaddr_in
	struct sockaddr_un c_addr;
	int c_len;

	//iovec
	struct iovec *hvec;

	struct timeval start_of_request;
	struct timeval end_of_request;

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

	char *path_info;
	uint16_t path_info_len;
	int path_info_pos;

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

	int *ovector;
	size_t post_cl;
	off_t post_pos;
	char *post_buffering_buf;
	uint64_t post_buffering_read;

	// current socket mapped to request
	struct uwsgi_socket *socket;

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

	// quiet startup
	int no_initial_output;

	// enable threads
	int has_threads;

	// default app id
	int default_app;

	char *logto2;

	// autoload plugins
	int autoload;

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

	// enable lazy mode
	int lazy;
	// enable cheap mode
	int cheap;
	// enable cheaper mode
	int cheaper;
	int cheaper_step;
	// minimal number of running workers in cheaper mode
	int cheaper_count;
	// enable idle mode
	int idle;
	
	// destroy the stack when idle
	int die_on_idle;

	// store the screen session
	char *screen_session;

	// true if run under the emperor
	int has_emperor;
	int emperor_fd;
	int emperor_tyrant;
	int emperor_fd_config;
	int early_emperor;
        int emperor_throttle;
	char *emperor_dir;
	pid_t emperor_pid;
	int	emperor_broodlord;
	int	emperor_broodlord_count;
	char *emperor_stats;
	int 	emperor_stats_fd;
	struct uwsgi_config_template *vassals_templates;
	// true if loyal to the emperor
	int loyal;

	// amqp support
	char *emperor_amqp_vhost;
	char *emperor_amqp_username;
	char *emperor_amqp_password;

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
	int option_index;
	struct option *long_options;
	struct uwsgi_opt **exported_opts;
	int exported_opts_cnt;

	// dump the whole set of options
	int dump_options;
	// show ini representation of the current config
	int show_config;

	//base for all the requests(even on async mode)
	struct wsgi_request **wsgi_requests;
	struct wsgi_request *wsgi_req;

	char *remap_modifier;

	// enable zerg mode
	int *zerg;
	char *zerg_server;
	int zerg_server_fd;

	// security
	char *chroot;
	gid_t gid;
	uid_t uid;
	char *uidname;
	char *gidname;

#ifdef UWSGI_CAP
	cap_value_t *cap;
	int cap_count;
#endif

#ifdef __linux__
	int unshare;
#endif

	// still working on it
	char *profiler;

	// mostly useless
	char *mode;

	// binary path the worker image
	char *worker_exec;

	// gateways
	struct uwsgi_gateway gateways[MAX_GATEWAYS];
	int gateways_cnt;


	int ignore_script_name;
	int manage_script_name;
	int no_default_app;

	int logdate;
	int log_micros;
	char *log_strftime;
	int log_x_forwarded_for;

	int honour_stdin;

	// route all of the logs to the master process
	int log_master;

	int log_reopen;
	int log_truncate;
	off_t log_maxsize;
	char *log_backupname;

	int original_log_fd;

	// static file serving
	int file_serve_mode;
	int build_mime_dict;
	char *mime_file;

	struct uwsgi_probe *probes;

	struct uwsgi_string_list *exec_as_root;
	struct uwsgi_string_list *exec_as_user;

	struct uwsgi_logger *loggers;
	struct uwsgi_logger *choosen_logger;
	char *requested_logger;
	char *choosen_logger_arg;
	int threaded_logger;

	struct uwsgi_daemon *daemons;
	int daemons_cnt;

	struct uwsgi_dyn_dict *static_maps;
	struct uwsgi_dyn_dict *check_static;
	struct uwsgi_dyn_dict *mimetypes;
	struct uwsgi_string_list *static_skip_ext;
	struct uwsgi_string_list *static_index;

	char *logfile;
	int logfile_chown;

	// enable vhost mode
	int vhost;
	int vhost_host;

	struct iovec **async_hvec;
	char **async_buf;
	char **async_post_buf;

	// async commodity
	struct wsgi_request **async_waiting_fd_table;
	struct wsgi_request **async_proto_fd_table;
	struct uwsgi_async_request *async_runqueue;
	struct uwsgi_async_request *async_runqueue_last;
	int async_runqueue_cnt;

	struct rb_root *rb_async_timeouts;

	int async_queue_unused_ptr;
	struct wsgi_request **async_queue_unused;


#ifdef UWSGI_ROUTING
	int **async_ovector;
#endif

	// store rlimit
	struct rlimit rl;
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
	char *multicast_group;
#endif

#ifdef UWSGI_SPOOLER
	char *spool_dir;
	char *spooler_chdir;
	int spooler_ordered;
	uint64_t spooler_respawned;
#endif

#ifdef UWSGI_SNMP
	int snmp;
	char *snmp_addr;
	char *snmp_community;
#endif


	int to_heaven;
	int to_hell;
	int to_outworld;

	int lazy_respawned;

	int buffer_size;
	int signal_bufsize;

	// post buffering
	int post_buffering;
	int post_buffering_harakiri;
	int post_buffering_bufsize;

	int master_process;
	int master_queue;

	// mainly iseful for broodlord mode
	int vassal_sos_backlog;

	int no_defer_accept;

	int page_size;

	char *pidfile;
	char *pidfile2;

	int harakiri_verbose;

	char *magic_table[256];

	int numproc;
	int async;
	int async_running;
	int async_queue;
	int async_nevents;

	int edge_triggered;

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

#ifdef UWSGI_XML
	char *xml_config;
#endif

	char *file_config;


#ifdef UWSGI_ROUTING
#ifndef MAX_UWSGI_ROUTES
#define MAX_UWSGI_ROUTES 64
#endif
	int routing;
	int nroutes;
	struct uwsgi_route routes[MAX_UWSGI_ROUTES];
#endif

#ifdef UWSGI_YAML
	char *yaml;
#endif

#ifdef UWSGI_JSON
	char *json;
#endif

#ifdef UWSGI_INI
	struct uwsgi_string_list *ini;
#endif

#ifdef UWSGI_SQLITE3
	char *sqlite3;
#endif

	struct uwsgi_config_template *config_templates;

	int single_interpreter;

	struct uwsgi_shared *shared;


	int no_orphans;

	char *chdir;
	char *chdir2;
	int catch_exceptions;

	int vacuum;
	int no_server;

#ifdef UWSGI_LDAP
	char *ldap;
#endif

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
#endif

	char *protocol;

	int signal_socket;
	int my_signal_socket;

#ifdef UWSGI_ZEROMQ
	char *zeromq;
	char *zmq_receiver;
	char *zmq_responder;
	struct uwsgi_socket *zmq_socket;
	void *zmq_context;
	//void *zmq_pull;
	void *zmq_pub;
	int zeromq_recv_flag;
	pthread_mutex_t zmq_lock;
	pthread_key_t zmq_pull;
#endif
	struct uwsgi_socket *sockets;
	struct uwsgi_socket *shared_sockets;

	struct uwsgi_string_list *map_socket;

	struct uwsgi_cron *crons;

	time_t respawn_delta;

	char *mounts[MAX_APPS];
	int mounts_cnt;

	int cores;

	struct uwsgi_core **core;

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

	int close_on_exec;

	char *loop;
	struct uwsgi_loop loops[MAX_LOOPS];
	int loops_cnt;

	struct uwsgi_plugin *p[0xFF];
	struct uwsgi_plugin *gp[MAX_GENERIC_PLUGINS];
	int gp_cnt;

	char *allowed_modifiers;

	char *upload_progress;

	char *cluster;
	int cluster_nodes;
	int cluster_fd;
	struct sockaddr_in mc_cluster_addr;

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

	char *cache_server;
	int cache_server_threads;
	int cache_server_fd;
	pthread_mutex_t cache_server_lock;

	// the stats server
	char *stats;
	int stats_fd;

	uint64_t queue_size;
	uint64_t queue_blocksize;
	void *queue;
	struct uwsgi_queue_header *queue_header;
	char *queue_store;
	size_t queue_filesize;
	int queue_store_sync;

	pthread_mutex_t thunder_mutex;

	int locks;

	void *cache_lock;
	void *queue_lock;
	void **user_lock;
	void *signal_table_lock;
	void *fmon_table_lock;
	void *timer_table_lock;
	void *probe_table_lock;
	void *rb_timer_table_lock;
	void *cron_table_lock;
	void *rpc_table_lock;
        void *sa_lock;
#ifdef UWSGI_SPOOLER
	void *spooler_lock;
#endif

	// subscription client
	int subscribe_freq;
	int subscription_tolerance;
	struct uwsgi_string_list *subscriptions;

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

#ifdef UWSGI_SPOOLER
	pid_t spooler_pid;
	int spooler_frequency;
	time_t spooler_harakiri;
#endif

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


	int worker_signal_pipe[2];
#ifdef UWSGI_SPOOLER
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
};

struct uwsgi_core {

	int id;
	int worker_id;

	time_t harakiri;

	//uint64_t        requests;
	uint64_t failed_requests;

#ifdef UWSGI_THREADING
	pthread_t thread_id;
#endif

	//multiple ts per - core are needed only with multiple_interpreter + threads
	void *ts[MAX_APPS];

	int in_request;
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

	uint64_t vsz_size;
	uint64_t rss_size;

	uint64_t running_time;

	int manage_next_request;

	uint64_t exceptions;

	int destroy;

	int apps_cnt;
	struct uwsgi_app apps[MAX_APPS];

	uint64_t tx;

	int busy;
	int cheaped;
	int suspended;
        int sig;
	uint8_t signum;

	// signals managed by this worker
        uint64_t signals;

	int signal_pipe[2];

	uint64_t avg_response_time;

	char name[0xff];
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
int bind_to_udp(char *, int, int);
int timed_connect(struct pollfd *, const struct sockaddr *, int, int, int);
int uwsgi_connect(char *, int, int);
int uwsgi_connectn(char *, uint16_t, int, int);
int connect_to_tcp(char *, int, int, int);
int connect_to_unix(char *, int, int);
#ifdef UWSGI_SCTP
int bind_to_sctp(char *, int, char *);
#endif

void daemonize(char *);
void logto(char *);

void log_request(struct wsgi_request *);
void get_memusage(uint64_t *, uint64_t *);
void harakiri(void);

void stats(int);

#ifdef UWSGI_XML
void uwsgi_xml_config(char *, struct wsgi_request *, int, char *[]);
#endif

void internal_server_error(struct wsgi_request *, char *);

#ifdef UWSGI_SNMP
void manage_snmp(int, uint8_t *, int, struct sockaddr_in *);
void snmp_init(void);
#endif

#ifdef UWSGI_SPOOLER
int spool_request(char *, int, int, char *, int, char *, time_t, char *, size_t);
void spooler(void);
pid_t spooler_start(void);
#endif

void set_harakiri(int);
void set_mule_harakiri(int);
void set_spooler_harakiri(int);
void inc_harakiri(int);

#ifdef __BIG_ENDIAN__
uint16_t uwsgi_swap16(uint16_t);
uint32_t uwsgi_swap32(uint32_t);
uint64_t uwsgi_swap64(uint64_t);
#endif

#ifdef UWSGI_UDP
ssize_t send_udp_message(uint8_t, uint8_t, char *, char *, uint16_t);
#endif

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

void *async_loop(void *);
struct wsgi_request *find_first_available_wsgi_req(void);
struct wsgi_request *find_first_accepting_wsgi_req(void);
struct wsgi_request *find_wsgi_req_by_fd(int);
struct wsgi_request *find_wsgi_req_by_id(int);

void async_add_fd_write(struct wsgi_request *, int, int);
void async_add_fd_read(struct wsgi_request *, int, int);

inline struct wsgi_request *next_wsgi_req(struct wsgi_request *);


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


void *uwsgi_load_plugin(int, char *, char *, int);

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
void uwsgi_ldap_schema_dump(void);
void uwsgi_ldap_schema_dump_ldif(void);
void uwsgi_ldap_config(void);
#endif

inline int uwsgi_strncmp(char *, int, char *, int);
inline int uwsgi_startswith(char *, char *, int);


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


void *simple_loop(void *);
void *zeromq_loop(void *);

int count_options(struct option *);

#ifdef UWSGI_SENDFILE
ssize_t uwsgi_do_sendfile(int, int, size_t, size_t, off_t *, int);
#endif

struct wsgi_request *simple_current_wsgi_req(void);
struct wsgi_request *threaded_current_wsgi_req(void);

void build_options(void);

int uwsgi_read_whole_body(struct wsgi_request *, char *, size_t);
int uwsgi_read_whole_body_in_mem(struct wsgi_request *, char *);

ssize_t uwsgi_sendfile(struct wsgi_request *);

void uwsgi_register_loop(char *, void *);
void *uwsgi_get_loop(char *);

void add_exported_option(char *, char *, int);

ssize_t uwsgi_send_empty_pkt(int, char *, uint8_t, uint8_t);

int uwsgi_waitfd(int, int);

int uwsgi_hooked_parse_dict_dgram(int, char *, size_t, uint8_t, uint8_t, void (*)(char *, uint16_t, char *, uint16_t, void *), void *);
int uwsgi_hooked_parse(char *, size_t, void (*)(char *, uint16_t, char *, uint16_t, void *), void *);
void manage_string_opt(char *, uint16_t, char *, uint16_t, void *);

int uwsgi_get_dgram(int, struct wsgi_request *);

int uwsgi_cluster_join(char *);

int uwsgi_string_sendto(int, uint8_t, uint8_t, struct sockaddr *, socklen_t, char *, size_t);

void uwsgi_stdin_sendto(char *, uint8_t, uint8_t);

int uwsgi_cluster_add_me(void);

char *generate_socket_name(char *);

#define UMIN(a,b) ((a)>(b)?(b):(a))

ssize_t uwsgi_send_message(int, uint8_t, uint8_t, char *, uint16_t, int, ssize_t, int);

char *uwsgi_cluster_best_node(void);

int uwsgi_cache_set(char *, uint16_t, char *, uint64_t, uint64_t, uint16_t);
int uwsgi_cache_del(char *, uint16_t);
char *uwsgi_cache_get(char *, uint16_t, uint64_t *);
uint32_t uwsgi_cache_exists(char *, uint16_t);

void uwsgi_lock_init(void *);
void uwsgi_lock(void *);
void uwsgi_unlock(void *);

void uwsgi_rwlock_init(void *);
void uwsgi_rlock(void *);
void uwsgi_wlock(void *);
void uwsgi_rwunlock(void *);

inline void *uwsgi_malloc(size_t);



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

int event_queue_add_timer(int, int *, int);
struct uwsgi_timer *event_queue_ack_timer(int);

int event_queue_add_file_monitor(int, char *, int *);
struct uwsgi_fmon *event_queue_ack_file_monitor(int, int);


void *uwsgi_mmap_shared_lock(void);
void *uwsgi_mmap_shared_rwlock(void);

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


struct uwsgi_gateway *register_gateway(char *, void (*)(void));
struct uwsgi_gateway *register_fat_gateway(char *, void (*)(void));
void gateway_respawn(int);

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

void spawn_daemon(struct uwsgi_daemon *);

void emperor_loop(void);
char *uwsgi_num2str(int);

char *magic_sub(char *, int, int *, char *[]);
void init_magic_table(char *[]);

char *uwsgi_simple_message_string(char *, uint8_t, uint8_t, char *, uint16_t, char *, uint16_t *, int);
int uwsgi_simple_send_string2(char *, uint8_t, uint8_t, char *, uint16_t, char *, uint16_t, int);
int uwsgi_simple_send_string(char *, uint8_t, uint8_t, char *, uint16_t, int);

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
};

#ifndef _NO_UWSGI_RB
#include "lib/rbtree.h"

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

inline int event_queue_read(void);
inline int event_queue_write(void);

void uwsgi_help(void);

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

int uwsgi_file_serve(struct wsgi_request *, char *, uint16_t, char *, uint16_t);
inline int uwsgi_starts_with(char *, int, char *, int);

#ifdef __sun__
time_t timegm(struct tm *);
#endif



int uwsgi_str_num(char *, int);


int uwsgi_proto_uwsgi_parser(struct wsgi_request *);
ssize_t uwsgi_proto_uwsgi_writev_header(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_uwsgi_writev(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_uwsgi_write(struct wsgi_request *, char *, size_t);
ssize_t uwsgi_proto_uwsgi_write_header(struct wsgi_request *, char *, size_t);

int uwsgi_proto_http_parser(struct wsgi_request *);
ssize_t uwsgi_proto_http_writev_header(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_http_writev(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_http_write(struct wsgi_request *, char *, size_t);
ssize_t uwsgi_proto_http_write_header(struct wsgi_request *, char *, size_t);

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
ssize_t uwsgi_zeromq_logger(struct uwsgi_logger *, char *, size_t len);
int uwsgi_proto_zeromq_accept(struct wsgi_request *, int);
void uwsgi_proto_zeromq_close(struct wsgi_request *);
ssize_t uwsgi_proto_zeromq_writev_header(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_zeromq_writev(struct wsgi_request *, struct iovec *, size_t);
ssize_t uwsgi_proto_zeromq_write(struct wsgi_request *, char *, size_t);
ssize_t uwsgi_proto_zeromq_write_header(struct wsgi_request *, char *, size_t);
ssize_t uwsgi_proto_zeromq_sendfile(struct wsgi_request *);
int uwsgi_proto_zeromq_parser(struct wsgi_request *);
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

void uwsgi_string_del_list(struct uwsgi_string_list **, struct uwsgi_string_list *);

void uwsgi_init_all_apps(void);
void uwsgi_socket_nb(int);

void uwsgi_destroy_request(struct wsgi_request *);

void uwsgi_systemd_init(char *);

void uwsgi_sig_pause(void);

void uwsgi_ignition(void);

void master_check_cluster_nodes(void);
int uwsgi_respawn_worker(int);

socklen_t socket_to_in_addr(char *, char *, int, struct sockaddr_in *);
socklen_t socket_to_un_addr(char *, struct sockaddr_un *);

int uwsgi_get_shared_socket_fd_by_num(int);
struct uwsgi_socket *uwsgi_get_shared_socket_by_num(int);

int uwsgi_get_shared_socket_num(struct uwsgi_socket *);

#ifdef __linux__
void uwsgi_set_cgroup(void);
#endif

void uwsgi_add_sockets_to_queue(int);
void uwsgi_del_sockets_from_queue(int);

int uwsgi_run_command_and_wait(char *, char *);

void uwsgi_manage_signal_cron(time_t);
int uwsgi_run_command(char *);

void uwsgi_manage_command_cron(time_t);

int *uwsgi_attach_fd(int, int, char *, size_t);

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

void uwsgi_send_stats(int);

void uwsgi_apply_config_pass(char symbol, char*(*)(char *) );

void uwsgi_mule(int);

char *uwsgi_string_get_list(struct uwsgi_string_list **, int, size_t *);

void uwsgi_fixup_fds(int, int);

void uwsgi_set_processname(char *);

void http_url_decode(char *, uint16_t *, char *);

pid_t uwsgi_fork(char *);

struct uwsgi_mule *get_mule_by_id(int);
struct uwsgi_mule_farm *uwsgi_mule_farm_new(struct uwsgi_mule_farm **, struct uwsgi_mule *);

int uwsgi_farm_has_mule(struct uwsgi_farm *, int);
struct uwsgi_farm *get_farm_by_name(char *);

struct uwsgi_subscribe_slot;

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

	struct uwsgi_subscribe_slot *slot;

        struct uwsgi_subscribe_node *next;
};

struct uwsgi_subscribe_slot {

        char key[0xff];
        uint16_t keylen;

#ifdef UWSGI_PCRE
	pcre *pattern;
	pcre_extra *pattern_extra;
#endif

        uint64_t hits;

	// used for round robin
	uint64_t rr;

        struct uwsgi_subscribe_node *nodes;

        struct uwsgi_subscribe_slot *prev;
        struct uwsgi_subscribe_slot *next;
};

void mule_send_msg(int, char *, size_t);

void create_signal_pipe(int *);
struct uwsgi_subscribe_slot *uwsgi_get_subscribe_slot(struct uwsgi_subscribe_slot **, char *, uint16_t, int);
struct uwsgi_subscribe_node *uwsgi_get_subscribe_node_by_name(struct uwsgi_subscribe_slot **, char *, uint16_t, char *, uint16_t, int);
struct uwsgi_subscribe_node *uwsgi_get_subscribe_node(struct uwsgi_subscribe_slot **, char *, uint16_t, int);
int uwsgi_remove_subscribe_node(struct uwsgi_subscribe_slot **, struct uwsgi_subscribe_node *);
struct uwsgi_subscribe_node *uwsgi_add_subscribe_node(struct uwsgi_subscribe_slot **, struct uwsgi_subscribe_req *, int);

ssize_t uwsgi_mule_get_msg(int, int, char *, size_t, int);

uint8_t uwsgi_signal_wait(int);
void uwsgi_add_app(int, uint8_t, char *, int);
int uwsgi_signal_send(int, uint8_t);
int uwsgi_remote_signal_send(char *, uint8_t); 

void uwsgi_configure(void);
void cluster_setup(void);
void manage_cluster_announce(char *, uint16_t, char *, uint16_t, void *);

int uwsgi_read_response(int, struct uwsgi_header *, int, char **);
char *uwsgi_simple_file_read(char *);

void uwsgi_send_subscription(char *, char *, size_t , uint8_t, uint8_t , uint8_t);

void uwsgi_subscribe(char *, uint8_t);

struct uwsgi_daemon *uwsgi_daemon_new(struct uwsgi_daemon **, char *);

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
struct uwsgi_logger *uwsgi_get_logger(char *);

char *uwsgi_getsockname(int);
char *uwsgi_get_var(struct wsgi_request *, char *, uint16_t, uint16_t *);

#ifdef UWSGI_AS_SHARED_LIBRARY
int uwsgi_init(int, char **, char **);
#endif

#ifdef __cplusplus
}
#endif


