/* uWSGI */

/* indent -i8 -br -brs -brf -l0 -npsl -nip -npcs -npsl -di1 */

#define UWSGI_VERSION	"0.9.6-dev"

#define uwsgi_error(x)  uwsgi_log("%s: %s [%s line %d]\n", x, strerror(errno), __FILE__, __LINE__);
#define uwsgi_debug(x, ...) uwsgi_log("[uWSGI DEBUG] " x, __VA_ARGS__);

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>

#include <dirent.h>

#include <pwd.h>
#include <grp.h>


#include <sys/utsname.h>

// linux has not strlcpy
#ifdef __linux
	#define strlcpy(x, y, z) strcpy(x, y)
	#define strlcat(x, y, z) strcat(x, y)
	#include <sys/prctl.h>
#endif

#ifdef UWSGI_SCTP
#include <netinet/sctp.h>
#endif

#ifdef UWSGI_UGREEN
#include <ucontext.h>
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

#define MAX_PYARGV 10

#include <sys/ioctl.h>

#ifdef __linux__
#include <sys/sendfile.h>
#include <sys/epoll.h>
#elif defined(__sun__)
#include <sys/devpoll.h>
#else
#include <sys/event.h>
#endif

#undef _XOPEN_SOURCE
#include <Python.h>

#ifdef UWSGI_STACKLESS
#include <stackless_api.h>
#endif

#if PY_MINOR_VERSION == 4 && PY_MAJOR_VERSION == 2
#define Py_ssize_t ssize_t
#endif

#if PY_MAJOR_VERSION > 2
#define PYTHREE
#endif

/* this value are taken from nginx */
#if defined(__APPLE__) || defined(__freebsd__)
#define UWSGI_LISTEN_QUEUE -1
#else
#define UWSGI_LISTEN_QUEUE 511
#endif

PyAPI_FUNC(PyObject *) PyMarshal_WriteObjectToString(PyObject *, int);
PyAPI_FUNC(PyObject *) PyMarshal_ReadObjectFromString(char *, Py_ssize_t);

#define MAX_CLUSTER_NODES	100

#define UWSGI_NODE_OK		0
#define UWSGI_NODE_FAILED	1

#define LONG_ARGS_PIDFILE		17001
#define LONG_ARGS_CHROOT		17002
#define LONG_ARGS_GID			17003
#define LONG_ARGS_UID			17004
#define LONG_ARGS_PYTHONPATH		17005
#define LONG_ARGS_PASTE			17006
#define LONG_ARGS_CHECK_INTERVAL	17007
#define LONG_ARGS_PYARGV		17008
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

#ifdef PYTHREE
#define PyInt_FromLong	PyLong_FromLong
#define PyInt_AsLong	PyLong_AsLong
#define PyInt_Check	PyLong_Check
#define PyString_Check	PyUnicode_Check
#define	PyString_FromStringAndSize	PyUnicode_FromStringAndSize
#define	PyString_FromFormat	PyUnicode_FromFormat
#define	PyString_FromString	PyUnicode_FromString
#define	PyString_Size		PyUnicode_GET_DATA_SIZE
#define	PyString_Concat		PyUnicode_Concat
#define	PyString_AsString	(char *) PyUnicode_AS_UNICODE
#define PyFile_FromFile(A,B,C,D) PyFile_FromFd(fileno((A)), (B), (C), -1, NULL, NULL, NULL, 0)
#endif

#define NL_SIZE 2
#define H_SEP_SIZE 2

#define UWSGI_RELOAD_CODE 17
#define UWSGI_END_CODE 30

#define MAX_VARS 64

struct wsgi_request;
struct uwsgi_server;

struct uwsgi_app {

	PyThreadState *interpreter;
	PyObject *pymain_dict;
	PyObject *wsgi_dict;
	PyObject *wsgi_callable;


#ifdef UWSGI_ASYNC
	PyObject **wsgi_args;
	PyObject **wsgi_environ;
#else
	PyObject *wsgi_args;
	PyObject *wsgi_environ;
#endif
	PyObject *wsgi_harakiri;

	PyObject *wsgi_sendfile;
	PyObject *wsgi_cprofile_run;

#ifdef UWSGI_ASYNC
	PyObject *wsgi_eventfd_read;
	PyObject *wsgi_eventfd_write;
#endif

	int requests;

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

	void (*action)(struct uwsgi_server *, struct wsgi_request *, struct uwsgi_route *);
};
#endif

struct __attribute__ ((packed)) uwsgi_header {
	uint8_t modifier1;
	uint16_t pktsize;
	uint8_t modifier2;
};


struct wsgi_request {
	struct uwsgi_header uh;
	// temporary attr

	int app_id;

	struct pollfd poll;

	// this is big enough to contain sockaddr_in
	struct sockaddr_un c_addr;
        int c_len;

	// iovec
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

	char *path_info;
	uint16_t path_info_len;

	char *wsgi_script;
	uint16_t wsgi_script_len;
	char *wsgi_module;
	uint16_t wsgi_module_len;
	char *wsgi_callable;
	uint16_t wsgi_callable_len;
	char *pyhome;
	uint16_t pyhome_len;

	int fd_closed;

	int sendfile_fd;
	size_t sendfile_fd_chunk;
	size_t sendfile_fd_size;
	off_t sendfile_fd_pos;
	void *sendfile_obj;

	uint16_t var_cnt;
	uint16_t header_cnt;

	int status;
	size_t response_size;
	int headers_size;

	int async_id;
	int async_status ;
	int async_waiting_fd;
	int async_waiting_fd_type;
	int async_waiting_fd_monitored;
	int async_switches;

	time_t async_timeout ;
	int async_timeout_expired ;

	void *async_app;
	void *async_result;
#ifdef UWSGI_WSGI2
	void *async_orig_result;
#endif
	void *async_placeholder;
	void *async_args;
	void *async_environ;
	void *async_post;
	void *async_sendfile;
	
	int async_plagued;

	int *ovector;
	size_t post_cl;
	char *post_buffering_buf;
	uint64_t post_buffering_read;

#ifdef UWSGI_STACKLESS
	PyTaskletObject* tasklet;
#endif

	char *buffer;
};

struct uwsgi_server {

	char *pyhome;

	int has_threads;
	int wsgi_cnt;
	int default_app;
	int enable_profiler;

	// base for all the requests (even on async mode)
	struct wsgi_request *wsgi_requests ;
	struct wsgi_request *wsgi_req ;

	PyThreadState *_save;
	char *chroot;
	gid_t gid;
	uid_t uid;

	char *mode;
	char *http;
	char *http_server_name;
	char *http_server_port;
	int http_only;
	int http_fd;

	int ignore_script_name;
	int logdate;

	int serverfd;
#ifdef UWSGI_PROXY
	int proxyfd;
	char *proxy_socket_name;
#endif

	char *logfile;

	int vhost;

	struct iovec *async_hvec;
	char **async_buf;
	char **async_post_buf;

#ifdef UWSGI_ROUTING
	int **async_ovector;
#endif

	struct rlimit rl;
	size_t limit_post;
	int prio;

	int grunt;

	char *binary_path;

	int is_a_reload;

	char *socket_name;

#ifdef UWSGI_UDP
	char *udp_socket;
#endif

#ifdef UWSGI_MULTICAST
	char *multicast_group;
#endif

#ifdef UWSGI_SPOOLER
	char *spool_dir;
#endif

#ifdef UWSGI_ERLANG
	char *erlang_node;
	char *erlang_cookie;
#endif

#ifdef UWSGI_NAGIOS
	int nagios;
#endif

#ifdef UWSGI_SNMP
	int snmp;
	char *snmp_community;
#endif


	int to_heaven;
	int to_hell;

	int buffer_size;

	int post_buffering;
	int post_buffering_harakiri;
	int post_buffering_bufsize;

	int master_process;

	int no_defer_accept;

	int page_size;

	char *test_module;

	char *pidfile;

	int numproc;
	int async;
	int async_running;
	int async_queue ;
	int async_nevents ;

	int stackless;

#ifdef UWSGI_UGREEN
	int ugreen;
	int ugreen_stackpages;
	ucontext_t ugreenmain;
	ucontext_t **ugreen_contexts;
#endif

#ifdef __linux__
	struct epoll_event *async_events;
#elif defined(__sun__)
	struct pollfd *async_events;
#else
	struct kevent *async_events;
#endif

	int max_vars;
	int vec_size;

	char *sharedarea;
	void *sharedareamutex;
	int sharedareasize;

	/* the list of workers */
	struct uwsgi_worker *workers;

	pid_t mypid;
	int mywid;

	struct timeval start_tv;

	int abstract_socket;
	int chmod_socket;
	mode_t chmod_socket_value;
	int listen_queue;

#ifdef UWSGI_XML
	char *xml_config;
#endif
	
	char *file_config;

	char *python_path[64];
	int python_path_cnt;
	char *pyargv;

	int pyargc;
#ifdef PYTHREE
        wchar_t *py_argv[MAX_PYARGV];
#else
        char *py_argv[MAX_PYARGV];
#endif

#ifdef UWSGI_ROUTING
#ifndef MAX_UWSGI_ROUTES
#define MAX_UWSGI_ROUTES 64
#endif
	int routing;
	int nroutes;
	struct uwsgi_route routes[MAX_UWSGI_ROUTES];
#endif

	char *wsgi_config;

#ifdef UWSGI_INI
	char *ini;
#endif
#ifdef UWSGI_PASTE
	char *paste;
#endif
	char *wsgi_file;

	int single_interpreter;
	int py_optimize;

	PyObject *embedded_dict;
	PyObject *embedded_args;
	PyObject *fastfuncslist;

	PyObject *wsgi_writeout;

#ifdef UWSGI_STACKLESS
	PyObject *wsgi_stackless;
	PyChannelObject *workers_channel;
	struct stackless_req **stackless_table;
#endif

	PyObject *workers_tuple;

	PyThreadState *main_thread;


	struct uwsgi_shared *shared;

	struct uwsgi_app wsgi_apps[64];
	PyObject *py_apps;

#ifdef UWSGI_ERLANG
	int erlang_nodes;
	int erlangfd;
#endif

	int no_orphans;

#ifdef UWSGI_EMBED_PLUGINS

#ifdef UWSGI_EMBED_PLUGIN_PSGI
	char *plugin_arg_psgi;
#endif

#ifdef UWSGI_EMBED_PLUGIN_LUA
	char *plugin_arg_lua;
#endif

#ifdef UWSGI_EMBED_PLUGIN_RACK
	char *plugin_arg_rack;
#endif

#endif

	char *chdir2;
	int catch_exceptions;

	int vacuum;
	int bind_to_unix;
	int no_server;

#ifdef UWSGI_LDAP
	char *ldap;
#endif
};

struct uwsgi_cluster_node {
	char name[101];

	struct sockaddr_in ucn_addr;

	int workers;
	int connections;
	int status;

	time_t last_seen;
	int errors;
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

struct uwsgi_shared {

	// vga 80x25 specific !
	char warning_message[81];

	int (*hooks[256]) (struct uwsgi_server *, struct wsgi_request *);
	void (*after_hooks[256]) (struct uwsgi_server *, struct wsgi_request *);
	uint32_t options[256];

	struct uwsgi_cluster_node nodes[MAX_CLUSTER_NODES];

	off_t logsize;

#ifdef UWSGI_SPOOLER
	pid_t spooler_pid;
	int spooler_frequency;
#endif

#ifdef UWSGI_PROXY
	pid_t proxy_pid;
#endif

#ifdef UWSGI_SNMP
	char snmp_community[72 + 1];
	struct uwsgi_snmp_server_value snmp_gvalue[100];
	struct uwsgi_snmp_custom_value snmp_value[100];

#define SNMP_COUNTER32 0x41
#define SNMP_GAUGE 0x42
#define SNMP_COUNTER64 0x46

#endif

};

struct uwsgi_worker {
	int id;
	pid_t pid;
	uint64_t status;

	int i_have_gil;

	time_t last_spawn;
	uint64_t respawn_count;

	uint64_t requests;
	uint64_t failed_requests;

	time_t harakiri;

	uint64_t vsz_size;
	uint64_t rss_size;

	double running_time;
	double last_running_time;

	int manage_next_request;

};

char *uwsgi_get_cwd(void);

void warn_pipe(void);
void goodbye_cruel_world(void);
void gracefully_kill(void);
void reap_them_all(void);
void kill_them_all(void);
void grace_them_all(void);
void reload_me(void);
void end_me(void);
int bind_to_unix(char *, int, int, int);
int bind_to_tcp(char *, int, char *);
int bind_to_udp(char *);
int timed_connect(struct pollfd *, const struct sockaddr *, int, int);
int uwsgi_connect(char *, int);
int connect_to_tcp(char *, int, int);
int connect_to_unix(char *, int);
#ifdef UWSGI_SCTP
int bind_to_sctp(char *, int, char *);
#endif

void daemonize(char *);
void logto(char *);

void log_request(struct wsgi_request *);
void get_memusage(void);
void harakiri(void);

void stats(void);

void init_uwsgi_vars(void);
void init_uwsgi_embedded_module(void);

#ifdef UWSGI_XML
void uwsgi_xml_config(struct wsgi_request *, struct option *);
#endif

void uwsgi_wsgi_config(char *);
void uwsgi_paste_config(void);
void uwsgi_wsgi_file_config(void);

void internal_server_error(int, char *);

void init_uwsgi_module_sharedarea(PyObject *);
void init_uwsgi_module_advanced(PyObject *);
#ifdef UWSGI_SPOOLER
void init_uwsgi_module_spooler(PyObject *);
#endif

#ifdef UWSGI_SNMP
void manage_snmp(int, uint8_t *, int, struct sockaddr_in *);
void snmp_init(void);
#endif

#ifdef UWSGI_SPOOLER
int spool_request(struct uwsgi_server *, char *, int, char *, int);
void spooler(struct uwsgi_server *, PyObject *);
pid_t spooler_start(int, PyObject *);
#endif

void set_harakiri(int);
void inc_harakiri(int);

#ifdef __BIG_ENDIAN__
uint16_t uwsgi_swap16(uint16_t);
uint32_t uwsgi_swap32(uint32_t);
uint64_t uwsgi_swap64(uint64_t);
#endif

int init_uwsgi_app(PyObject *, PyObject *);

PyObject *uwsgi_send_message(const char *, int, uint8_t, uint8_t, char *, int, int);

#ifdef UWSGI_UDP
ssize_t send_udp_message(uint8_t, char *, char *, uint16_t); 
#endif

int uwsgi_parse_response(struct pollfd *, int, struct uwsgi_header *, char *);
int uwsgi_parse_vars(struct uwsgi_server *, struct wsgi_request *);

int uwsgi_enqueue_message(char *, int, uint8_t, uint8_t, char *, int, int);

/* included HOOKS */
int uwsgi_request_wsgi(struct uwsgi_server *, struct wsgi_request *);
void uwsgi_after_request_wsgi(struct uwsgi_server *, struct wsgi_request *);

int uwsgi_request_admin(struct uwsgi_server *, struct wsgi_request *);
#ifdef UWSGI_SPOOLER
int uwsgi_request_spooler(struct uwsgi_server *, struct wsgi_request *);
#endif
int uwsgi_request_eval(struct uwsgi_server *, struct wsgi_request *);
int uwsgi_request_fastfunc(struct uwsgi_server *, struct wsgi_request *);
int uwsgi_request_marshal(struct uwsgi_server *, struct wsgi_request *);
int uwsgi_request_ping(struct uwsgi_server *, struct wsgi_request *);

#ifdef UWSGI_ERLANG

#include <erl_interface.h>
#include <ei.h>

int init_erlang(char *, char *);
void erlang_loop(struct wsgi_request *);
PyObject *eterm_to_py(ETERM *);
ETERM *py_to_eterm(PyObject *);

#endif

void manage_opt(int, char *);

#ifdef UWSGI_PROXY
void uwsgi_proxy(int);
pid_t proxy_start(int);
#endif

void uwsgi_cluster_add_node(char *, int);
int uwsgi_ping_node(int, struct wsgi_request *);

struct http_status_codes {
	char key[3];
	char *message;
	int message_size;
};

#ifdef UWSGI_ASYNC
struct wsgi_request *async_loop(struct uwsgi_server *);
struct wsgi_request *find_first_available_wsgi_req(struct uwsgi_server *); 
struct wsgi_request *find_wsgi_req_by_fd(struct uwsgi_server *, int, int); 
struct wsgi_request *find_wsgi_req_by_id(struct uwsgi_server *, int); 

#ifdef __clang__
struct wsgi_request *next_wsgi_req(struct uwsgi_server *, struct wsgi_request *);
#else
inline struct wsgi_request *next_wsgi_req(struct uwsgi_server *, struct wsgi_request *);
#endif


int async_add(int, int , int) ;
int async_mod(int, int , int) ;
int async_wait(int, void *, int, int, int);
int async_del(int, int , int) ;
int async_queue_init(int);

int async_get_timeout(struct uwsgi_server *);
void async_set_timeout(struct wsgi_request *, time_t);
void async_expire_timeouts(struct uwsgi_server *);
void async_write_all(struct uwsgi_server *, char *, size_t);
void async_unpause_all(struct uwsgi_server *);

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

PyObject *py_eventfd_read(PyObject *, PyObject *) ;
PyObject *py_eventfd_write(PyObject *, PyObject *) ;


#endif

#ifdef UWSGI_STACKLESS
PyObject *py_uwsgi_stackless(PyObject *, PyObject *) ;
#endif

int manage_python_response(struct uwsgi_server *, struct wsgi_request *);
int uwsgi_python_call(struct uwsgi_server *, struct wsgi_request *, PyObject *, PyObject *);
PyObject *python_call(PyObject *, PyObject *, int);

#ifdef UWSGI_SENDFILE
PyObject *py_uwsgi_sendfile(PyObject *, PyObject *) ;
ssize_t uwsgi_sendfile(struct uwsgi_server *, struct wsgi_request *);
ssize_t uwsgi_do_sendfile(int, int, size_t, size_t, off_t*, int);
#endif

PyObject *py_uwsgi_write(PyObject *, PyObject *) ;
PyObject *py_uwsgi_spit(PyObject *, PyObject *) ;

void uwsgi_as_root(void);

#ifdef UWSGI_NAGIOS
void nagios(struct uwsgi_server *);
#endif


#ifdef UWSGI_STACKLESS
struct stackless_req {
	PyTaskletObject *tasklet;
	struct wsgi_request *wsgi_req;
	PyChannelObject *channel;
};
struct wsgi_request *find_request_by_tasklet(PyTaskletObject *);

void stackless_init(struct uwsgi_server *);
void stackless_loop(struct uwsgi_server *);
#endif

void uwsgi_close_request(struct uwsgi_server *, struct wsgi_request *) ;

void wsgi_req_setup(struct wsgi_request *, int);
int wsgi_req_recv(struct wsgi_request *);
int wsgi_req_accept(int, struct wsgi_request *);

#ifdef UWSGI_UGREEN
void u_green_init(struct uwsgi_server *);
void u_green_loop(struct uwsgi_server *);
#endif

#ifdef __clang__
struct wsgi_request *current_wsgi_req(struct uwsgi_server *);
#else
inline struct wsgi_request *current_wsgi_req(struct uwsgi_server *);
#endif

void sanitize_args(struct uwsgi_server *);

void env_to_arg(char *, char *);
void parse_sys_envs(char **, struct option *);

void uwsgi_log(const char *, ...);


#ifdef UWSGI_EVDIS
#define EVDIS_TYPE_FILE
#define EVDIS_TYPE_DNSSD
#endif

int uwsgi_load_plugin(struct uwsgi_server *, int, char *, char *, int);
void embed_plugins(struct uwsgi_server *);


// PLUGINS

#define UWSGI_PLUGIN_LONGOPT_PSGI
#define UWSGI_PLUGIN_LONGOPT_LUA
#define UWSGI_PLUGIN_LONGOPT_RACK
#define LONG_ARGS_PLUGIN_EMBED_PSGI
#define LONG_ARGS_PLUGIN_EMBED_LUA
#define LONG_ARGS_PLUGIN_EMBED_RACK



#ifdef UWSGI_EMBED_PLUGINS


#ifdef UWSGI_EMBED_PLUGIN_PSGI

#undef UWSGI_PLUGIN_LONGOPT_PSGI
#define UWSGI_PLUGIN_LONGOPT_PSGI {"psgi", required_argument, 0, 30005},

#undef LONG_ARGS_PLUGIN_EMBED_PSGI
#define LONG_ARGS_PLUGIN_EMBED_PSGI case 30005:\
					uwsgi.plugin_arg_psgi = optarg;\
					break;
#endif

#ifdef UWSGI_EMBED_PLUGIN_LUA

#undef UWSGI_PLUGIN_LONGOPT_LUA
#define UWSGI_PLUGIN_LONGOPT_LUA {"lua", required_argument, 0, 30006},

#undef LONG_ARGS_PLUGIN_EMBED_LUA
#define LONG_ARGS_PLUGIN_EMBED_LUA case 30006:\
					uwsgi.plugin_arg_lua = optarg;\
					break;
#endif

#ifdef UWSGI_EMBED_PLUGIN_RACK

#undef UWSGI_PLUGIN_LONGOPT_RACK
#define UWSGI_PLUGIN_LONGOPT_RACK {"rack", required_argument, 0, 30007},

#undef LONG_ARGS_PLUGIN_EMBED_RACK
#define LONG_ARGS_PLUGIN_EMBED_RACK case 30007:\
					uwsgi.plugin_arg_rack = optarg;\
					break;
#endif


#endif

#ifdef UWSGI_ROUTING
void routing_setup(struct uwsgi_server *);
void check_route(struct uwsgi_server *, struct wsgi_request *);
void uwsgi_route_action_uwsgi(struct uwsgi_server *, struct wsgi_request *, struct uwsgi_route *);
void uwsgi_route_action_wsgi(struct uwsgi_server *, struct wsgi_request *, struct uwsgi_route *);
#endif

void init_pyargv(struct uwsgi_server *);

void http_loop(struct uwsgi_server *);

int unconfigured_hook(struct uwsgi_server *, struct wsgi_request *);

#ifdef UWSGI_INI
void uwsgi_ini_config(char *, struct option*);
#endif


#ifdef UWSGI_LDAP
void uwsgi_ldap_schema_dump(struct option*);
void uwsgi_ldap_schema_dump_ldif(struct option*);
void uwsgi_ldap_config(struct uwsgi_server *, struct option*);
#endif
