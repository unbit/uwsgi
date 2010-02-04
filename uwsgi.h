/* uWSGI */




#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/file.h>


#include <stdint.h>


#include <poll.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <fcntl.h>
#include <pthread.h>

#include <sys/resource.h>

#ifndef UNBIT
#ifndef ROCK_SOLID
#include <getopt.h>
#endif
#endif


#ifdef __APPLE__
	#include <libkern/OSAtomic.h>
	#include <mach/task.h>
	#include <mach/mach_init.h>
#endif

#ifdef UNBIT
#undef _XOPEN_SOURCE
#include "unbit.h"
#endif

#ifdef _POSIX_C_SOURCE
        #undef _POSIX_C_SOURCE
#endif
#ifdef __sun__
#undef _FILE_OFFSET_BITS
#define WAIT_ANY (-1)
#endif

#define MAX_PYARGV 10

#include <Python.h>

#if PY_MINOR_VERSION == 4 && PY_MAJOR_VERSION == 2
	#define Py_ssize_t int
#endif

#if PY_MAJOR_VERSION > 2
	#define PYTHREE
#endif

PyAPI_FUNC(PyObject *) PyMarshal_WriteObjectToString(PyObject *, int);
PyAPI_FUNC(PyObject *) PyMarshal_ReadObjectFromString(char *, Py_ssize_t);


#define LONG_ARGS_PIDFILE		17001
#define LONG_ARGS_CHROOT		17002
#define LONG_ARGS_GID			17003
#define LONG_ARGS_UID			17004
#define LONG_ARGS_PYTHONPATH		17005
#define LONG_ARGS_PASTE			17006
#define LONG_ARGS_CHECK_INTERVAL	17007
#define LONG_ARGS_PYARGV		17008
#define LONG_ARGS_LIMIT_AS		17009


#ifdef __linux__
#include <endian.h>
#elif __sun__
#elif __apple__
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

#ifdef UNBIT
#define UWSGI_MODIFIER_HT_S 1
#define UWSGI_MODIFIER_HT_M 2
#define UWSGI_MODIFIER_HT_H 3
#undef _XOPEN_SOURCE
#endif

#define UWSGI_MODIFIER_ADMIN_REQUEST	10
#define UWSGI_MODIFIER_SPOOL_REQUEST	17
#define UWSGI_MODIFIER_FASTFUNC		26
#define UWSGI_MODIFIER_MANAGE_PATH_INFO	30
#define UWSGI_MODIFIER_MESSAGE		31
#define UWSGI_MODIFIER_MESSAGE_ARRAY	32
#define UWSGI_MODIFIER_MESSAGE_MARSHAL	33
#define UWSGI_MODIFIER_PING		100

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
	#define	PyString_AsString	(char *) PyUnicode_AS_UNICODE
	#define PyFile_FromFile(A,B,C,D) PyFile_FromFd(fileno((A)), (B), (C), -1, NULL, NULL, NULL, 0)
#endif


#define NL_SIZE 2
#define H_SEP_SIZE 2

#define UWSGI_RELOAD_CODE 17
#define UWSGI_END_CODE 30

#define MAX_VARS 64

struct uwsgi_app {
#ifndef ROCK_SOLID
        PyThreadState *interpreter ;
        PyObject *pymain_dict ;
#endif

#ifdef ROCK_SOLID
        PyObject *wsgi_module;
        PyObject *wsgi_dict;
#endif
        PyObject *wsgi_callable ;
        PyObject *wsgi_environ ;
        PyObject *wsgi_args;
        PyObject *wsgi_harakiri;
#ifndef ROCK_SOLID
        PyObject *wsgi_sendfile;
        PyObject *wsgi_cprofile_run;
        int requests ;
#endif
};


struct uwsgi_server {
	char *pyhome;
#ifndef ROCK_SOLID
	int has_threads;
	int wsgi_cnt;
	int default_app;
	int enable_profiler;
#ifndef UNBIT
	char *chroot;
	gid_t gid;
	uid_t uid;
#endif
#endif

	int to_heaven ;
	int to_hell ;

	int buffer_size;

	int master_process;

	int no_defer_accept;

	int page_size ;

	char *sync_page ;
	int synclog;

	char *test_module;

	char *pidfile;

	int numproc;
	int maxworkers;

	int max_vars ;
	int vec_size ;

	char *sharedarea ;
#ifndef __OpenBSD__
	void *sharedareamutex ;
#endif
	int sharedareasize ;

	/* the list of workers */
	struct uwsgi_worker *workers ;
	pid_t mypid;
	int mywid;

	struct timeval start_tv;
#ifndef UNBIT
	int abstract_socket;
	int chmod_socket;
	int listen_queue;
#ifndef ROCK_SOLID
	char *xml_config;
	char *python_path[64];
	int python_path_cnt;
	char *pyargv ;
#endif
#endif

#ifndef ROCK_SOLID
	char *wsgi_config;
	char *paste;
#endif

#ifndef ROCK_SOLID
	int single_interpreter;
	int py_optimize;

	PyObject *py_sendfile ;
	PyObject *embedded_dict ;
	PyObject *embedded_args ;
	PyObject *fastfuncslist ;

	PyObject *workers_tuple ;

	PyThreadState *main_thread ;
#endif

	struct pollfd poll;

	uint32_t *options;

#ifndef ROCK_SOLID
	struct uwsgi_app wsgi_apps[64];
	PyObject *py_apps;
#endif
};


struct __attribute__((packed)) uwsgi_worker {
	int id ;
	pid_t pid;
	time_t last_spawn;
	unsigned long long requests;
	unsigned long long failed_requests;
	time_t harakiri;
	unsigned long long respawn_count;

	unsigned long long vsz_size;
	unsigned long long rss_size;
	double running_time ;

	double load ;

	double last_running_time ;

	int in_request;
	int manage_next_request;
	int blocking ;
	int current_workers ;
};

struct __attribute__((packed)) uwsgi_header {
	uint8_t	modifier1;
	uint16_t pktsize ;
	uint8_t	modifier2;
};

struct __attribute__((packed)) wsgi_request {
        uint8_t modifier;
        uint16_t size ;
        uint8_t modifier_arg;
        // temporary attr
#ifndef ROCK_SOLID
        int app_id ;
#endif
        struct timeval start_of_request ;
        char *uri;
        unsigned short uri_len;
        char *remote_addr;
        unsigned short remote_addr_len;
        char *remote_user;
        unsigned short remote_user_len;
        char *query_string;
        unsigned short query_string_len;
        char *protocol;
        unsigned short protocol_len;
        char *method;
        unsigned short method_len;
#ifdef UNBIT
	unsigned long long unbit_flags;
#endif
#ifndef ROCK_SOLID
        char *wsgi_script;
        unsigned short wsgi_script_len;
        char *wsgi_module;
        unsigned short wsgi_module_len;
        char *wsgi_callable;
        unsigned short wsgi_callable_len;
        char *script_name;
        unsigned short script_name_len;
        int sendfile_fd;
#endif
        unsigned short var_cnt;
        unsigned short header_cnt;
        int status;
        int response_size;
        int headers_size;
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
int bind_to_unix(char *, int,  int , int );
int bind_to_tcp(char *, int , char *);
#ifndef UNBIT
void daemonize(char *);
#endif
void log_request(struct wsgi_request*) ;
#ifndef ROCK_SOLID
void get_memusage(void) ;
#endif
void harakiri(void) ;
#ifndef UNBIT
void stats(void) ;
#endif
void init_uwsgi_vars(void);
void init_uwsgi_embedded_module(void);

#ifndef UNBIT
void uwsgi_xml_config(void);
#endif

#ifndef ROCK_SOLID
void uwsgi_wsgi_config(void);
void uwsgi_paste_config(void);
#endif

void init_uwsgi_module_sharedarea(PyObject *);
void init_uwsgi_module_advanced(PyObject *);
void init_uwsgi_module_spooler(PyObject *);

uint64_t get_free_memory(void);

#ifndef ROCK_SOLID
int spool_request(char *, int, char *, int);
void spooler(PyObject *);
pid_t spooler_start(int, PyObject *);
#endif

void set_harakiri(int);

#ifdef __BIG_ENDIAN__
uint16_t uwsgi_swap16( uint16_t );
#endif

#ifndef ROCK_SOLID
int init_uwsgi_app(PyObject *, PyObject *) ;
#endif

PyObject *uwsgi_send_message(const char *, int, uint8_t, uint8_t, char *, int, int);

int uwsgi_parse_response(struct pollfd*, int, struct uwsgi_header *, char *);

int uwsgi_enqueue_message(char *, int, uint8_t, uint8_t, char *, int, int);
