/* uWSGI */




#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
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
#include <Python.h>


#ifdef __linux__
#include <endian.h>
#elif __sun__
#elif __apple__
#include <libkern/OSByteOrder.h>
#else
#include <machine/endian.h>
#endif

#ifdef UNBIT
#define UWSGI_MODIFIER_HT_S 1
#define UWSGI_MODIFIER_HT_M 2
#define UWSGI_MODIFIER_HT_H 3
#undef _XOPEN_SOURCE
#endif

#define UWSGI_MODIFIER_SPOOL_REQUEST	17
#define UWSGI_MODIFIER_FASTFUNC		26
#define UWSGI_MODIFIER_MANAGE_PATH_INFO	30
#define UWSGI_MODIFIER_PING		100

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

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

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
	int requests;	
#ifndef ROCK_SOLID
	int has_threads;
	int wsgi_cnt;
	int default_app;
	int enable_profiler;
#endif
	int manage_next_request;
	int in_request;

	int buffer_size;

	char *test_module;

	int numproc;

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
#ifndef ROCK_SOLID
	int cgi_mode;
#endif
	int abstract_socket;
	int chmod_socket;
	int listen_queue;
#ifndef ROCK_SOLID
	char *xml_config;
	char *python_path[64];
	int python_path_cnt;
#endif
#endif

#ifndef ROCK_SOLID
	char *wsgi_config;
#endif

#ifndef ROCK_SOLID
	int single_interpreter;
	int py_optimize;

	PyObject *py_sendfile ;
	PyObject *fastfuncslist ;

	PyThreadState *main_thread ;
#endif

	struct pollfd poll;

	int harakiri_timeout;
	int socket_timeout;

#ifndef ROCK_SOLID
	int memory_debug;
#endif

#ifndef ROCK_SOLID
	struct uwsgi_app wsgi_apps[64];
	PyObject *py_apps;
#endif
};


struct __attribute__((packed)) uwsgi_worker {
	pid_t pid;
	time_t last_spawn;
	unsigned long long requests;
	unsigned long long failed_requests;
	time_t harakiri;
	unsigned long long respawn_count;
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
        // memory debug
        unsigned long long vsz_size;
        long long rss_size;
};



char *uwsgi_get_cwd(void);

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
void log_request(void) ;
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
#endif

void init_uwsgi_module_sharedarea(PyObject *);
void init_uwsgi_module_advanced(PyObject *);
void init_uwsgi_module_spooler(PyObject *);

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
