/* uWSGI */



#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <poll.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <fcntl.h>

#ifdef UNBIT
#undef _XOPEN_SOURCE
#endif

#ifdef _POSIX_C_SOURCE
        #undef _POSIX_C_SOURCE
#endif
#include <Python.h>

#ifdef UNBIT
#define UWSGI_MODIFIER_HT_S 1
#define UWSGI_MODIFIER_HT_M 2
#define UWSGI_MODIFIER_HT_H 3
#undef _XOPEN_SOURCE
#endif

#ifdef PYTHREE
	#define PyInt_FromLong	PyLong_FromLong
	#define PyInt_AsLong	PyLong_AsLong
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

#define PAGE_SIZE 4096


struct __attribute__((packed)) wsgi_request {
        unsigned char modifier;
        unsigned short size ;
        unsigned char modifier_arg;
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
        unsigned long vsz_size;
        long rss_size;
};


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



void goodbye_cruel_world(void);
void reap_them_all(void);
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

#ifndef UNBIT
void uwsgi_xml_config(void);
#endif

#ifndef ROCK_SOLID
void uwsgi_wsgi_config(void);
#endif
