/* 
	
    *** uWSGI ***

    Copyright 2009 Unbit S.a.s. <info@unbit.it>
	
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.



Compile on Linux 2.6
gcc -o uwsgi `python2.5-config --cflags` `python2.5-config --libs` `xml2-config --cflags` `xml2-config --libs` uwsgi.c
gcc -o uwsgi26 `python2.6-config --cflags` `python2.6-config --libs` `xml2-config --cflags` `xml2-config --libs` uwsgi.c
gcc -o uwsgi24 `python2.4-config --cflags` `python2.4-config --libs` `xml2-config --cflags` `xml2-config --libs` uwsgi.c
Compile on Unbit
gcc -o /usr/share/unbit/uwsgi `python2.5-config --cflags` `python2.5-config --libs` -DUNBIT uwsgi.c
gcc -o /usr/share/unbit/uwsgi26 `python2.6-config --cflags` `python2.6-config --libs` -DUNBIT uwsgi.c
gcc -o /usr/share/unbit/uwsgi24 `python2.4-config --cflags` `python2.4-config --libs` -DUNBIT uwsgi.c
(dapper)  gcc -o uwsgi24 -I/usr/include/python2.4 -I/usr/include/python2.4 -fno-strict-aliasing -DNDEBUG -g -O3 -Wall -Wstrict-prototypes -lpthread -ldl -lutil -lm -lpython2.4 -DUNBIT uwsgi.c
Compile on *BSD (FreeBSD and OSX)
gcc -o uwsgi `python2.5-config --cflags` `python2.5-config --libs` `xml2-config --cflags` `xml2-config --libs` -DBSD uwsgi.c


Compile ROCK_SOLID mode
gcc -o uwsgi_rs `python2.5-config --cflags` `python2.5-config --libs` -DROCK_SOLID uwsgi.c
gcc -o uwsgi26_rs `python2.6-config --cflags` `python2.6-config --libs` -DROCK_SOLID uwsgi.c


********* Note for OSX/BSD *********
the sockaddr_un structure is defined as
struct sockaddr_un {
        unsigned char  sun_len;
        sa_family_t    sun_family;
        char           sun_path[104];
};

to get the size of addr:
	s_addr.sun_path-s_addr

the sendfile() prototype on BSD is different
************************************

********* Note for Linux users *********
uWSGI supports UNIX socket on abstract namespace.
Use them if you have filesystem permission problems.

********* Note for Unbit users *********
Try to keep the same configuration on your unbit account (threading mode
in particular)

*/
#include <poll.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>


#ifndef ROCK_SOLID
#ifndef BSD
	#include <sys/sendfile.h>
#endif
#endif

#ifdef _POSIX_C_SOURCE
        #undef _POSIX_C_SOURCE
#endif
#include <Python.h>

#ifndef UNBIT

#ifndef ROCK_SOLID
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif
#include <fcntl.h>
#include <sys/wait.h>

#endif


#ifndef ROCK_SOLID
int init_uwsgi_app(void) ;
#endif


char *nl = "\r\n";
#define NL_SIZE 2
char *h_sep = ": " ;
#define H_SEP_SIZE 2

#define PAGE_SIZE 4096

int requests = 0 ;

#ifndef ROCK_SOLID
int has_threads = 0 ;
int wsgi_cnt = 1;
int default_app = -1 ;
int enable_profiler = 0;
#endif

int buffer_size = 4096 ;

// save my pid for logging
pid_t mypid;

struct timeval start_of_uwsgi ;

#ifndef UNBIT
#ifndef ROCK_SOLID
int cgi_mode = 0 ;
#endif
int abstract_socket = 0 ;
int chmod_socket = 0 ;
int listen_queue = 64 ;
#ifndef ROCK_SOLID
char *xml_config = NULL;
char *python_path[64];
int python_path_cnt = 0 ;
#endif
#endif

#ifndef ROCK_SOLID
int single_interpreter = 0 ;
int py_optimize = 0 ;

PyObject *py_sendfile ;

PyThreadState *wsgi_thread ;
#endif

struct pollfd wsgi_poll; 

int harakiri_timeout = 60 ;

PyObject *wsgi_writeout ;

#define MAX_VARS 64

int max_vars = MAX_VARS ;
int vec_size = 4+1+(4*MAX_VARS) ;

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
void daemonize(char *);
#endif

struct __attribute__((packed)) wsgi_request {
        unsigned char version;
        unsigned short size ;
        unsigned char pad_id ;     
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
} wsgi_req;

// iovec
struct iovec *hvec ;

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
#ifndef ROCK_SOLID
        PyObject *wsgi_sendfile;
        PyObject *wsgi_cprofile_run;
        int requests ;
#endif
};

#ifdef ROCK_SOLID
struct uwsgi_app *wi;
#endif

#ifndef ROCK_SOLID
struct uwsgi_app wsgi_apps[64] ;
PyObject *py_apps ;
#endif


void harakiri() {
        PyThreadState *_myself ;        
        _myself =  PyThreadState_Get();
        fprintf(stderr,"\nF*CK !!! i must kill myself (pid %d) %p %p...\n", mypid,  _myself, _myself->frame);
        Py_FatalError("HARAKIRI !\n");
}

#ifndef UNBIT
#ifndef ROCK_SOLID
void stats() {
	struct uwsgi_app *ua = NULL;
	int i;

	fprintf(stderr, "*** pid %d stats ***\n", getpid());
	fprintf(stderr, "\ttotal requests: %d\n", requests);
	for(i=0;i<wsgi_cnt;i++) {
		ua = &wsgi_apps[i];
		if (ua) {
			fprintf(stderr, "\tapp %d requests: %d\n", i, ua->requests);
		}
	}
	fprintf(stderr, "\n");
}
#endif
#endif

void internal_server_error(int fd, char *message) {
#ifndef UNBIT
#ifndef ROCK_SOLID
	if (cgi_mode == 0) {
#endif
#endif
        	wsgi_req.headers_size = write(fd, "HTTP/1.1 500 Internal Server Error\r\n\r\n", 38);
#ifndef UNBIT
#ifndef ROCK_SOLID
	}
	else {
        	wsgi_req.headers_size = write(fd, "Status: 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 62);
	}
#endif
#endif
        wsgi_req.response_size = write(fd, "<h1>uWSGI Error</h1>", 20);
        wsgi_req.response_size += write(fd, message, strlen(message));
}

#ifndef ROCK_SOLID
PyObject *py_uwsgi_sendfile(PyObject *self, PyObject *args) {

        PyObject *zero ;

        py_sendfile = PyTuple_GetItem(args, 0);

        if (PyFile_Check(py_sendfile)) {
                zero = PyFile_Name(py_sendfile) ;
                //fprintf(stderr,"->serving %s as static file...", PyString_AsString(zero));
                wsgi_req.sendfile_fd = PyObject_AsFileDescriptor(py_sendfile);
                Py_INCREF(py_sendfile);
        }


        return PyTuple_New(0);
}
#endif

PyObject *py_uwsgi_write(PyObject *self, PyObject *args) {
        PyObject *data;
        char *content ;
        int len;
        data = PyTuple_GetItem(args, 0);
        if (PyString_Check(data)) {
                content = PyString_AsString(data) ;
                len = PyString_Size(data);
#ifndef ROCK_SOLID
                if (has_threads) {
                        Py_BEGIN_ALLOW_THREADS
                        wsgi_req.response_size = write(wsgi_poll.fd, content, len);
                        Py_END_ALLOW_THREADS
                }
                else {
#endif
                        wsgi_req.response_size = write(wsgi_poll.fd, content, len);
#ifndef ROCK_SOLID
                }
#endif
        }
        Py_INCREF(Py_None);
        return Py_None;
}


PyObject *wsgi_spitout;

PyObject *py_uwsgi_spit(PyObject *self, PyObject *args) {
        PyObject *headers, *head ;
        PyObject *h_key, *h_value;
        int i,j ;
#ifndef UNBIT
#ifdef ROCK_SOLID
	int base = 4 ;
#else
	int base = 0 ;
#endif
#else
	int base = 4 ;
#endif

        // use writev()

        head = PyTuple_GetItem(args,0) ;
#ifndef UNBIT
#ifndef ROCK_SOLID
	if (cgi_mode == 0) {
		base = 4 ;
#endif
#endif


        	hvec[0].iov_base = wsgi_req.protocol ;
        	hvec[0].iov_len = wsgi_req.protocol_len ;
        	hvec[1].iov_base = " " ;
        	hvec[1].iov_len = 1 ;
        	hvec[2].iov_base = PyString_AsString(head) ;
        	hvec[2].iov_len = PyString_Size(head) ;
        	wsgi_req.status = atoi(hvec[2].iov_base) ;
        	hvec[3].iov_base = nl ;
        	hvec[3].iov_len = NL_SIZE ;
#ifndef UNBIT
#ifndef ROCK_SOLID
	}
	else {
		// drop http status on cgi mode
		base = 3 ;
        	hvec[0].iov_base = "Status: " ;
        	hvec[0].iov_len = 8 ;
        	hvec[1].iov_base = PyString_AsString(head) ;
        	hvec[1].iov_len = PyString_Size(head) ;
        	wsgi_req.status = atoi(hvec[1].iov_base) ;
        	hvec[2].iov_base = nl ;
        	hvec[2].iov_len = NL_SIZE ;
	}
#endif
#endif
        
        headers = PyTuple_GetItem(args,1) ;
        wsgi_req.header_cnt = PyList_Size(headers) ;

        if (wsgi_req.header_cnt > max_vars) {
                wsgi_req.header_cnt = max_vars ;
        }
        for(i=0;i<wsgi_req.header_cnt;i++) {
                j = (i*4)+base ;
                head = PyList_GetItem(headers, i);
                h_key = PyTuple_GetItem(head,0) ;
                h_value = PyTuple_GetItem(head,1) ;
                hvec[j].iov_base = PyString_AsString(h_key) ;
                hvec[j].iov_len = PyString_Size(h_key) ;
                hvec[j+1].iov_base = h_sep;
                hvec[j+1].iov_len = H_SEP_SIZE;
                hvec[j+2].iov_base = PyString_AsString(h_value) ;
                hvec[j+2].iov_len = PyString_Size(h_value) ;
                hvec[j+3].iov_base = nl;
                hvec[j+3].iov_len = NL_SIZE;
		//fprintf(stderr, "%.*s: %.*s\n", hvec[j].iov_len, (char *)hvec[j].iov_base, hvec[j+2].iov_len, (char *) hvec[j+2].iov_base);
        }

        // \r\n
        j = (i*4)+base ;
        hvec[j].iov_base = nl;
        hvec[j].iov_len = NL_SIZE;

        wsgi_req.headers_size = writev(wsgi_poll.fd, hvec,j+1);
        Py_INCREF(wsgi_writeout);

        return wsgi_writeout ;
}


PyMethodDef uwsgi_spit_method[] = {{"uwsgi_spit", py_uwsgi_spit, METH_VARARGS, ""}} ;
PyMethodDef uwsgi_write_method[] = {{"uwsgi_write", py_uwsgi_write, METH_VARARGS, ""}} ;

#ifndef ROCK_SOLID
PyMethodDef uwsgi_sendfile_method[] = {{"uwsgi_sendfile", py_uwsgi_sendfile, METH_VARARGS, ""}} ;
#endif


#ifndef UNBIT
pid_t masterpid;
pid_t diedpid;
int waitpid_status;
int master_process = 0;
#endif

#ifndef ROCK_SOLID
// flag for memory debug
int memory_debug = 0 ;
#endif

int main(int argc, char *argv[]) {

        PyObject *wsgi_result, *wsgi_chunks, *wchunk;
        PyObject *zero, *wsgi_socket;
#ifndef ROCK_SOLID
        PyThreadState *_save = NULL;
#endif

        FILE *wsgi_file;
        struct sockaddr_un c_addr ;
        int c_len = sizeof(struct sockaddr_un);
        int rlen,i ;
        pid_t pid ;
        
        int serverfd = 0 ;
#ifndef UNBIT
        char *socket_name = NULL ;
        struct sockaddr_un *s_addr;
#endif

        PyObject *pydictkey, *pydictvalue;

        char *buffer ;
        char *ptrbuf ;
        char *bufferend ;

        unsigned short strsize;
        struct uwsgi_app *wi;

        int numproc = 1;


	gettimeofday(&start_of_uwsgi, NULL) ;

	setlinebuf(stdout);

#ifndef UNBIT
	#ifndef ROCK_SOLID
        while ((i = getopt (argc, argv, "s:p:t:x:d:l:O:v:b:mcaCTPiMh")) != -1) {
	#else
        while ((i = getopt (argc, argv, "s:p:t:d:l:v:b:aCMh")) != -1) {
	#endif
#else
        while ((i = getopt (argc, argv, "p:t:mTPiv:b:")) != -1) {
#endif
                switch(i) {
#ifndef UNBIT
			case 'd':
				daemonize(optarg);
				break;
                        case 's':
                                socket_name = optarg;
                                break;
#ifndef ROCK_SOLID
			case 'x':
				xml_config = optarg;
				break;
#endif
			case 'l':
				listen_queue = atoi(optarg);
				break;
#endif
                        case 'v':
                                max_vars = atoi(optarg);
				vec_size = 4+1+(4*max_vars) ;
                                break;
                        case 'p':
                                numproc = atoi(optarg);
                                break;
#ifndef ROCK_SOLID
                        case 'm':
                                memory_debug = 1 ;
                                break;
                        case 'O':
                                py_optimize = atoi(optarg) ;
                                break;
#endif
                        case 't':
                                harakiri_timeout = atoi(optarg);
                                break;
			case 'b':
				buffer_size = atoi(optarg);
				break;
#ifndef UNBIT
#ifndef ROCK_SOLID
                        case 'c':
                                cgi_mode = 1;
                                break;
#endif
                        case 'a':
                                abstract_socket = 1;
                                break;
                        case 'C':
                                chmod_socket = 1;
                                break;
                        case 'M':
                                master_process = 1;
                                break;
#endif
#ifndef ROCK_SOLID
                        case 'T':
                                has_threads = 1;
                                break;
                        case 'P':
                                enable_profiler = 1;
                                break;
                        case 'i':
                                single_interpreter = 1;
                                break;
#endif
#ifndef UNBIT
			case 'h':
				fprintf(stderr, "Usage: %s [options...]\n\
\t-s <name>\tpath (or name) of UNIX socket to bind to\n\
\t-l <num>\tset socket listen queue to <n>\n\
\t-b <n>\t\tset buffer size to <n> bytes\n\
\t-x <path>\tpath of xml config file (no ROCK_SOLID)\n\
\t-t <sec>\tset harakiri timeout to <sec> seconds\n\
\t-p <n>\t\tspawn <n> uwsgi worker processes\n\
\t-O <n>\t\tset python optimization level to <n> (no ROCK_SOLID)\n\
\t-v <n>\t\tset maximum number of vars/headers to <n>\n\
\t-c\t\tset cgi mode (no ROCK_SOLID) \n\
\t-C\t\tchmod socket to 666\n\
\t-P\t\tenable profiler (no ROCK_SOLID)\n\
\t-m\t\tenable memory usage report (Linux only, no ROCK_SOLID)\n\
\t-i\t\tsingle interpreter mode (no ROCK_SOLID)\n\
\t-a\t\tset socket in the abstract namespace (Linux only)\n\
\t-T\t\tenable threads support (no ROCK_SOLID)\n\
\t-M\t\tenable master process manager\n\
\t-h\t\tthis help\n\
\t-d <logfile>	daemonize and log into <logfile>\n", argv[0]);
				exit(1);
			default:
				exit(1);
#endif
                }
        }

#ifndef UNBIT
#ifndef ROCK_SOLID
	if (cgi_mode == 0) {
#endif
#endif
        	fprintf(stderr,"*** Starting uWSGI on [%.*s] ***\n", 24, ctime(&start_of_uwsgi.tv_sec));
#ifndef UNBIT
#ifndef ROCK_SOLID
	}
	else {
        	fprintf(stderr,"*** Starting uWSGI (CGI mode) on [%.*s] ***\n", 24, ctime(&start_of_uwsgi.tv_sec));
	}
#endif
#endif

	Py_SetProgramName("uWSGI");
        Py_Initialize() ;



        wsgi_spitout = PyCFunction_New(uwsgi_spit_method,NULL) ;
        wsgi_writeout = PyCFunction_New(uwsgi_write_method,NULL) ;

#ifdef ROCK_SOLID

	wi = malloc(sizeof(struct uwsgi_app));
	if (wi == NULL) {
		perror("malloc()");
		exit(1);
	}
	memset(wi, 0, sizeof(struct uwsgi_app));

	// load wsgi module/script
	for (i = optind; i < argc; i++) {
		init_uwsgi_vars();
		wi->wsgi_module = PyImport_ImportModule(argv[i]);
		if (!wi->wsgi_module) {
			PyErr_Print();
			exit(1);
		}
		wi->wsgi_dict = PyModule_GetDict(wi->wsgi_module);
		if (!wi->wsgi_dict) {
			PyErr_Print();
			exit(1);
		}
		wi->wsgi_callable = PyDict_GetItemString(wi->wsgi_dict, "application");
		if (!wi->wsgi_callable) {
			PyErr_Print();
			exit(1);
		}
		wi->wsgi_environ = PyDict_New();
		if (!wi->wsgi_environ) {
			PyErr_Print();
			exit(1);
		}
		wi->wsgi_args = PyTuple_New(2) ;
		if (!wi->wsgi_args) {
			PyErr_Print();
			exit(1);
		}
		if (PyTuple_SetItem(wi->wsgi_args,0, wi->wsgi_environ)) {
			PyErr_Print();
			exit(1);
		}
		if (PyTuple_SetItem(wi->wsgi_args,1, wsgi_spitout)) {
			PyErr_Print();
			exit(1);
		}
		break;	
	}

	if (!wi->wsgi_module) {
		fprintf(stderr,"unable to find the wsgi script. Have you specified it ?\n");
		exit(1);
	}
#endif

#ifndef ROCK_SOLID
	Py_OptimizeFlag = py_optimize;

        wsgi_thread = PyThreadState_Get();


        if (has_threads) {
                PyEval_InitThreads() ;
                fprintf(stderr, "threads support enabled\n");
        }

#endif

#ifndef UNBIT
        if (socket_name != NULL) {
                fprintf(stderr, "binding on UNIX socket: %s\n", socket_name);

		// leave 1 byte for abstract namespace (108 linux -> 104 bsd/mac)
                if (strlen(socket_name) > 102) {
                	fprintf(stderr, "invalid socket name\n");
                	exit(1);
                }

                s_addr = malloc(sizeof(struct sockaddr_un));
                if (s_addr == NULL) {
                        perror("malloc()");
                        exit(1);
                }
                memset(s_addr, 0, sizeof(struct sockaddr_un)) ;
                serverfd = socket(AF_UNIX, SOCK_STREAM, 0);
                if (serverfd < 0) {
                        perror("socket()");
                        exit(1);
                }
		if (abstract_socket == 0) {
                	if (unlink(socket_name) != 0) {
                        	perror("unlink()");
                	}
		}

		if (abstract_socket ==1) {
			fprintf(stderr, "setting abstract socket mode (warning: only Linux supports this)\n");
		}
                s_addr->sun_family = AF_UNIX;
               	strcpy(s_addr->sun_path+abstract_socket, socket_name);
                
                if (bind(serverfd, (struct sockaddr *) s_addr, strlen(socket_name)+ abstract_socket + ( (void *)s_addr->sun_path - (void *)s_addr) ) != 0) {
                        perror("bind()");
                        exit(1);
                }

                if (listen(serverfd, listen_queue) != 0) {
                        perror("listen()");
                        exit(1);
                }

		// chmod unix socket for lazy users
		if (chmod_socket == 1 && abstract_socket == 0) {
			fprintf(stderr, "chmod() socket to 666 for lazy and brave users\n");
			if (chmod(socket_name, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) != 0) {
				perror("chmod()");
			}
		}
                
        }
#endif

#ifndef ROCK_SOLID
	if (single_interpreter == 1) {
		init_uwsgi_vars();
	}

        py_apps = PyDict_New();
        if (!py_apps) {
                PyErr_Print();
                exit(1);
        }

        memset(wsgi_apps, 0, sizeof(wsgi_apps));


        if (has_threads) {
                _save = PyEval_SaveThread();
        }
#endif

        if (harakiri_timeout > 0) {
                signal(SIGALRM, (void *) &harakiri);
        }

        signal(SIGINT, (void *) &harakiri);

#ifndef UNBIT
#ifndef ROCK_SOLID
	signal(SIGUSR1, (void *) &stats);
#endif
#endif

        wsgi_poll.events = POLLIN ;


#ifndef UNBIT
#ifndef ROCK_SOLID
	if (xml_config != NULL) {
        	memset(&wsgi_req, 0, sizeof(struct wsgi_request));
		uwsgi_xml_config();
	}
#endif
#endif


        mypid = getpid();
#ifndef UNBIT
	masterpid = mypid ;
#endif

	if (buffer_size > 65536) {
		fprintf(stderr,"invalid buffer size.\n");
		exit(1);
	}
	buffer = malloc(buffer_size);
	if (buffer == NULL) {
		fprintf(stderr,"unable to allocate memory for buffer.\n");
		exit(1);
	}

	fprintf(stderr,"request/response buffer (%d bytes) allocated.\n", buffer_size);

        /* preforking() */
#ifndef UNBIT
	if (master_process == 0) {
        	fprintf(stderr, "spawned uWSGI worker 0 (pid: %d)\n", mypid);
	}
	else {
        	fprintf(stderr, "spawned uWSGI master process (pid: %d)\n", mypid);
	}
        for(i=1;i<numproc+master_process;i++) {
#else
        fprintf(stderr, "spawned uWSGI worker 0 (pid: %d)\n", mypid);
        for(i=1;i<numproc;i++) {
#endif
                pid = fork();
                if (pid == 0 ) {
                        mypid = getpid();
                        break;
                }
                else if (pid < 1) {
                        perror("fork()");
                        exit(1);
                }
                else {
                        fprintf(stderr, "spawned uWSGI worker %d (pid: %d)\n", i, pid);
                }
        }

#ifndef UNBIT

	if (getpid() == masterpid && master_process == 1) {
		for(;;) {
			diedpid = waitpid(WAIT_ANY , &waitpid_status, 0) ;
			if (diedpid == -1) {
				perror("waitpid()");
				fprintf(stderr, "something horrible happened...\n");
				harakiri();
			}
			fprintf(stderr,"DAMN ! process %d died :( trying respawn ...\n", diedpid);
			pid = fork();
			if (pid == 0 ) {
				mypid = getpid();
				break;
			}
                	else if (pid < 1) {
                        	perror("fork()");
			}
			else {
                        	fprintf(stderr, "Respawned uWSGI worker (new pid: %d)\n", pid);
			}
		}
	}
#endif


	
        memset(&wsgi_req, 0, sizeof(struct wsgi_request));

#ifndef ROCK_SOLID
	wsgi_req.app_id = default_app ;	
        wsgi_req.sendfile_fd = -1 ;
#endif

	hvec = malloc(sizeof(struct iovec)*vec_size) ;
	if (hvec == NULL) {
		fprintf(stderr,"unable to allocate memory for iovec.\n");
		exit(1);
	}



        while( (wsgi_poll.fd = accept(serverfd,(struct sockaddr *)&c_addr, (socklen_t *) &c_len)) ) {

                if (wsgi_poll.fd < 0){
                        perror("accept()");
                        exit(1);
                }

                /*
                        poll con timeout ;
                */

                gettimeofday(&wsgi_req.start_of_request, NULL) ;

                /* first 4 byte header */
                rlen = poll(&wsgi_poll, 1, 4000) ;
                if (rlen < 0) {
                        perror("poll()");
                        exit(1);
                }
                else if (rlen == 0) {
                        fprintf(stderr, "timeout. skip request\n");
                        close(wsgi_poll.fd);
                        continue ;      
                }
                rlen = read(wsgi_poll.fd, &wsgi_req, 4) ;
                if (rlen != 4){
                        fprintf(stderr,"invalid request header size: %d...skip\n", rlen);
                        continue;
                }
                if (wsgi_req.size > buffer_size) {
                        fprintf(stderr,"invalid request block size: %d...skip\n", wsgi_req.size);
                        continue;
                }

                /* http headers parser */
                rlen = poll(&wsgi_poll, 1, 4000) ;
                if (rlen < 0) {
                        perror("poll()");
                        exit(1);
                }
                else if (rlen == 0) {
                        fprintf(stderr, "timeout. skip request\n");
                        close(wsgi_poll.fd);
                        continue ;
                }
                rlen = read(wsgi_poll.fd, buffer, wsgi_req.size);
                if (rlen != wsgi_req.size){
                        fprintf(stderr,"invalid request var size: %d (expected %d)...skip\n", rlen, wsgi_req.size);
                        continue;
                }


                ptrbuf = buffer ;
                bufferend = ptrbuf+wsgi_req.size ;


                        // pluginIZE this part (ucgi, fastcgi, scgi, http...)
                        while(ptrbuf < bufferend) {
                                if (ptrbuf+2 < bufferend) {
                                        memcpy(&strsize,ptrbuf,2);
                                        ptrbuf+=2;
                                        if (ptrbuf+strsize < bufferend) {
                                                // var key
                                                hvec[wsgi_req.var_cnt].iov_base = ptrbuf ;
                                                hvec[wsgi_req.var_cnt].iov_len = strsize ;
                                                ptrbuf+=strsize;
                                                if (ptrbuf+2 < bufferend) {
                                                        memcpy(&strsize,ptrbuf,2);
                                                        ptrbuf+=2 ;
                                                        if ( ptrbuf+strsize <= bufferend) {
#ifndef ROCK_SOLID
                                                                if (!strncmp("SCRIPT_NAME", hvec[wsgi_req.var_cnt].iov_base , hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        // set the request app_id
                                                                        // LOCKED SECTION
                                                                        if (strsize > 0) {
                                                                                if (has_threads) {
                                                                                        PyEval_RestoreThread(_save);
                                                                                }
                                                                                zero = PyString_FromStringAndSize(ptrbuf, strsize) ;
                                                                                if (PyDict_Contains(py_apps, zero)) {
                                                                                        wsgi_req.app_id = PyInt_AsLong( PyDict_GetItem(py_apps, zero) );
                                                                                }
                                                                                else {
                                                                                        /* unavailable app for this SCRIPT_NAME */
                                                                                        wsgi_req.app_id = -1 ;
                                                                                }
                                                                                Py_DECREF(zero);
                                                                                if (has_threads) {
                                                                                        _save = PyEval_SaveThread();
                                                                                }
                                                                        }
                                                                        // UNLOCK
                                                                }
                                                                else if (!strncmp("SERVER_PROTOCOL", hvec[wsgi_req.var_cnt].iov_base , hvec[wsgi_req.var_cnt].iov_len)) {
#else
                                                                if (!strncmp("SERVER_PROTOCOL", hvec[wsgi_req.var_cnt].iov_base , hvec[wsgi_req.var_cnt].iov_len)) {
#endif
                                                                        wsgi_req.protocol = ptrbuf ;
                                                                        wsgi_req.protocol_len = strsize ;
                                                                }
                                                                else if (!strncmp("REQUEST_URI", hvec[wsgi_req.var_cnt].iov_base, hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.uri = ptrbuf ;
                                                                        wsgi_req.uri_len = strsize ;
                                                                }
                                                                else if (!strncmp("QUERY_STRING", hvec[wsgi_req.var_cnt].iov_base, hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.query_string = ptrbuf ;
                                                                        wsgi_req.query_string_len = strsize ;
                                                                }
                                                                else if (!strncmp("REQUEST_METHOD", hvec[wsgi_req.var_cnt].iov_base, hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.method = ptrbuf ;
                                                                        wsgi_req.method_len = strsize ;
                                                                }
                                                                else if (!strncmp("REMOTE_ADDR", hvec[wsgi_req.var_cnt].iov_base, hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.remote_addr = ptrbuf ;
                                                                        wsgi_req.remote_addr_len = strsize ;
                                                                }
                                                                else if (!strncmp("REMOTE_USER", hvec[wsgi_req.var_cnt].iov_base, hvec[wsgi_req.var_cnt].iov_len)) {
                                                                        wsgi_req.remote_user = ptrbuf ;
                                                                        wsgi_req.remote_user_len = strsize ;
                                                                }
								if (wsgi_req.var_cnt < vec_size-(4+1)) {
                                                                	wsgi_req.var_cnt++ ;
								}
								else {
									fprintf(stderr, "max vec size reached. skip this header.\n");
									break;
								}
                                                                // var value
                                                                hvec[wsgi_req.var_cnt].iov_base = ptrbuf ;
                                                                hvec[wsgi_req.var_cnt].iov_len = strsize ;
								if (wsgi_req.var_cnt < vec_size-(4+1)) {
                                                                	wsgi_req.var_cnt++ ;
								}
								else {
									fprintf(stderr, "max vec size reached. skip this header.\n");
									break;
								}
                                                                ptrbuf+=strsize;
                                                        }
                                                        else {
                                                                break;
                                                        }
                                                }
                                                else {
                                                        break;
                                                }
                                        }
                                }
                                else {
                                        break;
                                }
                        }

#ifndef ROCK_SOLID
                if (has_threads) {
                        PyEval_RestoreThread(_save);
                }
#endif

                wsgi_file = fdopen(wsgi_poll.fd,"r") ;

#ifndef ROCK_SOLID

#ifndef UNBIT
                if (wsgi_req.app_id == -1 && xml_config == NULL) {
#else
                if (wsgi_req.app_id == -1) {
#endif
                        for(i=0;i<wsgi_req.var_cnt;i+=2) {
                                if (!strncmp("SCRIPT_NAME", hvec[i].iov_base, hvec[i].iov_len)) {
                                        wsgi_req.script_name = hvec[i+1].iov_base ;
                                        wsgi_req.script_name_len = hvec[i+1].iov_len ;
                                }
                                if (!strncmp("UWSGI_SCRIPT", hvec[i].iov_base, hvec[i].iov_len)) {
                                 	wsgi_req.wsgi_script = hvec[i+1].iov_base ;
                                      	wsgi_req.wsgi_script_len = hvec[i+1].iov_len ;
                               	}
                               	if (!strncmp("UWSGI_MODULE", hvec[i].iov_base, hvec[i].iov_len)) {
                                  	wsgi_req.wsgi_module = hvec[i+1].iov_base ;
                                       	wsgi_req.wsgi_module_len = hvec[i+1].iov_len ;
                                }
                                if (!strncmp("UWSGI_CALLABLE", hvec[i].iov_base, hvec[i].iov_len)) {
                                   	wsgi_req.wsgi_callable = hvec[i+1].iov_base ;
                                       	wsgi_req.wsgi_callable_len = hvec[i+1].iov_len ;
                               	}
                        }


                        if ((wsgi_req.app_id = init_uwsgi_app()) == -1) {
                                internal_server_error(wsgi_poll.fd, "wsgi application not found");
                                goto clean ;
                        }
                }


                if (wsgi_req.app_id == -1) {
                        internal_server_error(wsgi_poll.fd, "wsgi application not found");
                        goto clean;
                }

                wi = &wsgi_apps[wsgi_req.app_id] ;

		if (single_interpreter == 0) {
                	if (!wi->interpreter) {
                        	internal_server_error(wsgi_poll.fd, "wsgi application's %d interpreter not found");
                        	goto clean;
                	}

                	// set the interpreter
                	PyThreadState_Swap(wi->interpreter) ;
		}

#endif

                /* max 1 minute before harakiri */
                if (harakiri_timeout > 0) {
                        alarm(harakiri_timeout);
                }


                for(i=0;i<wsgi_req.var_cnt;i+=2) {
                        pydictkey = PyString_FromStringAndSize(hvec[i].iov_base, hvec[i].iov_len) ;
                        pydictvalue = PyString_FromStringAndSize(hvec[i+1].iov_base, hvec[i+1].iov_len) ;
                        PyDict_SetItem(wi->wsgi_environ, pydictkey, pydictvalue);
                        Py_DECREF(pydictkey);
                        Py_DECREF(pydictvalue);
                }



                // set wsgi vars

                wsgi_socket = PyFile_FromFile(wsgi_file,"wsgi_input","r", NULL) ;
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.input", wsgi_socket );
                Py_DECREF(wsgi_socket) ;

#ifndef ROCK_SOLID
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.file_wrapper", wi->wsgi_sendfile );
#endif

                zero = PyTuple_New(2);
                PyTuple_SetItem(zero, 0 , PyInt_FromLong(1));
                PyTuple_SetItem(zero, 1 , PyInt_FromLong(0));
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.version", zero);
                Py_DECREF(zero);

                zero = PyFile_FromFile(stderr, "wsgi_input","w", NULL) ;
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.errors", zero );
                Py_DECREF(zero) ;

                PyDict_SetItemString(wi->wsgi_environ, "wsgi.run_once", Py_False);

                PyDict_SetItemString(wi->wsgi_environ, "wsgi.multithread", Py_False);
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.multiprocess", Py_True);

                zero = PyString_FromString("http") ;
                PyDict_SetItemString(wi->wsgi_environ, "wsgi.url_scheme", zero);
                Py_DECREF(zero);



                // call
#ifndef ROCK_SOLID
                if (enable_profiler == 1) {
                	wsgi_result = PyEval_CallObject(wi->wsgi_cprofile_run, wi->wsgi_args);
                	if (PyErr_Occurred()) {
                        	PyErr_Print();
                	}
			if (wsgi_result) {
                        	Py_DECREF(wsgi_result);
				wsgi_result = PyDict_GetItemString(wi->pymain_dict, "uwsgi_out");
			}
		}
		else {
#endif

                	wsgi_result = PyEval_CallObject(wi->wsgi_callable, wi->wsgi_args);

                	if (PyErr_Occurred()) {
                        	PyErr_Print();
                	}
#ifndef ROCK_SOLID
		}
#endif


                if (wsgi_result) {

#ifndef ROCK_SOLID
                        if (wsgi_req.sendfile_fd > -1) {
                                rlen = lseek(wsgi_req.sendfile_fd, 0, SEEK_END) ;
                                if (rlen > 0) {
                                        lseek(wsgi_req.sendfile_fd, 0, SEEK_SET) ;
#ifdef BSD
                                        wsgi_req.response_size = sendfile(wsgi_req.sendfile_fd, wsgi_poll.fd, 0, (off_t *) &rlen, NULL, 0) ;
#else
                                        wsgi_req.response_size = sendfile(wsgi_poll.fd, wsgi_req.sendfile_fd, NULL, rlen) ;
#endif
                                }
                                Py_DECREF(py_sendfile);
                        }
                        else {

#endif
                                wsgi_chunks = PyObject_GetIter(wsgi_result);
                                if (wsgi_chunks) {
                                        while((wchunk = PyIter_Next(wsgi_chunks))) {
                                                if (PyString_Check(wchunk)) {
                                                        wsgi_req.response_size += write(wsgi_poll.fd, PyString_AsString(wchunk), PyString_Size(wchunk)) ;
                                                }
                                                Py_DECREF(wchunk);
                                        }
                                        Py_DECREF(wsgi_chunks);
                                }
#ifndef ROCK_SOLID
                        }
			if (enable_profiler == 0) {
#endif
                        	Py_DECREF(wsgi_result);
#ifndef ROCK_SOLID
			}
#endif
                }


                PyDict_Clear(wi->wsgi_environ);
#ifndef ROCK_SOLID
                wi->requests++;
#endif
                PyErr_Clear();
                if (harakiri_timeout > 0) {
                        alarm(0);
                }
#ifndef ROCK_SOLID
		if (single_interpreter == 0) {
                	PyThreadState_Swap(wsgi_thread);
		}
clean:
#endif
                fclose(wsgi_file);
#ifndef ROCK_SOLID
                if (has_threads) {
                        _save = PyEval_SaveThread();
                }
#endif
                requests++ ;
                // GO LOGGING...
                log_request() ;
                // reset request
                memset(&wsgi_req, 0,  sizeof(struct wsgi_request));

#ifndef ROCK_SOLID
                wsgi_req.app_id = default_app ;
                wsgi_req.sendfile_fd = -1 ;
#endif

        }

	return 0 ;

}

void log_request() {
        char *time_request ;
        struct timeval end_request ;
        time_t microseconds, microseconds2;

        char *msg3 = "?" ;
        char *msg4 = "" ;

        char *qs_sep;

#ifndef ROCK_SOLID
        char *msg1 = " via sendfile() " ;
        char *msg2 = " " ;
        char *via ;
	struct uwsgi_app *wi;
	int app_req = -1 ;

	if (wsgi_req.app_id >= 0) {
		wi = &wsgi_apps[wsgi_req.app_id] ;
		if (wi->requests > 0) {
			app_req = wi->requests ;
		}
	}
        via = msg2 ;
        if (wsgi_req.sendfile_fd > -1) {
                via = msg1 ;
        }
#endif

        qs_sep = msg4 ;
        if (wsgi_req.query_string_len > 0) {
                qs_sep = msg3 ;
        }
        
        time_request = ctime(&wsgi_req.start_of_request.tv_sec);
        gettimeofday(&end_request, NULL) ;
        microseconds = end_request.tv_sec*1000000+end_request.tv_usec ;
        microseconds2 = wsgi_req.start_of_request.tv_sec*1000000+wsgi_req.start_of_request.tv_usec ;
#ifndef ROCK_SOLID
        if (memory_debug == 1) {
                get_memusage();
                fprintf(stderr,"{address space usage: %ld bytes/%luMB} {rss usage: %lu bytes/%luMB} ", wsgi_req.vsz_size, wsgi_req.vsz_size/1024/1024, wsgi_req.rss_size*PAGE_SIZE, (wsgi_req.rss_size*PAGE_SIZE)/1024/1024) ;
        }
#endif

#ifdef ROCK_SOLID
        fprintf(stderr, "[pid: %d|req: %d] %.*s (%.*s) {%d vars in %d bytes} [%.*s] %.*s %.*s%s%.*s => generated %d bytes in %ld msecs (%.*s %d) %d headers in %d bytes\n",
                mypid, requests, wsgi_req.remote_addr_len, wsgi_req.remote_addr,
                wsgi_req.remote_user_len, wsgi_req.remote_user, wsgi_req.var_cnt, wsgi_req.size, 24, time_request,
                wsgi_req.method_len, wsgi_req.method, wsgi_req.uri_len, wsgi_req.uri, qs_sep, wsgi_req.query_string_len, wsgi_req.query_string, wsgi_req.response_size, 
                (microseconds-microseconds2)/1000,
                wsgi_req.protocol_len, wsgi_req.protocol, wsgi_req.status, wsgi_req.header_cnt, wsgi_req.headers_size) ;
#else
        fprintf(stderr, "[pid: %d|app: %d|req: %d/%d] %.*s (%.*s) {%d vars in %d bytes} [%.*s] %.*s %.*s%s%.*s => generated %d bytes in %ld msecs%s(%.*s %d) %d headers in %d bytes\n",
                mypid, wsgi_req.app_id, app_req, requests, wsgi_req.remote_addr_len, wsgi_req.remote_addr,
                wsgi_req.remote_user_len, wsgi_req.remote_user, wsgi_req.var_cnt, wsgi_req.size, 24, time_request,
                wsgi_req.method_len, wsgi_req.method, wsgi_req.uri_len, wsgi_req.uri, qs_sep, wsgi_req.query_string_len, wsgi_req.query_string, wsgi_req.response_size, 
                (microseconds-microseconds2)/1000, via,
                wsgi_req.protocol_len, wsgi_req.protocol, wsgi_req.status, wsgi_req.header_cnt, wsgi_req.headers_size) ;
#endif

}

#ifndef ROCK_SOLID
void get_memusage() {
        FILE *procfile;
	int i;

        procfile = fopen("/proc/self/stat","r");
        if (procfile) {
                i = fscanf(procfile,"%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %ld",&wsgi_req.vsz_size, &wsgi_req.rss_size) ;
		if (i != 2) {
			fprintf(stderr, "warning: invalid record in /proc/self/stat\n");
		}
                fclose(procfile);
        }
}
#endif

void init_uwsgi_vars() {

#ifndef UNBIT
#ifndef ROCK_SOLID
	int i;
#endif
#endif
	PyObject *wsgi_argv, *zero ;
	PyObject *pysys, *pysys_dict, *pypath ;

	/* stolen from mod_wsgi, sorry ;) */
        wsgi_argv = PyList_New(0);
        zero = PyString_FromString("uwsgi");
        PyList_Append(wsgi_argv, zero);
        PySys_SetObject("argv", wsgi_argv);
        Py_DECREF(zero);
        Py_DECREF(wsgi_argv);


        /* add cwd and cvalue(TODO) to pythonpath */
        pysys = PyImport_ImportModule("sys");
        if (!pysys) {
                PyErr_Print();
                exit(1);
        }
        pysys_dict = PyModule_GetDict(pysys);
        pypath = PyDict_GetItemString(pysys_dict, "path");
        if (!pypath) {
                PyErr_Print();
                exit(1);
        }
        if (PyList_Insert(pypath,0,PyString_FromString(".")) != 0) {
                PyErr_Print();
	}

#ifndef UNBIT
#ifndef ROCK_SOLID
	for(i=0; i< python_path_cnt; i++) {
        	if (PyList_Insert(pypath,0,PyString_FromString(python_path[i])) != 0) {
                	PyErr_Print();
		}
	}
#endif
#endif

}

#ifndef ROCK_SOLID
int init_uwsgi_app() {
        PyObject *wsgi_module, *wsgi_dict ;
	PyObject *pymain, *zero;
	PyObject *pycprof, *pycprof_dict;
        char tmpstring[256] ;
	int id ;

        struct uwsgi_app *wi ;

        memset(tmpstring,0, 256) ;


	if (wsgi_req.wsgi_script_len == 0 && (wsgi_req.wsgi_module_len == 0 || wsgi_req.wsgi_callable_len == 0)) {
		fprintf(stderr, "invalid application. skip.\n");
		return -1;
	}

	if (wsgi_req.wsgi_script_len > 255 || wsgi_req.wsgi_module_len > 255 || wsgi_req.wsgi_callable_len > 255) {
		fprintf(stderr, "invalid application's string size. skip.\n");
		return -1;
	}

	id = wsgi_cnt ;

	if (wsgi_req.script_name_len == 0 || (wsgi_req.script_name_len == 1 && wsgi_req.script_name[0] == '/')) {
		wsgi_req.script_name = "/" ;
		wsgi_req.script_name_len = 1;
		id = 0 ;
	}

	zero = PyString_FromStringAndSize(wsgi_req.script_name, wsgi_req.script_name_len);
	if (!zero) {
		Py_FatalError("cannot get mountpoint python object !\n");
	}
	if (PyDict_GetItem(py_apps, zero) != NULL) {
		Py_DECREF(zero);
		fprintf(stderr, "mountpoint %.*s already configured. skip.\n", wsgi_req.script_name_len, wsgi_req.script_name);
		return -1;
	}

	Py_DECREF(zero);

        wi = &wsgi_apps[id] ;

	memset(wi, 0, sizeof(struct uwsgi_app));

	if (single_interpreter == 0) {
        	wi->interpreter = Py_NewInterpreter();
        	PyThreadState_Swap(wi->interpreter) ;
		init_uwsgi_vars();
		fprintf(stderr,"interpreter for app %d initialized.\n", id);
	}

	

        if (wsgi_req.wsgi_script_len > 0) {
                memcpy(tmpstring, wsgi_req.wsgi_script, wsgi_req.wsgi_script_len) ;
                wsgi_module = PyImport_ImportModule(tmpstring) ;
                if (!wsgi_module) {
                        PyErr_Print();
			if (single_interpreter == 0) {
                        	Py_EndInterpreter(wi->interpreter);
                        	PyThreadState_Swap(wsgi_thread) ;
			}
                        return -1 ;
                }
                wsgi_req.wsgi_callable = "application" ;
                wsgi_req.wsgi_callable_len = 11;
        }
        else {
                memcpy(tmpstring, wsgi_req.wsgi_module, wsgi_req.wsgi_module_len) ;
                wsgi_module = PyImport_ImportModule(tmpstring) ;
                if (!wsgi_module) {
                        PyErr_Print();
			if (single_interpreter == 0) {
                        	Py_EndInterpreter(wi->interpreter);
                        	PyThreadState_Swap(wsgi_thread) ;
			}
                        return -1 ;
                }
                
        }

        wsgi_dict = PyModule_GetDict(wsgi_module);
        if (!wsgi_dict) {
                PyErr_Print();
		if (single_interpreter == 0) {
                	Py_EndInterpreter(wi->interpreter);
                	PyThreadState_Swap(wsgi_thread) ;
		}
                return -1 ;
        }

        memset(tmpstring, 0, 256);
        memcpy(tmpstring, wsgi_req.wsgi_callable, wsgi_req.wsgi_callable_len) ;
        wi->wsgi_callable = PyDict_GetItemString(wsgi_dict, tmpstring);
        if (!wi->wsgi_callable) {
                PyErr_Print();
		if (single_interpreter == 0) {
                	Py_EndInterpreter(wi->interpreter);
                	PyThreadState_Swap(wsgi_thread) ;
		}
                return -1 ;
        }


        wi->wsgi_environ = PyDict_New();
        if (!wi->wsgi_environ) {
                PyErr_Print();
		if (single_interpreter == 0) {
                	Py_EndInterpreter(wi->interpreter);
                	PyThreadState_Swap(wsgi_thread) ;
		}
                return -1 ;
        }


	if (enable_profiler) {
		pymain = PyImport_AddModule("__main__");
		if (!pymain) {
			PyErr_Print();
			exit(1);
		}
		wi->pymain_dict = PyModule_GetDict(pymain);
		if (!wi->pymain_dict) {
			PyErr_Print();
			exit(1);
		}
		if (PyDict_SetItem(wi->pymain_dict, PyString_FromFormat("uwsgi_application__%d", id), wi->wsgi_callable)) {
			PyErr_Print();
			exit(1);
		}
		if (PyDict_SetItem(wi->pymain_dict, PyString_FromFormat("uwsgi_environ__%d", id), wi->wsgi_environ)) {
			PyErr_Print();
			exit(1);
		}
		if (PyDict_SetItem(wi->pymain_dict, PyString_FromFormat("uwsgi_spit__%d", id), wsgi_spitout)) {
			PyErr_Print();
			exit(1);
		}
		
		pycprof =  PyImport_ImportModule("cProfile");
        	if (!pycprof) {
                	PyErr_Print();
			fprintf(stderr, "trying old profile module... ");
			pycprof =  PyImport_ImportModule("profile");
			if (!pycprof) {
				fprintf(stderr, "doh!!!\n");
                		PyErr_Print();
                		exit(1);
			}
			else {
				fprintf(stderr, "ok and set stdout to linebuf mode.\n");
			}
        	}
        	pycprof_dict = PyModule_GetDict(pycprof);
		if (!pycprof_dict) {
			PyErr_Print();
			exit(1);
		}
        	wi->wsgi_cprofile_run = PyDict_GetItemString(pycprof_dict, "run");
		if (!wi->wsgi_cprofile_run) {
			PyErr_Print();
			exit(1);
		}

        	wi->wsgi_args = PyTuple_New(1) ;
		if (PyTuple_SetItem(wi->wsgi_args,0, PyString_FromFormat("uwsgi_out = uwsgi_application__%d(uwsgi_environ__%d,uwsgi_spit__%d)", id, id, id) )) {
			PyErr_Print();
			if (single_interpreter == 0) {
				Py_EndInterpreter(wi->interpreter);
				PyThreadState_Swap(wsgi_thread) ;
			}
			return -1 ;
		}
	}
	else {
        	wi->wsgi_args = PyTuple_New(2) ;
        	if (PyTuple_SetItem(wi->wsgi_args,0, wi->wsgi_environ)) {
                	PyErr_Print();
			if (single_interpreter == 0) {
                		Py_EndInterpreter(wi->interpreter);
                		PyThreadState_Swap(wsgi_thread) ;
			}
                	return -1 ;
        	}
        	if (PyTuple_SetItem(wi->wsgi_args,1, wsgi_spitout)) {
                	PyErr_Print();
			if (single_interpreter == 0) {
                		Py_EndInterpreter(wi->interpreter);
                		PyThreadState_Swap(wsgi_thread) ;
			}
                	return -1 ;
        	}
	}

	// prepare sendfile()
        wi->wsgi_sendfile = PyCFunction_New(uwsgi_sendfile_method,NULL) ;

	if (single_interpreter == 0) {
        	PyThreadState_Swap(wsgi_thread);
	}

        memset(tmpstring, 0, 256);
        memcpy(tmpstring, wsgi_req.script_name, wsgi_req.script_name_len);
        PyDict_SetItemString(py_apps, tmpstring, PyInt_FromLong(id));
        PyErr_Print();

        fprintf(stderr,"application %d (%s) ready\n", id, tmpstring);

        if (id == 0){
                fprintf(stderr,"setting default application to 0\n");
                default_app = 0 ;
        }
	else {
        	wsgi_cnt++;
	}

        return id ;
}

#endif

// part useless for Unbit
#ifndef UNBIT

#ifndef ROCK_SOLID

void uwsgi_xml_config() {
	xmlDoc *doc = NULL;
	xmlNode *element = NULL;
	xmlNode *node = NULL;
	xmlNode *node2 = NULL;

	xmlChar *xml_uwsgi_mountpoint = NULL;
	xmlChar *xml_uwsgi_script = NULL ;

	
	doc = xmlReadFile(xml_config, NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "could not parse file %s.\n", xml_config);
		exit(1);
	}

	fprintf(stderr, "parsing config file %s\n", xml_config);

	element = xmlDocGetRootElement(doc);
	if (element == NULL) {
		fprintf(stderr, "invalid xml config file.\n");
		exit(1);
	}
	if (strcmp((char *)element->name, "uwsgi")) {
		fprintf(stderr, "invalid xml root element, <uwsgi> expected.\n");
		exit(1);
	}


	// first check for pythonpath
	for(node = element->children; node; node = node->next) {
		if (node->type == XML_ELEMENT_NODE) {
			if (!strcmp((char *) node->name, "pythonpath")) {
				if (!node->children) {
                                	fprintf(stderr, "no path defined for pythonpath. skip.\n");
                                        continue;
                                }
				if (!node->children->content) {
                                	fprintf(stderr, "invalid path for pythonpath. skip.\n");
                                        continue;
				}
				if (python_path_cnt < 63) {
					python_path[python_path_cnt] = malloc( strlen((char *)node->children->content) + 1 );
					memset(python_path[python_path_cnt], 0, strlen( (char *) node->children->content) + 1);
					strcpy(python_path[python_path_cnt], (char *) node->children->content);
					fprintf(stderr, "added %s to pythonpath.\n", python_path[python_path_cnt]);
					python_path_cnt++;
				}
				else {
                                	fprintf(stderr, "max pythonpath element reached. skip.\n");
					continue;
				}	
			}
		}	
	}

	// ... then for wsgi apps
	for(node = element->children; node; node = node->next) {
		if (node->type == XML_ELEMENT_NODE) {

			if (!strcmp((char *) node->name, "app")) {
				xml_uwsgi_mountpoint = xmlGetProp(node, (const xmlChar *)"mountpoint");
				if (xml_uwsgi_mountpoint == NULL) {
					fprintf(stderr, "no mountpoint defined for app. skip.\n");
					continue;
				}
				wsgi_req.script_name = (char *) xml_uwsgi_mountpoint ;
				wsgi_req.script_name_len = strlen(wsgi_req.script_name);

				for(node2 = node->children; node2; node2 = node2->next) {
					if (node2->type == XML_ELEMENT_NODE) {
						if (!strcmp((char *) node2->name, "script")) {
							if (!node2->children) {
								fprintf(stderr, "no wsgi script defined. skip.\n");
								continue;
							}
							xml_uwsgi_script = node2->children->content ;
							if (xml_uwsgi_script == NULL) {
								fprintf(stderr, "no wsgi script defined. skip.\n");
								continue;
							}
							wsgi_req.wsgi_script = (char *) xml_uwsgi_script ;
							wsgi_req.wsgi_script_len = strlen(wsgi_req.wsgi_script);
							init_uwsgi_app();
						}
					}
				}			
			}
		}
	}
	

	xmlFreeDoc(doc);
	xmlCleanupParser();

	fprintf(stderr, "config file parsed.\n");
}


#endif

void daemonize(char *logfile) {
        pid_t pid;
        int fd, fdin;


        pid = fork();
        if (pid < 0) {
                perror("fork()");
                exit(1) ;
        }
        if (pid != 0) {
                exit(0);
        }

        if (setsid() < 0) {
                perror("setsid()");
                exit(1) ;
        }


        /* refork... */
        pid = fork();
        if (pid < 0) {
                perror("fork()");
                exit(1) ;
        }
        if (pid != 0) {
                exit(0);
        }

        umask(0);


        /*if (chdir("/") != 0) {
                perror("chdir()");
                exit(1);
        }*/


        fdin = open("/dev/null", O_RDWR);
        if (fdin < 0) {
                perror("open()");
                exit(1);
        }

        fd = open(logfile, O_RDWR|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP );
        if (fd < 0) {
                perror("open()");
                exit(1);
        }

        /* stdin */
        if (dup2(fdin,0) < 0) {
                perror("dup2()");
                exit(1);
        }

        /* stdout */
        if (dup2(fd,1) < 0) {
                perror("dup2()");
                exit(1);
        }

        /* stderr */
        if (dup2(fd,2) < 0) {
                perror("dup2()");
                exit(1);
        }

        close(fd);


}


#endif

