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


*** Please use the supplied Makefiles ***

Compile on Linux 2.6
gcc -o uwsgi `python2.5-config --cflags` `python2.5-config --libs` `xml2-config --cflags` `xml2-config --libs` utils.c socket.c uwsgi.c
gcc -o uwsgi26 `python2.6-config --cflags` `python2.6-config --libs` `xml2-config --cflags` `xml2-config --libs` utils.c socket.c uwsgi.c
gcc -o uwsgi24 `python2.4-config --cflags` `python2.4-config --libs` `xml2-config --cflags` `xml2-config --libs` utils.c socket.c uwsgi.c
Compile on Unbit
gcc -o /usr/share/unbit/uwsgi `python2.5-config --cflags` `python2.5-config --libs` -DUNBIT uwsgi.c
gcc -o /usr/share/unbit/uwsgi26 `python2.6-config --cflags` `python2.6-config --libs` -DUNBIT uwsgi.c
gcc -o /usr/share/unbit/uwsgi24 `python2.4-config --cflags` `python2.4-config --libs` -DUNBIT uwsgi.c
(dapper)  gcc -o uwsgi24 -I/usr/include/python2.4 -I/usr/include/python2.4 -fno-strict-aliasing -DNDEBUG -g -O3 -Wall -Wstrict-prototypes -lpthread -ldl -lutil -lm -lpython2.4 -DUNBIT uwsgi.c
Compile on *BSD (FreeBSD and OSX)
gcc -o uwsgi `python2.5-config --cflags` `python2.5-config --libs` `xml2-config --cflags` `xml2-config --libs` -DBSD utils.c socket.c uwsgi.c

** Warning for FreeBSD users **
the sendfile() prototype is not very clear for all BSD systems.
If you have problem with compilation you can use the following:
gcc -o uwsgi `python2.5-config --cflags` `python2.5-config --libs` `xml2-config --cflags` `xml2-config --libs` -DBSD -DFREEBSD utils.c socket.c uwsgi.c
(thanks to Christopher Villalobos for the patch)


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


#ifndef ROCK_SOLID
#ifdef __linux__
	#include <sys/sendfile.h>
#endif
#endif

#ifndef UNBIT

#ifndef ROCK_SOLID
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif

#endif


#include <sys/wait.h>


#include "uwsgi.h"

#if PY_MINOR_VERSION < 5
	#define Py_ssize_t int
#endif


#ifndef ROCK_SOLID
int init_uwsgi_app(PyObject *, PyObject *) ;
#endif

char *pyhome;

char *nl = "\r\n";
char *h_sep = ": " ;
static const char *http_protocol = "HTTP/1.1" ;
static const char *app_slash = "/" ;

int requests = 0 ;

#ifndef ROCK_SOLID
int has_threads = 0 ;
int wsgi_cnt = 1;
int default_app = -1 ;
int enable_profiler = 0;
#endif

int manage_next_request = 1 ;
int in_request = 0;

int buffer_size = 4096 ;

char *test_module = NULL;

int numproc = 1;

char *sharedarea ;
#ifndef __OpenBSD__
void *sharedareamutex ;
#endif
int sharedareasize ;


// the list of workers
struct uwsgi_worker *workers ;

// save my pid for logging
pid_t mypid;
int mywid = 0 ;

int find_worker_id(pid_t pid) {
	int i ;
	for(i = 1 ; i<= numproc ; i++) {
		fprintf(stderr,"%d of %d\n", pid, workers[i].pid);
		if (workers[i].pid == pid)
			return i ;
	}

	return -1 ;
}

struct wsgi_request wsgi_req;

struct timeval start_of_uwsgi ;

extern PyMethodDef *uwsgi_methods ;
extern PyMethodDef *null_methods ;

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
char *wsgi_config;
#endif

#ifndef ROCK_SOLID
int single_interpreter = 0 ;
int py_optimize = 0 ;

PyObject *py_sendfile ;
PyObject *uwsgi_fastfuncslist ;

PyThreadState *wsgi_thread ;
#endif

struct pollfd wsgi_poll; 

int harakiri_timeout = 0 ;
int socket_timeout = 4 ;

#ifdef UNBIT
int save_to_disk = -1 ;
int tmp_dir_fd = -1 ;
char *tmp_filename ;
int uri_to_hex(void);
int check_for_memory_errors = 0 ;
#endif

PyObject *wsgi_writeout ;

#define MAX_VARS 64

int max_vars = MAX_VARS ;
int vec_size = 4+1+(4*MAX_VARS) ;

// iovec
struct iovec *hvec ;

#ifdef ROCK_SOLID
struct uwsgi_app *wi;
#endif

#ifndef ROCK_SOLID
struct uwsgi_app wsgi_apps[64] ;
PyObject *py_apps ;
#endif

void gracefully_kill() {
	fprintf(stderr, "Gracefully killing worker %d...\n", mypid);
	if (in_request) {
		manage_next_request = 0 ;	
	}
	else {
		reload_me();
	}
}

void reload_me() {
	exit(UWSGI_RELOAD_CODE);
}

void end_me() {
	exit(UWSGI_END_CODE);
}

void goodbye_cruel_world() {
	fprintf(stderr, "...The work of process %d is done. Seeya!\n", getpid());
	exit(0);
}

void kill_them_all() {
	int i ;
	fprintf(stderr,"SIGINT/SIGQUIT received...killing workers...\n");
	for(i=1;i<=numproc;i++) {	
		kill(workers[i].pid, SIGINT);
	}
}

void grace_them_all() {
	int i ;
	fprintf(stderr,"...gracefully killing workers...\n");
	for(i=1;i<=numproc;i++) {	
		kill(workers[i].pid, SIGHUP);
	}
}

void reap_them_all() {
	int i ;
	fprintf(stderr,"...brutally killing workers...\n");
	for(i=1;i<=numproc;i++) {
		kill(workers[i].pid, SIGTERM);
	}
}

void harakiri() {

	PyThreadState *_myself;
#ifndef ROCK_SOLID
	struct uwsgi_app *wi = NULL ;
	if (wsgi_req.app_id >= 0) {
		wi = &wsgi_apps[wsgi_req.app_id] ;
	}
#endif
	PyGILState_Ensure();
	_myself = PyThreadState_Get();
	if (wi) {
	#ifdef ROCK_SOLID
       		fprintf(stderr,"\nF*CK !!! i must kill myself (pid: %d) wi: %p wi->wsgi_harakiri: %p thread_state: %p frame: %p...\n", mypid, wi, wi->wsgi_harakiri, _myself, _myself->frame );
	#else
       		fprintf(stderr,"\nF*CK !!! i must kill myself (pid: %d app_id: %d) wi: %p wi->wsgi_harakiri: %p thread_state: %p frame: %p...\n", mypid, wsgi_req.app_id, wi, wi->wsgi_harakiri, _myself, _myself->frame );
	#endif

		if (wi->wsgi_harakiri) {
			PyEval_CallObject(wi->wsgi_harakiri, wi->wsgi_args);
                	if (PyErr_Occurred()) {
                		PyErr_Print();
                	}
		}
	}
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

        //PyObject *zero ;

        py_sendfile = PyTuple_GetItem(args, 0);

#ifdef PYTHREE
	if ((wsgi_req.sendfile_fd = PyObject_AsFileDescriptor(py_sendfile)) >= 0) {
		Py_INCREF(py_sendfile);
	}
#else
        if (PyFile_Check(py_sendfile)) {
                //zero = PyFile_Name(py_sendfile) ;
                //fprintf(stderr,"->serving %s as static file...", PyString_AsString(zero));
                wsgi_req.sendfile_fd = PyObject_AsFileDescriptor(py_sendfile);
                Py_INCREF(py_sendfile);
        }
#endif


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
#ifdef UNBIT
			if (save_to_disk >= 0) {
				if (write(save_to_disk, content, len) != len) {
					perror("write()");
					close(save_to_disk);
					save_to_disk = -1 ;
				}
			}
#endif
#ifndef ROCK_SOLID
                }
#endif
        }
#ifdef UNBIT
	if (save_to_disk >= 0) {
		close(save_to_disk);
		save_to_disk = -1 ;
		fprintf(stderr,"[uWSGI cacher] output of request %d (%.*s) on pid %d written to cache file %s\n",requests, wsgi_req.uri_len, wsgi_req.uri, mypid,tmp_filename);
	}
#endif
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

		if (wsgi_req.protocol_len == 0) {
        		hvec[0].iov_base = (char * )http_protocol ;
			wsgi_req.protocol_len = 8 ;
		}
		else {
        		hvec[0].iov_base = wsgi_req.protocol ;
		}
        	hvec[0].iov_len = wsgi_req.protocol_len ;
        	hvec[1].iov_base = " " ;
        	hvec[1].iov_len = 1 ;
#ifdef PYTHREE
        	hvec[2].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(head)) ;
        	hvec[2].iov_len = strlen(hvec[2].iov_base);
#else
        	hvec[2].iov_base = PyString_AsString(head) ;
        	hvec[2].iov_len = PyString_Size(head) ;
#endif
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
#ifdef PYTHREE
		hvec[1].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(head)) ;
                hvec[1].iov_len = strlen(hvec[1].iov_base);
#else
        	hvec[1].iov_base = PyString_AsString(head) ;
        	hvec[1].iov_len = PyString_Size(head) ;
#endif
        	wsgi_req.status = atoi(hvec[1].iov_base) ;
        	hvec[2].iov_base = nl ;
        	hvec[2].iov_len = NL_SIZE ;
	}
#endif
#endif

#ifdef UNBIT
	if (wsgi_req.unbit_flags & (unsigned long long) 1) {
		if (tmp_dir_fd >= 0 && tmp_filename[0] != 0 && wsgi_req.status == 200 && wsgi_req.method_len == 3 && wsgi_req.method[0] == 'G' && wsgi_req.method[1] == 'E' && wsgi_req.method[2] == 'T') {
			save_to_disk = openat(tmp_dir_fd, tmp_filename,O_CREAT | O_TRUNC | O_WRONLY , S_IRUSR |S_IWUSR |S_IRGRP);
		}
	}
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
#ifdef PYTHREE
		hvec[j].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(h_key)) ;
                hvec[j].iov_len = strlen(hvec[j].iov_base);
#else
                hvec[j].iov_base = PyString_AsString(h_key) ;
                hvec[j].iov_len = PyString_Size(h_key) ;
#endif
                hvec[j+1].iov_base = h_sep;
                hvec[j+1].iov_len = H_SEP_SIZE;
#ifdef PYTHREE
		hvec[j+2].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(h_value)) ;
                hvec[j+2].iov_len = strlen(hvec[j+2].iov_base);
#else
                hvec[j+2].iov_base = PyString_AsString(h_value) ;
                hvec[j+2].iov_len = PyString_Size(h_value) ;
#endif
                hvec[j+3].iov_base = nl;
                hvec[j+3].iov_len = NL_SIZE;
		//fprintf(stderr, "%.*s: %.*s\n", hvec[j].iov_len, (char *)hvec[j].iov_base, hvec[j+2].iov_len, (char *) hvec[j+2].iov_base);
        }

#ifdef UNBIT
	if (save_to_disk >= 0) {
		for(j=0;j<i;j+=4) {
			if (!strncasecmp(hvec[j].iov_base,"Set-Cookie",hvec[j].iov_len)) {
				close(save_to_disk);
				save_to_disk = -1 ;
				break;
			}
		}
	}
#endif

        // \r\n
        j = (i*4)+base ;
        hvec[j].iov_base = nl;
        hvec[j].iov_len = NL_SIZE;

        wsgi_req.headers_size = writev(wsgi_poll.fd, hvec,j+1);
	if (wsgi_req.headers_size < 0) {
		perror("writev()");
	}
        Py_INCREF(wsgi_writeout);

        return wsgi_writeout ;
}


PyMethodDef uwsgi_spit_method[] = {{"uwsgi_spit", py_uwsgi_spit, METH_VARARGS, ""}} ;
PyMethodDef uwsgi_write_method[] = {{"uwsgi_write", py_uwsgi_write, METH_VARARGS, ""}} ;

#ifndef ROCK_SOLID
PyMethodDef uwsgi_sendfile_method[] = {{"uwsgi_sendfile", py_uwsgi_sendfile, METH_VARARGS, ""}} ;
#endif


// process manager is now (20090725) available on Unbit
pid_t masterpid;
pid_t diedpid;
int waitpid_status;
int master_process = 0;
int process_reaper = 0 ;
int max_requests = 0;
struct timeval last_respawn;
time_t respawn_delta;
#ifdef UNBIT
int single_app_mode = 0;
#endif

#ifndef ROCK_SOLID
// flag for memory debug
int memory_debug = 0 ;
#endif

int main(int argc, char *argv[], char *envp[]) {

	struct timeval check_interval = {.tv_sec = 1, .tv_usec = 0 };
	
#ifndef PYTHREE
	PyObject *uwsgi_module;
#endif
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
#endif

#ifndef ROCK_SOLID
	char *spool_dir = NULL ;
	char spool_filename[1024];
	pid_t spooler_pid = 0 ;
#endif

	char *cwd ;
	char *binary_path ;
	int ready_to_reload = 0;
	int ready_to_die = 0;
	
	int is_a_reload = 0 ;

        PyObject *pydictkey, *pydictvalue;

        char *buffer ;
        char *ptrbuf ;
        char *bufferend ;

        unsigned short strsize = 0;
        struct uwsgi_app *wi;

#ifdef __linux__
	struct rlimit rl ;
#endif

#ifdef UNBIT
	struct uidsec_struct us;
#endif

	int socket_type; 
	socklen_t socket_type_len ; 

	sharedareasize = 0 ;

	gettimeofday(&start_of_uwsgi, NULL) ;

	setlinebuf(stdout);

	char *path_info;

	cwd = uwsgi_get_cwd();
	binary_path = malloc(strlen(argv[0])+1) ;
	if (binary_path == NULL) {
		perror("malloc()");
		exit(1);
	}
	strcpy(binary_path, argv[0]);

	socket_type_len = sizeof(int);
	if (!getsockopt(3, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_len)) {
		fprintf(stderr, "...fd 3 is a socket, i suppose this is a graceful reload of uWSGI, i will try to do my best...\n");
		is_a_reload = 1 ;
#ifdef UNBIT
		/* discard the 3'th fd as we will use the fd 0 */
		close(3);
#else
		serverfd = 3;
#endif
	}

#ifndef UNBIT
	#ifndef ROCK_SOLID
        while ((i = getopt (argc, argv, "s:p:t:x:d:l:O:v:b:mcaCTPiMhrR:z:w:j:H:A:Q:")) != -1) {
	#else
        while ((i = getopt (argc, argv, "s:p:t:d:l:v:b:aCMhrR:z:j:H:A:")) != -1) {
	#endif
#else
        while ((i = getopt (argc, argv, "p:t:mTPiv:b:rMR:Sz:w:C:j:H:A:EQ:")) != -1) {
#endif
                switch(i) {
			case 'j':
				test_module = optarg;
				break;
			case 'H':
				pyhome = optarg;
				break;
			case 'A':
				sharedareasize = atoi(optarg);	
				break;
#ifndef ROCK_SOLID
			case 'Q':
				spool_dir = optarg;
				if (access(spool_dir, R_OK|W_OK|X_OK)) {
					perror("access()");
					exit(1);
				}
                                master_process = 1;
				break;
#endif
#ifdef UNBIT
			case 'E':
				check_for_memory_errors = 1 ;
				break;
                        case 'S':
                                single_interpreter = 1;
                                single_app_mode = 1;
				default_app = 0;
                                break;
			case 'C':
				tmp_dir_fd = open(optarg, O_DIRECTORY);
				if (tmp_dir_fd <0) {
					perror("open()");
					exit(1);
				}
				tmp_filename = malloc(8192);
				if (!tmp_filename) {
					fprintf(stderr,"unable to allocate space (8k) for tmp_filename\n");
					exit(1);
				}
				memset(tmp_filename, 0 ,8192);
				break;
#endif
#ifndef UNBIT
			case 'd':
				if (!is_a_reload) {
					daemonize(optarg);
				}
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
                        case 'r':
                                process_reaper = 1;
                                break;
#ifndef ROCK_SOLID
			case 'w':
                                single_interpreter = 1;
				wsgi_config = optarg;
				break;
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
#endif
                        case 'M':
                                master_process = 1;
                                break;
                        case 'R':
                                max_requests = atoi(optarg);
                                break;
                        case 'z':
                                if (atoi(optarg) > 0) {
					socket_timeout = atoi(optarg) ;
				}
                                break;
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
\t-s <name>\tpath (or name) of UNIX/TCP socket to bind to\n\
\t-l <num>\tset socket listen queue to <n>\n\
\t-z <sec>\tset socket timeout to <sec> seconds\n\
\t-b <n>\t\tset buffer size to <n> bytes\n\
\t-x <path>\tpath of xml config file (no ROCK_SOLID)\n\
\t-w <path>\tname of wsgi config module (no ROCK_SOLID)\n\
\t-t <sec>\tset harakiri timeout to <sec> seconds\n\
\t-p <n>\t\tspawn <n> uwsgi worker processes\n\
\t-O <n>\t\tset python optimization level to <n> (no ROCK_SOLID)\n\
\t-v <n>\t\tset maximum number of vars/headers to <n>\n\
\t-A <n>\t\tcreate a shared memory area of <n> pages\n\
\t-c\t\tset cgi mode (no ROCK_SOLID) \n\
\t-C\t\tchmod socket to 666\n\
\t-P\t\tenable profiler (no ROCK_SOLID)\n\
\t-m\t\tenable memory usage report (Linux/OSX only, no ROCK_SOLID)\n\
\t-i\t\tsingle interpreter mode (no ROCK_SOLID)\n\
\t-a\t\tset socket in the abstract namespace (Linux only)\n\
\t-T\t\tenable threads support (no ROCK_SOLID)\n\
\t-M\t\tenable master process manager\n\
\t-H <path>\tset python home/virtualenv\n\
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
		if (test_module == NULL) {
        		fprintf(stderr,"*** Starting uWSGI on [%.*s] ***\n", 24, ctime( (const time_t *) &start_of_uwsgi.tv_sec));
		}
#ifndef UNBIT
#ifndef ROCK_SOLID
	}
	else {
        	fprintf(stderr,"*** Starting uWSGI (CGI mode) on [%.*s] ***\n", 24, ctime( (const time_t *) &start_of_uwsgi.tv_sec));
	}
#endif
#endif
	
#ifdef __linux__
	if (!getrlimit(RLIMIT_AS, &rl)) {
		fprintf(stderr,"your process address space limit is %lld bytes (%lld MB)\n", (long long) rl.rlim_max, (long long) rl.rlim_max/1024/1024);
	}
#endif

	if (pyhome != NULL) {
        	fprintf(stderr,"Setting PythonHome to %s...\n", pyhome);
#ifdef PYTHREE
		wchar_t *wpyhome ;
		wpyhome = malloc((sizeof(wchar_t)*strlen(pyhome))+2) ;
		if (!wpyhome) {
			perror("malloc()");
			exit(1);
		}
		mbstowcs(wpyhome, pyhome, strlen(pyhome));
		Py_SetPythonHome(wpyhome);		
		free(wpyhome);
#else
		Py_SetPythonHome(pyhome);		
#endif
	}

#ifdef PYTHREE
	wchar_t	pname[6] ;
	mbstowcs(pname, "uWSGI", 6);
	Py_SetProgramName(pname);
#else
	Py_SetProgramName("uWSGI");
#endif

        Py_Initialize() ;

#ifndef ROCK_SOLID
        py_apps = PyDict_New();
        if (!py_apps) {
                PyErr_Print();
                exit(1);
        }

#endif


        wsgi_spitout = PyCFunction_New(uwsgi_spit_method,NULL) ;
        wsgi_writeout = PyCFunction_New(uwsgi_write_method,NULL) ;

#ifndef PYTHREE
	uwsgi_module = Py_InitModule("uwsgi", null_methods);
        if (uwsgi_module == NULL) {
		fprintf(stderr,"could not initialize the uwsgi python module\n");
		exit(1);
	}
	if (sharedareasize > 0) {
		#ifndef __OpenBSD__
		sharedareamutex = mmap(NULL, sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE , MAP_SHARED|MAP_ANON , -1, 0);
		if (!sharedareamutex) {
			perror("mmap()");
			exit(1);
		}
		#else
			fprintf(stderr,"***WARNING*** the sharedarea on OpenBSD is not SMP-safe. Beware of race conditions !!!\n");
		#endif
		sharedarea = mmap(NULL, getpagesize() * sharedareasize, PROT_READ|PROT_WRITE , MAP_SHARED|MAP_ANON , -1, 0);
		if (sharedarea) { 
			fprintf(stderr,"shared area mapped at %p, you can access it with uwsgi.sharedarea* functions.\n", sharedarea);

#ifdef __APPLE__
			memset(sharedareamutex,0, sizeof(OSSpinLock));
#else
		#ifndef __OpenBSD__
			if (pthread_mutexattr_init((pthread_mutexattr_t *)sharedareamutex)) {
				fprintf(stderr,"unable to allocate mutexattr structure\n");
				exit(1);
			}
			if (pthread_mutexattr_setpshared((pthread_mutexattr_t *)sharedareamutex, PTHREAD_PROCESS_SHARED)) {
				fprintf(stderr,"unable to share mutex\n");
				exit(1);
			}
			if (pthread_mutex_init((pthread_mutex_t *) sharedareamutex + sizeof(pthread_mutexattr_t), (pthread_mutexattr_t *)sharedareamutex)) {
				fprintf(stderr,"unable to initialize mutex\n");
				exit(1);
			}
		#endif
#endif
			
		}
		else {
			perror("mmap()");
			exit(1);
		}

	}

	init_uwsgi_embedded_module();
#endif



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

		wi->wsgi_harakiri = PyDict_GetItemString(wi->wsgi_dict, "harakiri");

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
        if (socket_name != NULL && !is_a_reload) {
		char *tcp_port = strchr(socket_name, ':');
               	if (tcp_port == NULL) {
			serverfd = bind_to_unix(socket_name, listen_queue, chmod_socket, abstract_socket);
		}
		else {
			serverfd = bind_to_tcp(socket_name, listen_queue, tcp_port);
		}

		if (serverfd < 0) {
			fprintf(stderr,"unable to create the server socket.\n");
			exit(1);
		}
        }
#endif

	socket_type_len = sizeof(int);
	if (getsockopt(serverfd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_len)) {
		perror("getsockopt()");
		exit(1);
	}



#ifndef ROCK_SOLID
	if (single_interpreter == 1) {
		init_uwsgi_vars();
	}

        memset(wsgi_apps, 0, sizeof(wsgi_apps));


#endif



        wsgi_poll.events = POLLIN ;

	memset(&wsgi_req, 0, sizeof(struct wsgi_request));


#ifndef ROCK_SOLID
	if (wsgi_config != NULL) {
		uwsgi_wsgi_config();
	}
#endif

#ifndef UNBIT
#ifndef ROCK_SOLID
	else if (xml_config != NULL) {
		uwsgi_xml_config();
	}
#endif
#endif

	if (test_module != NULL) {
		if (PyImport_ImportModule(test_module)) {
			exit(0);
		}
		exit(1);
	}


        mypid = getpid();
	masterpid = mypid ;

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
	if (master_process == 0) {
        	fprintf(stderr, "spawned uWSGI worker 0 (pid: %d)\n", mypid);
	}
	else {
		if (is_a_reload) {
        		fprintf(stderr, "gracefully (RE)spawned uWSGI master process (pid: %d)\n", mypid);
		}
		else {
        		fprintf(stderr, "spawned uWSGI master process (pid: %d)\n", mypid);
		}
		workers = (struct uwsgi_worker *) mmap(NULL, sizeof(struct uwsgi_worker)*numproc+1, PROT_READ|PROT_WRITE , MAP_SHARED|MAP_ANON , -1, 0);
		if (!workers) {
			perror("mmap()");
			exit(1);
		}
	}

#ifdef UNBIT
	if (single_app_mode == 1) {
		wsgi_req.wsgi_script = getenv("UWSGI_SCRIPT");
		if (wsgi_req.wsgi_script) {
			wsgi_req.wsgi_script_len = strlen(wsgi_req.wsgi_script);
		}
		else {
			fprintf(stderr, "UWSGI_SCRIPT env var not set !\n");
			exit(1);
		}

		init_uwsgi_app(NULL, NULL);
	}
#endif

#ifndef ROCK_SOLID
	if (spool_dir != NULL) {
		spooler_pid = spooler_start(spool_dir, serverfd, uwsgi_module);
	}
#endif

        for(i=1;i<numproc+master_process;i++) {
		/* let the worker know his worker_id (wid) */
		mywid = i;
                pid = fork();
                if (pid == 0 ) {
                        mypid = getpid();
			if (serverfd != 0 && master_process == 1) {
				/* close STDIN for workers */
				close(0);
			}
                        break;
                }
                else if (pid < 1) {
                        perror("fork()");
                        exit(1);
                }
                else {
                        fprintf(stderr, "spawned uWSGI worker %d (pid: %d)\n", i, pid);
			if (master_process)
				workers[i].pid = pid ;
			gettimeofday(&last_respawn, NULL) ;
			respawn_delta = last_respawn.tv_sec;
                }
        }


	if (getpid() == masterpid && master_process == 1) {
		/* route signals to workers... */
		signal(SIGHUP, (void *) &grace_them_all);
		signal(SIGTERM, (void *) &reap_them_all);
        	signal(SIGINT, (void *) &kill_them_all);
        	signal(SIGQUIT, (void *) &kill_them_all);
		for(;;) {
			if (ready_to_die >= numproc) {
#ifndef ROCK_SOLID
				if (spool_dir && spooler_pid > 0) {
					kill(spooler_pid, SIGKILL);
				}
#endif
				fprintf(stderr,"goodbye to uWSGI.\n");
				exit(0);
			}		
			if (ready_to_reload >= numproc) {
#ifndef ROCK_SOLID
				if (spool_dir && spooler_pid > 0) {
					kill(spooler_pid, SIGKILL);
				}
#endif
				fprintf(stderr,"binary reloading uWSGI...\n");
				if (chdir(cwd)) {
					perror("chdir()");
					exit(1);
				}
				/* check fd table (a module can obviosly open some fd on initialization...) */
				fprintf(stderr,"closing all fds > 2 (_SC_OPEN_MAX = %ld)...\n",sysconf(_SC_OPEN_MAX));
				for(i=3;i<sysconf(_SC_OPEN_MAX);i++) {
					if (i == serverfd) {
						continue ;
					}
					close(i);
				}
				if (serverfd != 3) {
					if (dup2(serverfd,3) < 0) {
                				perror("dup2()");
                				exit(1);
					}
				}
				fprintf(stderr,"running %s\n", binary_path);
				strcpy(argv[0], binary_path);
				execve(binary_path, argv, envp);
				perror("execve()");
				exit(1);
			}
			diedpid = waitpid(WAIT_ANY , &waitpid_status, WNOHANG) ;
			if (diedpid == -1) {
				perror("waitpid()");
				fprintf(stderr, "something horrible happened...\n");
				reap_them_all();
				exit(1);
			}
			else if (diedpid == 0) {
				/* PLEASE, do not run python threads in the master process, you can potentially destroy the world,
				 we support this for hyperultramegagodprogrammer and systems
				*/
        			if (has_threads) {
                			_save = PyEval_SaveThread();
        			}
				/* all processes ok, doing status scan after 1 second */
				select(0, NULL, NULL, NULL, &check_interval);
                                if (has_threads) {
                                	PyEval_RestoreThread(_save);
                                }
				check_interval.tv_sec = 1 ;
				for(i=1;i<=numproc;i++) {
					/* first check for harakiri */
                			if (workers[i].harakiri > 0) {
						if (workers[i].harakiri < time(NULL)) {
							/* first try to invoke the harakiri() custom handler */
							/* the brutally kill the worker */
							kill(workers[i].pid, SIGKILL);
						}
					}
        			}
				continue;
			}
#ifndef ROCK_SOLID
			/* reload the spooler */
			if (spool_dir && spooler_pid > 0) {
				if (diedpid == spooler_pid) {
					spooler_pid = spooler_start(spool_dir,serverfd, uwsgi_module);
					continue;
				}
			}
#endif
			/* check for reloading */
			if (WIFEXITED(waitpid_status)) {
				if (WEXITSTATUS(waitpid_status) == UWSGI_RELOAD_CODE) {
					ready_to_reload++;
					continue;
				}
				else if (WEXITSTATUS(waitpid_status) == UWSGI_END_CODE) {
					ready_to_die++;
					continue;
				}
			}
			fprintf(stderr,"DAMN ! process %d died :( trying respawn ...\n", diedpid);
			gettimeofday(&last_respawn, NULL) ;
			if (last_respawn.tv_sec == respawn_delta) {
				fprintf(stderr,"worker respawning too fast !!! i have to sleep a bit...\n");
				/* TODO, user configurable fork throttler */
				sleep(2);
			}
			gettimeofday(&last_respawn, NULL) ;
			respawn_delta = last_respawn.tv_sec;
			mywid = find_worker_id(diedpid);
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
				if (mywid > 0) {
					workers[mywid].pid = pid ;
					workers[mywid].harakiri = 0 ;
					workers[mywid].requests = 0 ;
					workers[mywid].failed_requests = 0 ;
					workers[mywid].respawn_count++ ;
					workers[mywid].last_spawn = time(NULL) ;
				}
				else {
					fprintf(stderr, "warning the died pid was not in the workers list. Probably you hit a BUG of uWSGI\n") ;
				}
			}
		}
	}


	

#ifndef ROCK_SOLID
	wsgi_req.app_id = default_app ;	
        wsgi_req.sendfile_fd = -1 ;
#endif

	hvec = malloc(sizeof(struct iovec)*vec_size) ;
	if (hvec == NULL) {
		fprintf(stderr,"unable to allocate memory for iovec.\n");
		exit(1);
	}

        if (harakiri_timeout > 0 && workers == NULL) {
                signal(SIGALRM, (void *) &harakiri);
        }

	/* gracefully reload */
        signal(SIGHUP, (void *) &gracefully_kill);
	/* close the process (useful for master INT) */
        signal(SIGINT, (void *) &end_me);
	/* brutally reload */
        signal(SIGTERM, (void *) &reload_me);


#ifndef UNBIT
#ifndef ROCK_SOLID
	signal(SIGUSR1, (void *) &stats);
#endif
#endif

        if (has_threads) {
                _save = PyEval_SaveThread();
        }

        while(manage_next_request) {

		in_request = 0 ;
		wsgi_poll.fd = accept(serverfd,(struct sockaddr *)&c_addr, (socklen_t *) &c_len) ;
		in_request = 1 ;

                if (wsgi_poll.fd < 0){
                        perror("accept()");
			continue;
                }

                /*
                        poll with timeout ;
                */

                gettimeofday(&wsgi_req.start_of_request, NULL) ;

                /* first 4 byte header */
                rlen = poll(&wsgi_poll, 1, socket_timeout*1000) ;
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
		if (rlen > 0 && rlen < 4) {
			i = rlen ;
			while(i < 4) {
				rlen = poll(&wsgi_poll, 1, socket_timeout*1000) ;
				if (rlen < 0) {
					perror("poll()");
					exit(1);
				}
				else if (rlen == 0) {
                        		fprintf(stderr, "timeout waiting for header. skip request.\n");
                        		close(wsgi_poll.fd);
                        		break ;
				}	
				rlen = read(wsgi_poll.fd, (char *)(&wsgi_req)+i, 4-i);
				if (rlen <= 0) {
					fprintf(stderr, "broken header. skip request.\n");	
					close(wsgi_poll.fd);
					break ;
				}
				i += rlen;
			}
			if (i < 4) {
				continue;
			}
		}
                else if (rlen <= 0){
                        fprintf(stderr,"invalid request header size: %d...skip\n", rlen);
                        close(wsgi_poll.fd);
                        continue;
                }
		/* big endian ? */
		#ifdef __BIG_ENDIAN__
		wsgi_req.size = uwsgi_swap16(wsgi_req.size);
		#endif

		/* check for max buffer size */
                if (wsgi_req.size > buffer_size) {
                        fprintf(stderr,"invalid request block size: %d...skip\n", wsgi_req.size);
                        close(wsgi_poll.fd);
                        continue;
                }

		//fprintf(stderr,"ready for reading %d bytes\n", wsgi_req.size);

                /* http headers parser */
		i = 0 ;
		while(i < wsgi_req.size) {
                	rlen = poll(&wsgi_poll, 1, socket_timeout*1000) ;
                	if (rlen < 0) {
                        	perror("poll()");
                        	exit(1);
                	}
                	else if (rlen == 0) {
                        	fprintf(stderr, "timeout. skip request. (expecting %d bytes, got %d)\n", wsgi_req.size, i);
                        	close(wsgi_poll.fd);
                        	break ;
                	}
                	rlen = read(wsgi_poll.fd, buffer+i, wsgi_req.size-i);
			if (rlen <= 0) {
				fprintf(stderr, "broken vars. skip request.\n");             
                                close(wsgi_poll.fd);
                                break ;
			}
			i += rlen ;
		}


		if (i < wsgi_req.size) {
			continue;
		}

		
		if (wsgi_req.modifier == UWSGI_MODIFIER_PING) {
			fprintf(stderr,"PING\n");
			wsgi_req.modifier_arg = 1 ;
			if (write(wsgi_poll.fd,&wsgi_req,4) != 4) {
				perror("write()");
			}
			close(wsgi_poll.fd);
			memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
			requests++;
			continue;
		}
		else if (wsgi_req.modifier == UWSGI_MODIFIER_FASTFUNC) {
			zero = PyList_GetItem(uwsgi_fastfuncslist, wsgi_req.modifier_arg) ;
			if (zero) {
				fprintf(stderr,"managing fastfunc %d\n", wsgi_req.modifier_arg) ;
				wsgi_result = PyEval_CallObject(zero, NULL);
				if (PyErr_Occurred()) {
                                	PyErr_Print();
                        	}
				if (wsgi_result) {
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
					Py_DECREF(wsgi_result);
				}
			}
			PyErr_Clear();
			close(wsgi_poll.fd);
			memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
			requests++;
			continue;
		}
		/* check for spooler request */
		else if (wsgi_req.modifier == UWSGI_MODIFIER_SPOOL_REQUEST) {
			
			if (spool_dir == NULL) {
				fprintf(stderr,"the spooler is inactive !!!...skip\n");
				wsgi_req.modifier = 255 ;
				wsgi_req.size = 0 ;
				wsgi_req.modifier_arg = 0 ;
				i = write(wsgi_poll.fd,&wsgi_req,4);
				if (i != 4) {
					perror("write()");
				}
				close(wsgi_poll.fd);
				memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
				requests++;
				continue;	
			}

			fprintf(stderr,"managing spool request...\n");
			i = spool_request(spool_dir, spool_filename, requests+1, buffer,wsgi_req.size) ;
			wsgi_req.modifier = 255 ;
			wsgi_req.size = 0 ;
			if (i > 0) {
				wsgi_req.modifier_arg = 1 ;
				if (write(wsgi_poll.fd,&wsgi_req,4) != 4) {
					fprintf(stderr,"disconnected client, remove spool file.\n");
					/* client disconnect, remove spool file */	
					if (unlink(spool_filename)) {
						perror("unlink()");
						fprintf(stderr,"something horrible happened !!! check your spooler ASAP !!!\n");	
						goodbye_cruel_world();
					}
				}
			}
			else {
				/* announce a failed spool request */
				wsgi_req.modifier_arg = 0 ;
				i = write(wsgi_poll.fd,&wsgi_req,4);
				if (i != 4) {
					perror("write()");
				}
			}
			close(wsgi_poll.fd);
			memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
			requests++;
			continue;	
		}	

                ptrbuf = buffer ;
                bufferend = ptrbuf+wsgi_req.size ;


                        while(ptrbuf < bufferend) {
                                if (ptrbuf+2 < bufferend) {
                                        memcpy(&strsize,ptrbuf,2);
					#ifdef __BIG_ENDIAN__
					strsize = uwsgi_swap16(strsize);
					#endif
                                        ptrbuf+=2;
                                        if (ptrbuf+strsize < bufferend) {
                                                // var key
                                                hvec[wsgi_req.var_cnt].iov_base = ptrbuf ;
                                                hvec[wsgi_req.var_cnt].iov_len = strsize ;
                                                ptrbuf+=strsize;
                                                if (ptrbuf+2 < bufferend) {
                                                        memcpy(&strsize,ptrbuf,2);
							#ifdef __BIG_ENDIAN__
							strsize = uwsgi_swap16(strsize);
							#endif
                                                        ptrbuf+=2 ;
                                                        if ( ptrbuf+strsize <= bufferend) {
#ifndef ROCK_SOLID
						#ifdef UNBIT
                                                                if (single_app_mode == 0 && !strncmp("SCRIPT_NAME", hvec[wsgi_req.var_cnt].iov_base , hvec[wsgi_req.var_cnt].iov_len)) {
						#else
                                                                if (!strncmp("SCRIPT_NAME", hvec[wsgi_req.var_cnt].iov_base , hvec[wsgi_req.var_cnt].iov_len)) {
						#endif
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
#ifdef UNBIT
								else if (!strncmp("UNBIT_FLAGS", hvec[wsgi_req.var_cnt].iov_base, hvec[wsgi_req.var_cnt].iov_len)) {
									wsgi_req.unbit_flags = *(unsigned long long *) ptrbuf ;
								}
#endif
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
                if (wsgi_req.app_id == -1 && wsgi_config == NULL) {
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



			if (wsgi_req.wsgi_script_len > 0 || (wsgi_req.wsgi_callable_len > 0 && wsgi_req.wsgi_module_len > 0)) {
                        	if ((wsgi_req.app_id = init_uwsgi_app(NULL, NULL)) == -1) {
                                	internal_server_error(wsgi_poll.fd, "wsgi application not found");
                                	goto clean ;
                        	}
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
#ifdef UNBIT
			if (wsgi_req.modifier != 0) {
				switch(wsgi_req.modifier) {
					case UWSGI_MODIFIER_HT_S:
						set_harakiri(wsgi_req.modifier_arg);
					case UWSGI_MODIFIER_HT_M:
						set_harakiri(wsgi_req.modifier_arg*60);
					case UWSGI_MODIFIER_HT_H:
						set_harakiri(wsgi_req.modifier_arg*3600);
				}
			}
			else {
#endif
                        	set_harakiri(harakiri_timeout);
#ifdef UNBIT
			}
#endif
                }


                for(i=0;i<wsgi_req.var_cnt;i+=2) {
			/*fprintf(stderr,"%.*s: %.*s\n", hvec[i].iov_len, hvec[i].iov_base, hvec[i+1].iov_len, hvec[i+1].iov_base);*/
                        pydictkey = PyString_FromStringAndSize(hvec[i].iov_base, hvec[i].iov_len) ;
                        pydictvalue = PyString_FromStringAndSize(hvec[i+1].iov_base, hvec[i+1].iov_len) ;
                        PyDict_SetItem(wi->wsgi_environ, pydictkey, pydictvalue);
                        Py_DECREF(pydictkey);
                        Py_DECREF(pydictvalue);
                }

		if (wsgi_req.modifier == UWSGI_MODIFIER_MANAGE_PATH_INFO) {
			pydictkey = PyDict_GetItemString(wi->wsgi_environ,"SCRIPT_NAME");
			if (pydictkey) {
				if (PyString_Check(pydictkey)) {
					pydictvalue = PyDict_GetItemString(wi->wsgi_environ,"PATH_INFO");
					if (pydictvalue) {
						if (PyString_Check(pydictvalue)) {
							path_info = PyString_AsString(pydictvalue);
							PyDict_SetItemString(wi->wsgi_environ, "PATH_INFO", PyString_FromString(path_info + PyString_Size(pydictkey)));
						}
					}
				}
			}
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

#ifdef UNBIT
		if (wsgi_req.unbit_flags & (unsigned long long) 1) {	
			if (uri_to_hex() <= 0) {
				tmp_filename[0] = 0 ;
			}
		}
#endif




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
#ifndef __linux__
	#ifdef __freebsd__

					wsgi_req.response_size = sendfile(wsgi_req.sendfile_fd, wsgi_poll.fd, 0, 0, NULL, (off_t *) &rlen, 0) ;
	#elif __OpenBSD__ || __sun__
					char *no_sendfile_buf[4096] ;
					int jlen = 0 ;
					i = 0 ;
					while(i < rlen) {
						jlen = read(wsgi_req.sendfile_fd, no_sendfile_buf, 4096);
						if (jlen<=0) {
							perror("read()");
							break;
						}
						i += jlen;
						jlen = write(wsgi_poll.fd, no_sendfile_buf, jlen);		
						if (jlen<=0) {
							perror("write()");
							break;
						}
						
					}
	#else
                                        wsgi_req.response_size = sendfile(wsgi_req.sendfile_fd, wsgi_poll.fd, 0, (off_t *) &rlen, NULL, 0) ;
	#endif
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
#ifdef UNBIT
							if (save_to_disk >= 0) {
								if (write(save_to_disk, PyString_AsString(wchunk), PyString_Size(wchunk)) < 0) {
									perror("write()");
									close(save_to_disk);
									save_to_disk = -1 ;
									unlinkat(tmp_dir_fd, tmp_filename, 0);
								}
							}
#endif
                                                }
                                                Py_DECREF(wchunk);
                                        }
                                        Py_DECREF(wsgi_chunks);
#ifdef UNBIT
					if (save_to_disk >= 0) {
						close(save_to_disk);
						save_to_disk = -1 ;
						fprintf(stderr,"[uWSGI cacher] output of request %d (%.*s) on pid %d written to cache file %s\n",requests+1, wsgi_req.uri_len, wsgi_req.uri, mypid,tmp_filename);
					}
#endif
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
                        set_harakiri(0);
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
		// defunct process reaper
		if (process_reaper == 1) {
			waitpid(-1, &waitpid_status, WNOHANG);
		}
                // reset request
                memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
#ifdef UNBIT
		if (tmp_filename && tmp_dir_fd >= 0) {
			tmp_filename[0] = 0 ;
		}
#endif

#ifndef ROCK_SOLID
                wsgi_req.app_id = default_app ;
                wsgi_req.sendfile_fd = -1 ;
#endif

		if (max_requests > 0 && requests >= max_requests) {
			goodbye_cruel_world();
		}

#ifdef UNBIT
		if (check_for_memory_errors) {
			if (syscall(357,&us,0) > 0) {
				if (us.memory_errors > 0) {
					fprintf(stderr,"Unbit Kernel found a memory allocation error for process %d.\n", mypid);
					goodbye_cruel_world();
				}
			}
		}
#endif

        }

	if (manage_next_request == 0) {
		reload_me();
	}
	else {
		goodbye_cruel_world();
	}

	/* never here */
	return 0 ;
}

void log_request() {
        char *time_request ;
        struct timeval end_request ;
        time_t microseconds, microseconds2;


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

        time_request = ctime( (const time_t *) &wsgi_req.start_of_request.tv_sec);
        gettimeofday(&end_request, NULL) ;
        microseconds = end_request.tv_sec*1000000+end_request.tv_usec ;
        microseconds2 = wsgi_req.start_of_request.tv_sec*1000000+wsgi_req.start_of_request.tv_usec ;
#ifndef ROCK_SOLID
        if (memory_debug == 1) {
                get_memusage();
#ifndef UNBIT
#ifdef __APPLE__
                fprintf(stderr,"{address space usage: %lld bytes/%lluMB} {rss usage: %llu bytes/%lluMB} ", wsgi_req.vsz_size, wsgi_req.vsz_size/1024/1024, wsgi_req.rss_size, wsgi_req.rss_size/1024/1024) ;
#endif
#ifdef __linux__
                fprintf(stderr,"{address space usage: %lld bytes/%lluMB} {rss usage: %llu bytes/%lluMB} ", wsgi_req.vsz_size, wsgi_req.vsz_size/1024/1024, wsgi_req.rss_size*PAGE_SIZE, (wsgi_req.rss_size*PAGE_SIZE)/1024/1024) ;
#endif
#else
                fprintf(stderr,"{address space usage: %lld bytes/%lluMB} ", wsgi_req.vsz_size, wsgi_req.vsz_size/1024/1024) ;
#endif
        }
#endif

#ifdef ROCK_SOLID
        fprintf(stderr, "[pid: %d|req: %d] %.*s (%.*s) {%d vars in %d bytes} [%.*s] %.*s %.*s => generated %d bytes in %ld msecs (%.*s %d) %d headers in %d bytes\n",
                mypid, requests, wsgi_req.remote_addr_len, wsgi_req.remote_addr,
                wsgi_req.remote_user_len, wsgi_req.remote_user, wsgi_req.var_cnt, wsgi_req.size, 24, time_request,
                wsgi_req.method_len, wsgi_req.method, wsgi_req.uri_len, wsgi_req.uri, wsgi_req.response_size, 
                (microseconds-microseconds2)/1000,
                wsgi_req.protocol_len, wsgi_req.protocol, wsgi_req.status, wsgi_req.header_cnt, wsgi_req.headers_size) ;
#else
        fprintf(stderr, "[pid: %d|app: %d|req: %d/%d] %.*s (%.*s) {%d vars in %d bytes} [%.*s] %.*s %.*s => generated %d bytes in %ld msecs%s(%.*s %d) %d headers in %d bytes\n",
                mypid, wsgi_req.app_id, app_req, requests, wsgi_req.remote_addr_len, wsgi_req.remote_addr,
                wsgi_req.remote_user_len, wsgi_req.remote_user, wsgi_req.var_cnt, wsgi_req.size, 24, time_request,
                wsgi_req.method_len, wsgi_req.method, wsgi_req.uri_len, wsgi_req.uri, wsgi_req.response_size, 
                (microseconds-microseconds2)/1000, via,
                wsgi_req.protocol_len, wsgi_req.protocol, wsgi_req.status, wsgi_req.header_cnt, wsgi_req.headers_size) ;
#endif

}

#ifndef ROCK_SOLID
void get_memusage() {

#ifdef UNBIT
	wsgi_req.vsz_size = syscall(356);	
#else
#ifdef __linux__
        FILE *procfile;
	int i;
        procfile = fopen("/proc/self/stat","r");
        if (procfile) {
                i = fscanf(procfile,"%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu %lld",&wsgi_req.vsz_size, &wsgi_req.rss_size) ;
		if (i != 2) {
			fprintf(stderr, "warning: invalid record in /proc/self/stat\n");
		}
                fclose(procfile);
        }
#endif
#ifdef __APPLE__
	/* darwin documentation says that the value are in pages, bot they are bytes !!! */
	struct task_basic_info t_info;
	mach_msg_type_number_t t_size = sizeof(struct task_basic_info);

	if (task_info(mach_task_self(),TASK_BASIC_INFO, (task_info_t)&t_info, &t_size) == KERN_SUCCESS) {
		wsgi_req.rss_size = t_info.resident_size;
		wsgi_req.vsz_size = t_info.virtual_size;
	}

#endif
#endif
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
int init_uwsgi_app(PyObject *force_wsgi_dict, PyObject *my_callable) {
        PyObject *wsgi_module, *wsgi_dict ;
	PyObject *pymain, *zero;
	PyObject *pycprof, *pycprof_dict;
        char tmpstring[256] ;
	int id ;

        struct uwsgi_app *wi ;

        memset(tmpstring,0, 256) ;


	if (wsgi_req.wsgi_script_len == 0 && ( (wsgi_req.wsgi_module_len == 0 || wsgi_req.wsgi_callable_len == 0) && wsgi_config == NULL && my_callable == NULL) ) {
		fprintf(stderr, "invalid application (%.*s). skip.\n", wsgi_req.script_name_len, wsgi_req.script_name);
		return -1;
	}

	if (wsgi_config && wsgi_req.wsgi_callable_len == 0 && my_callable == NULL) {
		fprintf(stderr, "invalid application (%.*s). skip.\n", wsgi_req.script_name_len, wsgi_req.script_name);
		return -1;
	}

	if (wsgi_req.wsgi_script_len > 255 || wsgi_req.wsgi_module_len > 255 || wsgi_req.wsgi_callable_len > 255) {
		fprintf(stderr, "invalid application's string size. skip.\n");
		return -1;
	}

	id = wsgi_cnt ;


	if (wsgi_req.script_name_len == 0) {
		wsgi_req.script_name_len = 1 ;
		wsgi_req.script_name = (char *) app_slash ;
		id = 0 ;
	}
	else if (wsgi_req.script_name_len == 1) {
		if (wsgi_req.script_name[0] == '/') {
			id = 0 ;
		}
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
		if (!wi->interpreter) {
			fprintf(stderr,"unable to initialize the new interpreter\n");
			exit(1);
		}
        	PyThreadState_Swap(wi->interpreter) ;
#ifndef PYTHREE
		init_uwsgi_embedded_module();
#endif
		init_uwsgi_vars();
		fprintf(stderr,"interpreter for app %d initialized.\n", id);
	}



	if (wsgi_config == NULL) {
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

	}
	else {
		wsgi_dict = force_wsgi_dict;
	}


        memset(tmpstring, 0, 256);
        memcpy(tmpstring, wsgi_req.wsgi_callable, wsgi_req.wsgi_callable_len) ;
	if (my_callable) {
        	wi->wsgi_callable = my_callable;
		Py_INCREF(my_callable);
	}
	else if (wsgi_dict) {
        	wi->wsgi_callable = PyDict_GetItemString(wsgi_dict, tmpstring);
	}
	else {
		return -1;
	}


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

	wi->wsgi_harakiri = PyDict_GetItemString(wsgi_dict, "harakiri");
	if (wi->wsgi_harakiri) {
		fprintf(stderr, "initialized Harakiri custom handler: %p.\n", wi->wsgi_harakiri);
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


void uwsgi_wsgi_config() {

	PyObject *wsgi_module, *wsgi_dict ;
	PyObject *uwsgi_module, *uwsgi_dict ;
	PyObject *applications;
	PyObject *app_list;
	int ret;
	Py_ssize_t i;
	PyObject *app_mnt, *app_app ;

	wsgi_module = PyImport_ImportModule(wsgi_config) ;
        if (!wsgi_module) {
        	PyErr_Print();
		exit(1);
	}

	wsgi_dict = PyModule_GetDict(wsgi_module);
        if (!wsgi_dict) {
                PyErr_Print();
		exit(1);
	}

	fprintf(stderr,"...getting the applications list from the '%s' module...\n", wsgi_config);

	uwsgi_module = PyImport_ImportModule("uwsgi") ;
        if (!uwsgi_module) {
        	PyErr_Print();
		exit(1);
	}

	uwsgi_dict = PyModule_GetDict(uwsgi_module);
        if (!uwsgi_dict) {
                PyErr_Print();
		exit(1);
	}

	

	applications = PyDict_GetItemString(uwsgi_dict, "applications");
	if (!PyDict_Check(applications)) {
		fprintf(stderr,"uwsgi.applications dictionary is not defined, trying with the (deprecated) \"applications\" one...\n");
		applications = PyDict_GetItemString(wsgi_dict, "applications");
		if (!applications) {
			fprintf(stderr,"applications dictionary is not defined, now you have to use dynamic apps.\n");
			return;
		}
	}

	if (!PyDict_Check(applications)) {
		fprintf(stderr,"The 'applications' object must be a dictionary.\n");
		exit(1);
	}

	app_list = PyDict_Keys(applications);
	if (!app_list) {
                PyErr_Print();
		exit(1);
	}
	if (PyList_Size(app_list) < 1) {
		fprintf(stderr,"You must define an app.\n");
		exit(1);
	}

	for(i=0;i<PyList_Size(app_list);i++) {
		app_mnt = PyList_GetItem(app_list, i) ;

		if (!PyString_Check(app_mnt)) {
			fprintf(stderr, "the app mountpoint must be a string.\n");
			exit(1);
		}

		wsgi_req.script_name = PyString_AsString(app_mnt);
		wsgi_req.script_name_len = strlen(wsgi_req.script_name);

		app_app = PyDict_GetItem(applications, app_mnt);

		if (!PyString_Check(app_app) && !PyFunction_Check(app_app) && !PyCallable_Check(app_app)) {
                        fprintf(stderr, "the app callable must be a string, a function or a callable. (found %s)\n", app_app->ob_type->tp_name);
                        exit(1);
                }

		if (PyString_Check(app_app)) {
			wsgi_req.wsgi_callable = PyString_AsString(app_app) ;
			wsgi_req.wsgi_callable_len = strlen(wsgi_req.wsgi_callable);
			fprintf(stderr,"initializing [%s => %s] app...\n",  wsgi_req.script_name, wsgi_req.wsgi_callable);
			ret = init_uwsgi_app(wsgi_dict, NULL);
		}
		else {
			fprintf(stderr,"initializing [%s] app...\n",  wsgi_req.script_name);
			ret = init_uwsgi_app(wsgi_dict, app_app);
		}

		if (ret < 0) {
			fprintf(stderr,"...goodbye cruel world...\n");
			exit(1);
		}
		Py_DECREF(app_mnt);
		Py_DECREF(app_app);
	}

}

#endif

// useless part for Unbit
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
							init_uwsgi_app(NULL, NULL);
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

#endif


#ifdef UNBIT
int uri_to_hex()
{
	int i=0,j=0 ;

	if (wsgi_req.uri_len < 1) {
		return 0 ;
	}

	if (wsgi_req.uri_len*2 > 8192) {
		return 0 ;
	}

	for ( i = 0;i < wsgi_req.uri_len ; i++ ) {
		sprintf(tmp_filename+j, "%02X", wsgi_req.uri[i]); j+=2;
	}
	
	return j ;
}
#endif

#ifndef PYTHREE
void init_uwsgi_embedded_module() {
	PyObject *new_uwsgi_module;
	PyObject *uwsgi_dict;

	new_uwsgi_module = Py_InitModule("uwsgi", null_methods);
        if (new_uwsgi_module == NULL) {
                fprintf(stderr,"could not initialize the uwsgi python module\n");
                exit(1);
        }

	uwsgi_dict = PyModule_GetDict(new_uwsgi_module);
        if (!uwsgi_dict) {
                fprintf(stderr,"could not get uwsgi module __dict__\n");
                exit(1);
        }

	if (PyDict_SetItemString(uwsgi_dict, "SPOOL_RETRY", PyInt_FromLong(17))) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(uwsgi_dict, "start_response", wsgi_spitout)) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(uwsgi_dict, "fastfuncs", PyList_New(256))) {
		PyErr_Print();
		exit(1);
	}

#ifndef ROCK_SOLID
	if (PyDict_SetItemString(uwsgi_dict, "applist", py_apps)) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(uwsgi_dict, "applications", Py_None)) {
		PyErr_Print();
		exit(1);
	}
#endif

	uwsgi_fastfuncslist = PyDict_GetItemString(uwsgi_dict, "fastfuncs");
	if (!uwsgi_fastfuncslist) {
		PyErr_Print();
		exit(1);
	}

	init_uwsgi_module_advanced(new_uwsgi_module);


	if (sharedareasize > 0 && sharedarea) {
		init_uwsgi_module_sharedarea(new_uwsgi_module);
	}
}
#endif

#ifndef ROCK_SOLID
pid_t spooler_start(char *spool_dir, int serverfd, PyObject *uwsgi_module) {
	pid_t pid ;

	pid = fork();
        if (pid < 0) {
        	perror("fork()");
                exit(1);
        }
	else if (pid == 0) {
		close(serverfd);
        	spooler(spool_dir, uwsgi_module);
	}
	else if (pid > 0) {
        	fprintf(stderr,"spawned the uWSGI spooler on dir %s with pid %d\n", spool_dir, pid);
	}

	return pid ;
}
#endif
