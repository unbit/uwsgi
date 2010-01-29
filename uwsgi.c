/* 
	
    *** uWSGI ***

    Copyright (C) 2009-2010 Unbit S.a.s. <info@unbit.it>
	
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

struct uwsgi_server uwsgi;

static char *nl = "\r\n";
static char *h_sep = ": " ;
static const char *http_protocol = "HTTP/1.1" ;
#ifndef ROCK_SOLID
static const char *app_slash = "/" ;
#endif

int find_worker_id(pid_t pid) {
	int i ;
	for(i = 1 ; i<= uwsgi.numproc ; i++) {
		/* fprintf(stderr,"%d of %d\n", pid, uwsgi.workers[i].pid); */
		if (uwsgi.workers[i].pid == pid)
			return i ;
	}

	return -1 ;
}

struct wsgi_request wsgi_req;

PyMethodDef null_methods[] = {
  {NULL, NULL},
};

#ifdef UNBIT
int save_to_disk = -1 ;
int tmp_dir_fd = -1 ;
char *tmp_filename ;
int uri_to_hex(void);
int check_for_memory_errors = 0 ;
#endif

PyObject *wsgi_writeout ;

// iovec
struct iovec *hvec ;

#ifdef ROCK_SOLID
struct uwsgi_app *wi;
#endif

void gracefully_kill() {
	fprintf(stderr, "Gracefully killing worker %d...\n", uwsgi.mypid);
	if (uwsgi.workers[uwsgi.mywid].in_request) {
		uwsgi.workers[uwsgi.mywid].manage_next_request = 0 ;	
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
	uwsgi.to_hell = 1 ;
	fprintf(stderr,"SIGINT/SIGQUIT received...killing workers...\n");
	for(i=1;i<=uwsgi.numproc;i++) {	
		kill(uwsgi.workers[i].pid, SIGINT);
	}
}

void grace_them_all() {
	int i ;
	uwsgi.to_heaven = 1 ;
	fprintf(stderr,"...gracefully killing workers...\n");
	for(i=1;i<=uwsgi.numproc;i++) {	
		kill(uwsgi.workers[i].pid, SIGHUP);
	}
}

void reap_them_all() {
	int i ;
	fprintf(stderr,"...brutally killing workers...\n");
	for(i=1;i<=uwsgi.numproc;i++) {
		kill(uwsgi.workers[i].pid, SIGTERM);
	}
}

void harakiri() {

	PyThreadState *_myself;
#ifndef ROCK_SOLID
	struct uwsgi_app *wi = NULL ;
	if (wsgi_req.app_id >= 0) {
		wi = &uwsgi.wsgi_apps[wsgi_req.app_id] ;
	}
#endif
	PyGILState_Ensure();
	_myself = PyThreadState_Get();
	if (wi) {
	#ifdef ROCK_SOLID
       		fprintf(stderr,"\nF*CK !!! i must kill myself (pid: %d) wi: %p wi->wsgi_harakiri: %p thread_state: %p frame: %p...\n", uwsgi.mypid, wi, wi->wsgi_harakiri, _myself, _myself->frame );
	#else
       		fprintf(stderr,"\nF*CK !!! i must kill myself (pid: %d app_id: %d) wi: %p wi->wsgi_harakiri: %p thread_state: %p frame: %p...\n", uwsgi.mypid, wsgi_req.app_id, wi, wi->wsgi_harakiri, _myself, _myself->frame );
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
	fprintf(stderr, "\ttotal requests: %llu\n", uwsgi.workers[0].requests);
	for(i=0;i<uwsgi.wsgi_cnt;i++) {
		ua = &uwsgi.wsgi_apps[i];
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
	if (uwsgi.options[UWSGI_OPTION_CGI_MODE] == 0) {
#endif
#endif
        	wsgi_req.headers_size = write(fd, "HTTP/1.1 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 63);
#ifndef UNBIT
#ifndef ROCK_SOLID
	}
	else {
        	wsgi_req.headers_size = write(fd, "Status: 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 62);
	}
#endif
	wsgi_req.header_cnt = 2 ;
#endif
        wsgi_req.response_size = write(fd, "<h1>uWSGI Error</h1>", 20);
        wsgi_req.response_size += write(fd, message, strlen(message));
}

#ifndef ROCK_SOLID
PyObject *py_uwsgi_sendfile(PyObject *self, PyObject *args) {

        //PyObject *zero ;

        uwsgi.py_sendfile = PyTuple_GetItem(args, 0);

#ifdef PYTHREE
	if ((wsgi_req.sendfile_fd = PyObject_AsFileDescriptor(uwsgi.py_sendfile)) >= 0) {
		Py_INCREF(uwsgi.py_sendfile);
	}
#else
        if (PyFile_Check(uwsgi.py_sendfile)) {
                //zero = PyFile_Name(uwsgi.py_sendfile) ;
                //fprintf(stderr,"->serving %s as static file...", PyString_AsString(zero));
                wsgi_req.sendfile_fd = PyObject_AsFileDescriptor(uwsgi.py_sendfile);
                Py_INCREF(uwsgi.py_sendfile);
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
                if (uwsgi.has_threads && uwsgi.options[UWSGI_OPTION_THREADS] == 1) {
                        Py_BEGIN_ALLOW_THREADS
                        wsgi_req.response_size = write(uwsgi.poll.fd, content, len);
                        Py_END_ALLOW_THREADS
                }
                else {
#endif
                        wsgi_req.response_size = write(uwsgi.poll.fd, content, len);
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
		fprintf(stderr,"[uWSGI cacher] output of request %llu (%.*s) on pid %d written to cache file %s\n",uwsgi.workers[0].requests, wsgi_req.uri_len, wsgi_req.uri, uwsgi.mypid,tmp_filename);
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
	if (!head) {
		goto clear;
	}
	
	if (!PyString_Check(head)) {
		fprintf(stderr,"http status must be a string !\n");
		goto clear;
	}

#ifndef UNBIT
#ifndef ROCK_SOLID
	if (uwsgi.options[UWSGI_OPTION_CGI_MODE] == 0) {
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
	if (!headers) {
		goto clear;
	}	
	if (!PyList_Check(headers)) {
		fprintf(stderr,"http headers must be in a python list\n");
		goto clear;
	}
        wsgi_req.header_cnt = PyList_Size(headers) ;



        if (wsgi_req.header_cnt > uwsgi.max_vars) {
                wsgi_req.header_cnt = uwsgi.max_vars ;
        }
        for(i=0;i<wsgi_req.header_cnt;i++) {
                j = (i*4)+base ;
                head = PyList_GetItem(headers, i);
		if (!head) {
			goto clear;
		}
		if (!PyTuple_Check(head)) {
			fprintf(stderr,"http header must be defined in a tuple !\n");
			goto clear;
		}
                h_key = PyTuple_GetItem(head,0) ;
		if (!h_key) { goto clear; }
                h_value = PyTuple_GetItem(head,1) ;
		if (!h_value) { goto clear; }
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

        wsgi_req.headers_size = writev(uwsgi.poll.fd, hvec,j+1);
	if (wsgi_req.headers_size < 0) {
		perror("writev()");
	}
        Py_INCREF(wsgi_writeout);


        return wsgi_writeout ;

clear:

	Py_INCREF(Py_None);
	return Py_None;
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
struct timeval last_respawn;
time_t respawn_delta;
#ifdef UNBIT
int single_app_mode = 0;
#endif

char *spool_dir = NULL ;

int main(int argc, char *argv[], char *envp[]) {

	struct timeval check_interval = {.tv_sec = 1, .tv_usec = 0 };
	
#ifndef PYTHREE
#ifndef ROCK_SOLID
	PyObject *uwsgi_module;
#endif
#endif
        PyObject *wsgi_result, *wsgi_chunks, *wchunk;
        PyObject *zero, *wsgi_socket;
#ifndef ROCK_SOLID
        PyThreadState *_save = NULL;
#endif

	char *pyargv[MAX_PYARGV] ;
	int pyargc = 1 ;

        FILE *wsgi_file;
        struct sockaddr_un c_addr ;
        int c_len = sizeof(struct sockaddr_un);
        int i ;
#ifndef ROCK_SOLID
	int rlen;
	int i_have_gil = 1 ;
#endif
        pid_t pid ;
	int no_server = 0 ;

        int serverfd = 0 ;
#ifndef UNBIT
        char *socket_name = NULL ;
#ifndef ROCK_SOLID
	FILE *pidfile;
#endif
#endif

#ifndef ROCK_SOLID
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
	char *path_info;

	/* anti signal bombing */
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	memset(&uwsgi, 0, sizeof(struct uwsgi_server));

	/* shared area for dynamic options */
	uwsgi.options = (uint32_t *) mmap(NULL, sizeof(uint32_t)*(0xFF+1), PROT_READ|PROT_WRITE , MAP_SHARED|MAP_ANON , -1, 0);
	if (!uwsgi.options) {
		perror("mmap()");
		exit(1);
	}
	memset(uwsgi.options, 0, sizeof(uint32_t)*(0xFF+1));

#ifndef ROCK_SOLID
	uwsgi.wsgi_cnt = 1;
	uwsgi.default_app = -1;
#endif
	uwsgi.buffer_size = 4096;
	uwsgi.numproc = 1;
#ifndef UNBIT
	uwsgi.listen_queue = 64;
#endif
	
	uwsgi.maxworkers = 64 ;
	
	uwsgi.max_vars = MAX_VARS ;
	uwsgi.vec_size = 4+1+(4*MAX_VARS) ;

	uwsgi.options[UWSGI_OPTION_SOCKET_TIMEOUT] = 4 ;
	uwsgi.options[UWSGI_OPTION_LOGGING] = 1 ;

#ifndef UNBIT
#ifndef ROCK_SOLID
	int option_index = 0;
	struct option long_options[] = {
		{"socket", required_argument, 0, 's'},
		{"processes", required_argument, 0, 'p'},
		{"harakiri", required_argument, 0, 't'},
		{"xmlconfig", required_argument, 0, 'x'},
		{"daemonize", required_argument, 0, 'd'},
		{"listen", required_argument, 0, 'l'},
		{"optimize", required_argument, 0, 'O'},
		{"max-vars", required_argument, 0, 'v'},
		{"buffer-size", required_argument, 0, 'b'},
		{"memory-report", no_argument, 0, 'm'},
		{"cgi-mode", no_argument, 0, 'c'},
		{"abstract-socket", no_argument, 0, 'a'},
		{"chmod-socket", no_argument, 0, 'C'},
		{"enable-threads", no_argument, 0, 'T'},
		{"profiler", no_argument, 0, 'P'},
		{"single-interpreter", no_argument, 0, 'i'},
		{"master", no_argument, 0, 'M'},
		{"help", no_argument, 0, 'h'},
		{"reaper", no_argument, 0, 'r'},
		{"max-requests", required_argument, 0, 'R'},
		{"socket-timeout", required_argument, 0, 'z'},
		{"module", required_argument, 0, 'w'},
		{"test", required_argument, 0, 'j'},
		{"home", required_argument, 0, 'H'},
		{"sharedarea", required_argument, 0, 'A'},
		{"spooler", required_argument, 0, 'Q'},
		{"disable-logging", no_argument, 0, 'L'},

		{"pidfile", required_argument, 0, LONG_ARGS_PIDFILE},
		{"chroot", required_argument, 0, LONG_ARGS_CHROOT},
		{"gid", required_argument, 0, LONG_ARGS_GID},
		{"uid", required_argument, 0, LONG_ARGS_UID},
		{"pythonpath", required_argument, 0, LONG_ARGS_PYTHONPATH},
		{"pyargv", required_argument, 0, LONG_ARGS_PYARGV},
		{"paste", required_argument, 0, LONG_ARGS_PASTE},
		{"sync-log", no_argument, &uwsgi.synclog, 1},
		{"no-server", no_argument, &no_server, 1},
		{"no-defer-accept", no_argument, &uwsgi.no_defer_accept, 1},
		{"check-interval", required_argument, 0, LONG_ARGS_CHECK_INTERVAL},
		{0, 0, 0, 0}
	};
#endif
#endif


	gettimeofday(&uwsgi.start_tv, NULL) ;

	setlinebuf(stdout);


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
        while ((i = getopt_long(argc, argv, "s:p:t:x:d:l:O:v:b:mcaCTPiMhrR:z:w:j:H:A:Q:L", long_options, &option_index)) != -1) {
	#else
        while ((i = getopt (argc, argv, "s:p:t:d:l:v:b:aCMhrR:z:j:H:A:L")) != -1) {
	#endif
#else
        while ((i = getopt (argc, argv, "p:t:mTPiv:b:rMR:Sz:w:C:j:H:A:EQ:L")) != -1) {
#endif
                switch(i) {
#ifndef ROCK_SOLID
#ifndef UNBIT
			case LONG_ARGS_PIDFILE:
				uwsgi.pidfile = optarg;
				break;
			case LONG_ARGS_CHROOT:
				uwsgi.chroot = optarg;
				break;
			case LONG_ARGS_GID:
				uwsgi.gid = atoi(optarg);
				break;
			case LONG_ARGS_UID:
				uwsgi.uid = atoi(optarg);
				break;
			case LONG_ARGS_PYTHONPATH:
				uwsgi.python_path[0] = optarg;
				uwsgi.python_path_cnt = 1;
				break;
#endif
			case LONG_ARGS_PASTE:
                                uwsgi.single_interpreter = 1;
				uwsgi.paste = optarg;
				break;
			case LONG_ARGS_CHECK_INTERVAL:
				uwsgi.options[UWSGI_OPTION_MASTER_INTERVAL] = atoi(optarg);
				break;
			case LONG_ARGS_PYARGV:
				uwsgi.pyargv = optarg;
				break;
#endif
			case 'j':
				uwsgi.test_module = optarg;
				break;
			case 'H':
				uwsgi.pyhome = optarg;
				break;
			case 'A':
				uwsgi.sharedareasize = atoi(optarg);	
				break;
			case 'L':
				uwsgi.options[UWSGI_OPTION_LOGGING] = 0 ;
				break;
#ifndef ROCK_SOLID
			case 'Q':
				spool_dir = optarg;
				if (access(spool_dir, R_OK|W_OK|X_OK)) {
					perror("access()");
					exit(1);
				}
                                uwsgi.master_process = 1;
				break;
#endif
#ifdef UNBIT
			case 'E':
				check_for_memory_errors = 1 ;
				break;
                        case 'S':
                                uwsgi.single_interpreter = 1;
                                single_app_mode = 1;
				uwsgi.default_app = 0;
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
				uwsgi.xml_config = optarg;
				break;
#endif
			case 'l':
				uwsgi.listen_queue = atoi(optarg);
				break;
#endif
                        case 'v':
                                uwsgi.max_vars = atoi(optarg);
				uwsgi.vec_size = 4+1+(4*uwsgi.max_vars) ;
                                break;
                        case 'p':
                                uwsgi.numproc = atoi(optarg);
                                break;
                        case 'r':
                                uwsgi.options[UWSGI_OPTION_REAPER] = 1;
                                break;
#ifndef ROCK_SOLID
			case 'w':
                                uwsgi.single_interpreter = 1;
				uwsgi.wsgi_config = optarg;
				break;
                        case 'm':
                                uwsgi.options[UWSGI_OPTION_MEMORY_DEBUG] = 1 ;
                                break;
                        case 'O':
                                uwsgi.py_optimize = atoi(optarg) ;
                                break;
#endif
                        case 't':
                                uwsgi.options[UWSGI_OPTION_HARAKIRI] = atoi(optarg);
                                break;
			case 'b':
				uwsgi.buffer_size = atoi(optarg);
				break;
#ifndef UNBIT
#ifndef ROCK_SOLID
                        case 'c':
                                uwsgi.options[UWSGI_OPTION_CGI_MODE] = 1;
                                break;
#endif
                        case 'a':
                                uwsgi.abstract_socket = 1;
                                break;
                        case 'C':
                                uwsgi.chmod_socket = 1;
                                break;
#endif
                        case 'M':
                                uwsgi.master_process = 1;
                                break;
                        case 'R':
                                uwsgi.options[UWSGI_OPTION_MAX_REQUESTS] = atoi(optarg);
                                break;
                        case 'z':
                                if (atoi(optarg) > 0) {
					uwsgi.options[UWSGI_OPTION_SOCKET_TIMEOUT] = atoi(optarg) ;
				}
                                break;
#ifndef ROCK_SOLID
                        case 'T':
                                uwsgi.has_threads = 1;
				uwsgi.options[UWSGI_OPTION_THREADS] = 1 ;
                                break;
                        case 'P':
                                uwsgi.enable_profiler = 1;
                                break;
                        case 'i':
                                uwsgi.single_interpreter = 1;
                                break;
#endif
#ifndef UNBIT
			case 'h':
				fprintf(stderr, "Usage: %s [options...]\n\
\t-s|--socket <name>\t\tpath (or name) of UNIX/TCP socket to bind to\n\
\t-l|--listen <num>\t\tset socket listen queue to <n> (default 64, maximum is system dependent)\n\
\t-z|--socket-timeout <sec>\tset socket timeout to <sec> seconds (default 4 seconds)\n\
\t-b|--buffer-size <n>\t\tset buffer size to <n> bytes\n\
\t-L|--disable-logging\t\tdisable request logging (only errors or server messages will be logged)\n\
\t-x|--xmlconfig <path>\t\tpath of xml config file (no ROCK_SOLID)\n\
\t-w|--module <module>\t\tname of python config module (no ROCK_SOLID)\n\
\t-t|--harakiri <sec>\t\tset harakiri timeout to <sec> seconds\n\
\t-p|--processes <n>\t\tspawn <n> uwsgi worker processes\n\
\t-O|--optimize <n>\t\tset python optimization level to <n> (no ROCK_SOLID)\n\
\t-v|--max-vars <n>\t\tset maximum number of vars/headers to <n>\n\
\t-A|--sharedarea <n>\t\tcreate a shared memory area of <n> pages\n\
\t-c|--cgi-mode\t\t\tset cgi mode (no ROCK_SOLID) \n\
\t-C|--chmod-socket\t\tchmod socket to 666\n\
\t-P|--profiler\t\t\tenable profiler (no ROCK_SOLID)\n\
\t-m|--memory-report\t\tenable memory usage report (Linux/OSX only, no ROCK_SOLID)\n\
\t-i|--single-interpreter\t\tsingle interpreter mode (no ROCK_SOLID)\n\
\t-a|--abstract-socket\t\tset socket in the abstract namespace (Linux only)\n\
\t-T|--enable-threads\t\tenable threads support (no ROCK_SOLID)\n\
\t-M|--master\t\t\tenable master process manager\n\
\t-H|--home <path>\t\tset python home/virtualenv\n\
\t-h|--help\t\t\tthis help\n\
\t-r|--reaper\t\t\tprocess reaper (call waitpid(-1,...) after each request)\n\
\t-R|--max-requests\t\tmaximum number of requests for each worker\n\
\t-j|--test\t\t\ttest if uWSGI can import a module\n\
\t-Q|--spooler <dir>\t\trun the spooler on directory <dir>\n\
\t--pidfile <file>\t\twrite the masterpid to <file>\n\
\t--chroot <dir>\t\t\tchroot to directory <dir> (only root)\n\
\t--gid <id>\t\t\tsetgid to <id> (only root)\n\
\t--uid <id>\t\t\tsetuid to <id> (only root)\n\
\t--sync-log\t\t\tlet uWSGI does its best to avoid logfile mess\n\
\t--no-server\t\t\tinitialize the uWSGI server then exit. Useful for testing and using uwsgi embedded module\n\
\t--no-defer-accept\t\tdisable the no-standard way to defer the accept() call (TCP_DEFER_ACCEPT, SO_ACCEPTFILTER...)\n\
\t--paste <config:/egg:>\t\tload applications using paste.deploy.loadapp()\n\
\t--check-interval <sec>\t\tset the check interval (in seconds) of the master process\n\
\t--pythonpath <dir>\t\tadd <dir> to PYTHONPATH\n\
\t--pyargv <args>\t\t\tassign args to python sys.argv\n\
\t-d|--daemonize <logfile>\tdaemonize and log into <logfile>\n", argv[0]);
				exit(1);
			case 0:
				break;
			default:
				exit(1);
#endif
                }
        }

#ifndef UNBIT
#ifndef ROCK_SOLID
	if (uwsgi.options[UWSGI_OPTION_CGI_MODE] == 0) {
#endif
#endif
		if (uwsgi.test_module == NULL) {
        		fprintf(stderr,"*** Starting uWSGI on [%.*s] ***\n", 24, ctime( (const time_t *) &uwsgi.start_tv.tv_sec));
		}
#ifndef UNBIT
#ifndef ROCK_SOLID
	}
	else {
        	fprintf(stderr,"*** Starting uWSGI (CGI mode) on [%.*s] ***\n", 24, ctime( (const time_t *) &uwsgi.start_tv.tv_sec));
	}
#endif
#endif

#ifdef PYTHREE
	fprintf(stderr,"*** Warning Python3.x support is experimental, do not use it in production environment ***\n");
#endif

	fprintf(stderr,"Python version: %s\n", Py_GetVersion());

#ifndef UNBIT
	if (!getuid()) {
		fprintf(stderr,"uWSGI running as root, you can use --uid/--gid/--chroot options\n");
		if (uwsgi.chroot) {
			fprintf(stderr,"chroot() to %s\n", uwsgi.chroot);
			if (chroot(uwsgi.chroot)) {
				perror("chroot()");
				exit(1);
			}
#ifdef __linux__
			if (uwsgi.options[UWSGI_OPTION_MEMORY_DEBUG]) {
				fprintf(stderr,"*** Warning, on linux system you have to bind-mount the /proc fs in your chroot to get memory debug/report.\n");
			}			
#endif
		}
		if (uwsgi.gid) {
			fprintf(stderr,"setgid() to %d\n", uwsgi.gid);
			if (setgid(uwsgi.gid)) {
				perror("setgid()");
				exit(1);
			}
		}
		if (uwsgi.uid) {
			fprintf(stderr,"setuid() to %d\n", uwsgi.uid);
			if (setuid(uwsgi.uid)) {
				perror("setuid()");
				exit(1);
			}
		}
	}
	else {
		if (uwsgi.chroot) { fprintf(stderr,"cannot chroot() as non-root user\n"); exit(1); }
		if (uwsgi.gid) { fprintf(stderr,"cannot setgid() as non-root user\n"); exit(1); }
		if (uwsgi.uid) { fprintf(stderr,"cannot setuid() as non-root user\n"); exit(1); }
	}

#endif
	
#ifdef __linux__
	if (!getrlimit(RLIMIT_AS, &rl)) {
		fprintf(stderr,"your process address space limit is %lld bytes (%lld MB)\n", (long long) rl.rlim_max, (long long) rl.rlim_max/1024/1024);
	}
#endif

	uwsgi.page_size = getpagesize();
	fprintf(stderr,"your memory page size is %d bytes\n", uwsgi.page_size);

#ifndef UNBIT
	fprintf(stderr,"your server socket listen backlog is limited to %d connections\n", uwsgi.listen_queue);
#endif

	if (uwsgi.synclog) {
		fprintf(stderr,"allocating a memory page for synced logging.\n");
		uwsgi.sync_page = malloc(uwsgi.page_size);
		if (!uwsgi.sync_page) {
			perror("malloc()");
			exit(1);
		}
	}

	if (uwsgi.pyhome != NULL) {
        	fprintf(stderr,"Setting PythonHome to %s...\n", uwsgi.pyhome);
#ifdef PYTHREE
		wchar_t *wpyhome ;
		wpyhome = malloc((sizeof(wchar_t)*strlen(uwsgi.pyhome))+2) ;
		if (!wpyhome) {
			perror("malloc()");
			exit(1);
		}
		mbstowcs(wpyhome, uwsgi.pyhome, strlen(uwsgi.pyhome));
		Py_SetPythonHome(wpyhome);		
		free(wpyhome);
#else
		Py_SetPythonHome(uwsgi.pyhome);		
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

	pyargv[0] = "uwsgi" ;

	if (uwsgi.pyargv != NULL) {
		char *ap;
		while( (ap = strsep(&uwsgi.pyargv, " \t")) != NULL) {
			if (*ap != '\0') {
				pyargv[pyargc] = ap ;			
				pyargc++;
			}
			if (pyargc+1 > MAX_PYARGV)
				break;
		}
	}

	PySys_SetArgv(pyargc, pyargv);


#ifndef ROCK_SOLID
        uwsgi.py_apps = PyDict_New();
        if (!uwsgi.py_apps) {
                PyErr_Print();
                exit(1);
        }

#endif


        wsgi_spitout = PyCFunction_New(uwsgi_spit_method,NULL) ;
        wsgi_writeout = PyCFunction_New(uwsgi_write_method,NULL) ;

#ifndef PYTHREE
#ifndef ROCK_SOLID
	uwsgi_module = Py_InitModule("uwsgi", null_methods);
        if (uwsgi_module == NULL) {
		fprintf(stderr,"could not initialize the uwsgi python module\n");
		exit(1);
	}
	if (uwsgi.sharedareasize > 0) {
		#ifndef __OpenBSD__
		uwsgi.sharedareamutex = mmap(NULL, sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE , MAP_SHARED|MAP_ANON , -1, 0);
		if (!uwsgi.sharedareamutex) {
			perror("mmap()");
			exit(1);
		}
		#else
			fprintf(stderr,"***WARNING*** the sharedarea on OpenBSD is not SMP-safe. Beware of race conditions !!!\n");
		#endif
		uwsgi.sharedarea = mmap(NULL, uwsgi.page_size * uwsgi.sharedareasize, PROT_READ|PROT_WRITE , MAP_SHARED|MAP_ANON , -1, 0);
		if (uwsgi.sharedarea) { 
			fprintf(stderr,"shared area mapped at %p, you can access it with uwsgi.sharedarea* functions.\n", uwsgi.sharedarea);

#ifdef __APPLE__
			memset(uwsgi.sharedareamutex,0, sizeof(OSSpinLock));
#else
		#ifndef __OpenBSD__
			if (pthread_mutexattr_init((pthread_mutexattr_t *)uwsgi.sharedareamutex)) {
				fprintf(stderr,"unable to allocate mutexattr structure\n");
				exit(1);
			}
			if (pthread_mutexattr_setpshared((pthread_mutexattr_t *)uwsgi.sharedareamutex, PTHREAD_PROCESS_SHARED)) {
				fprintf(stderr,"unable to share mutex\n");
				exit(1);
			}
			if (pthread_mutex_init((pthread_mutex_t *) uwsgi.sharedareamutex + sizeof(pthread_mutexattr_t), (pthread_mutexattr_t *)uwsgi.sharedareamutex)) {
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
	Py_OptimizeFlag = uwsgi.py_optimize;

        uwsgi.main_thread = PyThreadState_Get();


        if (uwsgi.has_threads) {
                PyEval_InitThreads() ;
                fprintf(stderr, "threads support enabled\n");
        }

#endif

	if (!no_server) {
#ifndef UNBIT
        if (socket_name != NULL && !is_a_reload) {
		char *tcp_port = strchr(socket_name, ':');
               	if (tcp_port == NULL) {
			serverfd = bind_to_unix(socket_name, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
		}
		else {
			serverfd = bind_to_tcp(socket_name, uwsgi.listen_queue, tcp_port);
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

	}



#ifndef ROCK_SOLID
	if (uwsgi.single_interpreter == 1) {
		init_uwsgi_vars();
	}

        memset(uwsgi.wsgi_apps, 0, sizeof(uwsgi.wsgi_apps));


#endif



        uwsgi.poll.events = POLLIN ;

	memset(&wsgi_req, 0, sizeof(struct wsgi_request));


#ifndef ROCK_SOLID
	if (uwsgi.wsgi_config != NULL) {
		uwsgi_wsgi_config();
	}
#endif

#ifndef UNBIT
#ifndef ROCK_SOLID
	else if (uwsgi.xml_config != NULL) {
		uwsgi_xml_config();
	}
#endif
#endif

#ifndef ROCK_SOLID
	else if (uwsgi.paste != NULL) {
		uwsgi_paste_config();
	}
#endif

	if (uwsgi.test_module != NULL) {
		if (PyImport_ImportModule(uwsgi.test_module)) {
			exit(0);
		}
		exit(1);
	}


        uwsgi.mypid = getpid();
	masterpid = uwsgi.mypid ;

#ifndef ROCK_SOLID
#ifndef UNBIT
	if (uwsgi.pidfile) {
		fprintf(stderr,"writing pidfile to %s\n", uwsgi.pidfile);
		pidfile = fopen(uwsgi.pidfile, "w");
		if (!pidfile) {
			perror("fopen");
			exit(1);
		}
		if (fprintf(pidfile, "%d\n", masterpid) < 0) {
			fprintf(stderr,"could not write pidfile.\n");
		}
		fclose(pidfile);
	}
#endif
#endif

	if (uwsgi.buffer_size > 65536) {
		fprintf(stderr,"invalid buffer size.\n");
		exit(1);
	}
	buffer = malloc(uwsgi.buffer_size);
	if (buffer == NULL) {
		fprintf(stderr,"unable to allocate memory for buffer.\n");
		exit(1);
	}

	fprintf(stderr,"request/response buffer (%d bytes) allocated.\n", uwsgi.buffer_size);

	


	/* shared area for workers */
	uwsgi.workers = (struct uwsgi_worker *) mmap(NULL, sizeof(struct uwsgi_worker)*uwsgi.maxworkers+1, PROT_READ|PROT_WRITE , MAP_SHARED|MAP_ANON , -1, 0);
	if (!uwsgi.workers) {
		perror("mmap()");
		exit(1);
	}
	memset(uwsgi.workers, 0, sizeof(struct uwsgi_worker)*uwsgi.maxworkers+1);

#ifndef UNBIT
#ifndef ROCK_SOLID
	if (no_server) {
		fprintf(stderr,"no-server mode requested. Goodbye.\n");
		exit(0);
	}
#endif
#endif

        /* preforking() */
	if (uwsgi.master_process) {
		if (is_a_reload) {
        		fprintf(stderr, "gracefully (RE)spawned uWSGI master process (pid: %d)\n", uwsgi.mypid);
		}
		else {
        		fprintf(stderr, "spawned uWSGI master process (pid: %d)\n", uwsgi.mypid);
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
#ifndef PYTHREE
	if (spool_dir != NULL) {
		spooler_pid = spooler_start(serverfd, uwsgi_module);
	}
#endif
#endif

	/* save the masterpid */
	uwsgi.workers[0].pid = masterpid ;

	uwsgi.current_workers = uwsgi.numproc ;

	if (!uwsgi.master_process && uwsgi.numproc == 1) {
                        fprintf(stderr, "spawned uWSGI worker 1 (and the only) (pid: %d)\n",  masterpid);
			uwsgi.workers[1].pid = masterpid ;
			uwsgi.workers[1].id = 1 ;
			uwsgi.workers[1].last_spawn = time(NULL) ;
			uwsgi.workers[1].manage_next_request = 1 ;
			uwsgi.mywid = 1;
			gettimeofday(&last_respawn, NULL) ;
			respawn_delta = last_respawn.tv_sec;
	}
	else {
        	for(i=1;i<uwsgi.numproc+1;i++) {
			/* let the worker know his worker_id (wid) */
                	pid = fork();
                	if (pid == 0 ) {
                        	uwsgi.mypid = getpid();
				uwsgi.mywid = i;
				if (serverfd != 0 && uwsgi.master_process == 1) {
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
				uwsgi.workers[i].pid = pid ;
				uwsgi.workers[i].id = i ;
				uwsgi.workers[i].last_spawn = time(NULL) ;
				uwsgi.workers[i].manage_next_request = 1 ;
				gettimeofday(&last_respawn, NULL) ;
				respawn_delta = last_respawn.tv_sec;
                	}
        	}
	}

	if (getpid() == masterpid && uwsgi.master_process == 1) {
		/* route signals to workers... */
		signal(SIGHUP, (void *) &grace_them_all);
		signal(SIGTERM, (void *) &reap_them_all);
        	signal(SIGINT, (void *) &kill_them_all);
        	signal(SIGQUIT, (void *) &kill_them_all);
		/* used only to avoid human-errors */
#ifndef ROCK_SOLID
#ifndef UNBIT
		signal(SIGUSR1, (void *) &stats);
#endif
#endif
		for(;;) {
			if (ready_to_die >= uwsgi.numproc && uwsgi.to_hell) {
#ifndef ROCK_SOLID
				if (spool_dir && spooler_pid > 0) {
					kill(spooler_pid, SIGKILL);
				}
#endif
				fprintf(stderr,"goodbye to uWSGI.\n");
				exit(0);
			}		
			if (ready_to_reload >= uwsgi.numproc && uwsgi.to_heaven) {
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
#ifndef ROCK_SOLID
        			if (uwsgi.has_threads && uwsgi.options[UWSGI_OPTION_THREADS] == 1) {
                			_save = PyEval_SaveThread();
					i_have_gil = 0;
        			}
#endif
				/* all processes ok, doing status scan after N seconds */
				check_interval.tv_sec = uwsgi.options[UWSGI_OPTION_MASTER_INTERVAL] ;
				if (!check_interval.tv_sec)	
					check_interval.tv_sec = 1;
				select(0, NULL, NULL, NULL, &check_interval);
#ifndef ROCK_SOLID
                                if (uwsgi.has_threads && !i_have_gil) {
                                	PyEval_RestoreThread(_save);
					i_have_gil = 1 ;
                                }
#endif
				check_interval.tv_sec = uwsgi.options[UWSGI_OPTION_MASTER_INTERVAL] ;
				if (!check_interval.tv_sec)	
					check_interval.tv_sec = 1;
				for(i=1;i<=uwsgi.current_workers;i++) {
					/* first check for harakiri */
                			if (uwsgi.workers[i].harakiri > 0) {
						if (uwsgi.workers[i].harakiri < time(NULL)) {
							/* first try to invoke the harakiri() custom handler */
							/* TODO */
							/* the brutally kill the worker */
							kill(uwsgi.workers[i].pid, SIGKILL);
						}
					}
					if (uwsgi.workers[i].last_running_time > 0 && uwsgi.workers[i].running_time > 0) {
						uwsgi.workers[i].load = (((uwsgi.workers[i].running_time-uwsgi.workers[i].last_running_time)/1000) * 100)/check_interval.tv_sec ;
					}
					uwsgi.workers[i].last_running_time = uwsgi.workers[i].running_time ;
        			}
				continue;
			}
#ifndef ROCK_SOLID
#ifndef PYTHREE
			/* reload the spooler */
			if (spool_dir && spooler_pid > 0) {
				if (diedpid == spooler_pid) {
					spooler_pid = spooler_start(serverfd, uwsgi_module);
					continue;
				}
			}
#endif
#endif
			/* check for reloading */
			if (WIFEXITED(waitpid_status)) {
				if (WEXITSTATUS(waitpid_status) == UWSGI_RELOAD_CODE && uwsgi.to_heaven) {
					ready_to_reload++;
					continue;
				}
				else if (WEXITSTATUS(waitpid_status) == UWSGI_END_CODE && uwsgi.to_hell) {
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
			uwsgi.mywid = find_worker_id(diedpid);
			pid = fork();
			if (pid == 0 ) {
				uwsgi.mypid = getpid();
				break;
			}
                	else if (pid < 1) {
                        	perror("fork()");
			}
			else {
                        	fprintf(stderr, "Respawned uWSGI worker (new pid: %d)\n", pid);
				if (uwsgi.mywid > 0) {
					uwsgi.workers[uwsgi.mywid].pid = pid ;
					uwsgi.workers[uwsgi.mywid].harakiri = 0 ;
					uwsgi.workers[uwsgi.mywid].requests = 0 ;
					uwsgi.workers[uwsgi.mywid].failed_requests = 0 ;
					uwsgi.workers[uwsgi.mywid].respawn_count++ ;
					uwsgi.workers[uwsgi.mywid].last_spawn = time(NULL) ;
					uwsgi.workers[uwsgi.mywid].manage_next_request = 1 ;
				}
				else {
					fprintf(stderr, "warning the died pid was not in the workers list. Probably you hit a BUG of uWSGI\n") ;
				}
			}
		}
	}


	

	hvec = malloc(sizeof(struct iovec)*uwsgi.vec_size) ;
	if (hvec == NULL) {
		fprintf(stderr,"unable to allocate memory for iovec.\n");
		exit(1);
	}

        if (uwsgi.options[UWSGI_OPTION_HARAKIRI] > 0 && !uwsgi.master_process) {
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

#ifndef ROCK_SOLID
        if (uwsgi.has_threads) {
                _save = PyEval_SaveThread();
		i_have_gil = 0 ;
        }
#endif

        while(uwsgi.workers[uwsgi.mywid].manage_next_request) {

		
#ifndef ROCK_SOLID
                wsgi_req.app_id = uwsgi.default_app ;
                wsgi_req.sendfile_fd = -1 ;
#endif
		uwsgi.workers[uwsgi.mywid].in_request = 0 ;
		uwsgi.poll.fd = accept(serverfd,(struct sockaddr *)&c_addr, (socklen_t *) &c_len) ;
		uwsgi.workers[uwsgi.mywid].in_request = 1 ;

                if (uwsgi.poll.fd < 0){
                        perror("accept()");
			continue;
                }


                /*
                        poll with timeout ;
                */

		if (uwsgi.options[UWSGI_OPTION_LOGGING])
                	gettimeofday(&wsgi_req.start_of_request, NULL) ;


		if (!uwsgi_parse_response(&uwsgi.poll, uwsgi.options[UWSGI_OPTION_SOCKET_TIMEOUT], (struct uwsgi_header *) &wsgi_req, buffer)) {
			continue;
		}


		
		if (wsgi_req.modifier == UWSGI_MODIFIER_PING) {
			fprintf(stderr,"PING\n");
			wsgi_req.modifier_arg = 1 ;
			if (write(uwsgi.poll.fd,&wsgi_req,4) != 4) {
				perror("write()");
			}
			close(uwsgi.poll.fd);
			memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
			uwsgi.workers[0].requests++; uwsgi.workers[uwsgi.mywid].requests++;
			continue;
		}
		else if (wsgi_req.modifier == UWSGI_MODIFIER_ADMIN_REQUEST) {
			uint32_t opt_value = 0 ;
			if (wsgi_req.size >=4) {
				memcpy(&opt_value, buffer, 4);
				// TODO: check endianess
			}
			fprintf(stderr,"setting internal option %d to %d\n", wsgi_req.modifier_arg, opt_value);
			uwsgi.options[wsgi_req.modifier_arg] = opt_value ;
			wsgi_req.modifier = 255 ;
			wsgi_req.size = 0 ;
			wsgi_req.modifier_arg = 1 ;
			i = write(uwsgi.poll.fd,&wsgi_req,4);
			if (i != 4) {
				perror("write()");
			}
			close(uwsgi.poll.fd);
			memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
			uwsgi.workers[0].requests++; uwsgi.workers[uwsgi.mywid].requests++;
			continue;
		}
#ifndef ROCK_SOLID
		else if (wsgi_req.modifier == UWSGI_MODIFIER_FASTFUNC) {
			zero = PyList_GetItem(uwsgi.fastfuncslist, wsgi_req.modifier_arg) ;
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
                                                        	wsgi_req.response_size += write(uwsgi.poll.fd, PyString_AsString(wchunk), PyString_Size(wchunk)) ;
                                                	}
                                                	Py_DECREF(wchunk);
                                        	}
                                        	Py_DECREF(wsgi_chunks);
					}
					Py_DECREF(wsgi_result);
				}
			}
			PyErr_Clear();
			close(uwsgi.poll.fd);
			memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
			uwsgi.workers[0].requests++; uwsgi.workers[uwsgi.mywid].requests++;
			continue;
		}
		/* check for marshalled message */
		else if (wsgi_req.modifier == UWSGI_MODIFIER_MESSAGE_MARSHAL) {
			PyObject *umm = PyDict_GetItemString(uwsgi.embedded_dict, "message_manager_marshal");
			if (umm) {
				PyObject *ummo = PyMarshal_ReadObjectFromString(buffer, wsgi_req.size) ;
				if (ummo) {
					if (!PyTuple_SetItem(uwsgi.embedded_args, 0, ummo)) {
						if (!PyTuple_SetItem(uwsgi.embedded_args, 1, PyInt_FromLong(wsgi_req.modifier_arg))) {
							wsgi_result = PyEval_CallObject(umm, uwsgi.embedded_args);
							if (PyErr_Occurred()) {
								PyErr_Print();
							}
							if (wsgi_result) {
								PyObject *marshalled = PyMarshal_WriteObjectToString(wsgi_result, 1);
								if (!marshalled) {
									PyErr_Print() ;
								}
								else {
									if (PyString_Size(marshalled) <= 0xFFFF) {
										wsgi_req.size = (uint16_t) PyString_Size(marshalled) ;
										if (write(uwsgi.poll.fd, &wsgi_req, 4) == 4) {
											if (write(uwsgi.poll.fd, PyString_AsString(marshalled), wsgi_req.size) != wsgi_req.size) {
												perror("write()");
											}
										}
										else {
											perror("write()");
										}
									}
									else {
										fprintf(stderr,"marshalled object is too big. skip\n");
									}
									Py_DECREF(marshalled);
								}
								Py_DECREF(wsgi_result);
							}
						}
					}
					//Py_DECREF(ummo);
				}
			}		
			PyErr_Clear();
			close(uwsgi.poll.fd);
			memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
			uwsgi.workers[0].requests++; uwsgi.workers[uwsgi.mywid].requests++;
			continue;
		}
		/* check for spooler request */
		else if (wsgi_req.modifier == UWSGI_MODIFIER_SPOOL_REQUEST) {
			
			if (spool_dir == NULL) {
				fprintf(stderr,"the spooler is inactive !!!...skip\n");
				wsgi_req.modifier = 255 ;
				wsgi_req.size = 0 ;
				wsgi_req.modifier_arg = 0 ;
				i = write(uwsgi.poll.fd,&wsgi_req,4);
				if (i != 4) {
					perror("write()");
				}
				close(uwsgi.poll.fd);
				memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
				uwsgi.workers[0].requests++; uwsgi.workers[uwsgi.mywid].requests++;
				continue;	
			}

			fprintf(stderr,"managing spool request...\n");
			i = spool_request(spool_filename, uwsgi.workers[0].requests+1, buffer,wsgi_req.size) ;
			wsgi_req.modifier = 255 ;
			wsgi_req.size = 0 ;
			if (i > 0) {
				wsgi_req.modifier_arg = 1 ;
				if (write(uwsgi.poll.fd,&wsgi_req,4) != 4) {
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
				i = write(uwsgi.poll.fd,&wsgi_req,4);
				if (i != 4) {
					perror("write()");
				}
			}
			close(uwsgi.poll.fd);
			memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
			uwsgi.workers[0].requests++; uwsgi.workers[uwsgi.mywid].requests++;
			continue;	
		}	
#endif

		else if (!wsgi_req.modifier || wsgi_req.modifier == UWSGI_MODIFIER_MANAGE_PATH_INFO) {

		/* Standard WSGI request */

		if (!wsgi_req.size) {
			fprintf(stderr,"Invalid WSGI request. skip.\n");
			close(uwsgi.poll.fd);
                        memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
			uwsgi.workers[0].requests++; uwsgi.workers[uwsgi.mywid].requests++;
                        continue;
		}

                ptrbuf = buffer ;
                bufferend = ptrbuf+wsgi_req.size ;


		/* set an HTTP 500 status as default */
		wsgi_req.status = 500;



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
                                                                                if (uwsgi.has_threads && !i_have_gil) {
                                                                                        PyEval_RestoreThread(_save);
											i_have_gil = 1;
                                                                                }
                                                                                zero = PyString_FromStringAndSize(ptrbuf, strsize) ;
                                                                                if (PyDict_Contains(uwsgi.py_apps, zero)) {
                                                                                        wsgi_req.app_id = PyInt_AsLong( PyDict_GetItem(uwsgi.py_apps, zero) );
                                                                                }
                                                                                else {
                                                                                        /* unavailable app for this SCRIPT_NAME */
                                                                                        wsgi_req.app_id = -1 ;
                                                                                }
                                                                                Py_DECREF(zero);
                                                                                if (uwsgi.has_threads && uwsgi.options[UWSGI_OPTION_THREADS] == 1) {
                                                                                        _save = PyEval_SaveThread();
											i_have_gil = 0;
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
								if (wsgi_req.var_cnt < uwsgi.vec_size-(4+1)) {
                                                                	wsgi_req.var_cnt++ ;
								}
								else {
									fprintf(stderr, "max vec size reached. skip this header.\n");
									break;
								}
                                                                // var value
                                                                hvec[wsgi_req.var_cnt].iov_base = ptrbuf ;
                                                                hvec[wsgi_req.var_cnt].iov_len = strsize ;
								if (wsgi_req.var_cnt < uwsgi.vec_size-(4+1)) {
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
                if (uwsgi.has_threads && !i_have_gil) {
                        PyEval_RestoreThread(_save);
			i_have_gil = 1;
                }
#endif


                wsgi_file = fdopen(uwsgi.poll.fd,"r") ;

#ifndef ROCK_SOLID

#ifndef UNBIT
                if (wsgi_req.app_id == -1 && uwsgi.xml_config == NULL) {
#else
                if (wsgi_req.app_id == -1 && uwsgi.wsgi_config == NULL) {
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
                                	internal_server_error(uwsgi.poll.fd, "wsgi application not found");
                                	goto clean ;
                        	}
			}
                }


                if (wsgi_req.app_id == -1) {
                        internal_server_error(uwsgi.poll.fd, "wsgi application not found");
                        goto clean;
                }


                wi = &uwsgi.wsgi_apps[wsgi_req.app_id] ;

		if (uwsgi.single_interpreter == 0) {
                	if (!wi->interpreter) {
                        	internal_server_error(uwsgi.poll.fd, "wsgi application's %d interpreter not found");
                        	goto clean;
                	}

                	// set the interpreter
                	PyThreadState_Swap(wi->interpreter) ;
		}


#endif


		if (wsgi_req.protocol_len < 5) {
			fprintf(stderr,"INVALID PROTOCOL: %.*s", wsgi_req.protocol_len, wsgi_req.protocol);
                        internal_server_error(uwsgi.poll.fd, "invalid HTTP protocol !!!");
                        goto clean;
		}
		if (strncmp(wsgi_req.protocol, "HTTP/", 5)) {
			fprintf(stderr,"INVALID PROTOCOL: %.*s", wsgi_req.protocol_len, wsgi_req.protocol);
                        internal_server_error(uwsgi.poll.fd, "invalid HTTP protocol !!!");
                        goto clean;
		}



                /* max 1 minute before harakiri */
                if (uwsgi.options[UWSGI_OPTION_HARAKIRI] > 0) {
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
                        	set_harakiri(uwsgi.options[UWSGI_OPTION_HARAKIRI]);
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
		if (uwsgi.numproc == 1) {
                	PyDict_SetItemString(wi->wsgi_environ, "wsgi.multiprocess", Py_False);
		}
		else {
                	PyDict_SetItemString(wi->wsgi_environ, "wsgi.multiprocess", Py_True);
		}

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
                if (uwsgi.enable_profiler == 1) {
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
	#if defined(__FreeBSD__) || defined(__DragonFly__)

					wsgi_req.response_size = sendfile(wsgi_req.sendfile_fd, uwsgi.poll.fd, 0, 0, NULL, (off_t *) &rlen, 0) ;
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
						jlen = write(uwsgi.poll.fd, no_sendfile_buf, jlen);		
						if (jlen<=0) {
							perror("write()");
							break;
						}
						
					}
	#else
                                        wsgi_req.response_size = sendfile(wsgi_req.sendfile_fd, uwsgi.poll.fd, 0, (off_t *) &rlen, NULL, 0) ;
	#endif
#else
                                        wsgi_req.response_size = sendfile(uwsgi.poll.fd, wsgi_req.sendfile_fd, NULL, rlen) ;
#endif
                                }
                                Py_DECREF(uwsgi.py_sendfile);
                        }
                        else {

#endif

                                wsgi_chunks = PyObject_GetIter(wsgi_result);
                                if (wsgi_chunks) {
                                        while((wchunk = PyIter_Next(wsgi_chunks))) {
                                                if (PyString_Check(wchunk)) {
                                                        wsgi_req.response_size += write(uwsgi.poll.fd, PyString_AsString(wchunk), PyString_Size(wchunk)) ;
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
						else {
							fprintf(stderr,"invalid output returned by the wsgi callable !!!\n");
						}
                                                Py_DECREF(wchunk);
                                        }

					if (PyErr_Occurred()) {
						PyErr_Print();
					}

#ifdef UNBIT
					else if (save_to_disk >= 0) {
						close(save_to_disk);
						save_to_disk = -1 ;
						fprintf(stderr,"[uWSGI cacher] output of request %llu (%.*s) on pid %d written to cache file %s\n",uwsgi.workers[0].requests+1, wsgi_req.uri_len, wsgi_req.uri, uwsgi.mypid,tmp_filename);
					}
#endif
                                        Py_DECREF(wsgi_chunks);
                                }
#ifndef ROCK_SOLID
                        }
			if (uwsgi.enable_profiler == 0) {
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
                if (uwsgi.options[UWSGI_OPTION_HARAKIRI] > 0) {
                        set_harakiri(0);
                }
#ifndef ROCK_SOLID
		if (uwsgi.single_interpreter == 0) {
			// restoring main interpreter
                	PyThreadState_Swap(uwsgi.main_thread);
		}
#endif
clean:
                fclose(wsgi_file);
#ifndef ROCK_SOLID
                if (uwsgi.has_threads && uwsgi.options[UWSGI_OPTION_THREADS] == 1) {
                        _save = PyEval_SaveThread();
			i_have_gil = 0 ;
                }
#endif
		uwsgi.workers[0].requests++; uwsgi.workers[uwsgi.mywid].requests++;
                // GO LOGGING...
		if (uwsgi.options[UWSGI_OPTION_LOGGING])
                	log_request(&wsgi_req) ;
		// defunct process reaper
		if (uwsgi.options[UWSGI_OPTION_REAPER] == 1) {
			waitpid(-1, &waitpid_status, WNOHANG);
		}
                // reset request
                memset(&wsgi_req, 0,  sizeof(struct wsgi_request));
#ifdef UNBIT
		if (tmp_filename && tmp_dir_fd >= 0) {
			tmp_filename[0] = 0 ;
		}
#endif


		if (uwsgi.options[UWSGI_OPTION_MAX_REQUESTS] > 0 && uwsgi.workers[uwsgi.mywid].requests >= uwsgi.options[UWSGI_OPTION_MAX_REQUESTS]) {
			goodbye_cruel_world();
		}

#ifdef UNBIT
		if (check_for_memory_errors) {
			if (syscall(357,&us,0) > 0) {
				if (us.memory_errors > 0) {
					fprintf(stderr,"Unbit Kernel found a memory allocation error for process %d.\n", uwsgi.mypid);
					goodbye_cruel_world();
				}
			}
		}
#endif

		}
		else {
			fprintf(stderr,"Unsupported uwsgi modifier requested: %d\n", wsgi_req.modifier);
		}

        }

	if (uwsgi.workers[uwsgi.mywid].manage_next_request == 0) {
		/* am i a grunt ? */
		if (uwsgi.mywid > uwsgi.numproc) {
			end_me() ;
		}
		else {
			reload_me() ;
		}
	}
	else {
		goodbye_cruel_world();
	}

	/* never here */
	return 0 ;
}

void init_uwsgi_vars() {

#ifndef UNBIT
#ifndef ROCK_SOLID
	int i;
#endif
#endif
	PyObject *pysys, *pysys_dict, *pypath ;

        /* add cwd to pythonpath */
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
	for(i=0; i< uwsgi.python_path_cnt; i++) {
        	if (PyList_Insert(pypath,0,PyString_FromString(uwsgi.python_path[i])) != 0) {
                	PyErr_Print();
		}
		else {
			fprintf(stderr, "added %s to pythonpath.\n", uwsgi.python_path[i]);
		}
	}
#endif
#endif

}

#ifndef ROCK_SOLID
int init_uwsgi_app(PyObject *force_wsgi_dict, PyObject *my_callable) {
        PyObject *wsgi_module, *wsgi_dict = NULL ;
	PyObject *pymain, *zero;
	PyObject *pycprof, *pycprof_dict;
        char tmpstring[256] ;
	int id ;

        struct uwsgi_app *wi ;

        memset(tmpstring,0, 256) ;


	if (wsgi_req.wsgi_script_len == 0 && ( (wsgi_req.wsgi_module_len == 0 || wsgi_req.wsgi_callable_len == 0) && uwsgi.wsgi_config == NULL && my_callable == NULL) ) {
		fprintf(stderr, "invalid application (%.*s). skip.\n", wsgi_req.script_name_len, wsgi_req.script_name);
		return -1;
	}

	if (uwsgi.wsgi_config && wsgi_req.wsgi_callable_len == 0 && my_callable == NULL) {
		fprintf(stderr, "invalid application (%.*s). skip.\n", wsgi_req.script_name_len, wsgi_req.script_name);
		return -1;
	}

	if (wsgi_req.wsgi_script_len > 255 || wsgi_req.wsgi_module_len > 255 || wsgi_req.wsgi_callable_len > 255) {
		fprintf(stderr, "invalid application's string size. skip.\n");
		return -1;
	}

	id = uwsgi.wsgi_cnt ;


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

	if (PyDict_GetItem(uwsgi.py_apps, zero) != NULL) {
		Py_DECREF(zero);
		fprintf(stderr, "mountpoint %.*s already configured. skip.\n", wsgi_req.script_name_len, wsgi_req.script_name);
		return -1;
	}

	Py_DECREF(zero);

        wi = &uwsgi.wsgi_apps[id] ;

	memset(wi, 0, sizeof(struct uwsgi_app));

	if (uwsgi.single_interpreter == 0) {
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

	if (uwsgi.paste) {
		wi->wsgi_callable = my_callable ;
		Py_INCREF(my_callable);
	}

	else {

	if (uwsgi.wsgi_config == NULL) {
        	if (wsgi_req.wsgi_script_len > 0) {
                	memcpy(tmpstring, wsgi_req.wsgi_script, wsgi_req.wsgi_script_len) ;
                	wsgi_module = PyImport_ImportModule(tmpstring) ;
                	if (!wsgi_module) {
                        	PyErr_Print();
				if (uwsgi.single_interpreter == 0) {
                        		Py_EndInterpreter(wi->interpreter);
                        		PyThreadState_Swap(uwsgi.main_thread) ;
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
				if (uwsgi.single_interpreter == 0) {
                        		Py_EndInterpreter(wi->interpreter);
                        		PyThreadState_Swap(uwsgi.main_thread) ;
				}
                        	return -1 ;
                	}
               } 

        	wsgi_dict = PyModule_GetDict(wsgi_module);
        	if (!wsgi_dict) {
                	PyErr_Print();
			if (uwsgi.single_interpreter == 0) {
                		Py_EndInterpreter(wi->interpreter);
                		PyThreadState_Swap(uwsgi.main_thread) ;
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

	}


        if (!wi->wsgi_callable) {
                PyErr_Print();
		if (uwsgi.single_interpreter == 0) {
                	Py_EndInterpreter(wi->interpreter);
                	PyThreadState_Swap(uwsgi.main_thread) ;
		}
                return -1 ;
        }


        wi->wsgi_environ = PyDict_New();
        if (!wi->wsgi_environ) {
                PyErr_Print();
		if (uwsgi.single_interpreter == 0) {
                	Py_EndInterpreter(wi->interpreter);
                	PyThreadState_Swap(uwsgi.main_thread) ;
		}
                return -1 ;
        }

	if (wsgi_dict) {
		wi->wsgi_harakiri = PyDict_GetItemString(wsgi_dict, "harakiri");
		if (wi->wsgi_harakiri) {
			fprintf(stderr, "initialized Harakiri custom handler: %p.\n", wi->wsgi_harakiri);
		}
	}



	if (uwsgi.enable_profiler) {
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
			if (uwsgi.single_interpreter == 0) {
				Py_EndInterpreter(wi->interpreter);
				PyThreadState_Swap(uwsgi.main_thread) ;
			}
			return -1 ;
		}
	}
	else {
        	wi->wsgi_args = PyTuple_New(2) ;
        	if (PyTuple_SetItem(wi->wsgi_args,0, wi->wsgi_environ)) {
                	PyErr_Print();
			if (uwsgi.single_interpreter == 0) {
                		Py_EndInterpreter(wi->interpreter);
                		PyThreadState_Swap(uwsgi.main_thread) ;
			}
                	return -1 ;
        	}
        	if (PyTuple_SetItem(wi->wsgi_args,1, wsgi_spitout)) {
                	PyErr_Print();
			if (uwsgi.single_interpreter == 0) {
                		Py_EndInterpreter(wi->interpreter);
                		PyThreadState_Swap(uwsgi.main_thread) ;
			}
                	return -1 ;
        	}
	}

	// prepare sendfile()
        wi->wsgi_sendfile = PyCFunction_New(uwsgi_sendfile_method,NULL) ;

	if (uwsgi.single_interpreter == 0) {
        	PyThreadState_Swap(uwsgi.main_thread);
	}

        memset(tmpstring, 0, 256);
        memcpy(tmpstring, wsgi_req.script_name, wsgi_req.script_name_len);
        PyDict_SetItemString(uwsgi.py_apps, tmpstring, PyInt_FromLong(id));
        PyErr_Print();

        fprintf(stderr,"application %d (%s) ready\n", id, tmpstring);

        if (id == 0){
                fprintf(stderr,"setting default application to 0\n");
                uwsgi.default_app = 0 ;
        }
	else {
        	uwsgi.wsgi_cnt++;
	}

        return id ;
}

void uwsgi_paste_config() {
	PyObject *paste_module, *paste_dict, *paste_loadapp;
	PyObject *paste_arg, *paste_app ;

	fprintf(stderr,"Loading paste environment: %s\n", uwsgi.paste);
	paste_module = PyImport_ImportModule("paste.deploy");
	if (!paste_module) {
		PyErr_Print();
		exit(1);
	}

	paste_dict = PyModule_GetDict(paste_module);
	if (!paste_dict) {
                PyErr_Print();
                exit(1);
        }

	paste_loadapp = PyDict_GetItemString(paste_dict, "loadapp");
	if (!paste_loadapp) {
                PyErr_Print();
                exit(1);
	}

	paste_arg = PyTuple_New(1);
	if (!paste_arg) {
                PyErr_Print();
                exit(1);
	}

	if (PyTuple_SetItem(paste_arg, 0 , PyString_FromString(uwsgi.paste))) {
                PyErr_Print();
                exit(1);
	}

	paste_app = PyEval_CallObject(paste_loadapp, paste_arg);
	if (!paste_app) {
                PyErr_Print();
                exit(1);
	}

	init_uwsgi_app(NULL, paste_app);
}

void uwsgi_wsgi_config() {

	PyObject *wsgi_module, *wsgi_dict ;
#ifndef PYTHREE
	PyObject *uwsgi_module, *uwsgi_dict ;
#endif
	PyObject *applications;
	PyObject *app_list;
	int ret;
	Py_ssize_t i;
	PyObject *app_mnt, *app_app ;

	wsgi_module = PyImport_ImportModule(uwsgi.wsgi_config) ;
        if (!wsgi_module) {
        	PyErr_Print();
		exit(1);
	}

	wsgi_dict = PyModule_GetDict(wsgi_module);
        if (!wsgi_dict) {
                PyErr_Print();
		exit(1);
	}

	fprintf(stderr,"...getting the applications list from the '%s' module...\n", uwsgi.wsgi_config);

#ifndef PYTHREE
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
#endif
		applications = PyDict_GetItemString(wsgi_dict, "applications");
		if (!applications) {
			fprintf(stderr,"applications dictionary is not defined, trying with the \"application\" callable.\n");
			app_app = PyDict_GetItemString(wsgi_dict, "application");
			if (app_app) {
				applications = PyDict_New();
				if (!applications) {
					fprintf(stderr,"could not initialize applications dictionary\n");
					exit(1);
				}
				if (PyDict_SetItemString(applications, "/", app_app)) {
					PyErr_Print();
					fprintf(stderr,"unable to set default application\n");
					exit(1);
				}
			}
			else {
				fprintf(stderr,"static applications not defined, you have to used the dynamic one...\n");
				return ;
			}
		}
#ifndef PYTHREE
	}
#endif

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

	
	doc = xmlReadFile(uwsgi.xml_config, NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "could not parse file %s.\n", uwsgi.xml_config);
		exit(1);
	}

	fprintf(stderr, "parsing config file %s\n", uwsgi.xml_config);

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
				if (uwsgi.python_path_cnt < 63) {
					uwsgi.python_path[uwsgi.python_path_cnt] = malloc( strlen((char *)node->children->content) + 1 );
					memset(uwsgi.python_path[uwsgi.python_path_cnt], 0, strlen( (char *) node->children->content) + 1);
					strcpy(uwsgi.python_path[uwsgi.python_path_cnt], (char *) node->children->content);
					uwsgi.python_path_cnt++;
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
#ifndef ROCK_SOLID
void init_uwsgi_embedded_module() {
	PyObject *new_uwsgi_module, *zero;
	int i ;

	/* initialize for stats */
	uwsgi.workers_tuple = PyTuple_New(uwsgi.numproc);
	for(i=0;i<uwsgi.numproc;i++) {
		zero = PyDict_New() ;
		Py_INCREF(zero);
		PyTuple_SetItem(uwsgi.workers_tuple, i, zero);
	}
	

	new_uwsgi_module = Py_InitModule("uwsgi", null_methods);
        if (new_uwsgi_module == NULL) {
                fprintf(stderr,"could not initialize the uwsgi python module\n");
                exit(1);
        }

	uwsgi.embedded_dict = PyModule_GetDict(new_uwsgi_module);
        if (!uwsgi.embedded_dict) {
                fprintf(stderr,"could not get uwsgi module __dict__\n");
                exit(1);
        }

	if (PyDict_SetItemString(uwsgi.embedded_dict, "SPOOL_RETRY", PyInt_FromLong(17))) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(uwsgi.embedded_dict, "numproc", PyInt_FromLong(uwsgi.numproc))) {
		PyErr_Print();
		exit(1);
	}

#ifdef UNBIT
	if (PyDict_SetItemString(uwsgi.embedded_dict, "unbit", Py_True)) {
#else
	if (PyDict_SetItemString(uwsgi.embedded_dict, "unbit", Py_None)) {
#endif
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(uwsgi.embedded_dict, "buffer_size", PyInt_FromLong(uwsgi.buffer_size))) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(uwsgi.embedded_dict, "started_on", PyInt_FromLong(uwsgi.start_tv.tv_sec))) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(uwsgi.embedded_dict, "start_response", wsgi_spitout)) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(uwsgi.embedded_dict, "fastfuncs", PyList_New(256))) {
		PyErr_Print();
		exit(1);
	}


	if (PyDict_SetItemString(uwsgi.embedded_dict, "applist", uwsgi.py_apps)) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(uwsgi.embedded_dict, "applications", Py_None)) {
		PyErr_Print();
		exit(1);
	}

	uwsgi.embedded_args = PyTuple_New(2);
	if (!uwsgi.embedded_args) {
		PyErr_Print();
		exit(1);
	}

	if (PyDict_SetItemString(uwsgi.embedded_dict, "message_manager_marshal", Py_None)) {
		PyErr_Print();
		exit(1);
	}

	uwsgi.fastfuncslist = PyDict_GetItemString(uwsgi.embedded_dict, "fastfuncs");
	if (!uwsgi.fastfuncslist) {
		PyErr_Print();
		exit(1);
	}

	init_uwsgi_module_advanced(new_uwsgi_module);

	if (spool_dir != NULL) {
		init_uwsgi_module_spooler(new_uwsgi_module);
	}


	if (uwsgi.sharedareasize > 0 && uwsgi.sharedarea) {
		init_uwsgi_module_sharedarea(new_uwsgi_module);
	}
}
#endif
#endif

#ifndef ROCK_SOLID
pid_t spooler_start(int serverfd, PyObject *uwsgi_module) {
	pid_t pid ;

	pid = fork();
        if (pid < 0) {
        	perror("fork()");
                exit(1);
        }
	else if (pid == 0) {
		close(serverfd);
        	spooler(uwsgi_module);
	}
	else if (pid > 0) {
        	fprintf(stderr,"spawned the uWSGI spooler on dir %s with pid %d\n", spool_dir, pid);
	}

	return pid ;
}
#endif
