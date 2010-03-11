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


#include "uwsgi.h"

#if PY_MINOR_VERSION < 5
#define Py_ssize_t int
#endif

struct uwsgi_server uwsgi;

static char *nl = "\r\n";
static char *h_sep = ": ";
static const char *http_protocol = "HTTP/1.1";
static const char *app_slash = "/";

extern char **environ;

int find_worker_id(pid_t pid) {
	int i;
	for (i = 1; i <= uwsgi.numproc; i++) {
		/* fprintf(stderr,"%d of %d\n", pid, uwsgi.workers[i].pid); */
		if (uwsgi.workers[i].pid == pid)
			return i;
	}

	return -1;
}

struct wsgi_request wsgi_req;

PyMethodDef null_methods[] = {
	{NULL, NULL},
};

#ifdef UNBIT
int save_to_disk = -1;
int tmp_dir_fd = -1;
char *tmp_filename;
int uri_to_hex(void);
int check_for_memory_errors = 0;
#endif

PyObject *wsgi_writeout;


struct uwsgi_app *wi;

void warn_pipe() {
	fprintf(stderr, "writing to a closed pipe/socket/fd !!!\n");
}

void gracefully_kill() {
	fprintf(stderr, "Gracefully killing worker %d...\n", uwsgi.mypid);
	if (UWSGI_IS_IN_REQUEST) {
		uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
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
	int i;
	uwsgi.to_hell = 1;
	fprintf(stderr, "SIGINT/SIGQUIT received...killing workers...\n");
	for (i = 1; i <= uwsgi.numproc; i++) {
		kill(uwsgi.workers[i].pid, SIGINT);
	}
}

void grace_them_all() {
	int i;
	uwsgi.to_heaven = 1;
	fprintf(stderr, "...gracefully killing workers...\n");
	for (i = 1; i <= uwsgi.numproc; i++) {
		kill(uwsgi.workers[i].pid, SIGHUP);
	}
}

void reap_them_all() {
	int i;
	fprintf(stderr, "...brutally killing workers...\n");
	for (i = 1; i <= uwsgi.numproc; i++) {
		kill(uwsgi.workers[i].pid, SIGTERM);
	}
}

void harakiri() {

	PyThreadState *_myself;

/* CHECK ROCK_SOLID 
	struct uwsgi_app *wi = NULL;
	if (wsgi_req.app_id >= 0) {
		wi = &uwsgi.wsgi_apps[wsgi_req.app_id];
	}
 end rock_solid */

	PyGILState_Ensure();
	_myself = PyThreadState_Get();
	if (wi) {
/*
#ifdef ROCK_SOLID
		fprintf (stderr, "\nF*CK !!! i must kill myself (pid: %d) wi: %p wi->wsgi_harakiri: %p thread_state: %p frame: %p...\n", uwsgi.mypid, wi, wi->wsgi_harakiri, _myself, _myself->frame);
#else
*/
		fprintf(stderr, "\nF*CK !!! i must kill myself (pid: %d app_id: %d) wi: %p wi->wsgi_harakiri: %p thread_state: %p frame: %p...\n", uwsgi.mypid, wsgi_req.app_id, wi, wi->wsgi_harakiri, _myself, _myself->frame);

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
void stats() {
	struct uwsgi_app *ua = NULL;
	int i;

	fprintf(stderr, "*** pid %d stats ***\n", getpid());
	fprintf(stderr, "\ttotal requests: %llu\n", uwsgi.workers[0].requests);
	for (i = 0; i < uwsgi.wsgi_cnt; i++) {
		ua = &uwsgi.wsgi_apps[i];
		if (ua) {
			fprintf(stderr, "\tapp %d requests: %d\n", i, ua->requests);
		}
	}
	fprintf(stderr, "\n");
}
#endif

void internal_server_error(int fd, char *message) {
#ifndef UNBIT
	if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
#endif
		wsgi_req.headers_size = write(fd, "HTTP/1.1 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 63);
#ifndef UNBIT
	}
	else {
		wsgi_req.headers_size = write(fd, "Status: 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 62);
	}
	wsgi_req.header_cnt = 2;
#endif
	wsgi_req.response_size = write(fd, "<h1>uWSGI Error</h1>", 20);
	wsgi_req.response_size += write(fd, message, strlen(message));
}

PyObject *py_uwsgi_write(PyObject * self, PyObject * args) {
	PyObject *data;
	char *content;
	int len;
	data = PyTuple_GetItem(args, 0);
	if (PyString_Check(data)) {
		content = PyString_AsString(data);
		len = PyString_Size(data);

#ifdef UWSGI_THREADING
		if (uwsgi.has_threads && uwsgi.shared->options[UWSGI_OPTION_THREADS] == 1) {
			Py_BEGIN_ALLOW_THREADS wsgi_req.response_size = write(uwsgi.poll.fd, content, len);
		Py_END_ALLOW_THREADS}
		else {
#endif
			wsgi_req.response_size = write(uwsgi.poll.fd, content, len);
#ifdef UNBIT
			if (save_to_disk >= 0) {
				if (write(save_to_disk, content, len) != len) {
					perror("write()");
					close(save_to_disk);
					save_to_disk = -1;
				}
			}
#endif
#ifdef UWSGI_THREADING
		}
#endif
	}
#ifdef UNBIT
	if (save_to_disk >= 0) {
		close(save_to_disk);
		save_to_disk = -1;
		fprintf(stderr, "[uWSGI cacher] output of request %llu (%.*s) on pid %d written to cache file %s\n", uwsgi.workers[0].requests, wsgi_req.uri_len, wsgi_req.uri, uwsgi.mypid, tmp_filename);
	}
#endif
	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *wsgi_spitout;

PyObject *py_uwsgi_spit(PyObject * self, PyObject * args) {
	PyObject *headers, *head;
	PyObject *h_key, *h_value;
	int i, j;

#ifndef UNBIT
	int base = 0;
#else
	int base = 4;
#endif

	// use writev()


	head = PyTuple_GetItem(args, 0);
	if (!head) {
		goto clear;
	}

	if (!PyString_Check(head)) {
		fprintf(stderr, "http status must be a string !\n");
		goto clear;
	}


#ifndef UNBIT
	if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
		base = 4;
#endif


		if (wsgi_req.protocol_len == 0) {
			uwsgi.hvec[0].iov_base = (char *) http_protocol;
			wsgi_req.protocol_len = 8;
		}
		else {
			uwsgi.hvec[0].iov_base = wsgi_req.protocol;
		}

		uwsgi.hvec[0].iov_len = wsgi_req.protocol_len;
		uwsgi.hvec[1].iov_base = " ";
		uwsgi.hvec[1].iov_len = 1;
#ifdef PYTHREE
		uwsgi.hvec[2].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(head));
		uwsgi.hvec[2].iov_len = strlen(uwsgi.hvec[2].iov_base);
#else
		uwsgi.hvec[2].iov_base = PyString_AsString(head);
		uwsgi.hvec[2].iov_len = PyString_Size(head);
#endif
		wsgi_req.status = atoi(uwsgi.hvec[2].iov_base);
		uwsgi.hvec[3].iov_base = nl;
		uwsgi.hvec[3].iov_len = NL_SIZE;
#ifndef UNBIT
	}
	else {
		// drop http status on cgi mode
		base = 3;
		uwsgi.hvec[0].iov_base = "Status: ";
		uwsgi.hvec[0].iov_len = 8;
#ifdef PYTHREE
		uwsgi.hvec[1].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(head));
		uwsgi.hvec[1].iov_len = strlen(uwsgi.hvec[1].iov_base);
#else
		uwsgi.hvec[1].iov_base = PyString_AsString(head);
		uwsgi.hvec[1].iov_len = PyString_Size(head);
#endif
		wsgi_req.status = atoi(uwsgi.hvec[1].iov_base);
		uwsgi.hvec[2].iov_base = nl;
		uwsgi.hvec[2].iov_len = NL_SIZE;
	}
#endif


#ifdef UNBIT
	if (wsgi_req.unbit_flags & (unsigned long long) 1) {
		if (tmp_dir_fd >= 0 && tmp_filename[0] != 0 && wsgi_req.status == 200 && wsgi_req.method_len == 3 && wsgi_req.method[0] == 'G' && wsgi_req.method[1] == 'E' && wsgi_req.method[2] == 'T') {
			save_to_disk = openat(tmp_dir_fd, tmp_filename, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
		}
	}
#endif


	headers = PyTuple_GetItem(args, 1);
	if (!headers) {
		goto clear;
	}
	if (!PyList_Check(headers)) {
		fprintf(stderr, "http headers must be in a python list\n");
		goto clear;
	}
	wsgi_req.header_cnt = PyList_Size(headers);



	if (wsgi_req.header_cnt > uwsgi.max_vars) {
		wsgi_req.header_cnt = uwsgi.max_vars;
	}
	for (i = 0; i < wsgi_req.header_cnt; i++) {
		j = (i * 4) + base;
		head = PyList_GetItem(headers, i);
		if (!head) {
			goto clear;
		}
		if (!PyTuple_Check(head)) {
			fprintf(stderr, "http header must be defined in a tuple !\n");
			goto clear;
		}
		h_key = PyTuple_GetItem(head, 0);
		if (!h_key) {
			goto clear;
		}
		h_value = PyTuple_GetItem(head, 1);
		if (!h_value) {
			goto clear;
		}
#ifdef PYTHREE
		uwsgi.hvec[j].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(h_key));
		uwsgi.hvec[j].iov_len = strlen(uwsgi.hvec[j].iov_base);
#else
		uwsgi.hvec[j].iov_base = PyString_AsString(h_key);
		uwsgi.hvec[j].iov_len = PyString_Size(h_key);
#endif
		uwsgi.hvec[j + 1].iov_base = h_sep;
		uwsgi.hvec[j + 1].iov_len = H_SEP_SIZE;
#ifdef PYTHREE
		uwsgi.hvec[j + 2].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(h_value));
		uwsgi.hvec[j + 2].iov_len = strlen(uwsgi.hvec[j + 2].iov_base);
#else
		uwsgi.hvec[j + 2].iov_base = PyString_AsString(h_value);
		uwsgi.hvec[j + 2].iov_len = PyString_Size(h_value);
#endif
		uwsgi.hvec[j + 3].iov_base = nl;
		uwsgi.hvec[j + 3].iov_len = NL_SIZE;
		//fprintf(stderr, "%.*s: %.*s\n", uwsgi.hvec[j].iov_len, (char *)uwsgi.hvec[j].iov_base, uwsgi.hvec[j+2].iov_len, (char *) uwsgi.hvec[j+2].iov_base);
	}


#ifdef UNBIT
	if (save_to_disk >= 0) {
		for (j = 0; j < i; j += 4) {
			if (!strncasecmp(uwsgi.hvec[j].iov_base, "Set-Cookie", uwsgi.hvec[j].iov_len)) {
				close(save_to_disk);
				save_to_disk = -1;
				break;
			}
		}
	}
#endif

	// \r\n
	j = (i * 4) + base;
	uwsgi.hvec[j].iov_base = nl;
	uwsgi.hvec[j].iov_len = NL_SIZE;

	wsgi_req.headers_size = writev(uwsgi.poll.fd, uwsgi.hvec, j + 1);
	if (wsgi_req.headers_size < 0) {
		perror("writev()");
	}
	Py_INCREF(wsgi_writeout);


	return wsgi_writeout;

      clear:

	Py_INCREF(Py_None);
	return Py_None;
}

#ifdef UWSGI_SENDFILE
PyObject *py_uwsgi_sendfile(PyObject * self, PyObject * args) {

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

PyMethodDef uwsgi_spit_method[] = { {"uwsgi_spit", py_uwsgi_spit, METH_VARARGS, ""}
};
PyMethodDef uwsgi_write_method[] = { {"uwsgi_write", py_uwsgi_write, METH_VARARGS, ""}
};

#ifdef UWSGI_SENDFILE
PyMethodDef uwsgi_sendfile_method[] = { {"uwsgi_sendfile", py_uwsgi_sendfile, METH_VARARGS, ""}
};
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

char *spool_dir = NULL;

static int unconfigured_hook(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	fprintf(stderr, "-- unavailable modifier requested: %d --\n", wsgi_req->modifier);
	return -1;
}

static void unconfigured_after_hook(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	return;
}

int main(int argc, char *argv[], char *envp[]) {

	uint64_t master_cycles = 0;
	struct timeval check_interval = {.tv_sec = 1,.tv_usec = 0 };

#ifdef UWSGI_EMBEDDED
	PyObject *uwsgi_module;

#endif
	char *pyargv[MAX_PYARGV];
	int pyargc = 1;

	struct sockaddr_un c_addr;
	int c_len = sizeof(struct sockaddr_un);
	int i;
	int ret;

	int rlen;

#ifdef UWSGI_NAGIOS
	int nagios = 0;
#endif

#ifdef UWSGI_SCTP
	int i_am_sctp = 0;
	struct sctp_sndrcvinfo sctp_ss;
#endif

	struct pollfd uwsgi_poll;
	struct sockaddr_in udp_client;
	socklen_t udp_len;
	char udp_client_addr[16];

	pid_t pid;
	int no_server = 0;

#ifndef UNBIT
	FILE *pidfile;
#endif

	int working_workers = 0;
	int blocking_workers = 0;

	char *cwd = NULL;
	int ready_to_reload = 0;
	int ready_to_die = 0;

	char *env_reloads;
	unsigned int reloads = 0;
	char env_reload_buf[11];


#ifdef UNBIT
	struct uidsec_struct us;
#endif

	int socket_type = 0;
	socklen_t socket_type_len;

	/* anti signal bombing */
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	memset(&uwsgi, 0, sizeof(struct uwsgi_server));

	/* generic shared area */
	uwsgi.shared = (struct uwsgi_shared *) mmap(NULL, sizeof(struct uwsgi_shared), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (!uwsgi.shared) {
		perror("mmap()");
		exit(1);
	}
	memset(uwsgi.shared, 0, sizeof(struct uwsgi_shared));

	for (i = 0; i < 0xFF; i++) {
		uwsgi.shared->hooks[i] = unconfigured_hook;
		uwsgi.shared->after_hooks[i] = unconfigured_after_hook;
	}

	uwsgi.wsgi_cnt = 1;
	uwsgi.default_app = -1;

	uwsgi.buffer_size = 4096;
	uwsgi.numproc = 1;
#ifndef UNBIT
	uwsgi.listen_queue = 64;
#endif

	uwsgi.max_vars = MAX_VARS;
	uwsgi.vec_size = 4 + 1 + (4 * MAX_VARS);

	uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT] = 4;
	uwsgi.shared->options[UWSGI_OPTION_LOGGING] = 1;

#ifndef UNBIT
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
		{"limit-as", required_argument, 0, LONG_ARGS_LIMIT_AS},
		{"udp", required_argument, 0, LONG_ARGS_UDP},
		{"snmp", no_argument, &uwsgi.snmp, 1},
		{"check-interval", required_argument, 0, LONG_ARGS_CHECK_INTERVAL},
		{"erlang", required_argument, 0, LONG_ARGS_ERLANG},
		{"erlang-cookie", required_argument, 0, LONG_ARGS_ERLANG_COOKIE},
		{"nagios", no_argument, &nagios, 1},
		{"binary-path", required_argument, 0, LONG_ARGS_BINARY_PATH},
		{"proxy", required_argument, 0, LONG_ARGS_PROXY},
		{"proxy-node", required_argument, 0, LONG_ARGS_PROXY_NODE},
		{"proxy-max-connections", required_argument, 0, LONG_ARGS_PROXY_MAX_CONNECTIONS},
		{"wsgi-file", required_argument, 0, LONG_ARGS_WSGI_FILE},
		{"version", no_argument, 0, LONG_ARGS_VERSION},
		{0, 0, 0, 0}
	};
#endif


	gettimeofday(&uwsgi.start_tv, NULL);

	setlinebuf(stdout);

	uwsgi.rl.rlim_cur = 0;
	uwsgi.rl.rlim_max = 0;


	env_reloads = getenv("UWSGI_RELOADS");
	if (env_reloads) {
		// convert env value to int
		reloads = atoi(env_reloads);
		reloads++;
		// convert reloads to string
		rlen = snprintf(env_reload_buf, 10, "%u", reloads);
		if (rlen > 0) {
			env_reload_buf[rlen] = 0;
			if (setenv("UWSGI_RELOADS", env_reload_buf, 1)) {
				perror("setenv()");
			}
		}
	}
	else {
		if (setenv("UWSGI_RELOADS", "0", 1)) {
			perror("setenv()");
		}
	}

	socket_type_len = sizeof(int);
	if (!getsockopt(3, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_len)) {
		if (socket_type == SOCK_STREAM && reloads > 0) {
			fprintf(stderr, "...fd 3 is a socket, i suppose this is a graceful reload of uWSGI, i will try to do my best...\n");
			uwsgi.is_a_reload = 1;
#ifdef UNBIT
			/* discard the 3'th fd as we will use the fd 0 */
			close(3);
#else
			uwsgi.serverfd = 3;
#endif
		}
	}

	uwsgi.binary_path = argv[0];

#ifndef UNBIT
	while ((i = getopt_long(argc, argv, "s:p:t:x:d:l:O:v:b:mcaCTPiMhrR:z:w:j:H:A:Q:L", long_options, &option_index)) != -1) {
#else
	while ((i = getopt(argc, argv, "p:t:mTPiv:b:rMR:Sz:w:C:j:H:A:EQ:L")) != -1) {
#endif
		manage_opt(i, optarg);

	}

#ifdef UWSGI_XML
	if (uwsgi.xml_config != NULL) {
		uwsgi_xml_config(&wsgi_req, long_options);
	}
#endif

	if (uwsgi.binary_path == argv[0]) {
		cwd = uwsgi_get_cwd();
		uwsgi.binary_path = malloc(strlen(argv[0]) + 1);
		if (uwsgi.binary_path == NULL) {
			perror("malloc()");
			exit(1);
		}
		strcpy(uwsgi.binary_path, argv[0]);
	}

#ifndef UNBIT
	if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
#endif
		if (uwsgi.test_module == NULL) {
			fprintf(stderr, "*** Starting uWSGI %s (%dbit) on [%.*s] ***\n", UWSGI_VERSION, (int) (sizeof(void *)) * 8, 24, ctime((const time_t *) &uwsgi.start_tv.tv_sec));
		}
#ifndef UNBIT
	}
	else {
		fprintf(stderr, "*** Starting uWSGI %s (CGI mode) (%dbit) on [%.*s] ***\n", UWSGI_VERSION, (int) (sizeof(void *)) * 8, 24, ctime((const time_t *) &uwsgi.start_tv.tv_sec));
	}
#endif

#ifdef __BIG_ENDIAN__
	fprintf(stderr, "*** big endian arch detected ***\n");
#endif

#ifdef PYTHREE
	fprintf(stderr, "*** Warning Python3.x support is experimental, do not use it in production environment ***\n");
#endif

	fprintf(stderr, "Python version: %s\n", Py_GetVersion());

#ifndef UNBIT
	if (!getuid()) {
		fprintf(stderr, "uWSGI running as root, you can use --uid/--gid/--chroot options\n");
		if (uwsgi.chroot) {
			fprintf(stderr, "chroot() to %s\n", uwsgi.chroot);
			if (chroot(uwsgi.chroot)) {
				perror("chroot()");
				exit(1);
			}
#ifdef __linux__
			if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG]) {
				fprintf(stderr, "*** Warning, on linux system you have to bind-mount the /proc fs in your chroot to get memory debug/report.\n");
			}
#endif
		}
		if (uwsgi.gid) {
			fprintf(stderr, "setgid() to %d\n", uwsgi.gid);
			if (setgid(uwsgi.gid)) {
				perror("setgid()");
				exit(1);
			}
		}
		if (uwsgi.uid) {
			fprintf(stderr, "setuid() to %d\n", uwsgi.uid);
			if (setuid(uwsgi.uid)) {
				perror("setuid()");
				exit(1);
			}
		}

		if (!getuid()) {
			fprintf(stderr, " *** WARNING: you are running uWSGI as root !!! (use the --uid flag) *** \n");
		}
	}
	else {
		if (uwsgi.chroot) {
			fprintf(stderr, "cannot chroot() as non-root user\n");
			exit(1);
		}
		if (uwsgi.gid) {
			fprintf(stderr, "cannot setgid() as non-root user\n");
			exit(1);
		}
		if (uwsgi.uid) {
			fprintf(stderr, "cannot setuid() as non-root user\n");
			exit(1);
		}
	}



#endif

#ifndef UNBIT
	if (uwsgi.rl.rlim_max > 0) {
		fprintf(stderr, "limiting address space of processes...\n");
		if (setrlimit(RLIMIT_AS, &uwsgi.rl)) {
			perror("setrlimit()");
		}
	}
#endif

	if (!getrlimit(RLIMIT_AS, &uwsgi.rl)) {
#ifndef UNBIT
		// check for overflow
		if ((sizeof(void *) == 4 && (uint32_t) uwsgi.rl.rlim_max < UINT32_MAX) || (sizeof(void *) == 8 && (uint64_t) uwsgi.rl.rlim_max < UINT64_MAX)) {
#endif
			fprintf(stderr, "your process address space limit is %lld bytes (%lld MB)\n", (long long) uwsgi.rl.rlim_max, (long long) uwsgi.rl.rlim_max / 1024 / 1024);
#ifndef UNBIT
		}
#endif
	}

	uwsgi.page_size = getpagesize();
	fprintf(stderr, "your memory page size is %d bytes\n", uwsgi.page_size);


	if (uwsgi.synclog) {
		fprintf(stderr, "allocating a memory page for synced logging.\n");
		uwsgi.sync_page = malloc(uwsgi.page_size);
		if (!uwsgi.sync_page) {
			perror("malloc()");
			exit(1);
		}
	}

	if (uwsgi.pyhome != NULL) {
		fprintf(stderr, "Setting PythonHome to %s...\n", uwsgi.pyhome);
#ifdef PYTHREE
		wchar_t *wpyhome;
		wpyhome = malloc((sizeof(wchar_t) * strlen(uwsgi.pyhome)) + 2);
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
	wchar_t pname[6];
	mbstowcs(pname, "uWSGI", 6);
	Py_SetProgramName(pname);
#else
	Py_SetProgramName("uWSGI");
#endif


	Py_Initialize();

	pyargv[0] = "uwsgi";

	if (uwsgi.pyargv != NULL) {
		char *ap;
		while ((ap = strsep(&uwsgi.pyargv, " \t")) != NULL) {
			if (*ap != '\0') {
				pyargv[pyargc] = ap;
				pyargc++;
			}
			if (pyargc + 1 > MAX_PYARGV)
				break;
		}
	}

	PySys_SetArgv(pyargc, pyargv);


	uwsgi.py_apps = PyDict_New();
	if (!uwsgi.py_apps) {
		PyErr_Print();
		exit(1);
	}


	wsgi_spitout = PyCFunction_New(uwsgi_spit_method, NULL);
	wsgi_writeout = PyCFunction_New(uwsgi_write_method, NULL);

#ifdef UWSGI_EMBEDDED
	uwsgi_module = Py_InitModule("uwsgi", null_methods);
	if (uwsgi_module == NULL) {
		fprintf(stderr, "could not initialize the uwsgi python module\n");
		exit(1);
	}
	if (uwsgi.sharedareasize > 0) {
#ifndef __OpenBSD__
		uwsgi.sharedareamutex = mmap(NULL, sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (!uwsgi.sharedareamutex) {
			perror("mmap()");
			exit(1);
		}
#else
		fprintf(stderr, "***WARNING*** the sharedarea on OpenBSD is not SMP-safe. Beware of race conditions !!!\n");
#endif
		uwsgi.sharedarea = mmap(NULL, uwsgi.page_size * uwsgi.sharedareasize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (uwsgi.sharedarea) {
			fprintf(stderr, "shared area mapped at %p, you can access it with uwsgi.sharedarea* functions.\n", uwsgi.sharedarea);

#ifdef __APPLE__
			memset(uwsgi.sharedareamutex, 0, sizeof(OSSpinLock));
#else
#ifndef __OpenBSD__
			if (pthread_mutexattr_init((pthread_mutexattr_t *) uwsgi.sharedareamutex)) {
				fprintf(stderr, "unable to allocate mutexattr structure\n");
				exit(1);
			}
			if (pthread_mutexattr_setpshared((pthread_mutexattr_t *) uwsgi.sharedareamutex, PTHREAD_PROCESS_SHARED)) {
				fprintf(stderr, "unable to share mutex\n");
				exit(1);
			}
			if (pthread_mutex_init((pthread_mutex_t *) uwsgi.sharedareamutex + sizeof(pthread_mutexattr_t), (pthread_mutexattr_t *) uwsgi.sharedareamutex)) {
				fprintf(stderr, "unable to initialize mutex\n");
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



#ifdef UWSGI_ONEAPP


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

		wi->wsgi_args = PyTuple_New(2);
		if (!wi->wsgi_args) {
			PyErr_Print();
			exit(1);
		}
		if (PyTuple_SetItem(wi->wsgi_args, 0, wi->wsgi_environ)) {
			PyErr_Print();
			exit(1);
		}
		if (PyTuple_SetItem(wi->wsgi_args, 1, wsgi_spitout)) {
			PyErr_Print();
			exit(1);
		}
		break;
	}

	if (!wi->wsgi_module) {
		fprintf(stderr, "unable to find the wsgi script. Have you specified it ?\n");
		exit(1);
	}
#endif

	Py_OptimizeFlag = uwsgi.py_optimize;

	uwsgi.main_thread = PyThreadState_Get();


#ifdef UWSGI_THREADING
	if (uwsgi.has_threads) {
		PyEval_InitThreads();
		fprintf(stderr, "threads support enabled\n");
	}

#endif

	if (uwsgi.buffer_size > 65536) {
		fprintf(stderr, "invalid buffer size.\n");
		exit(1);
	}
	uwsgi.buffer = malloc(uwsgi.buffer_size);
	if (uwsgi.buffer == NULL) {
		fprintf(stderr, "unable to allocate memory for buffer.\n");
		exit(1);
	}

	fprintf(stderr, "request/response buffer (%d bytes) allocated.\n", uwsgi.buffer_size);

#ifdef UWSGI_NAGIOS
	if (nagios) {
		// connect and send
		if (uwsgi.socket_name == NULL) {
			fprintf(stdout, "UWSGI UNKNOWN: you have specified an invalid socket\n");
			exit(3);
		}
		char *tcp_port = strchr(uwsgi.socket_name, ':');
		if (tcp_port == NULL) {
			fprintf(stdout, "UWSGI UNKNOWN: you have specified an invalid socket\n");
			exit(3);
		}

		tcp_port[0] = 0;

		uwsgi_poll.fd = connect_to_tcp(uwsgi.socket_name, atoi(tcp_port + 1), uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (uwsgi_poll.fd < 0) {
			fprintf(stdout, "UWSGI CRITICAL: could not connect() to workers\n");
			exit(2);
		}
		wsgi_req.modifier = UWSGI_MODIFIER_PING;
		wsgi_req.size = 0;
		wsgi_req.modifier_arg = 0;
		if (write(uwsgi_poll.fd, &wsgi_req, 4) != 4) {
			perror("write()");
			fprintf(stdout, "UWSGI CRITICAL: could not send ping packet to workers\n");
			exit(2);
		}
		uwsgi_poll.events = POLLIN;
		if (!uwsgi_parse_response(&uwsgi_poll, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], (struct uwsgi_header *) &wsgi_req, uwsgi.buffer)) {
			fprintf(stdout, "UWSGI CRITICAL: timed out waiting for response\n");
			exit(2);
		}
		else {
			if (wsgi_req.size > 0) {
				fprintf(stdout, "UWSGI WARNING: %.*s\n", wsgi_req.size, uwsgi.buffer);
				exit(1);
			}
			else {
				fprintf(stdout, "UWSGI OK: armed and ready\n");
				exit(0);
			}
		}

		// never here
		fprintf(stdout, "UWSGI UNKNOWN: probably you hit a bug of uWSGI !!!\n");
		exit(3);

	}
#endif

	if (!no_server) {
#ifndef UNBIT
		if (uwsgi.socket_name != NULL && !uwsgi.is_a_reload) {
#ifdef UWSGI_SCTP
			if (!strncmp(uwsgi.socket_name, "sctp:", 5)) {
				char *sctp_port = strchr(uwsgi.socket_name + 5, ':');
				if (sctp_port == NULL) {
					fprintf(stderr, "invalid SCTP port ! syntax: sctp:ip1,ip2,ipN:port\n");
					exit(1);
				}
				uwsgi.serverfd = bind_to_sctp(uwsgi.socket_name + 5, uwsgi.listen_queue, sctp_port);
				i_am_sctp = 1;
			}
			else {
#endif
				char *tcp_port = strchr(uwsgi.socket_name, ':');
				if (tcp_port == NULL) {
					uwsgi.serverfd = bind_to_unix(uwsgi.socket_name, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
				}
				else {
					uwsgi.serverfd = bind_to_tcp(uwsgi.socket_name, uwsgi.listen_queue, tcp_port);
				}

				if (uwsgi.serverfd < 0) {
					fprintf(stderr, "unable to create the server socket.\n");
					exit(1);
				}
#ifdef UWSGI_SCTP
			}
#endif
		}
#endif

		socket_type_len = sizeof(int);
		if (getsockopt(uwsgi.serverfd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_len)) {
			//perror ("getsockopt()");
			uwsgi.numproc = 0;
		}

#ifdef UWSGI_PROXY
		if (uwsgi.proxy_socket_name) {
			uwsgi.shared->proxy_pid = proxy_start(uwsgi.master_process);
		}
#endif


	}

#ifdef UWSGI_PROXY
	if (uwsgi.numproc == 0 && (!uwsgi.proxy_socket_name || uwsgi.shared->proxy_pid <= 0)) {
#else
	if (uwsgi.numproc == 0) {
#endif
		fprintf(stderr, "The -s/--socket option is missing and stdin is not a socket.\n");
		exit(1);
	}



#ifndef UNBIT
	fprintf(stderr, "your server socket listen backlog is limited to %d connections\n", uwsgi.listen_queue);
#endif


	if (uwsgi.single_interpreter == 1) {
		init_uwsgi_vars();
	}

	memset(uwsgi.wsgi_apps, 0, sizeof(uwsgi.wsgi_apps));



	uwsgi.poll.events = POLLIN;

	memset(&wsgi_req, 0, sizeof(struct wsgi_request));

	/* shared area for workers */
	uwsgi.workers = (struct uwsgi_worker *) mmap(NULL, sizeof(struct uwsgi_worker) * uwsgi.numproc + 1, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (!uwsgi.workers) {
		perror("mmap()");
		exit(1);
	}
	memset(uwsgi.workers, 0, sizeof(struct uwsgi_worker) * uwsgi.numproc + 1);

	uwsgi.mypid = getpid();
	masterpid = uwsgi.mypid;

#ifndef UNBIT
	if (uwsgi.pidfile) {
		fprintf(stderr, "writing pidfile to %s\n", uwsgi.pidfile);
		pidfile = fopen(uwsgi.pidfile, "w");
		if (!pidfile) {
			perror("fopen");
			exit(1);
		}
		if (fprintf(pidfile, "%d\n", masterpid) < 0) {
			fprintf(stderr, "could not write pidfile.\n");
		}
		fclose(pidfile);
	}
#endif


	/* save the masterpid */
	uwsgi.workers[0].pid = masterpid;

	fprintf(stderr, "initializing hooks...");

	uwsgi.shared->hooks[0] = uwsgi_request_wsgi;
	uwsgi.shared->after_hooks[0] = uwsgi_after_request_wsgi;

	uwsgi.shared->hooks[UWSGI_MODIFIER_ADMIN_REQUEST] = uwsgi_request_admin;	//10
#ifdef UWSGI_SPOOLER
	uwsgi.shared->hooks[UWSGI_MODIFIER_SPOOL_REQUEST] = uwsgi_request_spooler;	//17
#endif
	uwsgi.shared->hooks[UWSGI_MODIFIER_FASTFUNC] = uwsgi_request_fastfunc;	//26

	uwsgi.shared->hooks[UWSGI_MODIFIER_MANAGE_PATH_INFO] = uwsgi_request_wsgi;	// 30
	uwsgi.shared->after_hooks[UWSGI_MODIFIER_MANAGE_PATH_INFO] = uwsgi_after_request_wsgi;	// 30

	uwsgi.shared->hooks[UWSGI_MODIFIER_MESSAGE_MARSHAL] = uwsgi_request_marshal;	//33
	uwsgi.shared->hooks[UWSGI_MODIFIER_PING] = uwsgi_request_ping;	//100

	fprintf(stderr, "done.\n");

#ifdef UWSGI_ERLANG
	if (uwsgi.erlang_node) {
		uwsgi.erlang_nodes = 1;
		uwsgi.erlangfd = init_erlang(uwsgi.erlang_node, uwsgi.erlang_cookie);
	}
#endif



	if (uwsgi.wsgi_config != NULL) {
		uwsgi_wsgi_config();
	}
	else if (uwsgi.wsgi_file != NULL) {
		uwsgi_wsgi_file_config();
	}
#ifdef UWSGI_XML
	else if (uwsgi.xml_config != NULL) {
		uwsgi_xml_config(&wsgi_req, NULL);
	}
#endif

#ifdef UWSGI_PASTE
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



#ifndef UNBIT
	if (no_server) {
		fprintf(stderr, "no-server mode requested. Goodbye.\n");
		exit(0);
	}
#endif

// is this a proxy only worker ?

	if (!uwsgi.master_process && uwsgi.numproc == 0) {
		exit(0);
	}

	if (!uwsgi.single_interpreter) {
		fprintf(stderr, "*** uWSGI is running in multiple interpreter mode !!! ***\n");
	}

	/* preforking() */
	if (uwsgi.master_process) {
		if (uwsgi.is_a_reload) {
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

#ifdef UWSGI_SPOOLER
	if (spool_dir != NULL && uwsgi.numproc > 0) {
		uwsgi.shared->spooler_pid = spooler_start(uwsgi.serverfd, uwsgi_module);
	}
#endif


	if (!uwsgi.master_process) {
		if (uwsgi.numproc == 1) {
			fprintf(stderr, "spawned uWSGI worker 1 (and the only) (pid: %d)\n", masterpid);
		}
		else {
			fprintf(stderr, "spawned uWSGI worker 1 (pid: %d)\n", masterpid);
		}
		uwsgi.workers[1].pid = masterpid;
		uwsgi.workers[1].id = 1;
		uwsgi.workers[1].last_spawn = time(NULL);
		uwsgi.workers[1].manage_next_request = 1;
#ifdef UWSGI_THREADING
		uwsgi.workers[1].i_have_gil = 1;
#endif
		uwsgi.mywid = 1;
		gettimeofday(&last_respawn, NULL);
		respawn_delta = last_respawn.tv_sec;
	}


	for (i = 2 - uwsgi.master_process; i < uwsgi.numproc + 1; i++) {
		/* let the worker know his worker_id (wid) */
		pid = fork();
		if (pid == 0) {
			uwsgi.mypid = getpid();
			uwsgi.workers[i].pid = uwsgi.mypid;
			uwsgi.workers[i].id = i;
			uwsgi.workers[i].last_spawn = time(NULL);
			uwsgi.workers[i].manage_next_request = 1;
#ifdef UWSGI_THREADING
			uwsgi.workers[i].i_have_gil = 1;
#endif
			uwsgi.mywid = i;
			if (uwsgi.serverfd != 0 && uwsgi.master_process == 1) {
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
			gettimeofday(&last_respawn, NULL);
			respawn_delta = last_respawn.tv_sec;
		}
	}


	if (getpid() == masterpid && uwsgi.master_process == 1) {
		/* route signals to workers... */
		signal(SIGHUP, (void *) &grace_them_all);
		signal(SIGTERM, (void *) &reap_them_all);
		signal(SIGINT, (void *) &kill_them_all);
		signal(SIGQUIT, (void *) &kill_them_all);
		/* used only to avoid human-errors */
#ifndef UNBIT
		signal(SIGUSR1, (void *) &stats);
#endif

		if (uwsgi.udp_socket) {
			uwsgi_poll.fd = bind_to_udp(uwsgi.udp_socket);
			if (uwsgi_poll.fd < 0) {
				fprintf(stderr, "unable to bind to udp socket. SNMP and cluster management services will be disabled.\n");
			}
			else {
				fprintf(stderr, "UDP server enabled.\n");
				uwsgi_poll.events = POLLIN;
			}
		}
		for (;;) {
			if (ready_to_die >= uwsgi.numproc && uwsgi.to_hell) {
#ifdef UWSGI_SPOOLER
				if (spool_dir && uwsgi.shared->spooler_pid > 0) {
					kill(uwsgi.shared->spooler_pid, SIGKILL);
					fprintf(stderr, "killed the spooler with pid %d\n", uwsgi.shared->spooler_pid);
				}

#endif

#ifdef UWSGI_PROXY
				if (uwsgi.proxy_socket_name && uwsgi.shared->proxy_pid > 0) {
					kill(uwsgi.shared->proxy_pid, SIGKILL);
					fprintf(stderr, "killed proxy with pid %d\n", uwsgi.shared->proxy_pid);
				}
#endif
				fprintf(stderr, "goodbye to uWSGI.\n");
				exit(0);
			}
			if (ready_to_reload >= uwsgi.numproc && uwsgi.to_heaven) {
#ifdef UWSGI_SPOOLER
				if (spool_dir && uwsgi.shared->spooler_pid > 0) {
					kill(uwsgi.shared->spooler_pid, SIGKILL);
					fprintf(stderr, "wait4() the spooler with pid %d...", uwsgi.shared->spooler_pid);
					diedpid = waitpid(uwsgi.shared->spooler_pid, &waitpid_status, 0);
					fprintf(stderr, "done.");
				}
#endif

#ifdef UWSGI_PROXY
				if (uwsgi.proxy_socket_name && uwsgi.shared->proxy_pid > 0) {
					kill(uwsgi.shared->proxy_pid, SIGKILL);
					fprintf(stderr, "wait4() the proxy with pid %d...", uwsgi.shared->proxy_pid);
					diedpid = waitpid(uwsgi.shared->proxy_pid, &waitpid_status, 0);
					fprintf(stderr, "done.");
				}
#endif
				fprintf(stderr, "binary reloading uWSGI...\n");
				if (cwd) {
					if (chdir(cwd)) {
						perror("chdir()");
						exit(1);
					}
				}
				/* check fd table (a module can obviosly open some fd on initialization...) */
				fprintf(stderr, "closing all fds > 2 (_SC_OPEN_MAX = %ld)...\n", sysconf(_SC_OPEN_MAX));
				for (i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
					if (i == uwsgi.serverfd) {
						continue;
					}
					close(i);
				}
				if (uwsgi.serverfd != 3) {
					if (dup2(uwsgi.serverfd, 3) < 0) {
						perror("dup2()");
						exit(1);
					}
				}
				fprintf(stderr, "running %s\n", uwsgi.binary_path);
				argv[0] = uwsgi.binary_path;
				//strcpy (argv[0], uwsgi.binary_path);
				execve(uwsgi.binary_path, argv, environ);
				perror("execve()");
				// never here
				exit(1);
			}
			diedpid = waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
			if (diedpid == -1) {
				perror("waitpid()");
				/* here is better to reload all the uWSGI stack */
				fprintf(stderr, "something horrible happened...\n");
				reap_them_all();
				exit(1);
			}
			else if (diedpid == 0) {
				/* PLEASE, do not run python threads in the master process, you can potentially destroy the world,
				   we support this for hyperultramegagodprogrammer and systems
				 */
#ifdef UWSGI_THREADING
				if (uwsgi.has_threads && uwsgi.shared->options[UWSGI_OPTION_THREADS] == 1) {
					uwsgi._save = PyEval_SaveThread();
					uwsgi.workers[uwsgi.mywid].i_have_gil = 0;
				}
#endif
				/* all processes ok, doing status scan after N seconds */
				check_interval.tv_sec = uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL];
				if (!check_interval.tv_sec)
					check_interval.tv_sec = 1;

				if (uwsgi.udp_socket && uwsgi_poll.fd >= 0) {
					rlen = poll(&uwsgi_poll, 1, check_interval.tv_sec * 1000);
					if (rlen < 0) {
						perror("poll()");
					}
					else if (rlen > 0) {
						udp_len = sizeof(udp_client);
						rlen = recvfrom(uwsgi_poll.fd, uwsgi.buffer, uwsgi.buffer_size, 0, (struct sockaddr *) &udp_client, &udp_len);
						if (rlen < 0) {
							perror("recvfrom()");
						}
						else if (rlen > 0) {
							memset(udp_client_addr, 0, 16);
							if (inet_ntop(AF_INET, &udp_client.sin_addr.s_addr, udp_client_addr, 16)) {
								fprintf(stderr, "received udp packet of %d bytes from %s:%d\n", rlen, udp_client_addr, ntohs(udp_client.sin_port));
#ifdef UWSGI_SNMP
								if (uwsgi.buffer[0] == 0x30 && uwsgi.snmp) {
									manage_snmp(uwsgi_poll.fd, (uint8_t *) uwsgi.buffer, rlen, &udp_client);
								}
#endif
							}
							else {
								perror("inet_ntop()");
							}
						}
					}
				}
				else {
					select(0, NULL, NULL, NULL, &check_interval);
				}
				master_cycles++;
				working_workers = 0;
				blocking_workers = 0;
#ifdef UWSGI_THREADING
				if (uwsgi.has_threads && !uwsgi.workers[uwsgi.mywid].i_have_gil) {
					PyEval_RestoreThread(uwsgi._save);
					uwsgi.workers[uwsgi.mywid].i_have_gil = 1;
				}
#endif
				check_interval.tv_sec = uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL];
				if (!check_interval.tv_sec)
					check_interval.tv_sec = 1;
				for (i = 1; i <= uwsgi.numproc; i++) {
					/* first check for harakiri */
					if (uwsgi.workers[i].harakiri > 0) {
						if (uwsgi.workers[i].harakiri < time(NULL)) {
							/* first try to invoke the harakiri() custom handler */
							/* TODO */
							/* then brutally kill the worker */
							kill(uwsgi.workers[i].pid, SIGKILL);
						}
					}
					/* load counters */
					if (uwsgi.workers[i].status & UWSGI_STATUS_IN_REQUEST)
						working_workers++;

					if (uwsgi.workers[i].status & UWSGI_STATUS_BLOCKING)
						blocking_workers++;

					uwsgi.workers[i].last_running_time = uwsgi.workers[i].running_time;
				}

				// check for cluster nodes
				for (i = 0; i < MAX_CLUSTER_NODES; i++) {
					struct uwsgi_cluster_node *ucn = &uwsgi.shared->nodes[i];

					if (ucn->name[0] != 0 && ucn->status == UWSGI_NODE_FAILED) {
						// should i retry ?
						if (master_cycles % ucn->errors == 0) {
							if (!uwsgi_ping_node(i, &wsgi_req)) {
								ucn->status = UWSGI_NODE_OK;
								fprintf(stderr, "re-enabled cluster node %d/%s\n", i, ucn->name);
							}
							else {
								ucn->errors++;
							}
						}
					}
				}

				continue;

			}
#ifdef UWSGI_SPOOLER
			/* reload the spooler */
			if (spool_dir && uwsgi.shared->spooler_pid > 0) {
				if (diedpid == uwsgi.shared->spooler_pid) {
					fprintf(stderr, "OOOPS the spooler is no more...trying respawn...\n");
					uwsgi.shared->spooler_pid = spooler_start(uwsgi.serverfd, uwsgi_module);
					continue;
				}
			}
#endif

#ifdef UWSGI_PROXY
			/* reload the proxy (can be the only process running) */
			if (uwsgi.proxy_socket_name && uwsgi.shared->proxy_pid > 0) {
				if (diedpid == uwsgi.shared->proxy_pid) {
					if (WIFEXITED(waitpid_status)) {
						if (WEXITSTATUS(waitpid_status) != UWSGI_END_CODE) {
							fprintf(stderr, "OOOPS the proxy is no more...trying respawn...\n");
							uwsgi.shared->spooler_pid = proxy_start(1);
							continue;
						}
					}
				}
			}
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

			fprintf(stderr, "DAMN ! process %d died :( trying respawn ...\n", diedpid);
			gettimeofday(&last_respawn, NULL);
			if (last_respawn.tv_sec == respawn_delta) {
				fprintf(stderr, "worker respawning too fast !!! i have to sleep a bit...\n");
				/* TODO, user configurable fork throttler */
				sleep(2);
			}
			gettimeofday(&last_respawn, NULL);
			respawn_delta = last_respawn.tv_sec;
			uwsgi.mywid = find_worker_id(diedpid);
			pid = fork();
			if (pid == 0) {
				uwsgi.mypid = getpid();
				uwsgi.workers[uwsgi.mywid].pid = uwsgi.mypid;
				uwsgi.workers[uwsgi.mywid].harakiri = 0;
				uwsgi.workers[uwsgi.mywid].requests = 0;
				uwsgi.workers[uwsgi.mywid].failed_requests = 0;
				uwsgi.workers[uwsgi.mywid].respawn_count++;
				uwsgi.workers[uwsgi.mywid].last_spawn = time(NULL);
				uwsgi.workers[uwsgi.mywid].manage_next_request = 1;
				uwsgi.workers[uwsgi.mywid].i_have_gil = 1;
				break;
			}
			else if (pid < 1) {
				perror("fork()");
			}
			else {
				fprintf(stderr, "Respawned uWSGI worker (new pid: %d)\n", pid);
#ifdef UWSGI_SPOOLER
				if (uwsgi.mywid <= 0 && diedpid != uwsgi.shared->spooler_pid) {
#else
				if (uwsgi.mywid <= 0) {
#endif

#ifdef UWSGI_PROXY
					if (diedpid != uwsgi.shared->proxy_pid) {
#endif
						fprintf(stderr, "warning the died pid was not in the workers list. Probably you hit a BUG of uWSGI\n");
#ifdef UWSGI_PROXY
					}
#endif
				}
			}
		}
	}




	uwsgi.hvec = malloc(sizeof(struct iovec) * uwsgi.vec_size);
	if (uwsgi.hvec == NULL) {
		fprintf(stderr, "unable to allocate memory for iovec.\n");
		exit(1);
	}

	if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0 && !uwsgi.master_process) {
		signal(SIGALRM, (void *) &harakiri);
	}

	/* gracefully reload */
	signal(SIGHUP, (void *) &gracefully_kill);
	/* close the process (useful for master INT) */
	signal(SIGINT, (void *) &end_me);
	/* brutally reload */
	signal(SIGTERM, (void *) &reload_me);


#ifndef UNBIT
	signal(SIGUSR1, (void *) &stats);
#endif


	signal(SIGPIPE, (void *) &warn_pipe);


#ifdef UWSGI_ERLANG
	if (uwsgi.erlang_nodes > 0) {
		if (uwsgi.numproc <= uwsgi.erlang_nodes) {
			fprintf(stderr, "You do not have enough worker for Erlang. Please respawn with at least %d processes.\n", uwsgi.erlang_nodes + 1);
		}
		else if (uwsgi.mywid > (uwsgi.numproc - uwsgi.erlang_nodes)) {
			fprintf(stderr, "Erlang mode enabled for worker %d.\n", uwsgi.mywid);
			erlang_loop();
			// NEVER HERE
			exit(1);
		}
	}
	// close the erlang server fd for python workers
	close(uwsgi.erlangfd);
#endif

#ifdef UWSGI_THREADING
	// release the GIL
	if (uwsgi.has_threads) {
		uwsgi._save = PyEval_SaveThread();
		uwsgi.workers[uwsgi.mywid].i_have_gil = 0;
	}
#endif


	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {


		wsgi_req.app_id = uwsgi.default_app;
#ifdef UWSGI_SENDFILE
		wsgi_req.sendfile_fd = -1;
#endif
		// clear all status bits
		UWSGI_CLEAR_STATUS;

		uwsgi.poll.fd = accept(uwsgi.serverfd, (struct sockaddr *) &c_addr, (socklen_t *) & c_len);

		if (uwsgi.poll.fd < 0) {
			perror("accept()");
			continue;
		}

		UWSGI_SET_IN_REQUEST;

		if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
			gettimeofday(&wsgi_req.start_of_request, NULL);



#ifdef UWSGI_SCTP
		if (i_am_sctp == 1) {
			// get stream id, and map it to uwsgi modifiers
			struct sctp_status sstatus;
			memset(&sstatus, 0, sizeof(sstatus));
			socklen_t slen = sizeof(sstatus);
			sstatus.sstat_assoc_id = 1;
			if (getsockopt(uwsgi.poll.fd, IPPROTO_SCTP, SCTP_STATUS, &sstatus, &slen)) {
				perror("getsockopt()");
			}

			memset(&sctp_ss, 0, sizeof(sctp_ss));

			fprintf(stderr, "%d %d\n", sstatus.sstat_instrms, sstatus.sstat_outstrms);

			i = 0;
			wsgi_req.size = sctp_recvmsg(uwsgi.poll.fd, uwsgi.buffer, uwsgi.buffer_size, 0, 0, &sctp_ss, 0);
			if (wsgi_req.size < 0) {
				perror("sctp_recvmsg()");
			}
			fprintf(stderr, "received uwsgi message of %d bytes on stream id %d flags %d\n", wsgi_req.size, ntohs(sctp_ss.sinfo_stream), i);

		}
		else {
#endif
			if (!uwsgi_parse_response(&uwsgi.poll, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], (struct uwsgi_header *) &wsgi_req, uwsgi.buffer)) {
				continue;
			}
#ifdef UWSGI_SCTP
		}
#endif

		// enter harakiri mode
		if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
			set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
		}

		ret = (*uwsgi.shared->hooks[wsgi_req.modifier]) (&uwsgi, &wsgi_req);
		// calculate execution time
		gettimeofday(&wsgi_req.end_of_request, NULL);
		uwsgi.workers[uwsgi.mywid].running_time += (double) (((double) (wsgi_req.end_of_request.tv_sec * 1000000 + wsgi_req.end_of_request.tv_usec) - (double) (wsgi_req.start_of_request.tv_sec * 1000000 + wsgi_req.start_of_request.tv_usec)) / (double) 1000.0);


		// get memory usage
		if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1)
			get_memusage();

		// close the connection with the webserver
		close(uwsgi.poll.fd);
		uwsgi.workers[0].requests++;
		uwsgi.workers[uwsgi.mywid].requests++;

		if (!ret)
			(*uwsgi.shared->after_hooks[wsgi_req.modifier]) (&uwsgi, &wsgi_req);


		// leave harakiri mode
		if (uwsgi.workers[uwsgi.mywid].harakiri > 0) {
			set_harakiri(0);
		}


		// defunct process reaper
		if (uwsgi.shared->options[UWSGI_OPTION_REAPER] == 1) {
			waitpid(-1, &waitpid_status, WNOHANG);
		}
		// reset request
		memset(&wsgi_req, 0, sizeof(struct wsgi_request));
#ifdef UNBIT
		if (tmp_filename && tmp_dir_fd >= 0) {
			tmp_filename[0] = 0;
		}
#endif

		if (uwsgi.shared->options[UWSGI_OPTION_MAX_REQUESTS] > 0 && uwsgi.workers[uwsgi.mywid].requests >= uwsgi.shared->options[UWSGI_OPTION_MAX_REQUESTS]) {
			goodbye_cruel_world();
		}

#ifdef UNBIT
		if (check_for_memory_errors) {
			if (syscall(357, &us, 0) > 0) {
				if (us.memory_errors > 0) {
					fprintf(stderr, "Unbit Kernel found a memory allocation error for process %d.\n", uwsgi.mypid);
					goodbye_cruel_world();
				}
			}
		}
#endif

	}

	if (uwsgi.workers[uwsgi.mywid].manage_next_request == 0) {
		reload_me();
	}
	else {
		goodbye_cruel_world();
	}

	/* never here */
	return 0;
}

void init_uwsgi_vars() {

#ifndef UNBIT
	int i;
#endif
	PyObject *pysys, *pysys_dict, *pypath;

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
	if (PyList_Insert(pypath, 0, PyString_FromString(".")) != 0) {
		PyErr_Print();
	}

#ifndef UNBIT
	for (i = 0; i < uwsgi.python_path_cnt; i++) {
		if (PyList_Insert(pypath, 0, PyString_FromString(uwsgi.python_path[i])) != 0) {
			PyErr_Print();
		}
		else {
			fprintf(stderr, "added %s to pythonpath.\n", uwsgi.python_path[i]);
		}
	}
#endif

}

int init_uwsgi_app(PyObject * force_wsgi_dict, PyObject * my_callable) {
	PyObject *wsgi_module, *wsgi_dict = NULL;
	PyObject *pymain, *zero;
	PyObject *pycprof, *pycprof_dict;
	char tmpstring[256];
	int id;

	struct uwsgi_app *wi;

	memset(tmpstring, 0, 256);


	if (wsgi_req.wsgi_script_len == 0 && ((wsgi_req.wsgi_module_len == 0 || wsgi_req.wsgi_callable_len == 0) && uwsgi.wsgi_config == NULL && my_callable == NULL)) {
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

	id = uwsgi.wsgi_cnt;


	if (wsgi_req.script_name_len == 0) {
		wsgi_req.script_name_len = 1;
		wsgi_req.script_name = (char *) app_slash;
		id = 0;
	}
	else if (wsgi_req.script_name_len == 1) {
		if (wsgi_req.script_name[0] == '/') {
			id = 0;
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

	wi = &uwsgi.wsgi_apps[id];

	memset(wi, 0, sizeof(struct uwsgi_app));

	if (uwsgi.single_interpreter == 0) {
		wi->interpreter = Py_NewInterpreter();
		if (!wi->interpreter) {
			fprintf(stderr, "unable to initialize the new interpreter\n");
			exit(1);
		}
		PyThreadState_Swap(wi->interpreter);
#ifndef PYTHREE
		init_uwsgi_embedded_module();
#endif
		init_uwsgi_vars();
		fprintf(stderr, "interpreter for app %d initialized.\n", id);
	}

	if (uwsgi.paste) {
		wi->wsgi_callable = my_callable;
		Py_INCREF(my_callable);
	}
	else if (uwsgi.wsgi_file) {
		wi->wsgi_callable = my_callable;
		Py_INCREF(my_callable);
	}
	else {

		if (uwsgi.wsgi_config == NULL) {
			if (wsgi_req.wsgi_script_len > 0) {
				memcpy(tmpstring, wsgi_req.wsgi_script, wsgi_req.wsgi_script_len);
				wsgi_module = PyImport_ImportModule(tmpstring);
				if (!wsgi_module) {
					PyErr_Print();
					if (uwsgi.single_interpreter == 0) {
						Py_EndInterpreter(wi->interpreter);
						PyThreadState_Swap(uwsgi.main_thread);
					}
					return -1;
				}
				wsgi_req.wsgi_callable = "application";
				wsgi_req.wsgi_callable_len = 11;
			}
			else {
				memcpy(tmpstring, wsgi_req.wsgi_module, wsgi_req.wsgi_module_len);
				wsgi_module = PyImport_ImportModule(tmpstring);
				if (!wsgi_module) {
					PyErr_Print();
					if (uwsgi.single_interpreter == 0) {
						Py_EndInterpreter(wi->interpreter);
						PyThreadState_Swap(uwsgi.main_thread);
					}
					return -1;
				}
			}

			wsgi_dict = PyModule_GetDict(wsgi_module);
			if (!wsgi_dict) {
				PyErr_Print();
				if (uwsgi.single_interpreter == 0) {
					Py_EndInterpreter(wi->interpreter);
					PyThreadState_Swap(uwsgi.main_thread);
				}
				return -1;
			}

		}
		else {
			wsgi_dict = force_wsgi_dict;
		}


		memset(tmpstring, 0, 256);
		memcpy(tmpstring, wsgi_req.wsgi_callable, wsgi_req.wsgi_callable_len);
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
			PyThreadState_Swap(uwsgi.main_thread);
		}
		return -1;
	}


	wi->wsgi_environ = PyDict_New();
	if (!wi->wsgi_environ) {
		PyErr_Print();
		if (uwsgi.single_interpreter == 0) {
			Py_EndInterpreter(wi->interpreter);
			PyThreadState_Swap(uwsgi.main_thread);
		}
		return -1;
	}

	if (wsgi_dict) {
		wi->wsgi_harakiri = PyDict_GetItemString(wsgi_dict, "harakiri");
		if (wi->wsgi_harakiri) {
			fprintf(stderr, "initialized Harakiri custom handler: %p.\n", wi->wsgi_harakiri);
		}
	}



#ifdef UWSGI_PROFILER
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

		pycprof = PyImport_ImportModule("cProfile");
		if (!pycprof) {
			PyErr_Print();
			fprintf(stderr, "trying old profile module... ");
			pycprof = PyImport_ImportModule("profile");
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

		wi->wsgi_args = PyTuple_New(1);
		if (PyTuple_SetItem(wi->wsgi_args, 0, PyString_FromFormat("uwsgi_out = uwsgi_application__%d(uwsgi_environ__%d,uwsgi_spit__%d)", id, id, id))) {
			PyErr_Print();
			if (uwsgi.single_interpreter == 0) {
				Py_EndInterpreter(wi->interpreter);
				PyThreadState_Swap(uwsgi.main_thread);
			}
			return -1;
		}
	}
	else {
#endif
		wi->wsgi_args = PyTuple_New(2);
		if (PyTuple_SetItem(wi->wsgi_args, 0, wi->wsgi_environ)) {
			PyErr_Print();
			if (uwsgi.single_interpreter == 0) {
				Py_EndInterpreter(wi->interpreter);
				PyThreadState_Swap(uwsgi.main_thread);
			}
			return -1;
		}
		if (PyTuple_SetItem(wi->wsgi_args, 1, wsgi_spitout)) {
			PyErr_Print();
			if (uwsgi.single_interpreter == 0) {
				Py_EndInterpreter(wi->interpreter);
				PyThreadState_Swap(uwsgi.main_thread);
			}
			return -1;
		}
#ifdef UWSGI_PROFILER
	}
#endif

#ifdef UWSGI_SENDFILE
	// prepare sendfile()
	wi->wsgi_sendfile = PyCFunction_New(uwsgi_sendfile_method, NULL);
#endif

	if (uwsgi.single_interpreter == 0) {
		PyThreadState_Swap(uwsgi.main_thread);
	}

	memset(tmpstring, 0, 256);
	memcpy(tmpstring, wsgi_req.script_name, wsgi_req.script_name_len);
	PyDict_SetItemString(uwsgi.py_apps, tmpstring, PyInt_FromLong(id));
	PyErr_Print();

	fprintf(stderr, "application %d (%s) ready\n", id, tmpstring);

	if (id == 0) {
		fprintf(stderr, "setting default application to 0\n");
		uwsgi.default_app = 0;
	}
	else {
		uwsgi.wsgi_cnt++;
	}

	return id;
}

#ifdef UWSGI_PASTE
void uwsgi_paste_config() {
	PyObject *paste_module, *paste_dict, *paste_loadapp;
	PyObject *paste_arg, *paste_app;

	fprintf(stderr, "Loading paste environment: %s\n", uwsgi.paste);
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

	if (PyTuple_SetItem(paste_arg, 0, PyString_FromString(uwsgi.paste))) {
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

#endif

/* trying to emulate Graham's mod_wsgi, this will allows easy and fast migrations */
void uwsgi_wsgi_file_config() {

	FILE *wsgifile;
	struct _node *wsgi_file_node = NULL;
	PyObject *wsgi_compiled_node, *wsgi_file_module, *wsgi_file_dict;
	PyObject *wsgi_file_callable;
	int ret;


	wsgifile = fopen(uwsgi.wsgi_file, "r");
	if (!wsgifile) {
		perror("fopen()");
		exit(1);
	}

	wsgi_file_node = PyParser_SimpleParseFile(wsgifile, uwsgi.wsgi_file, Py_file_input);
	if (!wsgi_file_node) {
		PyErr_Print();
		fprintf(stderr, "failed to parse wsgi file %s\n", uwsgi.wsgi_file);
		exit(1);
	}

	fclose(wsgifile);

	wsgi_compiled_node = (PyObject *) PyNode_Compile(wsgi_file_node, uwsgi.wsgi_file);

	if (!wsgi_compiled_node) {
		PyErr_Print();
		fprintf(stderr, "failed to compile wsgi file %s\n", uwsgi.wsgi_file);
		exit(1);
	}

	wsgi_file_module = PyImport_ExecCodeModule("uwsgi_wsgi_file", wsgi_compiled_node);
	if (!wsgi_file_module) {
		PyErr_Print();
		exit(1);
	}

	Py_DECREF(wsgi_compiled_node);

	wsgi_file_dict = PyModule_GetDict(wsgi_file_module);
	if (!wsgi_file_dict) {
		PyErr_Print();
		exit(1);
	}


	wsgi_file_callable = PyDict_GetItemString(wsgi_file_dict, "application");
	if (!wsgi_file_callable) {
		PyErr_Print();
		fprintf(stderr, "unable to find \"application\" callable in wsgi file %s\n", uwsgi.wsgi_file);
		exit(1);
	}

	if (!PyFunction_Check(wsgi_file_callable) && !PyCallable_Check(wsgi_file_callable)) {
		fprintf(stderr, "\"application\" must be a callable object in wsgi file %s\n", uwsgi.wsgi_file);
		exit(1);
	}


	ret = init_uwsgi_app(NULL, wsgi_file_callable);

}


void uwsgi_wsgi_config() {

	PyObject *wsgi_module, *wsgi_dict;
#ifndef PYTHREE
	PyObject *uwsgi_module, *uwsgi_dict;
#endif
	PyObject *applications;
	PyObject *app_list;
	int ret;
	Py_ssize_t i;
	PyObject *app_mnt, *app_app;

	wsgi_module = PyImport_ImportModule(uwsgi.wsgi_config);
	if (!wsgi_module) {
		PyErr_Print();
		exit(1);
	}

	wsgi_dict = PyModule_GetDict(wsgi_module);
	if (!wsgi_dict) {
		PyErr_Print();
		exit(1);
	}

	fprintf(stderr, "...getting the applications list from the '%s' module...\n", uwsgi.wsgi_config);

#ifndef PYTHREE
	uwsgi_module = PyImport_ImportModule("uwsgi");
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
		fprintf(stderr, "uwsgi.applications dictionary is not defined, trying with the \"applications\" one...\n");
#endif
		applications = PyDict_GetItemString(wsgi_dict, "applications");
		if (!applications) {
			fprintf(stderr, "applications dictionary is not defined, trying with the \"application\" callable.\n");
			app_app = PyDict_GetItemString(wsgi_dict, "application");
			if (app_app) {
				applications = PyDict_New();
				if (!applications) {
					fprintf(stderr, "could not initialize applications dictionary\n");
					exit(1);
				}
				if (PyDict_SetItemString(applications, "/", app_app)) {
					PyErr_Print();
					fprintf(stderr, "unable to set default application\n");
					exit(1);
				}
			}
			else {
				fprintf(stderr, "static applications not defined, you have to used the dynamic one...\n");
				return;
			}
		}
#ifndef PYTHREE
	}
#endif

	if (!PyDict_Check(applications)) {
		fprintf(stderr, "The 'applications' object must be a dictionary.\n");
		exit(1);
	}

	app_list = PyDict_Keys(applications);
	if (!app_list) {
		PyErr_Print();
		exit(1);
	}
	if (PyList_Size(app_list) < 1) {
		fprintf(stderr, "You must define an app.\n");
		exit(1);
	}

	for (i = 0; i < PyList_Size(app_list); i++) {
		app_mnt = PyList_GetItem(app_list, i);

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
			wsgi_req.wsgi_callable = PyString_AsString(app_app);
			wsgi_req.wsgi_callable_len = strlen(wsgi_req.wsgi_callable);
			fprintf(stderr, "initializing [%s => %s] app...\n", wsgi_req.script_name, wsgi_req.wsgi_callable);
			ret = init_uwsgi_app(wsgi_dict, NULL);
		}
		else {
			fprintf(stderr, "initializing [%s] app...\n", wsgi_req.script_name);
			ret = init_uwsgi_app(wsgi_dict, app_app);
		}

		if (ret < 0) {
			fprintf(stderr, "...goodbye cruel world...\n");
			exit(1);
		}
		Py_DECREF(app_mnt);
		Py_DECREF(app_app);
	}

}


#ifdef UNBIT
int uri_to_hex() {
	int i = 0, j = 0;

	if (wsgi_req.uri_len < 1) {
		return 0;
	}

	if (wsgi_req.uri_len * 2 > 8192) {
		return 0;
	}

	for (i = 0; i < wsgi_req.uri_len; i++) {
		sprintf(tmp_filename + j, "%02X", wsgi_req.uri[i]);
		j += 2;
	}

	return j;
}
#endif

#ifdef UWSGI_EMBEDDED
void init_uwsgi_embedded_module() {
	PyObject *new_uwsgi_module, *zero;
	int i;

	/* initialize for stats */
	uwsgi.workers_tuple = PyTuple_New(uwsgi.numproc);
	for (i = 0; i < uwsgi.numproc; i++) {
		zero = PyDict_New();
		Py_INCREF(zero);
		PyTuple_SetItem(uwsgi.workers_tuple, i, zero);
	}



	new_uwsgi_module = Py_InitModule("uwsgi", null_methods);
	if (new_uwsgi_module == NULL) {
		fprintf(stderr, "could not initialize the uwsgi python module\n");
		exit(1);
	}

	uwsgi.embedded_dict = PyModule_GetDict(new_uwsgi_module);
	if (!uwsgi.embedded_dict) {
		fprintf(stderr, "could not get uwsgi module __dict__\n");
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

#ifdef UWSGI_SPOOLER
	if (spool_dir != NULL) {
		init_uwsgi_module_spooler(new_uwsgi_module);
	}
#endif


	if (uwsgi.sharedareasize > 0 && uwsgi.sharedarea) {
		init_uwsgi_module_sharedarea(new_uwsgi_module);
	}
}
#endif

#ifdef UWSGI_PROXY
pid_t proxy_start(has_master) {

	pid_t pid;

	char *tcp_port = strchr(uwsgi.proxy_socket_name, ':');

	if (tcp_port == NULL) {
		uwsgi.proxyfd = bind_to_unix(uwsgi.proxy_socket_name, UWSGI_LISTEN_QUEUE, uwsgi.chmod_socket, uwsgi.abstract_socket);
	}
	else {
		uwsgi.proxyfd = bind_to_tcp(uwsgi.proxy_socket_name, UWSGI_LISTEN_QUEUE, tcp_port);
		tcp_port[0] = ':';
	}

	if (uwsgi.proxyfd < 0) {
		fprintf(stderr, "unable to create the server socket.\n");
		exit(1);
	}

	if (!has_master && uwsgi.numproc == 0) {
		uwsgi_proxy(uwsgi.proxyfd);
		// never here
		exit(1);
	}
	else {
		pid = fork();
		if (pid < 0) {
			perror("fork()");
			exit(1);
		}
		else if (pid > 0) {
			close(uwsgi.proxyfd);
			return pid;
			// continue with uWSGI spawn...
		}
		else {
			uwsgi_proxy(uwsgi.proxyfd);
			// never here
			exit(1);
		}
	}
}
#endif

#ifdef UWSGI_SPOOLER
pid_t spooler_start(int serverfd, PyObject * uwsgi_module) {
	pid_t pid;

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
		fprintf(stderr, "spawned the uWSGI spooler on dir %s with pid %d\n", spool_dir, pid);
	}

	return pid;
}
#endif

void manage_opt(int i, char *optarg) {

	switch (i) {
#ifndef UNBIT
	case LONG_ARGS_VERSION:
		fprintf(stdout, "uWSGI %s\n", UWSGI_VERSION);
		exit(0);
	case LONG_ARGS_PIDFILE:
		uwsgi.pidfile = optarg;
		break;
	case LONG_ARGS_UDP:
		uwsgi.udp_socket = optarg;
		uwsgi.master_process = 1;
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
	case LONG_ARGS_BINARY_PATH:
		uwsgi.binary_path = optarg;
		break;
	case LONG_ARGS_WSGI_FILE:
		uwsgi.single_interpreter = 1;
		uwsgi.wsgi_file = optarg;
		break;
#ifdef UWSGI_PROXY
	case LONG_ARGS_PROXY_NODE:
		uwsgi_cluster_add_node(optarg, 1);
		break;
	case LONG_ARGS_PROXY:
		uwsgi.proxy_socket_name = optarg;
		break;
#endif
#ifdef UWSGI_ERLANG
	case LONG_ARGS_ERLANG:
		uwsgi.erlang_node = optarg;
		break;
	case LONG_ARGS_ERLANG_COOKIE:
		uwsgi.erlang_cookie = optarg;
		break;
#endif
	case LONG_ARGS_PYTHONPATH:
		if (uwsgi.python_path_cnt < 63) {
			uwsgi.python_path[uwsgi.python_path_cnt] = optarg;
			uwsgi.python_path_cnt++;
		}
		else {
			fprintf(stderr, "you can specify at most 64 --pythonpath options\n");
		}
		break;
	case LONG_ARGS_LIMIT_AS:
		uwsgi.rl.rlim_cur = (atoi(optarg)) * 1024 * 1024;
		uwsgi.rl.rlim_max = uwsgi.rl.rlim_cur;
		break;
	case LONG_ARGS_PASTE:
		uwsgi.single_interpreter = 1;
		uwsgi.paste = optarg;
		break;
	case LONG_ARGS_CHECK_INTERVAL:
		uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL] = atoi(optarg);
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
		uwsgi.shared->options[UWSGI_OPTION_LOGGING] = 0;
		break;
#ifdef UWSGI_SPOOLER
	case 'Q':
		spool_dir = optarg;
		if (access(spool_dir, R_OK | W_OK | X_OK)) {
			perror("[spooler directory] access()");
			exit(1);
		}
		uwsgi.master_process = 1;
		break;
#endif
#ifdef UNBIT
	case 'E':
		check_for_memory_errors = 1;
		break;
	case 'S':
		uwsgi.single_interpreter = 1;
		single_app_mode = 1;
		uwsgi.default_app = 0;
		break;
	case 'C':
		tmp_dir_fd = open(optarg, O_DIRECTORY);
		if (tmp_dir_fd < 0) {
			perror("open()");
			exit(1);
		}
		tmp_filename = malloc(8192);
		if (!tmp_filename) {
			fprintf(stderr, "unable to allocate space (8k) for tmp_filename\n");
			exit(1);
		}
		memset(tmp_filename, 0, 8192);
		break;
#endif
#ifndef UNBIT
	case 'd':
		if (!uwsgi.is_a_reload) {
			daemonize(optarg);
		}
		break;
	case 's':
		uwsgi.socket_name = optarg;
		break;
#ifdef UWSGI_XML
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
		uwsgi.vec_size = 4 + 1 + (4 * uwsgi.max_vars);
		break;
	case 'p':
		uwsgi.numproc = atoi(optarg);
		break;
	case 'r':
		uwsgi.shared->options[UWSGI_OPTION_REAPER] = 1;
		break;
	case 'w':
		uwsgi.single_interpreter = 1;
		uwsgi.wsgi_config = optarg;
		break;
	case 'm':
		uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] = 1;
		break;
	case 'O':
		uwsgi.py_optimize = atoi(optarg);
		break;
	case 't':
		uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] = atoi(optarg);
		break;
	case 'b':
		uwsgi.buffer_size = atoi(optarg);
		break;
#ifndef UNBIT
	case 'c':
		uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] = 1;
		break;
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
		uwsgi.shared->options[UWSGI_OPTION_MAX_REQUESTS] = atoi(optarg);
		break;
	case 'z':
		if (atoi(optarg) > 0) {
			uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT] = atoi(optarg);
		}
		break;
	case 'T':
		uwsgi.has_threads = 1;
		uwsgi.shared->options[UWSGI_OPTION_THREADS] = 1;
		break;
	case 'P':
		uwsgi.enable_profiler = 1;
		break;
	case 'i':
		uwsgi.single_interpreter = 1;
		break;
#ifndef UNBIT
	case 'h':
		fprintf(stdout, "Usage: %s [options...]\n\
\t-s|--socket <name>\t\tpath (or name) of UNIX/TCP socket to bind to\n\
\t-l|--listen <num>\t\tset socket listen queue to <n> (default 64, maximum is system dependent)\n\
\t-z|--socket-timeout <sec>\tset socket timeout to <sec> seconds (default 4 seconds)\n\
\t-b|--buffer-size <n>\t\tset buffer size to <n> bytes\n\
\t-L|--disable-logging\t\tdisable request logging (only errors or server messages will be logged)\n\
\t-x|--xmlconfig <path>\t\tpath of xml config file\n\
\t-w|--module <module>\t\tname of python config module\n\
\t-t|--harakiri <sec>\t\tset harakiri timeout to <sec> seconds\n\
\t-p|--processes <n>\t\tspawn <n> uwsgi worker processes\n\
\t-O|--optimize <n>\t\tset python optimization level to <n>\n\
\t-v|--max-vars <n>\t\tset maximum number of vars/headers to <n>\n\
\t-A|--sharedarea <n>\t\tcreate a shared memory area of <n> pages\n\
\t-c|--cgi-mode\t\t\tset cgi mode\n\
\t-C|--chmod-socket\t\tchmod socket to 666\n\
\t-P|--profiler\t\t\tenable profiler\n\
\t-m|--memory-report\t\tenable memory usage report\n\
\t-i|--single-interpreter\t\tsingle interpreter mode\n\
\t-a|--abstract-socket\t\tset socket in the abstract namespace (Linux only)\n\
\t-T|--enable-threads\t\tenable threads support\n\
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
\t--limit-as <MB>\t\t\tlimit the address space of processes to MB megabytes\n\
\t--udp <ip:port>\t\t\tbind master process to udp socket on ip:port\n\
\t--snmp\t\t\tenable SNMP support in the UDP server\n\
\t--erlang <name@ip>\t\tenable the Erlang server with node name <node@ip>\n\
\t--erlang-cookie <cookie>\ttset the erlang cookie to <cookie>\n\
\t--nagios\t\t\tdo a nagios check\n\
\t--binary-path <bin-path>\ttset the path for the next reload of uWSGI (needed for chroot environments)\n\
\t--proxy <socket>\t\trun the uwsgi proxy on socket <socket>\n\
\t--proxy-node <socket>\t\tadd the node <socket> to the proxy\n\
\t--proxy-max-connections <n>\tset the max number of concurrent connections mnaged by the proxy\n\
\t--wsgi-file <file>\t\tload the <file> wsgi file\n\
\t--version\t\t\tprint server version\n\
\t-d|--daemonize <logfile>\tdaemonize and log into <logfile>\n", uwsgi.binary_path);
		exit(1);
	case 0:
		break;
	default:
		exit(1);
#endif
	}
}


void uwsgi_cluster_add_node(char *nodename, int workers) {

	int i;
	struct uwsgi_cluster_node *ucn;
	char *tcp_port;

	if (strlen(nodename) > 100) {
		fprintf(stderr, "invalid cluster node name %s\n", nodename);
		return;
	}

	tcp_port = strchr(nodename, ':');
	if (tcp_port == NULL) {
		fprintf(stdout, "invalid cluster node name %s\n", nodename);
		return;
	}

	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
		ucn = &uwsgi.shared->nodes[i];

		if (ucn->name[0] == 0) {
			strcpy(ucn->name, nodename);
			ucn->workers = workers;
			ucn->ucn_addr.sin_family = AF_INET;
			ucn->ucn_addr.sin_port = htons(atoi(tcp_port + 1));
			tcp_port[0] = 0;
			if (nodename[0] == 0) {
				ucn->ucn_addr.sin_addr.s_addr = INADDR_ANY;
			}
			else {
				fprintf(stderr, "%s\n", nodename);
				ucn->ucn_addr.sin_addr.s_addr = inet_addr(nodename);
			}

			ucn->last_seen = time(NULL);

			return;
		}
	}

	fprintf(stderr, "unable to add node %s\n", nodename);
}
