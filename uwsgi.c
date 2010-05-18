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

struct uwsgi_server uwsgi;

extern char **environ;

static const char *app_slash = "/";

#ifdef UWSGI_SENDFILE
PyMethodDef uwsgi_sendfile_method[] = {{"uwsgi_sendfile", py_uwsgi_sendfile, METH_VARARGS, ""}};
#endif

int find_worker_id(pid_t pid) {
	int i;
	for (i = 1; i <= uwsgi.numproc; i++) {
		/* uwsgi_log("%d of %d\n", pid, uwsgi.workers[i].pid); */
		if (uwsgi.workers[i].pid == pid)
			return i;
	}

	return -1;
}


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


struct uwsgi_app *wi;

void warn_pipe() {
	uwsgi_log("SIGPIPE: writing to a closed pipe/socket/fd !!!\n");
}

void gracefully_kill() {
	uwsgi_log("Gracefully killing worker %d...\n", uwsgi.mypid);
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
	uwsgi_log("...The work of process %d is done. Seeya!\n", getpid());
	exit(0);
}

void kill_them_all() {
	int i;
	uwsgi.to_hell = 1;
	uwsgi_log("SIGINT/SIGQUIT received...killing workers...\n");
	for (i = 1; i <= uwsgi.numproc; i++) {
		kill(uwsgi.workers[i].pid, SIGINT);
	}
}

void grace_them_all() {
	int i;
	uwsgi.to_heaven = 1;
	uwsgi_log("...gracefully killing workers...\n");
	for (i = 1; i <= uwsgi.numproc; i++) {
		kill(uwsgi.workers[i].pid, SIGHUP);
	}
}

void reap_them_all() {
	int i;
	uwsgi_log("...brutally killing workers...\n");
	for (i = 1; i <= uwsgi.numproc; i++) {
		kill(uwsgi.workers[i].pid, SIGTERM);
	}
}

void harakiri() {

	PyThreadState *_myself;

	PyGILState_Ensure();
	_myself = PyThreadState_Get();
	if (wi) {
		uwsgi_log("\nF*CK !!! i must kill myself (pid: %d app_id: %d) wi: %p wi->wsgi_harakiri: %p thread_state: %p frame: %p...\n", uwsgi.mypid, uwsgi.wsgi_req->app_id, wi, wi->wsgi_harakiri, _myself, _myself->frame);

/*
		// NEED TO FIND A SAFER WAY !!!
		if (wi->wsgi_harakiri) {
			PyEval_CallObject(wi->wsgi_harakiri, wi->wsgi_args);
			if (PyErr_Occurred()) {
				PyErr_Print();
			}
		}
*/
	}
	else {
		uwsgi_log("\nF*CK !!! i must kill myself (pid: %d app_id: %d) thread_state: %p frame: %p...\n", uwsgi.mypid, uwsgi.wsgi_req->app_id, _myself, _myself->frame);
	}

	uwsgi_log("*** if you want your workers to be automatically respawned consider enabling the uWSGI master process ***\n");

	Py_FatalError("HARAKIRI !\n");
}

#ifndef UNBIT
void stats() {
	// fix this for better logging (this cause races)
	struct uwsgi_app *ua = NULL;
	int i;

	uwsgi_log("*** pid %d stats ***\n", getpid());
	uwsgi_log("\ttotal requests: %llu\n", uwsgi.workers[0].requests);
	for (i = 0; i < uwsgi.wsgi_cnt; i++) {
		ua = &uwsgi.wsgi_apps[i];
		if (ua) {
			uwsgi_log("\tapp %d requests: %d\n", i, ua->requests);
		}
	}
	uwsgi_log("\n");
}
#endif

PyObject *wsgi_spitout;

PyMethodDef uwsgi_spit_method[] = { {"uwsgi_spit", py_uwsgi_spit, METH_VARARGS, ""} };
PyMethodDef uwsgi_write_method[] = { {"uwsgi_write", py_uwsgi_write, METH_VARARGS, ""} };

#ifdef UWSGI_ASYNC
PyMethodDef uwsgi_eventfd_read_method[] = { {"uwsgi_eventfd_read", py_eventfd_read, METH_VARARGS, ""}};
PyMethodDef uwsgi_eventfd_write_method[] = { {"uwsgi_eventfd_write", py_eventfd_write, METH_VARARGS, ""}};
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


static int unconfigured_hook(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	uwsgi_log("-- unavailable modifier requested: %d --\n", wsgi_req->uh.modifier1);
	return -1;
}

static void unconfigured_after_hook(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	return;
}

int main(int argc, char *argv[], char *envp[]) {

	uint64_t master_cycles = 0;
	struct timeval check_interval = {.tv_sec = 1,.tv_usec = 0 };

#ifdef PYTHREE
	wchar_t *pyargv[MAX_PYARGV];
#else
	char *pyargv[MAX_PYARGV];
#endif
	int pyargc = 1;

	int i;

	int rlen;

	int uwsgi_will_starts = 0;

#ifdef UWSGI_ASYNC
	int current_async_timeout = 0;
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
		uwsgi_error("mmap()");
		exit(1);
	}
	memset(uwsgi.shared, 0, sizeof(struct uwsgi_shared));

	for (i = 0; i <= 0xFF; i++) {
		uwsgi.shared->hooks[i] = unconfigured_hook;
		uwsgi.shared->after_hooks[i] = unconfigured_after_hook;
	}

	uwsgi.wsgi_cnt = 1;
	uwsgi.default_app = -1;

	uwsgi.buffer_size = 4096;
	uwsgi.numproc = 1;

	uwsgi.async = 1;
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
#ifdef UWSGI_XML
		{"xmlconfig", required_argument, 0, 'x'},
#endif
		{"daemonize", required_argument, 0, 'd'},
		{"listen", required_argument, 0, 'l'},
		{"optimize", required_argument, 0, 'O'},
		{"max-vars", required_argument, 0, 'v'},
		{"buffer-size", required_argument, 0, 'b'},
		{"memory-report", no_argument, 0, 'm'},
		{"cgi-mode", no_argument, 0, 'c'},
		{"abstract-socket", no_argument, 0, 'a'},
		{"chmod-socket", no_argument, 0, 'C'},
#ifdef UWSGI_THREADING
		{"enable-threads", no_argument, 0, 'T'},
#endif
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
#ifdef UWSGI_SPOOLER
		{"spooler", required_argument, 0, 'Q'},
#endif
		{"disable-logging", no_argument, 0, 'L'},

		{"pidfile", required_argument, 0, LONG_ARGS_PIDFILE},
		{"chroot", required_argument, 0, LONG_ARGS_CHROOT},
		{"gid", required_argument, 0, LONG_ARGS_GID},
		{"uid", required_argument, 0, LONG_ARGS_UID},
		{"pythonpath", required_argument, 0, LONG_ARGS_PYTHONPATH},
		{"python-path", required_argument, 0, LONG_ARGS_PYTHONPATH},
		{"pyargv", required_argument, 0, LONG_ARGS_PYARGV},
		{"paste", required_argument, 0, LONG_ARGS_PASTE},
		{"no-server", no_argument, &no_server, 1},
		{"no-defer-accept", no_argument, &uwsgi.no_defer_accept, 1},
		{"limit-as", required_argument, 0, LONG_ARGS_LIMIT_AS},
		{"limit-post", required_argument, 0, LONG_ARGS_LIMIT_POST},
		{"prio", required_argument, 0, LONG_ARGS_PRIO},
		{"post-buffering", required_argument, 0, LONG_ARGS_POST_BUFFERING},
		{"post-buffering-bufsize", required_argument, 0, LONG_ARGS_POST_BUFFERING_SIZE},
#ifdef UWSGI_UDP
		{"udp", required_argument, 0, LONG_ARGS_UDP},
#endif
#ifdef UWSGI_MULTICAST
		{"multicast", required_argument, 0, LONG_ARGS_MULTICAST},
#endif
#ifdef UWSGI_SNMP
		{"snmp", no_argument, 0, LONG_ARGS_SNMP},
		{"snmp-community", required_argument, 0, LONG_ARGS_SNMP_COMMUNITY},
#endif
		{"check-interval", required_argument, 0, LONG_ARGS_CHECK_INTERVAL},
#ifdef UWSGI_ERLANG
		{"erlang", required_argument, 0, LONG_ARGS_ERLANG},
		{"erlang-cookie", required_argument, 0, LONG_ARGS_ERLANG_COOKIE},
#endif

#ifdef UWSGI_NAGIOS
		{"nagios", no_argument, &uwsgi.nagios, 1},
#endif
		{"binary-path", required_argument, 0, LONG_ARGS_BINARY_PATH},
#ifdef UWSGI_PROXY
		{"proxy", required_argument, 0, LONG_ARGS_PROXY},
		{"proxy-node", required_argument, 0, LONG_ARGS_PROXY_NODE},
		{"proxy-max-connections", required_argument, 0, LONG_ARGS_PROXY_MAX_CONNECTIONS},
#endif
		{"wsgi-file", required_argument, 0, LONG_ARGS_WSGI_FILE},
		{"file", required_argument, 0, LONG_ARGS_FILE_CONFIG},
#ifdef UWSGI_ASYNC
		{"async", required_argument, 0, LONG_ARGS_ASYNC},
#endif
#ifdef UWSGI_STACKLESS
		{"stackless", no_argument, &uwsgi.stackless, 1},
#endif
#ifdef UWSGI_UGREEN
		{"ugreen", no_argument, &uwsgi.ugreen, 1},
		{"ugreen-stacksize", required_argument, 0, LONG_ARGS_UGREEN_PAGES},
#endif
		{"logto", required_argument, 0, LONG_ARGS_LOGTO},
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
				uwsgi_error("setenv()");
			}
		}
	}
	else {
		if (setenv("UWSGI_RELOADS", "0", 1)) {
			uwsgi_error("setenv()");
		}
	}

	socket_type_len = sizeof(int);
	if (!getsockopt(3, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_len)) {
		if (socket_type == SOCK_STREAM && reloads > 0) {
			uwsgi_log("...fd 3 is a socket, i suppose this is a graceful reload of uWSGI, i will try to do my best...\n");
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

	if (optind < argc) {
		char *lazy = argv[optind];
		if (!strcmp(lazy+strlen(lazy)-3, ".py")) {
			uwsgi.file_config = lazy;
		}
	}

#ifdef UWSGI_XML
	if (uwsgi.xml_config != NULL) {
		uwsgi_xml_config(uwsgi.wsgi_req, long_options);
	}
#endif

//parse environ

	parse_sys_envs(environ, long_options);

	if (uwsgi.binary_path == argv[0]) {
		cwd = uwsgi_get_cwd();
		uwsgi.binary_path = malloc(strlen(argv[0]) + 1);
		if (uwsgi.binary_path == NULL) {
			uwsgi_error("malloc()");
			exit(1);
		}
		strlcpy(uwsgi.binary_path, argv[0], strlen(argv[0]) + 1);
	}

#ifndef UNBIT
	if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
#endif
		if (uwsgi.test_module == NULL) {
			uwsgi_log("*** Starting uWSGI %s (%dbit) on [%.*s] ***\n", UWSGI_VERSION, (int) (sizeof(void *)) * 8, 24, ctime((const time_t *) &uwsgi.start_tv.tv_sec));
		}
#ifndef UNBIT
	}
	else {
		uwsgi_log("*** Starting uWSGI %s (CGI mode) (%dbit) on [%.*s] ***\n", UWSGI_VERSION, (int) (sizeof(void *)) * 8, 24, ctime((const time_t *) &uwsgi.start_tv.tv_sec));
	}
#endif

	uwsgi_log("compiled with version: %s\n", __VERSION__);

#ifdef __BIG_ENDIAN__
	uwsgi_log("*** big endian arch detected ***\n");
#endif

#ifdef PYTHREE
	uwsgi_log("*** Warning Python3.x support is experimental, do not use it in production environment ***\n");
#endif

	uwsgi_log("Python version: %s\n", Py_GetVersion());

#ifndef UNBIT
	uwsgi_as_root();
#endif

	if (!uwsgi.master_process) {
		uwsgi_log(" *** WARNING: you are running uWSGI without its master process manager ***\n");
	}

#ifndef __OpenBSD__
#ifndef UNBIT
	if (uwsgi.rl.rlim_max > 0) {
		uwsgi_log("limiting address space of processes...\n");
		if (setrlimit(RLIMIT_AS, &uwsgi.rl)) {
			uwsgi_error("setrlimit()");
		}
	}
#endif

	if (uwsgi.prio != 0) {
		if (setpriority(PRIO_PROCESS, 0, uwsgi.prio)) {
			uwsgi_error("setpriority()");
		}
		else {
			uwsgi_log("scheduler priority set to %d\n", uwsgi.prio);
		}
	}
	

	if (!getrlimit(RLIMIT_AS, &uwsgi.rl)) {
#ifndef UNBIT
		// check for overflow
		if (uwsgi.rl.rlim_max != RLIM_INFINITY) {
#endif
			uwsgi_log("your process address space limit is %lld bytes (%lld MB)\n", (long long) uwsgi.rl.rlim_max, (long long) uwsgi.rl.rlim_max / 1024 / 1024);
#ifndef UNBIT
		}
#endif
	}
#endif

	uwsgi.page_size = getpagesize();
	uwsgi_log("your memory page size is %d bytes\n", uwsgi.page_size);

	if (uwsgi.buffer_size > 65536) {
		uwsgi_log("invalid buffer size.\n");
		exit(1);
	}

	sanitize_args(&uwsgi);
	
	if (uwsgi.async > 1) {
		if (!getrlimit(RLIMIT_NOFILE, &uwsgi.rl)) {
			if (uwsgi.rl.rlim_cur < uwsgi.async) {
				uwsgi_log("- your current max open files limit is %lu, this is lower than requested async cores !!! -\n", (unsigned long) uwsgi.rl.rlim_cur);
				if (uwsgi.rl.rlim_cur < uwsgi.rl.rlim_max && uwsgi.rl.rlim_max > uwsgi.async) {
					unsigned long tmp_nofile = (unsigned long) uwsgi.rl.rlim_cur ;
					uwsgi.rl.rlim_cur = uwsgi.async;
					if (!setrlimit(RLIMIT_NOFILE, &uwsgi.rl)) {
						uwsgi_log("max open files limit reset to %lu\n", (unsigned long) uwsgi.rl.rlim_cur);
						uwsgi.async = uwsgi.rl.rlim_cur;
					}
					else {
						uwsgi.async = (int) tmp_nofile ;
					}
				}
				else {
					uwsgi.async = uwsgi.rl.rlim_cur;
				}

				uwsgi_log("- async cores set to %d -\n", uwsgi.async);
			}
		}
	}

	// allocate more wsgi_req for async mode
	uwsgi.wsgi_requests = malloc(sizeof(struct wsgi_request) * uwsgi.async);
	if (uwsgi.wsgi_requests == NULL) {
		uwsgi_log("unable to allocate memory for requests.\n");
		exit(1);
	}
	memset(uwsgi.wsgi_requests, 0, sizeof(struct wsgi_request) * uwsgi.async);

	uwsgi.async_buf = malloc( sizeof(char *) * uwsgi.async);
	if (!uwsgi.async_buf) {
		uwsgi_error("malloc()");
		exit(1);
	}

	if (uwsgi.post_buffering > 0) {
		uwsgi.async_post_buf = malloc( sizeof(char *) * uwsgi.async);
		if (!uwsgi.async_post_buf) {
			uwsgi_error("malloc()");
			exit(1);
		}

		if (!uwsgi.post_buffering_bufsize) {
			uwsgi.post_buffering_bufsize = 8192 ;
		}
	}

	for(i=0;i<uwsgi.async;i++) {
		uwsgi.async_buf[i] = malloc(uwsgi.buffer_size);
		if (!uwsgi.async_buf[i]) {
			uwsgi_error("malloc()");
			exit(1);
		}
		if (uwsgi.post_buffering > 0) {
			uwsgi.async_post_buf[i] = malloc(uwsgi.post_buffering_bufsize);
			if (!uwsgi.async_post_buf[i]) {
				uwsgi_error("malloc()");
				exit(1);
			}
		}
	}
	

	// by default set wsgi_req to the first slot
	uwsgi.wsgi_req = uwsgi.wsgi_requests ;

	uwsgi_log("allocated %llu bytes (%llu KB) for %d request's buffer.\n", (uint64_t) (sizeof(struct wsgi_request) * uwsgi.async), 
								 (uint64_t)( (sizeof(struct wsgi_request) * uwsgi.async ) / 1024),
								 uwsgi.async);

	if (uwsgi.pyhome != NULL) {
		uwsgi_log("Setting PythonHome to %s...\n", uwsgi.pyhome);
#ifdef PYTHREE
		wchar_t *wpyhome;
		wpyhome = malloc((sizeof(wchar_t) * strlen(uwsgi.pyhome)) + 2);
		if (!wpyhome) {
			uwsgi_error("malloc()");
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



#ifdef PYTHREE
	mbstowcs(pname, "uwsgi", 6);
	pyargv[0] = pname;
#else
	pyargv[0] = "uwsgi";
#endif

	if (uwsgi.pyargv != NULL) {
#ifdef PYTHREE
	wchar_t *wcargv = malloc( sizeof( wchar_t ) * strlen(uwsgi.pyargv));
	if (!wcargv) {
		uwsgi_error("malloc()");
		exit(1);
	}
	wchar_t *wa;
#endif
		char *ap;
#ifdef __sun__
		// FIX THIS !!!
		ap = strtok(uwsgi.pyargv, " ");
		while ((ap = strtok(NULL, " ")) != NULL) {
#else
		while ((ap = strsep(&uwsgi.pyargv, " \t")) != NULL) {
#endif
			if (*ap != '\0') {
#ifdef PYTHREE
				wa = (wchar_t *) ( (ap-uwsgi.pyargv) * sizeof(wchar_t) );
				mbstowcs(wa, ap, strlen(ap));
				pyargv[pyargc] = wa;
#else
				pyargv[pyargc] = ap;
#endif
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
	uwsgi.wsgi_writeout = PyCFunction_New(uwsgi_write_method, NULL);

#ifdef UWSGI_EMBEDDED
	if (uwsgi.sharedareasize > 0) {
#ifndef __OpenBSD__
		uwsgi.sharedareamutex = mmap(NULL, sizeof(pthread_mutexattr_t) + sizeof(pthread_mutex_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (!uwsgi.sharedareamutex) {
			uwsgi_error("mmap()");
			exit(1);
		}
#else
		uwsgi_log("***WARNING*** the sharedarea on OpenBSD is not SMP-safe. Beware of race conditions !!!\n");
#endif
		uwsgi.sharedarea = mmap(NULL, uwsgi.page_size * uwsgi.sharedareasize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (uwsgi.sharedarea) {
			uwsgi_log("shared area mapped at %p, you can access it with uwsgi.sharedarea* functions.\n", uwsgi.sharedarea);

#ifdef __APPLE__
			memset(uwsgi.sharedareamutex, 0, sizeof(OSSpinLock));
#else
#if !defined(__OpenBSD__) && !defined(__NetBSD__)
			if (pthread_mutexattr_init((pthread_mutexattr_t *) uwsgi.sharedareamutex)) {
				uwsgi_log("unable to allocate mutexattr structure\n");
				exit(1);
			}
			if (pthread_mutexattr_setpshared((pthread_mutexattr_t *) uwsgi.sharedareamutex, PTHREAD_PROCESS_SHARED)) {
				uwsgi_log("unable to share mutex\n");
				exit(1);
			}
			if (pthread_mutex_init((pthread_mutex_t *) uwsgi.sharedareamutex + sizeof(pthread_mutexattr_t), (pthread_mutexattr_t *) uwsgi.sharedareamutex)) {
				uwsgi_log("unable to initialize mutex\n");
				exit(1);
			}
#endif
#endif

		}
		else {
			uwsgi_error("mmap()");
			exit(1);
		}

	}

	init_uwsgi_embedded_module();
#endif



	Py_OptimizeFlag = uwsgi.py_optimize;

	uwsgi.main_thread = PyThreadState_Get();


#ifdef UWSGI_NAGIOS
	if (uwsgi.nagios) {
		nagios(&uwsgi);
		// never here
	}
#endif

#ifdef UWSGI_UGREEN
	if (uwsgi.ugreen) {
		u_green_init(&uwsgi);
	}
#endif

#ifdef UWSGI_THREADING
	if (uwsgi.has_threads) {
		PyEval_InitThreads();
		uwsgi_log("threads support enabled\n");
	}

#endif


	if (!no_server) {
#ifndef UNBIT
		if (uwsgi.socket_name != NULL && !uwsgi.is_a_reload) {
				char *tcp_port = strchr(uwsgi.socket_name, ':');
				if (tcp_port == NULL) {
					uwsgi.serverfd = bind_to_unix(uwsgi.socket_name, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
				}
				else {
					uwsgi.serverfd = bind_to_tcp(uwsgi.socket_name, uwsgi.listen_queue, tcp_port);
				}

				if (uwsgi.serverfd < 0) {
					uwsgi_log("unable to create the server socket.\n");
					exit(1);
				}
		}
#endif

		socket_type_len = sizeof(int);
		if (!getsockopt(uwsgi.serverfd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_len)) {
			uwsgi_will_starts = 1;
		}
		else {
			uwsgi.numproc = 0 ;
		}

#ifdef UWSGI_PROXY
		if (uwsgi.proxy_socket_name) {
			uwsgi.shared->proxy_pid = proxy_start(uwsgi.master_process);
			uwsgi_will_starts = 1;
		}
#endif

#ifdef UWSGI_UDP
		if (uwsgi.udp_socket) {
			uwsgi_will_starts = 1;
		}
#endif


	}


	if (!uwsgi_will_starts && !no_server) {
		uwsgi_log( "The -s/--socket option is missing and stdin is not a socket.\n");
		exit(1);
	}

#ifdef UWSGI_ASYNC
	if (uwsgi.async > 1) {
#ifdef __linux__
		uwsgi.async_events = malloc( sizeof(struct epoll_event) * uwsgi.async ) ;
#elif defined(__sun__)
		uwsgi.async_events = malloc( sizeof(struct pollfd) * uwsgi.async ) ;
#else
		uwsgi.async_events = malloc( sizeof(struct kevent) * uwsgi.async ) ;
#endif
		if (!uwsgi.async_events) {
			uwsgi_error("malloc()");
			exit(1);
		}
	}
#endif




#ifndef UNBIT
	uwsgi_log( "your server socket listen backlog is limited to %d connections\n", uwsgi.listen_queue);
#endif


	if (uwsgi.single_interpreter == 1) {
		init_uwsgi_vars();
	}

	memset(uwsgi.wsgi_apps, 0, sizeof(uwsgi.wsgi_apps));





	/* shared area for workers */
	uwsgi.workers = (struct uwsgi_worker *) mmap(NULL, sizeof(struct uwsgi_worker) * uwsgi.numproc + 1, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (!uwsgi.workers) {
		uwsgi_error("mmap()");
		exit(1);
	}
	memset(uwsgi.workers, 0, sizeof(struct uwsgi_worker) * uwsgi.numproc + 1);

	uwsgi.mypid = getpid();
	masterpid = uwsgi.mypid;

#ifndef UNBIT
	if (uwsgi.pidfile) {
		uwsgi_log( "writing pidfile to %s\n", uwsgi.pidfile);
		pidfile = fopen(uwsgi.pidfile, "w");
		if (!pidfile) {
			uwsgi_error("fopen");
			exit(1);
		}
		if (fprintf(pidfile, "%d\n", masterpid) < 0) {
			uwsgi_log( "could not write pidfile.\n");
		}
		fclose(pidfile);
	}
#endif


	/* save the masterpid */
	uwsgi.workers[0].pid = masterpid;

	uwsgi_log( "initializing hooks...");

	uwsgi.shared->hooks[0] = uwsgi_request_wsgi;
	uwsgi.shared->after_hooks[0] = uwsgi_after_request_wsgi;

	uwsgi.shared->hooks[UWSGI_MODIFIER_ADMIN_REQUEST] = uwsgi_request_admin;	//10
#ifdef UWSGI_SPOOLER
	uwsgi.shared->hooks[UWSGI_MODIFIER_SPOOL_REQUEST] = uwsgi_request_spooler;	//17
#endif
	uwsgi.shared->hooks[UWSGI_MODIFIER_EVAL] = uwsgi_request_eval;	//22
	uwsgi.shared->hooks[UWSGI_MODIFIER_FASTFUNC] = uwsgi_request_fastfunc;	//26

	uwsgi.shared->hooks[UWSGI_MODIFIER_MANAGE_PATH_INFO] = uwsgi_request_wsgi;	// 30
	uwsgi.shared->after_hooks[UWSGI_MODIFIER_MANAGE_PATH_INFO] = uwsgi_after_request_wsgi;	// 30

	uwsgi.shared->hooks[UWSGI_MODIFIER_MESSAGE_MARSHAL] = uwsgi_request_marshal;	//33
	uwsgi.shared->hooks[UWSGI_MODIFIER_PING] = uwsgi_request_ping;	//100

	uwsgi_log( "done.\n");

#ifdef UWSGI_ERLANG
	if (uwsgi.erlang_node) {
		uwsgi.erlang_nodes = 1;
		uwsgi.erlangfd = init_erlang(uwsgi.erlang_node, uwsgi.erlang_cookie);
	}
#endif

#ifdef UWSGI_SNMP
	if (uwsgi.snmp) {
		snmp_init();
	}
#endif

	if (uwsgi.wsgi_config != NULL) {
		uwsgi_wsgi_config(NULL);
	}
	else if (uwsgi.file_config != NULL) {
		uwsgi_wsgi_config(uwsgi.file_config);
	}
	else if (uwsgi.wsgi_file != NULL) {
		uwsgi_wsgi_file_config();
	}
#ifdef UWSGI_XML
	else if (uwsgi.xml_config != NULL) {
		uwsgi_xml_config(uwsgi.wsgi_req, NULL);
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
		uwsgi_log( "no-server mode requested. Goodbye.\n");
		exit(0);
	}
#endif

// is this a proxy only worker ?

	if (!uwsgi.master_process && uwsgi.numproc == 0) {
		exit(0);
	}

	if (!uwsgi.single_interpreter) {
		uwsgi_log( "*** uWSGI is running in multiple interpreter mode !!! ***\n");
	}

	/* preforking() */
	if (uwsgi.master_process) {
		if (uwsgi.is_a_reload) {
			uwsgi_log( "gracefully (RE)spawned uWSGI master process (pid: %d)\n", uwsgi.mypid);
		}
		else {
			uwsgi_log( "spawned uWSGI master process (pid: %d)\n", uwsgi.mypid);
		}
	}

#ifdef UNBIT
	if (single_app_mode == 1) {
		uwsgi.wsgi_req->wsgi_script = getenv("UWSGI_SCRIPT");
		if (uwsgi.wsgi_req->wsgi_script) {
			uwsgi.wsgi_req->wsgi_script_len = strlen(uwsgi.wsgi_req->wsgi_script);
		}
		else {
			uwsgi_log( "UWSGI_SCRIPT env var not set !\n");
			exit(1);
		}

		init_uwsgi_app(NULL, NULL);
	}
#endif

#ifdef UWSGI_SPOOLER
	if (uwsgi.spool_dir != NULL && uwsgi.numproc > 0) {
		uwsgi.shared->spooler_pid = spooler_start(uwsgi.serverfd, uwsgi.embedded_dict);
	}
#endif

#ifdef UWSGI_STACKLESS
	if (uwsgi.stackless) {
		stackless_init(&uwsgi);
	}
#endif


	if (!uwsgi.master_process) {
		if (uwsgi.numproc == 1) {
			uwsgi_log( "spawned uWSGI worker 1 (and the only) (pid: %d)\n", masterpid);
		}
		else {
			uwsgi_log( "spawned uWSGI worker 1 (pid: %d)\n", masterpid);
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
			uwsgi_error("fork()");
			exit(1);
		}
		else {
			uwsgi_log( "spawned uWSGI worker %d (pid: %d)\n", i, pid);
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

		uwsgi.wsgi_req->buffer = uwsgi.async_buf[0];
#ifdef UWSGI_UDP
		if (uwsgi.udp_socket) {
			uwsgi_poll.fd = bind_to_udp(uwsgi.udp_socket);
			if (uwsgi_poll.fd < 0) {
				uwsgi_log( "unable to bind to udp socket. SNMP and cluster management services will be disabled.\n");
			}
			else {
				uwsgi_log( "UDP server enabled.\n");
				uwsgi_poll.events = POLLIN;
			}
		}
#endif

#ifdef UWSGI_SNMP
		if (uwsgi.snmp) {
			if (uwsgi.snmp_community) {
				if (strlen(uwsgi.snmp_community) > 72) {
					uwsgi_log( "*** warning the supplied SNMP community string will be truncated to 72 chars ***\n");
					memcpy(uwsgi.shared->snmp_community, uwsgi.snmp_community, 72);
				}
				else {
					strlcpy(uwsgi.shared->snmp_community, uwsgi.snmp_community, 73);
				}
			}
			uwsgi_log( "filling SNMP table...");

			uwsgi.shared->snmp_gvalue[0].type = SNMP_COUNTER64;
			uwsgi.shared->snmp_gvalue[0].val = &uwsgi.workers[0].requests;

			uwsgi_log( "done\n");

		}
#endif

#ifdef UWSGI_UDP
		PyObject *udp_callable = PyDict_GetItemString(uwsgi.embedded_dict, "udp_callable");
		PyObject *udp_callable_args = NULL;
		if (udp_callable) {
			udp_callable_args = PyTuple_New(3);
		}
#endif
		for (;;) {
			if (ready_to_die >= uwsgi.numproc && uwsgi.to_hell) {
#ifdef UWSGI_SPOOLER
				if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
					kill(uwsgi.shared->spooler_pid, SIGKILL);
					uwsgi_log( "killed the spooler with pid %d\n", uwsgi.shared->spooler_pid);
				}

#endif

#ifdef UWSGI_PROXY
				if (uwsgi.proxy_socket_name && uwsgi.shared->proxy_pid > 0) {
					kill(uwsgi.shared->proxy_pid, SIGKILL);
					uwsgi_log( "killed proxy with pid %d\n", uwsgi.shared->proxy_pid);
				}
#endif
				uwsgi_log( "goodbye to uWSGI.\n");
				exit(0);
			}
			if (ready_to_reload >= uwsgi.numproc && uwsgi.to_heaven) {
#ifdef UWSGI_SPOOLER
				if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
					kill(uwsgi.shared->spooler_pid, SIGKILL);
					uwsgi_log( "wait4() the spooler with pid %d...", uwsgi.shared->spooler_pid);
					diedpid = waitpid(uwsgi.shared->spooler_pid, &waitpid_status, 0);
					uwsgi_log( "done.");
				}
#endif

#ifdef UWSGI_PROXY
				if (uwsgi.proxy_socket_name && uwsgi.shared->proxy_pid > 0) {
					kill(uwsgi.shared->proxy_pid, SIGKILL);
					uwsgi_log( "wait4() the proxy with pid %d...", uwsgi.shared->proxy_pid);
					diedpid = waitpid(uwsgi.shared->proxy_pid, &waitpid_status, 0);
					uwsgi_log( "done.");
				}
#endif
				uwsgi_log( "binary reloading uWSGI...\n");
				if (cwd) {
					if (chdir(cwd)) {
						uwsgi_error("chdir()");
						exit(1);
					}
				}
				/* check fd table (a module can obviosly open some fd on initialization...) */
				uwsgi_log( "closing all fds > 2 (_SC_OPEN_MAX = %ld)...\n", sysconf(_SC_OPEN_MAX));
				for (i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
					if (i == uwsgi.serverfd) {
						continue;
					}
					close(i);
				}
				if (uwsgi.serverfd != 3) {
					if (dup2(uwsgi.serverfd, 3) < 0) {
						uwsgi_error("dup2()");
						exit(1);
					}
				}
				uwsgi_log( "running %s\n", uwsgi.binary_path);
				argv[0] = uwsgi.binary_path;
				//strcpy (argv[0], uwsgi.binary_path);
				execve(uwsgi.binary_path, argv, environ);
				uwsgi_error("execve()");
				// never here
				exit(1);
			}

			int master_has_children = 0;

			if (uwsgi.numproc > 0 ) {
				master_has_children = 1;
			}
#ifdef UWSGI_SPOOLER
			if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
				master_has_children = 1;
			}
#endif
#ifdef UWSGI_PROXY
			if (uwsgi.proxy_socket_name && uwsgi.shared->proxy_pid > 0) {
				master_has_children = 1;
			}
#endif

			if (!master_has_children) {
				diedpid = 0;
			}
			else {
				diedpid = waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
				if (diedpid == -1) {
					uwsgi_error("waitpid()");
					/* here is better to reload all the uWSGI stack */
					uwsgi_log( "something horrible happened...\n");
					reap_them_all();
					exit(1);
				}
			}

			if (diedpid == 0) {
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
						uwsgi_error("poll()");
					}
					else if (rlen > 0) {
						udp_len = sizeof(udp_client);
						rlen = recvfrom(uwsgi_poll.fd, uwsgi.wsgi_req->buffer, uwsgi.buffer_size, 0, (struct sockaddr *) &udp_client, &udp_len);
						if (rlen < 0) {
							uwsgi_error("recvfrom()");
						}
						else if (rlen > 0) {
							memset(udp_client_addr, 0, 16);
							if (inet_ntop(AF_INET, &udp_client.sin_addr.s_addr, udp_client_addr, 16)) {
								if (uwsgi.wsgi_req->buffer[0] == UWSGI_MODIFIER_MULTICAST_ANNOUNCE) {
								}
#ifdef UWSGI_SNMP
								else if (uwsgi.wsgi_req->buffer[0] == 0x30 && uwsgi.snmp) {
									manage_snmp(uwsgi_poll.fd, (uint8_t *) uwsgi.wsgi_req->buffer, rlen, &udp_client);
								}
#endif
								else {
									if (udp_callable && udp_callable_args) {
										PyTuple_SetItem(udp_callable_args, 0, PyString_FromString(udp_client_addr));
										PyTuple_SetItem(udp_callable_args, 1, PyInt_FromLong(ntohs(udp_client.sin_port)));
										PyTuple_SetItem(udp_callable_args, 2, PyString_FromStringAndSize(uwsgi.wsgi_req->buffer, rlen));
										PyObject *udp_response = python_call(udp_callable, udp_callable_args);
										if (udp_response) {
											Py_DECREF(udp_response);
										}
										if (PyErr_Occurred())
											PyErr_Print();
									}
									else {
										// a simple udp logger
										uwsgi_log( "[udp:%s:%d] %.*s", udp_client_addr, ntohs(udp_client.sin_port), rlen, uwsgi.wsgi_req->buffer);
									}
								}
							}
							else {
								uwsgi_error("inet_ntop()");
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
							uwsgi_log("*** HARAKIRI ON WORKER %d (pid: %d) ***\n", i, uwsgi.workers[i].pid);
							kill(uwsgi.workers[i].pid, SIGKILL);
							// to avoid races
							uwsgi.workers[i].harakiri = 0;
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
							if (!uwsgi_ping_node(i, uwsgi.wsgi_req)) {
								ucn->status = UWSGI_NODE_OK;
								uwsgi_log( "re-enabled cluster node %d/%s\n", i, ucn->name);
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
			if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
				if (diedpid == uwsgi.shared->spooler_pid) {
					uwsgi_log( "OOOPS the spooler is no more...trying respawn...\n");
					uwsgi.shared->spooler_pid = spooler_start(uwsgi.serverfd, uwsgi.embedded_dict);
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
							uwsgi_log( "OOOPS the proxy is no more...trying respawn...\n");
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

			uwsgi_log( "DAMN ! process %d died :( trying respawn ...\n", diedpid);
			gettimeofday(&last_respawn, NULL);
			if (last_respawn.tv_sec == respawn_delta) {
				uwsgi_log( "worker respawning too fast !!! i have to sleep a bit...\n");
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
				uwsgi_error("fork()");
			}
			else {
				uwsgi_log( "Respawned uWSGI worker (new pid: %d)\n", pid);
#ifdef UWSGI_SPOOLER
				if (uwsgi.mywid <= 0 && diedpid != uwsgi.shared->spooler_pid) {
#else
				if (uwsgi.mywid <= 0) {
#endif

#ifdef UWSGI_PROXY
					if (diedpid != uwsgi.shared->proxy_pid) {
#endif
						uwsgi_log( "warning the died pid was not in the workers list. Probably you hit a BUG of uWSGI\n");
#ifdef UWSGI_PROXY
					}
#endif
				}
			}
		}
	}


	// postpone the queue initialization as kevent do not pass kfd after fork()
#ifdef UWSGI_ASYNC
	if (uwsgi.async > 1) {
		uwsgi.async_queue = async_queue_init(uwsgi.serverfd);
		if (uwsgi.async_queue < 0) {
			exit(1);
		}
	}
#endif



	uwsgi.async_hvec = malloc((sizeof(struct iovec) * uwsgi.vec_size)*uwsgi.async);
	if (uwsgi.async_hvec == NULL) {
		uwsgi_log( "unable to allocate memory for iovec.\n");
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
			uwsgi_log( "You do not have enough worker for Erlang. Please respawn with at least %d processes.\n", uwsgi.erlang_nodes + 1);
		}
		else if (uwsgi.mywid > (uwsgi.numproc - uwsgi.erlang_nodes)) {
			uwsgi_log( "Erlang mode enabled for worker %d.\n", uwsgi.mywid);
			erlang_loop(uwsgi.wsgi_req);
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


#ifdef UWSGI_ASYNC
	uwsgi.async_running = -1 ;
#endif

#ifdef UWSGI_UGREEN
	if (uwsgi.ugreen) {
		u_green_loop(&uwsgi);
		// never here
	}
#endif

#ifdef UWSGI_STACKLESS
	if (uwsgi.stackless) {
		stackless_loop(&uwsgi);
		// never here
	}
#endif

	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {



		// clear all status bits
		UWSGI_CLEAR_STATUS;

#ifdef UWSGI_ASYNC
	
	if (uwsgi.async > 1) {

		current_async_timeout = async_get_timeout(&uwsgi) ;
		uwsgi.async_nevents = async_wait(uwsgi.async_queue, uwsgi.async_events, uwsgi.async, uwsgi.async_running, current_async_timeout);
		async_expire_timeouts(&uwsgi);

		if (uwsgi.async_nevents < 0) {
			continue;
		}
	
		for(i=0; i<uwsgi.async_nevents;i++) {

			if (uwsgi.async_events[i].ASYNC_FD == uwsgi.serverfd) {

				uwsgi.wsgi_req = find_first_available_wsgi_req(&uwsgi);
				if (uwsgi.wsgi_req == NULL) {
					// async system is full !!!
					goto cycle;
				}

				wsgi_req_setup(uwsgi.wsgi_req, ( (uint8_t *)uwsgi.wsgi_req - (uint8_t *)uwsgi.wsgi_requests)/sizeof(struct wsgi_request) );

				if (wsgi_req_accept(uwsgi.serverfd, uwsgi.wsgi_req)) {
					continue;
				}

				if (wsgi_req_recv(uwsgi.wsgi_req)) {
					continue;
				}

				if (uwsgi.wsgi_req->async_status == UWSGI_OK) {
					goto reqclear;
				}

			}
			else {
				uwsgi.wsgi_req = find_wsgi_req_by_fd(&uwsgi, uwsgi.async_events[i].ASYNC_FD, uwsgi.async_events[i].ASYNC_EV);
				if (uwsgi.wsgi_req) {
					uwsgi.wsgi_req->async_status = UWSGI_AGAIN ;
					uwsgi.wsgi_req->async_waiting_fd = -1 ;
					uwsgi.wsgi_req->async_waiting_fd_monitored = 0 ;
				}

				async_del(uwsgi.async_queue, uwsgi.async_events[i].ASYNC_FD, uwsgi.async_events[i].ASYNC_EV);
			}
		}

cycle:
		uwsgi.wsgi_req = async_loop(&uwsgi);

		if (uwsgi.wsgi_req == NULL)
			continue ;
		uwsgi.wsgi_req->async_status = UWSGI_OK ;

	}
	else {
#endif
		wsgi_req_setup(uwsgi.wsgi_req, 0);

		if (wsgi_req_accept(uwsgi.serverfd, uwsgi.wsgi_req)) {
			continue;
		}

		if (wsgi_req_recv(uwsgi.wsgi_req)) {
			continue;
		}

#ifdef UWSGI_ASYNC
	}
reqclear:
#endif


		uwsgi_close_request(&uwsgi, uwsgi.wsgi_req);
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
			uwsgi_log( "added %s to pythonpath.\n", uwsgi.python_path[i]);
		}
	}
#endif

}

int init_uwsgi_app(PyObject * force_wsgi_dict, PyObject * my_callable) {
	PyObject *wsgi_module, *wsgi_dict = NULL;
	PyObject *zero;
#ifdef UWSGI_PROFILER
	PyObject *pymain, *pycprof, *pycprof_dict;
#endif
	char tmpstring[256];
	int id;
#ifdef UWSGI_ASYNC
	int i;
#endif

	struct uwsgi_app *wi;

	memset(tmpstring, 0, 256);


	if (uwsgi.wsgi_req->wsgi_script_len == 0 && ((uwsgi.wsgi_req->wsgi_module_len == 0 || uwsgi.wsgi_req->wsgi_callable_len == 0) && uwsgi.wsgi_config == NULL && my_callable == NULL)) {
		uwsgi_log( "invalid application (%.*s). skip.\n", uwsgi.wsgi_req->script_name_len, uwsgi.wsgi_req->script_name);
		return -1;
	}

	if (uwsgi.wsgi_config && uwsgi.wsgi_req->wsgi_callable_len == 0 && my_callable == NULL) {
		uwsgi_log( "invalid application (%.*s). skip.\n", uwsgi.wsgi_req->script_name_len, uwsgi.wsgi_req->script_name);
		return -1;
	}

	if (uwsgi.wsgi_req->wsgi_script_len > 255 || uwsgi.wsgi_req->wsgi_module_len > 255 || uwsgi.wsgi_req->wsgi_callable_len > 255) {
		uwsgi_log( "invalid application's string size. skip.\n");
		return -1;
	}

	id = uwsgi.wsgi_cnt;


	if (uwsgi.wsgi_req->script_name_len == 0) {
		uwsgi.wsgi_req->script_name_len = 1;
		uwsgi.wsgi_req->script_name = (char *) app_slash;
		id = 0;
	}
	else if (uwsgi.wsgi_req->script_name_len == 1) {
		if (uwsgi.wsgi_req->script_name[0] == '/') {
			id = 0;
		}
	}


	zero = PyString_FromStringAndSize(uwsgi.wsgi_req->script_name, uwsgi.wsgi_req->script_name_len);
	if (!zero) {
		Py_FatalError("cannot get mountpoint python object !\n");
	}

	if (PyDict_GetItem(uwsgi.py_apps, zero) != NULL) {
		Py_DECREF(zero);
		uwsgi_log( "mountpoint %.*s already configured. skip.\n", uwsgi.wsgi_req->script_name_len, uwsgi.wsgi_req->script_name);
		return -1;
	}

	Py_DECREF(zero);

	wi = &uwsgi.wsgi_apps[id];

	memset(wi, 0, sizeof(struct uwsgi_app));

	if (uwsgi.single_interpreter == 0) {
		wi->interpreter = Py_NewInterpreter();
		if (!wi->interpreter) {
			uwsgi_log( "unable to initialize the new interpreter\n");
			exit(1);
		}
		PyThreadState_Swap(wi->interpreter);

#ifdef UWSGI_EMBEDDED
		// we need to inizialize an embedded module for every interpreter
		init_uwsgi_embedded_module();
#endif
		init_uwsgi_vars();
		uwsgi_log( "interpreter for app %d initialized.\n", id);
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
			if (uwsgi.wsgi_req->wsgi_script_len > 0) {
				memcpy(tmpstring, uwsgi.wsgi_req->wsgi_script, uwsgi.wsgi_req->wsgi_script_len);
				wsgi_module = PyImport_ImportModule(tmpstring);
				if (!wsgi_module) {
					PyErr_Print();
					if (uwsgi.single_interpreter == 0) {
						Py_EndInterpreter(wi->interpreter);
						PyThreadState_Swap(uwsgi.main_thread);
					}
					return -1;
				}
				uwsgi.wsgi_req->wsgi_callable = "application";
				uwsgi.wsgi_req->wsgi_callable_len = 11;
			}
			else {
				memcpy(tmpstring, uwsgi.wsgi_req->wsgi_module, uwsgi.wsgi_req->wsgi_module_len);
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
		memcpy(tmpstring, uwsgi.wsgi_req->wsgi_callable, uwsgi.wsgi_req->wsgi_callable_len);
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

#ifdef UWSGI_ASYNC
	wi->wsgi_environ = malloc(sizeof(PyObject*)*uwsgi.async);
	if (!wi->wsgi_environ) {
		uwsgi_error("malloc()");
                if (uwsgi.single_interpreter == 0) {
                        Py_EndInterpreter(wi->interpreter);
                        PyThreadState_Swap(uwsgi.main_thread) ;
                }
                return -1 ;
	}

	for(i=0;i<uwsgi.async;i++) {
		wi->wsgi_environ[i] = PyDict_New();
		// this will leak all the already allocated dictionary !!!
		if (!wi->wsgi_environ[i]) {
                	if (uwsgi.single_interpreter == 0) {
                        	Py_EndInterpreter(wi->interpreter);
                        	PyThreadState_Swap(uwsgi.main_thread) ;
                	}
                	return -1 ;
		}
	}
#else
	wi->wsgi_environ = PyDict_New();
        if (!wi->wsgi_environ) {
                PyErr_Print();
                if (uwsgi.single_interpreter == 0) {
                        Py_EndInterpreter(wi->interpreter);
                        PyThreadState_Swap(uwsgi.main_thread) ;
                }
                return -1 ;
        }
#endif


	if (wsgi_dict) {
		wi->wsgi_harakiri = PyDict_GetItemString(wsgi_dict, "harakiri");
		if (wi->wsgi_harakiri) {
			uwsgi_log( "initialized Harakiri custom handler: %p.\n", wi->wsgi_harakiri);
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

		if (PyDict_SetItem(wi->pymain_dict, PyString_FromFormat("uwsgi_spit__%d", id), wsgi_spitout)) {
			PyErr_Print();
			exit(1);
		}

		pycprof = PyImport_ImportModule("cProfile");
		if (!pycprof) {
			PyErr_Print();
			uwsgi_log( "trying old profile module...\n");
			pycprof = PyImport_ImportModule("profile");
			if (!pycprof) {
				PyErr_Print();
				exit(1);
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

#ifdef UWSGI_ASYNC
		wi->wsgi_args = malloc(sizeof(PyObject*));
		if (!wi->wsgi_args) {
                	uwsgi_error("malloc()");
                	if (uwsgi.single_interpreter == 0) {
                        	Py_EndInterpreter(wi->interpreter);
                        	PyThreadState_Swap(uwsgi.main_thread) ;
                	}
                	return -1 ;
        	}
		wi->wsgi_args[0] = PyTuple_New(1);
		if (PyTuple_SetItem(wi->wsgi_args[0], 0, PyString_FromFormat("uwsgi_out = uwsgi_application__%d(uwsgi_environ__%d,uwsgi_spit__%d)", id, id, id))) {
#else
		wi->wsgi_args = PyTuple_New(1);
		if (PyTuple_SetItem(wi->wsgi_args, 0, PyString_FromFormat("uwsgi_out = uwsgi_application__%d(uwsgi_environ__%d,uwsgi_spit__%d)", id, id, id))) {
#endif
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

#ifdef UWSGI_ASYNC
        wi->wsgi_args = malloc(sizeof(PyObject*)*uwsgi.async);
        if (!wi->wsgi_args) {
                uwsgi_error("malloc()");
                if (uwsgi.single_interpreter == 0) {
                        Py_EndInterpreter(wi->interpreter);
                        PyThreadState_Swap(uwsgi.main_thread) ;
                }
                return -1 ;
        }

        for(i=0;i<uwsgi.async;i++) {
                wi->wsgi_args[i] = PyTuple_New(2);
                // this will leak all the already allocated dictionary !!!
                if (!wi->wsgi_args[i]) {
                        if (uwsgi.single_interpreter == 0) {
                                Py_EndInterpreter(wi->interpreter);
                                PyThreadState_Swap(uwsgi.main_thread) ;
                        }
                        return -1 ;
                }
		if (PyTuple_SetItem(wi->wsgi_args[i], 1, wsgi_spitout)) {
			PyErr_Print();
			if (uwsgi.single_interpreter == 0) {
				Py_EndInterpreter(wi->interpreter);
				PyThreadState_Swap(uwsgi.main_thread);
			}
			return -1;
		}
        }
#else

		wi->wsgi_args = PyTuple_New(2);
		if (PyTuple_SetItem(wi->wsgi_args, 1, wsgi_spitout)) {
			PyErr_Print();
			if (uwsgi.single_interpreter == 0) {
				Py_EndInterpreter(wi->interpreter);
				PyThreadState_Swap(uwsgi.main_thread);
			}
			return -1;
		}
#endif

#ifdef UWSGI_PROFILER
	}
#endif

#ifdef UWSGI_SENDFILE
	// prepare sendfile()
	wi->wsgi_sendfile = PyCFunction_New(uwsgi_sendfile_method, NULL);
#endif

#ifdef UWSGI_ASYNC
	wi->wsgi_eventfd_read = PyCFunction_New(uwsgi_eventfd_read_method, NULL);
	wi->wsgi_eventfd_write = PyCFunction_New(uwsgi_eventfd_write_method, NULL);
#endif

	if (uwsgi.single_interpreter == 0) {
		PyThreadState_Swap(uwsgi.main_thread);
	}

	memset(tmpstring, 0, 256);
	memcpy(tmpstring, uwsgi.wsgi_req->script_name, uwsgi.wsgi_req->script_name_len);
	PyDict_SetItemString(uwsgi.py_apps, tmpstring, PyInt_FromLong(id));
	PyErr_Print();

	uwsgi_log( "application %d (%s) ready\n", id, tmpstring);

	if (id == 0) {
		uwsgi_log( "setting default application to 0\n");
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

	uwsgi.single_interpreter = 1;

	uwsgi_log( "Loading paste environment: %s\n", uwsgi.paste);
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

	uwsgi.single_interpreter = 1;

	wsgifile = fopen(uwsgi.wsgi_file, "r");
	if (!wsgifile) {
		uwsgi_error("fopen()");
		exit(1);
	}

	wsgi_file_node = PyParser_SimpleParseFile(wsgifile, uwsgi.wsgi_file, Py_file_input);
	if (!wsgi_file_node) {
		PyErr_Print();
		uwsgi_log( "failed to parse wsgi file %s\n", uwsgi.wsgi_file);
		exit(1);
	}

	fclose(wsgifile);

	wsgi_compiled_node = (PyObject *) PyNode_Compile(wsgi_file_node, uwsgi.wsgi_file);

	if (!wsgi_compiled_node) {
		PyErr_Print();
		uwsgi_log( "failed to compile wsgi file %s\n", uwsgi.wsgi_file);
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
		uwsgi_log( "unable to find \"application\" callable in wsgi file %s\n", uwsgi.wsgi_file);
		exit(1);
	}

	if (!PyFunction_Check(wsgi_file_callable) && !PyCallable_Check(wsgi_file_callable)) {
		uwsgi_log( "\"application\" must be a callable object in wsgi file %s\n", uwsgi.wsgi_file);
		exit(1);
	}


	ret = init_uwsgi_app(NULL, wsgi_file_callable);

}


void uwsgi_wsgi_config(char *filename) {

	PyObject *wsgi_module, *wsgi_dict;
#ifdef UWSGI_EMBEDDED
	PyObject *uwsgi_module, *uwsgi_dict;
#endif
	PyObject *applications;
	PyObject *app_list;
	int ret;
	Py_ssize_t i;
	PyObject *app_mnt, *app_app;
	FILE *uwsgifile;

	uwsgi.single_interpreter = 1;

	if (filename) {
		uwsgifile = fopen(filename, "r");
        	if (!uwsgifile) {
                	uwsgi_error("fopen()");
                	exit(1);
        	}

        	struct _node *uwsgi_file_node = PyParser_SimpleParseFile(uwsgifile, filename, Py_file_input);
        	if (!uwsgi_file_node) {
                	PyErr_Print();
                	uwsgi_log( "failed to parse wsgi file %s\n", filename);
                	exit(1);
        	}

        	fclose(uwsgifile);

        	PyObject *uwsgi_compiled_node = (PyObject *) PyNode_Compile(uwsgi_file_node, filename);

        	if (!uwsgi_compiled_node) {
                	PyErr_Print();
                	uwsgi_log( "failed to compile wsgi file %s\n", filename);
                	exit(1);
        	}

        	wsgi_module = PyImport_ExecCodeModule("uwsgi_config_file", uwsgi_compiled_node);
        	if (!wsgi_module) {
                	PyErr_Print();
                	exit(1);
        	}

        	Py_DECREF(uwsgi_compiled_node);
		uwsgi.wsgi_config = "uwsgi_config_file";
	}
	else {
		wsgi_module = PyImport_ImportModule(uwsgi.wsgi_config);
		if (!wsgi_module) {
			PyErr_Print();
			exit(1);
		}
	}
	

	wsgi_dict = PyModule_GetDict(wsgi_module);
	if (!wsgi_dict) {
		PyErr_Print();
		exit(1);
	}

	uwsgi_log( "...getting the applications list from the '%s' module...\n", uwsgi.wsgi_config);

#ifdef UWSGI_EMBEDDED
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
		uwsgi_log( "uwsgi.applications dictionary is not defined, trying with the \"applications\" one...\n");
#endif
		applications = PyDict_GetItemString(wsgi_dict, "applications");
		if (!applications) {
			uwsgi_log( "applications dictionary is not defined, trying with the \"application\" callable.\n");
			app_app = PyDict_GetItemString(wsgi_dict, "application");
			if (app_app) {
				applications = PyDict_New();
				if (!applications) {
					uwsgi_log( "could not initialize applications dictionary\n");
					exit(1);
				}
				if (PyDict_SetItemString(applications, "/", app_app)) {
					PyErr_Print();
					uwsgi_log( "unable to set default application\n");
					exit(1);
				}
			}
			else {
				uwsgi_log( "static applications not defined, you have to use the dynamic one...\n");
				return;
			}
		}
#ifdef UWSGI_EMBEDDED
	}
#endif

	if (!PyDict_Check(applications)) {
		uwsgi_log( "The 'applications' object must be a dictionary.\n");
		exit(1);
	}

	app_list = PyDict_Keys(applications);
	if (!app_list) {
		PyErr_Print();
		exit(1);
	}
	if (PyList_Size(app_list) < 1) {
		uwsgi_log( "You must define an app.\n");
		exit(1);
	}

	for (i = 0; i < PyList_Size(app_list); i++) {
		app_mnt = PyList_GetItem(app_list, i);

		if (!PyString_Check(app_mnt)) {
			uwsgi_log( "the app mountpoint must be a string.\n");
			exit(1);
		}

		uwsgi.wsgi_req->script_name = PyString_AsString(app_mnt);
		uwsgi.wsgi_req->script_name_len = strlen(uwsgi.wsgi_req->script_name);

		app_app = PyDict_GetItem(applications, app_mnt);

		if (!PyString_Check(app_app) && !PyFunction_Check(app_app) && !PyCallable_Check(app_app)) {
			uwsgi_log( "the app callable must be a string, a function or a callable. (found %s)\n", app_app->ob_type->tp_name);
			exit(1);
		}

		if (PyString_Check(app_app)) {
			uwsgi.wsgi_req->wsgi_callable = PyString_AsString(app_app);
			uwsgi.wsgi_req->wsgi_callable_len = strlen(uwsgi.wsgi_req->wsgi_callable);
			uwsgi_log( "initializing [%s => %s] app...\n", uwsgi.wsgi_req->script_name, uwsgi.wsgi_req->wsgi_callable);
			ret = init_uwsgi_app(wsgi_dict, NULL);
		}
		else {
			uwsgi_log( "initializing [%s] app...\n", uwsgi.wsgi_req->script_name);
			ret = init_uwsgi_app(wsgi_dict, app_app);
		}

		if (ret < 0) {
			uwsgi_log( "...goodbye cruel world...\n");
			exit(1);
		}
		Py_DECREF(app_mnt);
		Py_DECREF(app_app);
	}

}


#ifdef UNBIT
int uri_to_hex() {
	int i = 0, j = 0;

	if (uwsgi.wsgi_req->uri_len < 1) {
		return 0;
	}

	if (uwsgi.wsgi_req->uri_len * 2 > 8192) {
		return 0;
	}

	for (i = 0; i < uwsgi.wsgi_req->uri_len; i++) {
		sprintf(tmp_filename + j, "%02X", uwsgi.wsgi_req->uri[i]);
		j += 2;
	}

	return j;
}
#endif

#ifdef PYTHREE
static PyModuleDef uwsgi_module3 = {
	PyModuleDef_HEAD_INIT,
	"uwsgi",
	NULL,
	-1,
	null_methods,
};
PyObject *init_uwsgi3(void) {
	return PyModule_Create(&uwsgi_module3);
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



#ifdef PYTHREE
	PyImport_AppendInittab("uwsgi", init_uwsgi3);
	new_uwsgi_module = PyImport_AddModule("uwsgi");
#else
	new_uwsgi_module = Py_InitModule("uwsgi", null_methods);
#endif
	if (new_uwsgi_module == NULL) {
		uwsgi_log( "could not initialize the uwsgi python module\n");
		exit(1);
	}

	uwsgi.embedded_dict = PyModule_GetDict(new_uwsgi_module);
	if (!uwsgi.embedded_dict) {
		uwsgi_log( "could not get uwsgi module __dict__\n");
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
	if (uwsgi.spool_dir != NULL) {
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
		uwsgi_log( "unable to create the server socket.\n");
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
			uwsgi_error("fork()");
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
pid_t spooler_start(int serverfd, PyObject * uwsgi_module_dict) {
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		uwsgi_error("fork()");
		exit(1);
	}
	else if (pid == 0) {
		close(serverfd);
		spooler(&uwsgi, uwsgi_module_dict);
	}
	else if (pid > 0) {
		uwsgi_log( "spawned the uWSGI spooler on dir %s with pid %d\n", uwsgi.spool_dir, pid);
	}

	return pid;
}
#endif

void manage_opt(int i, char *optarg) {

	switch (i) {
#ifdef UWSGI_ASYNC
	case LONG_ARGS_ASYNC:
		uwsgi.async = atoi(optarg);
		break;
#endif
	case LONG_ARGS_LOGTO:
		logto(optarg);
		break;
#ifdef UWSGI_UGREEN
	case LONG_ARGS_UGREEN_PAGES:
		uwsgi.ugreen_stackpages = atoi(optarg);
		break;
#endif
#ifndef UNBIT
	case LONG_ARGS_VERSION:
		fprintf(stdout, "uWSGI %s\n", UWSGI_VERSION);
		exit(0);
#ifdef UWSGI_SNMP
	case LONG_ARGS_SNMP:
		uwsgi.snmp = 1;
		break;
	case LONG_ARGS_SNMP_COMMUNITY:
		uwsgi.snmp = 1;
		uwsgi.snmp_community = optarg;
		break;
#endif
	case LONG_ARGS_PIDFILE:
		uwsgi.pidfile = optarg;
		break;
#ifdef UWSGI_UDP
	case LONG_ARGS_UDP:
		uwsgi.udp_socket = optarg;
		uwsgi.master_process = 1;
		break;
#endif
#ifdef UWSGI_MULTICAST
	case LONG_ARGS_MULTICAST:
		uwsgi.multicast_group = optarg;
		uwsgi.master_process = 1;
		break;
#endif
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
		uwsgi.wsgi_file = optarg;
		break;
	case LONG_ARGS_FILE_CONFIG:
		uwsgi.file_config = optarg;
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
			uwsgi_log( "you can specify at most 64 --pythonpath options\n");
		}
		break;
	case LONG_ARGS_LIMIT_AS:
		uwsgi.rl.rlim_cur = (atoi(optarg)) * 1024 * 1024;
		uwsgi.rl.rlim_max = uwsgi.rl.rlim_cur;
		break;
	case LONG_ARGS_LIMIT_POST:
		uwsgi.limit_post = (int) strtol(optarg, NULL, 10);
		break;
	case LONG_ARGS_PRIO:
		uwsgi.prio = (int) strtol(optarg, NULL, 10);
		break;
	case LONG_ARGS_POST_BUFFERING:
		uwsgi.post_buffering = atoi(optarg);
		break;
	case LONG_ARGS_POST_BUFFERING_SIZE:
		uwsgi.post_buffering_bufsize = atoi(optarg);
		break;
	case LONG_ARGS_PASTE:
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
		uwsgi.spool_dir = malloc(PATH_MAX);
		if (!uwsgi.spool_dir) {
			uwsgi_error("malloc()");
			exit(1);
		}
		if (access(optarg, R_OK | W_OK | X_OK)) {
			uwsgi_error("[spooler directory] access()");
			exit(1);
		}
		if (!realpath(optarg, uwsgi.spool_dir)) {
			uwsgi_error("realpath()");
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
			uwsgi_error("open()");
			exit(1);
		}
		tmp_filename = malloc(8192);
		if (!tmp_filename) {
			uwsgi_log( "unable to allocate space (8k) for tmp_filename\n");
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
\t--no-server\t\t\tinitialize the uWSGI server then exit. Useful for testing and using uwsgi embedded module\n\
\t--no-defer-accept\t\tdisable the no-standard way to defer the accept() call (TCP_DEFER_ACCEPT, SO_ACCEPTFILTER...)\n\
\t--paste <config:/egg:>\t\tload applications using paste.deploy.loadapp()\n\
\t--check-interval <sec>\t\tset the check interval (in seconds) of the master process\n\
\t--pythonpath <dir>\t\tadd <dir> to PYTHONPATH\n\
\t--pyargv <args>\t\t\tassign args to python sys.argv\n\
\t--limit-as <MB>\t\t\tlimit the address space of processes to MB megabytes\n\
\t--limit-post <bytes>\t\tlimit HTTP content_length size to <bytes>\n\
\t--post-buffering <bytes>\tbuffer HTTP POST request higher than <bytes> to disk\n\
\t--post-buffering-bufsize <b>\tset the buffer size to <b> bytes for post-buffering\n\
\t--prio <N>\t\t\tset process priority/nice to N\n\
\t--udp <ip:port>\t\t\tbind master process to udp socket on ip:port\n\
\t--snmp\t\t\t\tenable SNMP support in the UDP server\n\
\t--erlang <name@ip>\t\tenable the Erlang server with node name <node@ip>\n\
\t--erlang-cookie <cookie>\ttset the erlang cookie to <cookie>\n\
\t--nagios\t\t\tdo a nagios check\n\
\t--binary-path <bin-path>\ttset the path for the next reload of uWSGI (needed for chroot environments)\n\
\t--proxy <socket>\t\trun the uwsgi proxy on socket <socket>\n\
\t--proxy-node <socket>\t\tadd the node <socket> to the proxy\n\
\t--proxy-max-connections <n>\tset the max number of concurrent connections mnaged by the proxy\n\
\t--wsgi-file <file>\t\tload the <file> wsgi file\n\
\t--async <n>\t\t\tenable async mode with n core\n\
\t--logto <logfile|addr>\t\tlog to file/udp\n\
\t--stackless\t\t\tenable usage of tasklet (only on Stackless Python)\n\
\t--version\t\t\tprint server version\n\
\t-d|--daemonize <logfile|addr>\tdaemonize and log into <logfile> or udp <addr>\n", uwsgi.binary_path);
		exit(1);
	case 0:
		break;
	default:
		if (i != '?') {
			uwsgi_log( "invalid argument -%c  exiting \n", i);
		}
		exit(1);
#endif
	}
}


void uwsgi_cluster_add_node(char *nodename, int workers) {

	int i;
	struct uwsgi_cluster_node *ucn;
	char *tcp_port;

	if (strlen(nodename) > 100) {
		uwsgi_log( "invalid cluster node name %s\n", nodename);
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
			strlcpy(ucn->name, nodename, 101);
			ucn->workers = workers;
			ucn->ucn_addr.sin_family = AF_INET;
			ucn->ucn_addr.sin_port = htons(atoi(tcp_port + 1));
			tcp_port[0] = 0;
			if (nodename[0] == 0) {
				ucn->ucn_addr.sin_addr.s_addr = INADDR_ANY;
			}
			else {
				uwsgi_log( "%s\n", nodename);
				ucn->ucn_addr.sin_addr.s_addr = inet_addr(nodename);
			}

			ucn->last_seen = time(NULL);

			return;
		}
	}

	uwsgi_log( "unable to add node %s\n", nodename);
}
