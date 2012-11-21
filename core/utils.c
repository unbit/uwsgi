#include "uwsgi.h"


extern struct uwsgi_server uwsgi;
extern char **environ;

/* statistically ordered */
struct http_status_codes hsc[] = {
	{"200", "OK"},
	{"302", "Found"},
	{"404", "Not Found"},
	{"500", "Internal Server Error"},
	{"301", "Moved Permanently"},
	{"304", "Not Modified"},
	{"303", "See Other"},
	{"403", "Forbidden"},
	{"307", "Temporary Redirect"},
	{"401", "Unauthorized"},
	{"400", "Bad Request"},
	{"405", "Method Not Allowed"},
	{"408", "Request Timeout"},

	{"100", "Continue"},
	{"101", "Switching Protocols"},
	{"201", "Created"},
	{"202", "Accepted"},
	{"203", "Non-Authoritative Information"},
	{"204", "No Content"},
	{"205", "Reset Content"},
	{"206", "Partial Content"},
	{"300", "Multiple Choices"},
	{"305", "Use Proxy"},
	{"402", "Payment Required"},
	{"406", "Not Acceptable"},
	{"407", "Proxy Authentication Required"},
	{"409", "Conflict"},
	{"410", "Gone"},
	{"411", "Length Required"},
	{"412", "Precondition Failed"},
	{"413", "Request Entity Too Large"},
	{"414", "Request-URI Too Long"},
	{"415", "Unsupported Media Type"},
	{"416", "Requested Range Not Satisfiable"},
	{"417", "Expectation Failed"},
	{"501", "Not Implemented"},
	{"502", "Bad Gateway"},
	{"503", "Service Unavailable"},
	{"504", "Gateway Timeout"},
	{"505", "HTTP Version Not Supported"},
	{"", NULL},
};



#ifdef __BIG_ENDIAN__
uint16_t uwsgi_swap16(uint16_t x) {
	return (uint16_t) ((x & 0xff) << 8 | (x & 0xff00) >> 8);
}

uint32_t uwsgi_swap32(uint32_t x) {
	x = ((x << 8) & 0xFF00FF00) | ((x >> 8) & 0x00FF00FF);
	return (x >> 16) | (x << 16);
}

// thanks to ffmpeg project for this idea :P
uint64_t uwsgi_swap64(uint64_t x) {
	union {
		uint64_t ll;
		uint32_t l[2];
	} w, r;
	w.ll = x;
	r.l[0] = uwsgi_swap32(w.l[1]);
	r.l[1] = uwsgi_swap32(w.l[0]);
	return r.ll;
}

#endif

// check if a string is a valid hex number
int check_hex(char *str, int len) {
	int i;
	for (i = 0; i < len; i++) {
		if ((str[i] < '0' && str[i] > '9') && (str[i] < 'a' && str[i] > 'f') && (str[i] < 'A' && str[i] > 'F')
			) {
			return 0;
		}
	}

	return 1;

}

// increase worker harakiri
void inc_harakiri(int sec) {
	if (uwsgi.master_process) {
		uwsgi.workers[uwsgi.mywid].harakiri += sec;
	}
	else {
		alarm(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] + sec);
	}
}

// set worker harakiri
void set_harakiri(int sec) {
	if (sec == 0) {
		uwsgi.workers[uwsgi.mywid].harakiri = 0;
	}
	else {
		uwsgi.workers[uwsgi.mywid].harakiri = uwsgi_now() + sec;
	}
	if (!uwsgi.master_process) {
		alarm(sec);
	}
}

// set user harakiri
void set_user_harakiri(int sec) {
	if (!uwsgi.master_process) {
		uwsgi_log("!!! unable to set user harakiri without the master process !!!\n");
		return;
	}
	if (sec == 0) {
		uwsgi.workers[uwsgi.mywid].user_harakiri = 0;
	}
	else {
		uwsgi.workers[uwsgi.mywid].user_harakiri = uwsgi_now() + sec;
	}
}

// set mule harakiri
void set_mule_harakiri(int sec) {
	if (sec == 0) {
		uwsgi.mules[uwsgi.muleid - 1].harakiri = 0;
	}
	else {
		uwsgi.mules[uwsgi.muleid - 1].harakiri = uwsgi_now() + sec;
	}
	if (!uwsgi.master_process) {
		alarm(sec);
	}
}

#ifdef UWSGI_SPOOLER
// set spooler harakiri
void set_spooler_harakiri(int sec) {
	if (sec == 0) {
		uwsgi.i_am_a_spooler->harakiri = 0;
	}
	else {
		uwsgi.i_am_a_spooler->harakiri = uwsgi_now() + sec;
	}
	if (!uwsgi.master_process) {
		alarm(sec);
	}
}
#endif


// daemonize to the specified logfile
void daemonize(char *logfile) {
	pid_t pid;
	int fdin;

	// do not daemonize under emperor
	if (uwsgi.has_emperor) {
		logto(logfile);
		return;
	}

	pid = fork();
	if (pid < 0) {
		uwsgi_error("fork()");
		exit(1);
	}
	if (pid != 0) {
		_exit(0);
	}

	if (setsid() < 0) {
		uwsgi_error("setsid()");
		exit(1);
	}

	/* refork... */
	pid = fork();
	if (pid < 0) {
		uwsgi_error("fork()");
		exit(1);
	}
	if (pid != 0) {
		_exit(0);
	}

	if (!uwsgi.do_not_change_umask) {
		umask(0);
	}

	/*if (chdir("/") != 0) {
	   uwsgi_error("chdir()");
	   exit(1);
	   } */

	fdin = open("/dev/null", O_RDWR);
	if (fdin < 0) {
		uwsgi_error_open("/dev/null");
		exit(1);
	}

	/* stdin */
	if (fdin != 0) {
		if (dup2(fdin, 0) < 0) {
			uwsgi_error("dup2()");
			exit(1);
		}
		close(fdin);
	}


	logto(logfile);
}

// get current working directory
char *uwsgi_get_cwd() {

	// set this to static to avoid useless reallocations in stats mode
	static size_t newsize = 256;

	char *cwd = uwsgi_malloc(newsize);

	if (getcwd(cwd, newsize) == NULL && errno == ERANGE) {
		newsize += 256;
		uwsgi_log("need a bigger buffer (%d bytes) for getcwd(). doing reallocation.\n", newsize);
		free(cwd);
		cwd = uwsgi_malloc(newsize);
		if (getcwd(cwd, newsize) == NULL) {
			uwsgi_error("getcwd()");
			exit(1);
		}
	}

	return cwd;

}

// generate internal server error message
void internal_server_error(struct wsgi_request *wsgi_req, char *message) {

	if (uwsgi.wsgi_req->headers_size == 0) {
		if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
			uwsgi.wsgi_req->headers_size = wsgi_req->socket->proto_write_header(wsgi_req, "HTTP/1.1 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 63);
		}
		else {
			uwsgi.wsgi_req->headers_size = wsgi_req->socket->proto_write_header(wsgi_req, "Status: 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 62);
		}
		uwsgi.wsgi_req->header_cnt = 2;
	}

	uwsgi.wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, "<h1>uWSGI Error</h1>", 20);
	uwsgi.wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, message, strlen(message));
}

// check if a string_list containes an item
struct uwsgi_string_list *uwsgi_string_list_has_item(struct uwsgi_string_list *list, char *key, size_t keylen) {
	struct uwsgi_string_list *usl = list;
	while (usl) {
		if (keylen == usl->len) {
			if (!memcmp(key, usl->value, keylen)) {
				return usl;
			}
		}
		usl = usl->next;
	}
	return NULL;
}

#ifdef __linux__
void uwsgi_set_cgroup() {

	char *cgroup_taskfile;
	FILE *cgroup;
	char *cgroup_opt;
	struct uwsgi_string_list *usl, *uslo;

	if (!uwsgi.cgroup)
		return;

	usl = uwsgi.cgroup;

	while (usl) {
		if (mkdir(usl->value, 0700)) {
			uwsgi_log("using Linux cgroup %s\n", usl->value);
			if (errno != EEXIST) {
				uwsgi_error("mkdir()");
			}
		}
		else {
			uwsgi_log("created Linux cgroup %s\n", usl->value);
		}

		cgroup_taskfile = uwsgi_concat2(usl->value, "/tasks");
		cgroup = fopen(cgroup_taskfile, "w");
		if (!cgroup) {
			uwsgi_error_open(cgroup_taskfile);
			exit(1);
		}
		if (fprintf(cgroup, "%d", (int) getpid()) <= 0) {
			uwsgi_log("could not set cgroup\n");
			exit(1);
		}
		uwsgi_log("assigned process %d to cgroup %s\n", (int) getpid(), cgroup_taskfile);
		fclose(cgroup);
		free(cgroup_taskfile);


		uslo = uwsgi.cgroup_opt;
		while (uslo) {
			cgroup_opt = strchr(uslo->value, '=');
			if (!cgroup_opt) {
				cgroup_opt = strchr(uslo->value, ':');
				if (!cgroup_opt) {
					uwsgi_log("invalid cgroup-opt syntax\n");
					exit(1);
				}
			}

			cgroup_opt[0] = 0;
			cgroup_opt++;

			cgroup_taskfile = uwsgi_concat3(usl->value, "/", uslo->value);
			cgroup = fopen(cgroup_taskfile, "w");
			if (cgroup) {
				if (fprintf(cgroup, "%s\n", cgroup_opt) < 0) {
					uwsgi_log("could not set cgroup option %s to %s\n", uslo->value, cgroup_opt);
					exit(1);
				}
				fclose(cgroup);
				uwsgi_log("set %s to %s\n", cgroup_opt, cgroup_taskfile);
			}
			free(cgroup_taskfile);

			cgroup_opt[-1] = '=';

			uslo = uslo->next;
		}

		usl = usl->next;
	}

}
#endif

// drop privileges (as root)
void uwsgi_as_root() {


	if (!getuid()) {
		if (!uwsgi.master_as_root && !uwsgi.uidname) {
			uwsgi_log_initial("uWSGI running as root, you can use --uid/--gid/--chroot options\n");
		}

#ifdef UWSGI_CAP
		if (uwsgi.cap && uwsgi.cap_count > 0 && !uwsgi.reloads) {

			cap_value_t minimal_cap_values[] = { CAP_SYS_CHROOT, CAP_SETUID, CAP_SETGID, CAP_SETPCAP };

			cap_t caps = cap_init();

			if (!caps) {
				uwsgi_error("cap_init()");
				exit(1);
			}
			cap_clear(caps);

			cap_set_flag(caps, CAP_EFFECTIVE, 4, minimal_cap_values, CAP_SET);

			cap_set_flag(caps, CAP_PERMITTED, 4, minimal_cap_values, CAP_SET);
			cap_set_flag(caps, CAP_PERMITTED, uwsgi.cap_count, uwsgi.cap, CAP_SET);

			cap_set_flag(caps, CAP_INHERITABLE, uwsgi.cap_count, uwsgi.cap, CAP_SET);

			if (cap_set_proc(caps) < 0) {
				uwsgi_error("cap_set_proc()");
				exit(1);
			}
			cap_free(caps);

#ifdef __linux__
#ifdef SECBIT_KEEP_CAPS
			if (prctl(SECBIT_KEEP_CAPS, 1, 0, 0, 0) < 0) {
				uwsgi_error("prctl()");
				exit(1);
			}
#else
			if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
				uwsgi_error("prctl()");
				exit(1);
			}
#endif
#endif
		}
#endif

#if defined(__linux__) && !defined(OBSOLETE_LINUX_KERNEL)
		if (uwsgi.unshare && !uwsgi.reloads) {

			if (unshare(uwsgi.unshare)) {
				uwsgi_error("unshare()");
				exit(1);
			}
			else {
				uwsgi_log("[linux-namespace] applied unshare() mask: %d\n", uwsgi.unshare);
			}
		}
#endif


		if (uwsgi.chroot && !uwsgi.reloads) {
			if (!uwsgi.master_as_root)
				uwsgi_log("chroot() to %s\n", uwsgi.chroot);
			if (chroot(uwsgi.chroot)) {
				uwsgi_error("chroot()");
				exit(1);
			}
#ifdef __linux__
			if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG]) {
				uwsgi_log("*** Warning, on linux system you have to bind-mount the /proc fs in your chroot to get memory debug/report.\n");
			}
#endif
		}

		// now run the scripts needed by root
		struct uwsgi_string_list *usl = uwsgi.exec_as_root;
		while (usl) {
			uwsgi_log("running \"%s\" (as root)...\n", usl->value);
			int ret = uwsgi_run_command_and_wait(NULL, usl->value);
			if (ret != 0) {
				uwsgi_log("command \"%s\" exited with non-zero code: %d\n", usl->value, ret);
				exit(1);
			}
			usl = usl->next;
		}

		if (uwsgi.gidname) {
			struct group *ugroup = getgrnam(uwsgi.gidname);
			if (ugroup) {
				uwsgi.gid = ugroup->gr_gid;
			}
			else {
				uwsgi_log("group %s not found.\n", uwsgi.gidname);
				exit(1);
			}
		}
		if (uwsgi.uidname) {
			struct passwd *upasswd = getpwnam(uwsgi.uidname);
			if (upasswd) {
				uwsgi.uid = upasswd->pw_uid;
			}
			else {
				uwsgi_log("user %s not found.\n", uwsgi.uidname);
				exit(1);
			}
		}

		if (uwsgi.logfile_chown) {
			if (fchown(2, uwsgi.uid, uwsgi.gid)) {
				uwsgi_error("fchown()");
				exit(1);
			}
		}

		// fix ipcsem owner
		if (uwsgi.lock_ops.lock_init == uwsgi_lock_ipcsem_init) {
			struct uwsgi_lock_item *uli = uwsgi.registered_locks;

			while (uli) {
				union semun {
					int val;
					struct semid_ds *buf;
					ushort *array;
				} semu;

				struct semid_ds sds;
				memset(&sds, 0, sizeof(sds));
				semu.buf = &sds;
				int semid = 0;
				memcpy(&semid, uli->lock_ptr, sizeof(int));

				if (semctl(semid, 0, IPC_STAT, semu)) {
					uwsgi_error("semctl()");
					exit(1);
				}

				semu.buf->sem_perm.uid = uwsgi.uid;
				semu.buf->sem_perm.gid = uwsgi.gid;

				if (semctl(semid, 0, IPC_SET, semu)) {
					uwsgi_error("semctl()");
					exit(1);
				}
				uli = uli->next;
			}

		}

		// ok try to call some special hook before finally dropping privileges
		int i;
		for (i = 0; i < uwsgi.gp_cnt; i++) {
			if (uwsgi.gp[i]->before_privileges_drop) {
				uwsgi.gp[i]->before_privileges_drop();
			}
		}

		if (uwsgi.gid) {
			if (!uwsgi.master_as_root)
				uwsgi_log("setgid() to %d\n", uwsgi.gid);
			if (setgid(uwsgi.gid)) {
				uwsgi_error("setgid()");
				exit(1);
			}
			if (uwsgi.no_initgroups || !uwsgi.uid) {
				if (setgroups(0, NULL)) {
					uwsgi_error("setgroups()");
					exit(1);
				}
			}
			else {
				char *uidname = uwsgi.uidname;
				if (!uidname) {
					struct passwd *pw = getpwuid(uwsgi.uid);
					if (pw)
						uidname = pw->pw_name;

				}
				if (!uidname)
					uidname = uwsgi_num2str(uwsgi.uid);
				if (initgroups(uidname, uwsgi.gid)) {
					uwsgi_error("setgroups()");
					exit(1);
				}
			}
			int additional_groups = getgroups(0, NULL);
			gid_t *gids = uwsgi_calloc(sizeof(gid_t) * additional_groups);
			int i;
			if (getgroups(additional_groups, gids) > 0) {
				for (i = 0; i < additional_groups; i++) {
					if (gids[i] == uwsgi.gid)
						continue;
					struct group *gr = getgrgid(gids[i]);
					if (gr) {
						uwsgi_log("set additional group %d (%s)\n", gids[i], gr->gr_name);
					}
					else {
						uwsgi_log("set additional group %d\n", gids[i]);
					}
				}
			}
		}
		if (uwsgi.uid) {
			if (!uwsgi.master_as_root)
				uwsgi_log("setuid() to %d\n", uwsgi.uid);
			if (setuid(uwsgi.uid)) {
				uwsgi_error("setuid()");
				exit(1);
			}
		}

		if (!getuid()) {
			uwsgi_log_initial("*** WARNING: you are running uWSGI as root !!! (use the --uid flag) *** \n");
		}

#ifdef UWSGI_CAP

		if (uwsgi.cap && uwsgi.cap_count > 0 && !uwsgi.reloads) {

			cap_t caps = cap_init();

			if (!caps) {
				uwsgi_error("cap_init()");
				exit(1);
			}
			cap_clear(caps);

			cap_set_flag(caps, CAP_EFFECTIVE, uwsgi.cap_count, uwsgi.cap, CAP_SET);
			cap_set_flag(caps, CAP_PERMITTED, uwsgi.cap_count, uwsgi.cap, CAP_SET);
			cap_set_flag(caps, CAP_INHERITABLE, uwsgi.cap_count, uwsgi.cap, CAP_SET);

			if (cap_set_proc(caps) < 0) {
				uwsgi_error("cap_set_proc()");
				exit(1);
			}
			cap_free(caps);
		}
#endif

		// now run the scripts needed by the user
		usl = uwsgi.exec_as_user;
		while (usl) {
			uwsgi_log("running \"%s\" (as uid: %d gid: %d) ...\n", usl->value, (int) getuid(), (int) getgid());
			int ret = uwsgi_run_command_and_wait(NULL, usl->value);
			if (ret != 0) {
				uwsgi_log("command \"%s\" exited with non-zero code: %d\n", usl->value, ret);
				exit(1);
			}
			usl = usl->next;
		}

		// we could now patch the binary
		if (uwsgi.unprivileged_binary_patch) {
			uwsgi.argv[0] = uwsgi.unprivileged_binary_patch;
			execvp(uwsgi.unprivileged_binary_patch, uwsgi.argv);
			uwsgi_error("execvp()");
			exit(1);
		}

		if (uwsgi.unprivileged_binary_patch_arg) {
			uwsgi_exec_command_with_args(uwsgi.unprivileged_binary_patch_arg);
		}
	}
	else {
		if (uwsgi.chroot && !uwsgi.is_a_reload) {
			uwsgi_log("cannot chroot() as non-root user\n");
			exit(1);
		}
		if (uwsgi.gid && getgid() != uwsgi.gid) {
			uwsgi_log("cannot setgid() as non-root user\n");
			exit(1);
		}
		if (uwsgi.uid && getuid() != uwsgi.uid) {
			uwsgi_log("cannot setuid() as non-root user\n");
			exit(1);
		}
	}
}

// destroy a request
void uwsgi_destroy_request(struct wsgi_request *wsgi_req) {

	wsgi_req->socket->proto_close(wsgi_req);

#ifdef UWSGI_THREADING
	int foo;
	if (uwsgi.threads > 1) {
		// now the thread can die...
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &foo);
	}
#endif

	memset(wsgi_req, 0, sizeof(struct wsgi_request));


}

// finalize/close/free a request
void uwsgi_close_request(struct wsgi_request *wsgi_req) {

	int waitpid_status;
	int tmp_id;
	uint64_t tmp_rt, rss = 0, vsz = 0;

	wsgi_req->end_of_request = uwsgi_micros();

	tmp_rt = wsgi_req->end_of_request - wsgi_req->start_of_request;

	uwsgi.workers[uwsgi.mywid].running_time += tmp_rt;
	uwsgi.workers[uwsgi.mywid].avg_response_time = (uwsgi.workers[uwsgi.mywid].avg_response_time + tmp_rt) / 2;

	// get memory usage
	if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1 || uwsgi.force_get_memusage) {
		get_memusage(&rss, &vsz);
		uwsgi.workers[uwsgi.mywid].vsz_size = vsz;
		uwsgi.workers[uwsgi.mywid].rss_size = rss;
	}


	// close the connection with the webserver
	if (!wsgi_req->fd_closed || wsgi_req->body_as_file) {
		// NOTE, if we close the socket before receiving eventually sent data, socket layer will send a RST
		wsgi_req->socket->proto_close(wsgi_req);
	}
	uwsgi.workers[0].requests++;
	uwsgi.workers[uwsgi.mywid].requests++;
	uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].requests++;
	// this is used for MAX_REQUESTS
	uwsgi.workers[uwsgi.mywid].delta_requests++;

	// after_request hook
	if (uwsgi.p[wsgi_req->uh.modifier1]->after_request)
		uwsgi.p[wsgi_req->uh.modifier1]->after_request(wsgi_req);

#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1) {
		// now the thread can die...
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &tmp_id);
	}
#endif

	// leave harakiri mode
	if (uwsgi.workers[uwsgi.mywid].harakiri > 0) {
		set_harakiri(0);
	}

	// leave user harakiri mode
	if (uwsgi.workers[uwsgi.mywid].user_harakiri > 0) {
		set_user_harakiri(0);
	}

	// this is racy in multithread mode
	if (wsgi_req->response_size > 0) {
		uwsgi.workers[uwsgi.mywid].tx += wsgi_req->response_size;
	}
	if (wsgi_req->headers_size > 0) {
		uwsgi.workers[uwsgi.mywid].tx += wsgi_req->headers_size;
	}

	// defunct process reaper
	if (uwsgi.shared->options[UWSGI_OPTION_REAPER] == 1 || uwsgi.grunt) {
		while (waitpid(WAIT_ANY, &waitpid_status, WNOHANG) > 0);
	}

	// free logvars
	struct uwsgi_logvar *lv = wsgi_req->logvars;
	while (lv) {
		struct uwsgi_logvar *ptr = lv;
		lv = lv->next;
		free(ptr);
	}


	// reset request
	tmp_id = wsgi_req->async_id;
	memset(wsgi_req, 0, sizeof(struct wsgi_request));
	wsgi_req->async_id = tmp_id;

	if (uwsgi.shared->options[UWSGI_OPTION_MAX_REQUESTS] > 0 && uwsgi.workers[uwsgi.mywid].delta_requests >= uwsgi.shared->options[UWSGI_OPTION_MAX_REQUESTS]) {
		goodbye_cruel_world();
	}

	if (uwsgi.reload_on_as && (rlim_t) vsz >= uwsgi.reload_on_as) {
		goodbye_cruel_world();
	}

	if (uwsgi.reload_on_rss && (rlim_t) rss >= uwsgi.reload_on_rss) {
		goodbye_cruel_world();
	}


	// ready to accept request, if i am a vassal signal Emperor about my loyalty
	if (uwsgi.has_emperor && !uwsgi.loyal) {
		uwsgi_log("announcing my loyalty to the Emperor...\n");
		char byte = 17;
		if (write(uwsgi.emperor_fd, &byte, 1) != 1) {
			uwsgi_error("write()");
		}
		uwsgi.loyal = 1;
	}

#ifdef __linux__
#ifdef MADV_MERGEABLE
	// run the ksm mapper
	if (uwsgi.linux_ksm > 0 && (uwsgi.workers[uwsgi.mywid].requests % uwsgi.linux_ksm) == 0) {
		uwsgi_linux_ksm_map();
	}
#endif
#endif

}

#ifdef __linux__
#ifdef MADV_MERGEABLE

void uwsgi_linux_ksm_map(void) {

	int dirty = 0;
	size_t i;
	unsigned long long start = 0, end = 0;
	int errors = 0;
	int lines = 0;

	int fd = open("/proc/self/maps", O_RDONLY);
	if (fd < 0) {
		uwsgi_error_open("[uwsgi-KSM] /proc/self/maps");
		return;
	}

	// allocate memory if not available;
	if (uwsgi.ksm_mappings_current == NULL) {
		if (!uwsgi.ksm_buffer_size)
			uwsgi.ksm_buffer_size = 32768;
		uwsgi.ksm_mappings_current = uwsgi_malloc(uwsgi.ksm_buffer_size);
		uwsgi.ksm_mappings_current_size = 0;
	}
	if (uwsgi.ksm_mappings_last == NULL) {
		if (!uwsgi.ksm_buffer_size)
			uwsgi.ksm_buffer_size = 32768;
		uwsgi.ksm_mappings_last = uwsgi_malloc(uwsgi.ksm_buffer_size);
		uwsgi.ksm_mappings_last_size = 0;
	}

	uwsgi.ksm_mappings_current_size = read(fd, uwsgi.ksm_mappings_current, uwsgi.ksm_buffer_size);
	close(fd);
	if (uwsgi.ksm_mappings_current_size <= 0) {
		uwsgi_log("[uwsgi-KSM] unable to read /proc/self/maps data\n");
		return;
	}

	// we now have areas
	if (uwsgi.ksm_mappings_last_size == 0 || uwsgi.ksm_mappings_current_size == 0 || uwsgi.ksm_mappings_current_size != uwsgi.ksm_mappings_last_size) {
		dirty = 1;
	}
	else {
		if (memcmp(uwsgi.ksm_mappings_current, uwsgi.ksm_mappings_last, uwsgi.ksm_mappings_current_size) != 0) {
			dirty = 1;
		}
	}

	// it is dirty, swap addresses and parse it
	if (dirty) {
		char *tmp = uwsgi.ksm_mappings_last;
		uwsgi.ksm_mappings_last = uwsgi.ksm_mappings_current;
		uwsgi.ksm_mappings_current = tmp;

		size_t tmp_size = uwsgi.ksm_mappings_last_size;
		uwsgi.ksm_mappings_last_size = uwsgi.ksm_mappings_current_size;
		uwsgi.ksm_mappings_current_size = tmp_size;

		// scan each line and call madvise on it
		char *ptr = uwsgi.ksm_mappings_last;
		for (i = 0; i < uwsgi.ksm_mappings_last_size; i++) {
			if (uwsgi.ksm_mappings_last[i] == '\n') {
				lines++;
				uwsgi.ksm_mappings_last[i] = 0;
				if (sscanf(ptr, "%llx-%llx %*s", &start, &end) == 2) {
					if (madvise((void *) (long) start, (size_t) (end - start), MADV_MERGEABLE)) {
						errors++;
					}
				}
				uwsgi.ksm_mappings_last[i] = '\n';
				ptr = uwsgi.ksm_mappings_last + i + 1;
			}
		}

		if (errors >= lines) {
			uwsgi_error("[uwsgi-KSM] unable to share pages");
		}
	}
}
#endif
#endif

#ifdef __linux__
long uwsgi_num_from_file(char *filename) {
	char buf[16];
	ssize_t len;
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_error_open(filename);
		return -1L;
	}
	len = read(fd, buf, sizeof(buf));
	if (len == 0) {
		uwsgi_log("read error %s\n", filename);
		close(fd);
		return -1L;
	}
	close(fd);
	return strtol(buf, (char **) NULL, 10);
}
#endif

// setup for a new request
void wsgi_req_setup(struct wsgi_request *wsgi_req, int async_id, struct uwsgi_socket *uwsgi_sock) {

	wsgi_req->poll.events = POLLIN;

	wsgi_req->app_id = uwsgi.default_app;

	wsgi_req->async_id = async_id;
	wsgi_req->sendfile_fd = -1;

	wsgi_req->hvec = uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].hvec;
	wsgi_req->buffer = uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].buffer;

	if (uwsgi.post_buffering > 0) {
		wsgi_req->post_buffering_buf = uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].post_buf;
	}

	if (uwsgi_sock) {
		wsgi_req->socket = uwsgi_sock;
	}

	uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 0;
	uwsgi.workers[uwsgi.mywid].busy = 0;

	// now check for suspend request
	if (uwsgi.workers[uwsgi.mywid].suspended == 1) {
		uwsgi_log_verbose("*** worker %d suspended ***\n", uwsgi.mywid);
cycle:
		// wait for some signal (normally SIGTSTP) or 10 seconds (as fallback)
		(void) poll(NULL, 0, 10 * 1000);
		if (uwsgi.workers[uwsgi.mywid].suspended == 1)
			goto cycle;
		uwsgi_log_verbose("*** worker %d resumed ***\n", uwsgi.mywid);
	}
}

#ifdef UWSGI_ASYNC
int wsgi_req_async_recv(struct wsgi_request *wsgi_req) {

	uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 1;
	uwsgi.workers[uwsgi.mywid].busy = 1;

	wsgi_req->start_of_request = uwsgi_micros();
	wsgi_req->start_of_request_in_sec = wsgi_req->start_of_request / 1000000;

	if (!wsgi_req->do_not_add_to_async_queue) {
		if (event_queue_add_fd_read(uwsgi.async_queue, wsgi_req->poll.fd) < 0)
			return -1;

		async_add_timeout(wsgi_req, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		uwsgi.async_proto_fd_table[wsgi_req->poll.fd] = wsgi_req;
	}



	// enter harakiri mode
	if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
		set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
	}

	return 0;
}
#endif

// receive a new request
int wsgi_req_recv(struct wsgi_request *wsgi_req) {

	uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 1;
	uwsgi.workers[uwsgi.mywid].busy = 1;

	wsgi_req->start_of_request = uwsgi_micros();
	wsgi_req->start_of_request_in_sec = wsgi_req->start_of_request / 1000000;

	// edge triggered sockets get the whole request during accept() phase
	if (!wsgi_req->socket->edge_trigger) {
		if (!uwsgi_parse_packet(wsgi_req, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT])) {
			return -1;
		}
	}

	// enter harakiri mode
	if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
		set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
	}

#ifdef UWSGI_ROUTING
	if (uwsgi_apply_routes(wsgi_req) == UWSGI_ROUTE_BREAK)
		return 0;
#endif

	wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);

	return 0;
}


// accept a new request
int wsgi_req_simple_accept(struct wsgi_request *wsgi_req, int fd) {

	wsgi_req->poll.fd = wsgi_req->socket->proto_accept(wsgi_req, fd);

	if (wsgi_req->poll.fd < 0) {
		return -1;
	}

	// set close on exec (if not a new socket)
	if (!wsgi_req->socket->edge_trigger && uwsgi.close_on_exec) {
		fcntl(wsgi_req->poll.fd, F_SETFD, FD_CLOEXEC);
	}

	return 0;
}

// send heartbeat to the emperor
void uwsgi_heartbeat() {

	if (!uwsgi.has_emperor)
		return;

	time_t now = uwsgi_now();
	if (uwsgi.next_heartbeat < now) {
		char byte = 26;
		if (write(uwsgi.emperor_fd, &byte, 1) != 1) {
			uwsgi_error("write()");
		}
		uwsgi.next_heartbeat = now + uwsgi.heartbeat;
	}

}

// accept a request
int wsgi_req_accept(int queue, struct wsgi_request *wsgi_req) {

	int ret;
	int interesting_fd = -1;
	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
	int timeout = -1;


	thunder_lock;

	// heartbeat
	// in multithreaded mode we are now locked
	if (uwsgi.has_emperor && uwsgi.heartbeat) {
		timeout = uwsgi.heartbeat;
	}

	// need edge trigger ?
	if (uwsgi.is_et) {
		while (uwsgi_sock) {
			if (uwsgi_sock->retry && uwsgi_sock->retry[wsgi_req->async_id]) {
				timeout = 0;
				break;
			}
			uwsgi_sock = uwsgi_sock->next;
		}
		// reset pointer
		uwsgi_sock = uwsgi.sockets;
	}

	ret = event_queue_wait(queue, timeout, &interesting_fd);
	if (ret < 0) {
		thunder_unlock;
		return -1;
	}

	// check for heartbeat
	if (timeout > 0) {
		uwsgi_heartbeat();
		// no need to continue if timed-out
		if (ret == 0)
			return -1;
	}

#ifdef UWSGI_THREADING
	// kill the thread after the request completion
	if (uwsgi.threads > 1)
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ret);
#endif

	if (uwsgi.signal_socket > -1 && (interesting_fd == uwsgi.signal_socket || interesting_fd == uwsgi.my_signal_socket)) {

		thunder_unlock;

		uwsgi_receive_signal(interesting_fd, "worker", uwsgi.mywid);

#ifdef UWSGI_THREADING
		if (uwsgi.threads > 1)
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ret);
#endif
		return -1;
	}


	while (uwsgi_sock) {
		if (interesting_fd == uwsgi_sock->fd || (uwsgi_sock->retry && uwsgi_sock->retry[wsgi_req->async_id]) || (uwsgi_sock->fd_threads && interesting_fd == uwsgi_sock->fd_threads[wsgi_req->async_id])) {
			wsgi_req->socket = uwsgi_sock;
			wsgi_req->poll.fd = wsgi_req->socket->proto_accept(wsgi_req, interesting_fd);
			thunder_unlock;
			if (wsgi_req->poll.fd < 0) {
#ifdef UWSGI_THREADING
				if (uwsgi.threads > 1)
					pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ret);
#endif
				return -1;
			}

			if (!uwsgi_sock->edge_trigger) {
// in Linux, new sockets do not inherit attributes
#ifndef __linux__
				/* re-set blocking socket */
				int arg = uwsgi_sock->arg;
				arg &= (~O_NONBLOCK);
				if (fcntl(wsgi_req->poll.fd, F_SETFL, arg) < 0) {
					uwsgi_error("fcntl()");
#ifdef UWSGI_THREADING
					if (uwsgi.threads > 1)
						pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ret);
#endif
					return -1;
				}

#endif

				if (uwsgi.close_on_exec) {
					fcntl(wsgi_req->poll.fd, F_SETFD, FD_CLOEXEC);
				}

			}
			return 0;
		}

		uwsgi_sock = uwsgi_sock->next;
	}

	thunder_unlock;
#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1)
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &ret);
#endif
	return -1;
}

// fix related options
void sanitize_args() {

	if (uwsgi.async > 1) {
		uwsgi.cores = uwsgi.async;
	}

	if (uwsgi.threads > 1) {
		uwsgi.has_threads = 1;
		uwsgi.cores = uwsgi.threads;
	}

	if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
		if (!uwsgi.post_buffering) {
			uwsgi_log(" *** WARNING: you have enabled harakiri without post buffering. Slow upload could be rejected on post-unbuffered webservers *** \n");
		}
	}

#ifdef UWSGI_HTTP
	if (uwsgi.http && !uwsgi.http_only) {
		uwsgi.vacuum = 1;
	}
#endif

	if (uwsgi.write_errors_exception_only) {
		uwsgi.ignore_sigpipe = 1;
		uwsgi.ignore_write_errors = 1;
	}


	if (uwsgi.cheaper_count > 0 && uwsgi.cheaper_count >= uwsgi.numproc) {
		uwsgi_log("invalid cheaper value: must be lower than processes\n");
		exit(1);
	}

	if (uwsgi.auto_snapshot > 0 && uwsgi.auto_snapshot > uwsgi.numproc) {
		uwsgi_log("invalid auto-snapshot value: must be <= than processes\n");
		exit(1);
	}
}

// translate a OS env to a uWSGI option
void env_to_arg(char *src, char *dst) {
	int i;
	int val = 0;

	for (i = 0; i < (int) strlen(src); i++) {
		if (src[i] == '=') {
			val = 1;
		}
		if (val) {
			dst[i] = src[i];
		}
		else {
			dst[i] = tolower((int) src[i]);
			if (dst[i] == '_') {
				dst[i] = '-';
			}
		}
	}

	dst[strlen(src)] = 0;
}

// lower a string
char *uwsgi_lower(char *str, size_t size) {
	size_t i;
	for (i = 0; i < size; i++) {
		str[i] = tolower((int) str[i]);
	}

	return str;
}

// parse OS envs
void parse_sys_envs(char **envs) {

	char **uenvs = envs;
	char *earg, *eq_pos;

	while (*uenvs) {
		if (!strncmp(*uenvs, "UWSGI_", 6) && strncmp(*uenvs, "UWSGI_RELOADS=", 14) && strncmp(*uenvs, "UWSGI_ORIGINAL_PROC_NAME=", 25)) {
			earg = uwsgi_malloc(strlen(*uenvs + 6) + 1);
			env_to_arg(*uenvs + 6, earg);
			eq_pos = strchr(earg, '=');
			if (!eq_pos) {
				break;
			}
			eq_pos[0] = 0;

			add_exported_option(earg, eq_pos + 1, 0);
		}
		uenvs++;
	}

}

// check if a string is contained in another one
char *uwsgi_str_contains(char *str, int slen, char what) {

	int i;
	for (i = 0; i < slen; i++) {
		if (str[i] == what) {
			return str + i;
		}
	}
	return NULL;
}

// fast compare 2 sized strings
int uwsgi_strncmp(char *src, int slen, char *dst, int dlen) {

	if (slen != dlen)
		return 1;

	return memcmp(src, dst, dlen);

}

// fast sized check of initial part of a string
int uwsgi_starts_with(char *src, int slen, char *dst, int dlen) {

	if (slen < dlen)
		return -1;

	return memcmp(src, dst, dlen);
}

// unsized check
int uwsgi_startswith(char *src, char *what, int wlen) {

	int i;

	for (i = 0; i < wlen; i++) {
		if (src[i] != what[i])
			return -1;
	}

	return 0;
}

// concatenate strings
char *uwsgi_concatn(int c, ...) {

	va_list s;
	char *item;
	int j = c;
	char *buf;
	size_t len = 1;
	size_t tlen = 1;

	va_start(s, c);
	while (j > 0) {
		item = va_arg(s, char *);
		if (item == NULL) {
			break;
		}
		len += va_arg(s, int);
		j--;
	}
	va_end(s);


	buf = uwsgi_malloc(len);
	memset(buf, 0, len);

	j = c;

	len = 0;

	va_start(s, c);
	while (j > 0) {
		item = va_arg(s, char *);
		if (item == NULL) {
			break;
		}
		tlen = va_arg(s, int);
		memcpy(buf + len, item, tlen);
		len += tlen;
		j--;
	}
	va_end(s);


	return buf;

}

char *uwsgi_concat2(char *one, char *two) {

	char *buf;
	size_t len = strlen(one) + strlen(two) + 1;


	buf = uwsgi_malloc(len);
	buf[len - 1] = 0;

	memcpy(buf, one, strlen(one));
	memcpy(buf + strlen(one), two, strlen(two));

	return buf;

}

char *uwsgi_concat4(char *one, char *two, char *three, char *four) {

	char *buf;
	size_t len = strlen(one) + strlen(two) + strlen(three) + strlen(four) + 1;


	buf = uwsgi_malloc(len);
	buf[len - 1] = 0;

	memcpy(buf, one, strlen(one));
	memcpy(buf + strlen(one), two, strlen(two));
	memcpy(buf + strlen(one) + strlen(two), three, strlen(three));
	memcpy(buf + strlen(one) + strlen(two) + strlen(three), four, strlen(four));

	return buf;

}


char *uwsgi_concat3(char *one, char *two, char *three) {

	char *buf;
	size_t len = strlen(one) + strlen(two) + strlen(three) + 1;


	buf = uwsgi_malloc(len);
	buf[len - 1] = 0;

	memcpy(buf, one, strlen(one));
	memcpy(buf + strlen(one), two, strlen(two));
	memcpy(buf + strlen(one) + strlen(two), three, strlen(three));

	return buf;

}

char *uwsgi_concat2n(char *one, int s1, char *two, int s2) {

	char *buf;
	size_t len = s1 + s2 + 1;


	buf = uwsgi_malloc(len);
	buf[len - 1] = 0;

	memcpy(buf, one, s1);
	memcpy(buf + s1, two, s2);

	return buf;

}

char *uwsgi_concat2nn(char *one, int s1, char *two, int s2, int *len) {

	char *buf;
	*len = s1 + s2 + 1;


	buf = uwsgi_malloc(*len);
	buf[*len - 1] = 0;

	memcpy(buf, one, s1);
	memcpy(buf + s1, two, s2);

	return buf;

}


char *uwsgi_concat3n(char *one, int s1, char *two, int s2, char *three, int s3) {

	char *buf;
	size_t len = s1 + s2 + s3 + 1;


	buf = uwsgi_malloc(len);
	buf[len - 1] = 0;

	memcpy(buf, one, s1);
	memcpy(buf + s1, two, s2);
	memcpy(buf + s1 + s2, three, s3);

	return buf;

}

char *uwsgi_concat4n(char *one, int s1, char *two, int s2, char *three, int s3, char *four, int s4) {

	char *buf;
	size_t len = s1 + s2 + s3 + s4 + 1;


	buf = uwsgi_malloc(len);
	buf[len - 1] = 0;

	memcpy(buf, one, s1);
	memcpy(buf + s1, two, s2);
	memcpy(buf + s1 + s2, three, s3);
	memcpy(buf + s1 + s2 + s3, four, s4);

	return buf;

}



// concat unsized strings
char *uwsgi_concat(int c, ...) {

	va_list s;
	char *item;
	size_t len = 1;
	int j = c;
	char *buf;

	va_start(s, c);
	while (j > 0) {
		item = va_arg(s, char *);
		if (item == NULL) {
			break;
		}
		len += (int) strlen(item);
		j--;
	}
	va_end(s);


	buf = uwsgi_malloc(len);
	memset(buf, 0, len);

	j = c;

	len = 0;

	va_start(s, c);
	while (j > 0) {
		item = va_arg(s, char *);
		if (item == NULL) {
			break;
		}
		memcpy(buf + len, item, strlen(item));
		len += strlen(item);
		j--;
	}
	va_end(s);


	return buf;

}

char *uwsgi_strncopy(char *s, int len) {

	char *buf;

	buf = uwsgi_malloc(len + 1);
	buf[len] = 0;

	memcpy(buf, s, len);

	return buf;

}


// get the application id
int uwsgi_get_app_id(char *app_name, int app_name_len, int modifier1) {

	int i;
	struct stat st;
	int found;

	for (i = 0; i < uwsgi_apps_cnt; i++) {
		// reset check
		found = 0;
#ifdef UWSGI_DEBUG
		uwsgi_log("searching for %.*s in %.*s %p\n", app_name_len, app_name, uwsgi_apps[i].mountpoint_len, uwsgi_apps[i].mountpoint, uwsgi_apps[i].callable);
#endif
		if (!uwsgi_apps[i].callable) {
			continue;
		}

		if (!uwsgi_strncmp(uwsgi_apps[i].mountpoint, uwsgi_apps[i].mountpoint_len, app_name, app_name_len)) {
			found = 1;
		}

		if (found) {
			if (uwsgi_apps[i].touch_reload[0]) {
				if (!stat(uwsgi_apps[i].touch_reload, &st)) {
					if (st.st_mtime != uwsgi_apps[i].touch_reload_mtime) {
						// serve the new request and reload
						uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
						if (uwsgi.threads > 1) {
							uwsgi.workers[uwsgi.mywid].destroy = 1;
						}

#ifdef UWSGI_DEBUG
						uwsgi_log("mtime %d %d\n", st.st_mtime, uwsgi_apps[i].touch_reload_mtime);
#endif
					}
				}
			}
			if (modifier1 == -1)
				return i;
			if (modifier1 == uwsgi_apps[i].modifier1)
				return i;
		}
	}

	return -1;
}

int uwsgi_count_options(struct uwsgi_option *uopt) {

	struct uwsgi_option *aopt;
	int count = 0;

	while ((aopt = uopt)) {
		if (!aopt->name)
			break;
		count++;
		uopt++;
	}

	return count;
}

int uwsgi_read_whole_body_in_mem(struct wsgi_request *wsgi_req, char *buf) {

	size_t post_remains = wsgi_req->post_cl;
	int ret;
	ssize_t len;
	char *ptr = buf;

	while (post_remains > 0) {
		if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
			inc_harakiri(uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		}

		ret = uwsgi_waitfd(wsgi_req->poll.fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (ret < 0) {
			return 0;
		}

		if (!ret) {
			uwsgi_log("buffering POST data to memory timed-out !!! (Content-Length: %llu received: %llu)\n", (unsigned long long) wsgi_req->post_cl, (unsigned long long) wsgi_req->post_cl - post_remains);
			return 0;
		}

		if (wsgi_req->socket->proto_read_body) {
			len = wsgi_req->socket->proto_read_body(wsgi_req, ptr, post_remains);
		}
		else {
			len = read(wsgi_req->poll.fd, ptr, post_remains);
		}

		if (len < 0) {
			uwsgi_error("read()");
			return 0;
		}

		if (len == 0) {
			uwsgi_log("client did not send the whole body: %s (Content-Length: %llu received: %llu)\n", strerror(errno), (unsigned long long) wsgi_req->post_cl, (unsigned long long) wsgi_req->post_cl - post_remains);
			return 0;
		}

		ptr += len;
		post_remains -= len;
	}

	return 1;

}

int uwsgi_read_whole_body(struct wsgi_request *wsgi_req, char *buf, size_t len) {

	size_t post_remains = wsgi_req->post_cl;
	ssize_t post_chunk;
	int ret, i;
	int upload_progress_fd = -1;
	char *upload_progress_filename = NULL;
	const char *x_progress_id = "X-Progress-ID=";
	char *xpi_ptr = (char *) x_progress_id;

	wsgi_req->async_post = tmpfile();
	if (!wsgi_req->async_post) {
		uwsgi_error("tmpfile()");
		return 0;
	}

	if (uwsgi.upload_progress) {
		// first check for X-Progress-ID size
		// separator + 'X-Progress-ID' + '=' + uuid     
		if (wsgi_req->uri_len > 51) {
			for (i = 0; i < wsgi_req->uri_len; i++) {
				if (wsgi_req->uri[i] == xpi_ptr[0]) {
					if (xpi_ptr[0] == '=') {
						if (wsgi_req->uri + i + 36 <= wsgi_req->uri + wsgi_req->uri_len) {
							upload_progress_filename = wsgi_req->uri + i + 1;
						}
						break;
					}
					xpi_ptr++;
				}
				else {
					xpi_ptr = (char *) x_progress_id;
				}
			}

			// now check for valid uuid (from spec available at http://en.wikipedia.org/wiki/Universally_unique_identifier)
			if (upload_progress_filename) {

				uwsgi_log("upload progress uuid = %.*s\n", 36, upload_progress_filename);
				if (!check_hex(upload_progress_filename, 8))
					goto cycle;
				if (upload_progress_filename[8] != '-')
					goto cycle;

				if (!check_hex(upload_progress_filename + 9, 4))
					goto cycle;
				if (upload_progress_filename[13] != '-')
					goto cycle;

				if (!check_hex(upload_progress_filename + 14, 4))
					goto cycle;
				if (upload_progress_filename[18] != '-')
					goto cycle;

				if (!check_hex(upload_progress_filename + 19, 4))
					goto cycle;
				if (upload_progress_filename[23] != '-')
					goto cycle;

				if (!check_hex(upload_progress_filename + 24, 12))
					goto cycle;

				upload_progress_filename = uwsgi_concat4n(uwsgi.upload_progress, strlen(uwsgi.upload_progress), "/", 1, upload_progress_filename, 36, ".js", 3);
				// here we use O_EXCL to avoid eventual application bug in uuid generation/using
				upload_progress_fd = open(upload_progress_filename, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP);
				if (upload_progress_fd < 0) {
					uwsgi_error_open(upload_progress_filename);
					free(upload_progress_filename);
				}
			}
		}
	}

cycle:
	if (upload_progress_filename && upload_progress_fd == -1) {
		uwsgi_log("invalid X-Progress-ID value: must be a UUID\n");
	}
	// manage buffered data and upload progress
	while (post_remains > 0) {

		if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
			inc_harakiri(uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		}

		ret = uwsgi_waitfd(wsgi_req->poll.fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (ret < 0) {
			return 0;
		}

		if (!ret) {
			uwsgi_log("buffering POST data to disk timed-out !!! (Content-Length: %llu received: %llu)\n", (unsigned long long) wsgi_req->post_cl, (unsigned long long) wsgi_req->post_cl - post_remains);
			goto end;
		}

		if (post_remains > len) {
			if (wsgi_req->socket->proto_read_body) {
				post_chunk = wsgi_req->socket->proto_read_body(wsgi_req, buf, len);
			}
			else {
				post_chunk = read(wsgi_req->poll.fd, buf, len);
			}
		}
		else {
			if (wsgi_req->socket->proto_read_body) {
				post_chunk = wsgi_req->socket->proto_read_body(wsgi_req, buf, len);
			}
			else {
				post_chunk = read(wsgi_req->poll.fd, buf, post_remains);
			}
		}

		if (post_chunk < 0) {
			uwsgi_error("read()");
			goto end;
		}

		if (post_chunk == 0) {
			uwsgi_log("client did not send the whole body: %s (Content-Length: %llu received: %llu)\n", strerror(errno), (unsigned long long) wsgi_req->post_cl, (unsigned long long) wsgi_req->post_cl - post_remains);
			goto end;
		}

		if (fwrite(buf, post_chunk, 1, wsgi_req->async_post) != 1) {
			uwsgi_error("fwrite()");
			goto end;
		}
		if (upload_progress_fd > -1) {
			//write json data to the upload progress file
			if (lseek(upload_progress_fd, 0, SEEK_SET)) {
				uwsgi_error("lseek()");
				goto end;
			}

			// reuse buf for json buffer
			ret = snprintf(buf, len, "{ \"state\" : \"uploading\", \"received\" : %d, \"size\" : %d }\r\n", (int) (wsgi_req->post_cl - post_remains), (int) wsgi_req->post_cl);
			if (ret < 0) {
				uwsgi_log("unable to write JSON data in upload progress file %s\n", upload_progress_filename);
				goto end;
			}
			if (write(upload_progress_fd, buf, ret) < 0) {
				uwsgi_error("write()");
				goto end;
			}

			if (fsync(upload_progress_fd)) {
				uwsgi_error("fsync()");
			}
		}
		post_remains -= post_chunk;
	}
	rewind(wsgi_req->async_post);

	if (upload_progress_fd > -1) {
		close(upload_progress_fd);
		if (unlink(upload_progress_filename)) {
			uwsgi_error("unlink()");
		}
		free(upload_progress_filename);
	}

	return 1;

end:
	if (upload_progress_fd > -1) {
		close(upload_progress_fd);
		if (unlink(upload_progress_filename)) {
			uwsgi_error("unlink()");
		}
		free(upload_progress_filename);
	}
	return 0;
}

struct uwsgi_option *uwsgi_opt_get(char *name) {
	struct uwsgi_option *op = uwsgi.options;

	while (op->name) {
		if (!strcmp(name, op->name)) {
			return op;
		}
		op++;
	}

	return NULL;
}

char *uwsgi_substitute(char *src, char *what, char *with) {

	int count = 0;
	if (!with)
		return src;

	size_t len = strlen(src);
	size_t wlen = strlen(what);
	size_t with_len = strlen(with);

	char *p = strstr(src, what);
	if (!p) {
		return src;
	}

	while (p) {
		count++;
		p = strstr(p + wlen, what);
	}

	len += (count * with_len) + 1;

	char *dst = uwsgi_calloc(len);
	char *ptr = src;

	p = strstr(ptr, what);
	while (p) {
		strncat(dst, ptr, (p - ptr));
		strncat(dst, with, with_len);
		ptr = p + wlen;
		p = strstr(ptr, what);
	}

	strncat(dst, ptr, strlen(ptr));

	return dst;
}

int uwsgi_is_file(char *filename) {
	struct stat st;
	if (stat(filename, &st)) {
		return 0;
	}
	if (S_ISREG(st.st_mode))
		return 1;
	return 0;
}

int uwsgi_is_dir(char *filename) {
	struct stat st;
	if (stat(filename, &st)) {
		return 0;
	}
	if (S_ISDIR(st.st_mode))
		return 1;
	return 0;
}

int uwsgi_is_link(char *filename) {
	struct stat st;
	if (lstat(filename, &st)) {
		return 0;
	}
	if (S_ISLNK(st.st_mode))
		return 1;
	return 0;
}


int uwsgi_logic_opt_if_opt(char *key, char *value) {

	// check for env-value syntax
	char *equal = strchr(uwsgi.logic_opt_data, '=');
	if (equal)
		*equal = 0;

	char *p = uwsgi_get_exported_opt(uwsgi.logic_opt_data);
	if (equal)
		*equal = '=';

	if (p) {
		if (equal) {
			if (strcmp(equal + 1, p))
				return 0;
		}
		add_exported_option(key, uwsgi_substitute(value, "%(_)", p), 0);
		return 1;
	}

	return 0;
}


int uwsgi_logic_opt_if_not_opt(char *key, char *value) {

	// check for env-value syntax
	char *equal = strchr(uwsgi.logic_opt_data, '=');
	if (equal)
		*equal = 0;

	char *p = uwsgi_get_exported_opt(uwsgi.logic_opt_data);
	if (equal)
		*equal = '=';

	if (p) {
		if (equal) {
			if (!strcmp(equal + 1, p))
				return 0;
		}
		else {
			return 0;
		}
	}

	add_exported_option(key, uwsgi_substitute(value, "%(_)", p), 0);
	return 1;
}



int uwsgi_logic_opt_if_env(char *key, char *value) {

	// check for env-value syntax
	char *equal = strchr(uwsgi.logic_opt_data, '=');
	if (equal)
		*equal = 0;

	char *p = getenv(uwsgi.logic_opt_data);
	if (equal)
		*equal = '=';

	if (p) {
		if (equal) {
			if (strcmp(equal + 1, p))
				return 0;
		}
		add_exported_option(key, uwsgi_substitute(value, "%(_)", p), 0);
		return 1;
	}

	return 0;
}

int uwsgi_logic_opt_if_not_env(char *key, char *value) {

	// check for env-value syntax
	char *equal = strchr(uwsgi.logic_opt_data, '=');
	if (equal)
		*equal = 0;

	char *p = getenv(uwsgi.logic_opt_data);
	if (equal)
		*equal = '=';

	if (p) {
		if (equal) {
			if (!strcmp(equal + 1, p))
				return 0;
		}
		else {
			return 0;
		}
	}

	add_exported_option(key, uwsgi_substitute(value, "%(_)", p), 0);
	return 1;
}

int uwsgi_logic_opt_if_reload(char *key, char *value) {
	if (uwsgi.is_a_reload) {
		add_exported_option(key, value, 0);
		return 1;
	}
	return 0;
}

int uwsgi_logic_opt_if_not_reload(char *key, char *value) {
	if (!uwsgi.is_a_reload) {
		add_exported_option(key, value, 0);
		return 1;
	}
	return 0;
}

int uwsgi_logic_opt_if_file(char *key, char *value) {

	if (uwsgi_is_file(uwsgi.logic_opt_data)) {
		add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
		return 1;
	}

	return 0;
}

int uwsgi_logic_opt_if_not_file(char *key, char *value) {

	if (!uwsgi_is_file(uwsgi.logic_opt_data)) {
		add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
		return 1;
	}

	return 0;
}

int uwsgi_logic_opt_if_dir(char *key, char *value) {

	if (uwsgi_is_dir(uwsgi.logic_opt_data)) {
		add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
		return 1;
	}

	return 0;
}

int uwsgi_logic_opt_if_not_dir(char *key, char *value) {

	if (!uwsgi_is_dir(uwsgi.logic_opt_data)) {
		add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
		return 1;
	}

	return 0;
}


int uwsgi_logic_opt_if_exists(char *key, char *value) {

	if (uwsgi_file_exists(uwsgi.logic_opt_data)) {
		add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
		return 1;
	}

	return 0;
}

int uwsgi_logic_opt_if_not_exists(char *key, char *value) {

	if (!uwsgi_file_exists(uwsgi.logic_opt_data)) {
		add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
		return 1;
	}

	return 0;
}


int uwsgi_logic_opt_for(char *key, char *value) {

	char *p = strtok(uwsgi.logic_opt_data, " ");
	while (p) {
		add_exported_option(key, uwsgi_substitute(value, "%(_)", p), 0);
		p = strtok(NULL, " ");
	}

	return 1;
}

void add_exported_option(char *key, char *value, int configured) {

	struct uwsgi_string_list *blacklist = uwsgi.blacklist;
	struct uwsgi_string_list *whitelist = uwsgi.whitelist;

	while (blacklist) {
		if (!strcmp(key, blacklist->value)) {
			uwsgi_log("uWSGI error: forbidden option \"%s\"\n", key);
			exit(1);
		}
		blacklist = blacklist->next;
	}

	if (whitelist) {
		int allowed = 0;
		while (whitelist) {
			if (!strcmp(key, whitelist->value)) {
				allowed = 1;
				break;
			}
			whitelist = whitelist->next;
		}
		if (!allowed) {
			uwsgi_log("uWSGI error: forbidden option \"%s\"\n", key);
			exit(1);
		}
	}

	if (uwsgi.logic_opt_running)
		goto add;

	if (!strcmp(key, "end") || !strcmp(key, "endfor") || !strcmp(key, "endif")) {
		if (uwsgi.logic_opt_data) {
			free(uwsgi.logic_opt_data);
		}
		uwsgi.logic_opt = NULL;
		uwsgi.logic_opt_arg = NULL;
		uwsgi.logic_opt_cycles = 0;
		uwsgi.logic_opt_data = NULL;
	}

	if (uwsgi.logic_opt) {
		if (uwsgi.logic_opt_data) {
			free(uwsgi.logic_opt_data);
		}
		uwsgi.logic_opt_data = uwsgi_str(uwsgi.logic_opt_arg);
		uwsgi.logic_opt_cycles++;
		uwsgi.logic_opt_running = 1;
		uwsgi.logic_opt(key, value);
		uwsgi.logic_opt_running = 0;
		return;
	}

add:

	if (!uwsgi.exported_opts) {
		uwsgi.exported_opts = uwsgi_malloc(sizeof(struct uwsgi_opt *));
	}
	else {
		uwsgi.exported_opts = realloc(uwsgi.exported_opts, sizeof(struct uwsgi_opt *) * (uwsgi.exported_opts_cnt + 1));
		if (!uwsgi.exported_opts) {
			uwsgi_error("realloc()");
			exit(1);
		}
	}

	int id = uwsgi.exported_opts_cnt;
	uwsgi.exported_opts[id] = uwsgi_malloc(sizeof(struct uwsgi_opt));
	uwsgi.exported_opts[id]->key = key;
	uwsgi.exported_opts[id]->value = value;
	uwsgi.exported_opts[id]->configured = configured;
	uwsgi.exported_opts_cnt++;
	uwsgi.dirty_config = 1;

	struct uwsgi_option *op = uwsgi_opt_get(key);
	if (op) {
		// requires master ?
		if (op->flags & UWSGI_OPT_MASTER) {
			uwsgi.master_process = 1;
		}
		// requires log_master ?
		if (op->flags & UWSGI_OPT_LOG_MASTER) {
			uwsgi.master_process = 1;
			uwsgi.log_master = 1;
		}
		// requires threads ?
		if (op->flags & UWSGI_OPT_THREADS) {
			uwsgi.has_threads = 1;
		}
		// requires cheaper mode ?
		if (op->flags & UWSGI_OPT_CHEAPER) {
			uwsgi.cheaper = 1;
		}
		// requires virtualhosting ?
		if (op->flags & UWSGI_OPT_VHOST) {
			uwsgi.vhost = 1;
		}
		// requires memusage ?
		if (op->flags & UWSGI_OPT_MEMORY) {
			uwsgi.force_get_memusage = 1;
		}
		// requires auto procname ?
		if (op->flags & UWSGI_OPT_PROCNAME) {
			uwsgi.auto_procname = 1;
		}
		// requires lazy ?
		if (op->flags & UWSGI_OPT_LAZY) {
			uwsgi.lazy = 1;
		}
		// requires no_initial ?
		if (op->flags & UWSGI_OPT_NO_INITIAL) {
			uwsgi.no_initial_output = 1;
		}
		// requires no_server ?
		if (op->flags & UWSGI_OPT_NO_SERVER) {
			uwsgi.no_server = 1;
		}
		// requires cluster ?
		if (op->flags & UWSGI_OPT_CLUSTER) {
			uwsgi.cluster = value;
		}
		// requires post_buffering ?
		if (op->flags & UWSGI_OPT_POST_BUFFERING) {
			if (!uwsgi.post_buffering)
				uwsgi.post_buffering = 4096;
		}
		// requires building mime dict ?
		if (op->flags & UWSGI_OPT_MIME) {
			uwsgi.build_mime_dict = 1;
		}
		// immediate ?
		if (op->flags & UWSGI_OPT_IMMEDIATE) {
			op->func(key, value, op->data);
			uwsgi.exported_opts[id]->configured = 1;
		}
	}

}

int uwsgi_waitfd_event(int fd, int timeout, int event) {

	int ret;
	struct pollfd upoll;

	if (!timeout)
		timeout = uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT];

	timeout = timeout * 1000;
	if (timeout < 0)
		timeout = -1;

	upoll.fd = fd;
	upoll.events = event;
	upoll.revents = 0;
	ret = poll(&upoll, 1, timeout);

	if (ret < 0) {
		uwsgi_error("poll()");
	}
	else if (ret > 0) {
		if (upoll.revents & event) {
			return ret;
		}
		return -1;
	}

	return ret;
}

void *uwsgi_malloc(size_t size) {

	char *ptr = malloc(size);
	if (ptr == NULL) {
		uwsgi_error("malloc()");
		uwsgi_log("!!! tried memory allocation of %llu bytes !!!\n", (unsigned long long) size);
		uwsgi_backtrace(uwsgi.backtrace_depth);
		exit(1);
	}

	return ptr;
}

void *uwsgi_calloc(size_t size) {

	char *ptr = uwsgi_malloc(size);
	memset(ptr, 0, size);
	return ptr;
}


char *uwsgi_cheap_string(char *buf, int len) {

	int i;
	char *cheap_buf = buf - 1;


	for (i = 0; i < len; i++) {
		*cheap_buf++ = buf[i];
	}


	buf[len - 1] = 0;

	return buf - 1;
}

char *uwsgi_resolve_ip(char *domain) {

	struct hostent *he;

	he = gethostbyname(domain);
	if (!he || !*he->h_addr_list || (he->h_addrtype != AF_INET
#ifdef UWSGI_IPV6
					 && he->h_addrtype != AF_INET6
#endif
	    )) {
		return NULL;
	}

	return inet_ntoa(*(struct in_addr *) he->h_addr_list[0]);
}

int uwsgi_file_exists(char *filename) {
	// TODO check for http url or stdin
	return !access(filename, R_OK);
}

char *uwsgi_read_fd(int fd, int *size, int add_zero) {

	char stack_buf[4096];
	ssize_t len;
	char *buffer = NULL;

	len = 1;
	while (len > 0) {
		len = read(fd, stack_buf, 4096);
		if (len > 0) {
			*size += len;
			buffer = realloc(buffer, *size);
			memcpy(buffer + (*size - len), stack_buf, len);
		}
	}

	if (add_zero) {
		*size = *size + 1;
		buffer = realloc(buffer, *size);
		buffer[*size - 1] = 0;
	}

	return buffer;

}

char *uwsgi_simple_file_read(char *filename) {

	struct stat sb;
	char *buffer;
	ssize_t len;
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_error_open(filename);
		goto end;
	}

	if (fstat(fd, &sb)) {
		uwsgi_error("fstat()");
		close(fd);
		goto end;
	}

	buffer = uwsgi_malloc(sb.st_size + 1);

	len = read(fd, buffer, sb.st_size);
	if (len != sb.st_size) {
		uwsgi_error("read()");
		free(buffer);
		close(fd);
		goto end;
	}

	close(fd);
	if (buffer[sb.st_size - 1] == '\n' || buffer[sb.st_size - 1] == '\r') {
		buffer[sb.st_size - 1] = 0;
	}
	buffer[sb.st_size] = 0;
	return buffer;
end:
	return (char *) "";

}

char *uwsgi_open_and_read(char *url, int *size, int add_zero, char *magic_table[]) {

	int fd;
	struct stat sb;
	char *buffer = NULL;
	char byte;
	ssize_t len;
	char *uri, *colon;
	char *domain;
	char *ip;
	int body = 0;
	char *magic_buf;

	// stdin ?
	if (!strcmp(url, "-")) {
		buffer = uwsgi_read_fd(0, size, add_zero);
	}
	// fd ?
	else if (!strncmp("fd://", url, 5)) {
		fd = atoi(url + 5);
		buffer = uwsgi_read_fd(fd, size, add_zero);
	}
	// exec ?
	else if (!strncmp("exec://", url, 5)) {
		int cpipe[2];
		if (pipe(cpipe)) {
			uwsgi_error("pipe()");
			exit(1);
		}
		uwsgi_run_command(url + 7, NULL, cpipe[1]);
		buffer = uwsgi_read_fd(cpipe[0], size, add_zero);
		close(cpipe[0]);
		close(cpipe[1]);
	}
	// http url ?
	else if (!strncmp("http://", url, 7)) {
		domain = url + 7;
		uri = strchr(domain, '/');
		if (!uri) {
			uwsgi_log("invalid http url\n");
			exit(1);
		}
		uri[0] = 0;
		uwsgi_log("domain: %s\n", domain);

		colon = uwsgi_get_last_char(domain, ':');

		if (colon) {
			colon[0] = 0;
		}


		ip = uwsgi_resolve_ip(domain);
		if (!ip) {
			uwsgi_log("unable to resolve address %s\n", domain);
			exit(1);
		}

		if (colon) {
			colon[0] = ':';
			ip = uwsgi_concat2(ip, colon);
		}
		else {
			ip = uwsgi_concat2(ip, ":80");
		}

		fd = uwsgi_connect(ip, 0, 0);

		if (fd < 0) {
			exit(1);
		}

		uri[0] = '/';

		len = write(fd, "GET ", 4);
		len = write(fd, uri, strlen(uri));
		len = write(fd, " HTTP/1.0\r\n", 11);
		len = write(fd, "Host: ", 6);

		uri[0] = 0;
		len = write(fd, domain, strlen(domain));
		uri[0] = '/';

		len = write(fd, "\r\nUser-Agent: uWSGI on ", 23);
		len = write(fd, uwsgi.hostname, uwsgi.hostname_len);
		len = write(fd, "\r\n\r\n", 4);

		int http_status_code_ptr = 0;

		while (read(fd, &byte, 1) == 1) {
			if (byte == '\r' && body == 0) {
				body = 1;
			}
			else if (byte == '\n' && body == 1) {
				body = 2;
			}
			else if (byte == '\r' && body == 2) {
				body = 3;
			}
			else if (byte == '\n' && body == 3) {
				body = 4;
			}
			else if (body == 4) {
				*size = *size + 1;
				buffer = realloc(buffer, *size);
				if (!buffer) {
					uwsgi_error("realloc()");
					exit(1);
				}
				buffer[*size - 1] = byte;
			}
			else {
				body = 0;
				http_status_code_ptr++;
				if (http_status_code_ptr == 10) {
					if (byte != '2') {
						uwsgi_log("Not usable HTTP response: %cxx\n", byte);
						if (uwsgi.has_emperor) {
							exit(UWSGI_EXILE_CODE);
						}
						else {
							exit(1);
						}
					}
				}
			}
		}

		close(fd);

		if (add_zero) {
			*size = *size + 1;
			buffer = realloc(buffer, *size);
			buffer[*size - 1] = 0;
		}

	}
	else if (!strncmp("emperor://", url, 10)) {
		if (uwsgi.emperor_fd_config < 0) {
			uwsgi_log("this is not a vassal instance\n");
			exit(1);
		}
		char *tmp_buffer[4096];
		ssize_t rlen = 1;
		*size = 0;
		while (rlen > 0) {
			rlen = read(uwsgi.emperor_fd_config, tmp_buffer, 4096);
			if (rlen > 0) {
				*size += rlen;
				buffer = realloc(buffer, *size);
				if (!buffer) {
					uwsgi_error("realloc()");
					exit(1);
				}
				memcpy(buffer + (*size - rlen), tmp_buffer, rlen);
			}
		}
		close(uwsgi.emperor_fd_config);
		uwsgi.emperor_fd_config = -1;

		if (add_zero) {
			*size = *size + 1;
			buffer = realloc(buffer, *size);
			buffer[*size - 1] = 0;
		}
	}
#ifdef UWSGI_EMBED_CONFIG
	else if (url[0] == 0) {
		*size = &UWSGI_EMBED_CONFIG_END - &UWSGI_EMBED_CONFIG;
		if (add_zero) {
			*size += 1;
		}
		buffer = uwsgi_malloc(*size);
		memset(buffer, 0, *size);
		memcpy(buffer, &UWSGI_EMBED_CONFIG, &UWSGI_EMBED_CONFIG_END - &UWSGI_EMBED_CONFIG);
	}
#endif
	else if (!strncmp("data://", url, 7)) {
		fd = open(uwsgi.binary_path, O_RDONLY);
		if (fd < 0) {
			uwsgi_error_open(uwsgi.binary_path);
			exit(1);
		}
		int slot = atoi(url + 7);
		if (slot < 0) {
			uwsgi_log("invalid binary data slot requested\n");
			exit(1);
		}
		uwsgi_log("requesting binary data slot %d\n", slot);
		off_t fo = lseek(fd, 0, SEEK_END);
		if (fo < 0) {
			uwsgi_error("lseek()");
			uwsgi_log("invalid binary data slot requested\n");
			exit(1);
		}
		int i = 0;
		uint64_t datasize = 0;
		for (i = 0; i <= slot; i++) {
			fo = lseek(fd, -9, SEEK_CUR);
			if (fo < 0) {
				uwsgi_error("lseek()");
				uwsgi_log("invalid binary data slot requested\n");
				exit(1);
			}
			ssize_t len = read(fd, &datasize, 8);
			if (len != 8) {
				uwsgi_error("read()");
				uwsgi_log("invalid binary data slot requested\n");
				exit(1);
			}
			if (datasize == 0) {
				uwsgi_log("0 size binary data !!!\n");
				exit(1);
			}
			fo = lseek(fd, -(datasize + 9), SEEK_CUR);
			if (fo < 0) {
				uwsgi_error("lseek()");
				uwsgi_log("invalid binary data slot requested\n");
				exit(1);
			}

			if (i == slot) {
				*size = datasize;
				if (add_zero) {
					*size += 1;
				}
				buffer = uwsgi_malloc(*size);
				memset(buffer, 0, *size);
				len = read(fd, buffer, datasize);
				if (len != (ssize_t) datasize) {
					uwsgi_error("read()");
					uwsgi_log("invalid binary data slot requested\n");
					exit(1);
				}
			}
		}
	}
	else if (!strncmp("sym://", url, 6)) {
		char *symbol = uwsgi_concat3("_binary_", url + 6, "_start");
		void *sym_start_ptr = dlsym(RTLD_DEFAULT, symbol);
		if (!sym_start_ptr) {
			uwsgi_log("unable to find symbol %s\n", symbol);
			exit(1);
		}
		free(symbol);
		symbol = uwsgi_concat3("_binary_", url + 6, "_end");
		void *sym_end_ptr = dlsym(RTLD_DEFAULT, symbol);
		if (!sym_end_ptr) {
			uwsgi_log("unable to find symbol %s\n", symbol);
			exit(1);
		}
		free(symbol);

		*size = sym_end_ptr - sym_start_ptr;
		if (add_zero) {
			*size += 1;
		}
		buffer = uwsgi_malloc(*size);
		memset(buffer, 0, *size);
		memcpy(buffer, sym_start_ptr, sym_end_ptr - sym_start_ptr);

	}
#ifdef UWSGI_ELF
	else if (!strncmp("section://", url, 10)) {
		size_t s_len = 0;
		buffer = uwsgi_elf_section(uwsgi.binary_path, url + 10, &s_len);
		if (!buffer) {
			uwsgi_log("unable to find section %s in %s\n", url + 10, uwsgi.binary_path);
			exit(1);
		}
		*size = s_len;
		if (add_zero)
			*size += 1;
	}
#endif
	// fallback to file
	else {
		fd = open(url, O_RDONLY);
		if (fd < 0) {
			uwsgi_error_open(url);
			exit(1);
		}

		if (fstat(fd, &sb)) {
			uwsgi_error("fstat()");
			exit(1);
		}

		if (S_ISFIFO(sb.st_mode)) {
			buffer = uwsgi_read_fd(fd, size, add_zero);
			close(fd);
			goto end;
		}

		buffer = malloc(sb.st_size + add_zero);

		if (!buffer) {
			uwsgi_error("malloc()");
			exit(1);
		}


		len = read(fd, buffer, sb.st_size);
		if (len != sb.st_size) {
			uwsgi_error("read()");
			exit(1);
		}

		close(fd);

		*size = sb.st_size + add_zero;

		if (add_zero)
			buffer[sb.st_size] = 0;
	}

end:

	if (magic_table) {

		magic_buf = magic_sub(buffer, *size, size, magic_table);
		free(buffer);
		return magic_buf;
	}

	return buffer;
}

char *magic_sub(char *buffer, int len, int *size, char *magic_table[]) {

	int i;
	size_t magic_len = 0;
	char *magic_buf = uwsgi_malloc(len);
	char *magic_ptr = magic_buf;
	char *old_magic_buf;

	for (i = 0; i < len; i++) {
		if (buffer[i] == '%' && (i + 1) < len && magic_table[(unsigned char) buffer[i + 1]]) {
			old_magic_buf = magic_buf;
			magic_buf = uwsgi_concat3n(old_magic_buf, magic_len, magic_table[(unsigned char) buffer[i + 1]], strlen(magic_table[(unsigned char) buffer[i + 1]]), buffer + i + 2, len - i);
			free(old_magic_buf);
			magic_len += strlen(magic_table[(unsigned char) buffer[i + 1]]);
			magic_ptr = magic_buf + magic_len;
			i++;
		}
		else {
			*magic_ptr = buffer[i];
			magic_ptr++;
			magic_len++;
		}
	}

	*size = magic_len;

	return magic_buf;

}

void init_magic_table(char *magic_table[]) {

	int i;
	for (i = 0; i <= 0xff; i++) {
		magic_table[i] = "";
	}

	magic_table['%'] = "%";
	magic_table['('] = "%(";
}

char *uwsgi_get_last_char(char *what, char c) {
	int i;
	char *ptr = NULL;

	for (i = 0; i < (int) strlen(what); i++) {
		if (what[i] == c) {
			ptr = what + i;
		}
	}

	return ptr;
}

char *uwsgi_num2str(int num) {

	char *str = uwsgi_malloc(11);

	snprintf(str, 11, "%d", num);
	return str;
}

int uwsgi_num2str2(int num, char *ptr) {

	return snprintf(ptr, 11, "%d", num);
}

int uwsgi_num2str2n(int num, char *ptr, int size) {
	return snprintf(ptr, size, "%d", num);
}

int uwsgi_long2str2n(unsigned long long num, char *ptr, int size) {
	int ret = snprintf(ptr, size, "%llu", num);
	if (ret < 0)
		return 0;
	return ret;
}

int is_unix(char *socket_name, int len) {
	int i;
	for (i = 0; i < len; i++) {
		if (socket_name[i] == ':')
			return 0;
	}

	return 1;
}

int is_a_number(char *what) {
	int i;

	for (i = 0; i < (int) strlen(what); i++) {
		if (!isdigit((int) what[i]))
			return 0;
	}

	return 1;
}

void uwsgi_unix_signal(int signum, void (*func) (int)) {

	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));

	sa.sa_handler = func;

	sigemptyset(&sa.sa_mask);

	if (sigaction(signum, &sa, NULL) < 0) {
		uwsgi_error("sigaction()");
	}
}

char *uwsgi_get_exported_opt(char *key) {

	int i;

	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
		if (!strcmp(uwsgi.exported_opts[i]->key, key)) {
			return uwsgi.exported_opts[i]->value;
		}
	}

	return NULL;
}

char *uwsgi_get_optname_by_index(int index) {

	struct uwsgi_option *op = uwsgi.options;

	while (op->name) {
		if (op->shortcut == index) {
			return op->name;
		}
		op++;
	}

	return NULL;
}

int uwsgi_list_has_num(char *list, int num) {

	char *list2 = uwsgi_concat2(list, "");

	char *p = strtok(list2, ",");
	while (p != NULL) {
		if (atoi(p) == num) {
			free(list2);
			return 1;
		}
		p = strtok(NULL, ",");
	}

	free(list2);
	return 0;
}

int uwsgi_list_has_str(char *list, char *str) {

	char *list2 = uwsgi_concat2(list + 1, "");

	char *p = strtok(list2, " ");
	while (p != NULL) {
		if (!strcasecmp(p, str)) {
			free(list2);
			return 1;
		}
		p = strtok(NULL, " ");
	}

	free(list2);
	return 0;
}

char hex2num(char *str) {

	char val = 0;

	val <<= 4;

	if (str[0] >= '0' && str[0] <= '9') {
		val += str[0] & 0x0F;
	}
	else if (str[0] >= 'A' && str[0] <= 'F') {
		val += (str[0] & 0x0F) + 9;
	}
	else {
		return 0;
	}

	val <<= 4;

	if (str[1] >= '0' && str[1] <= '9') {
		val += str[1] & 0x0F;
	}
	else if (str[1] >= 'A' && str[1] <= 'F') {
		val += (str[1] & 0x0F) + 9;
	}
	else {
		return 0;
	}

	return val;
}

int uwsgi_str2_num(char *str) {

	int num = 0;

	num = 10 * (str[0] - 48);
	num += str[1] - 48;

	return num;
}

int uwsgi_str3_num(char *str) {

	int num = 0;

	num = 100 * (str[0] - 48);
	num += 10 * (str[1] - 48);
	num += str[2] - 48;

	return num;
}


int uwsgi_str4_num(char *str) {

	int num = 0;

	num = 1000 * (str[0] - 48);
	num += 100 * (str[1] - 48);
	num += 10 * (str[2] - 48);
	num += str[3] - 48;

	return num;
}

size_t uwsgi_str_num(char *str, int len) {

	int i;
	size_t num = 0;

	size_t delta = pow(10, len);

	for (i = 0; i < len; i++) {
		delta = delta / 10;
		num += delta * (str[i] - 48);
	}

	return num;
}

char *uwsgi_split3(char *buf, size_t len, char sep, char **part1, size_t * part1_len, char **part2, size_t * part2_len, char **part3, size_t * part3_len) {

	size_t i;
	int status = 0;

	*part1 = NULL;
	*part2 = NULL;
	*part3 = NULL;

	for (i = 0; i < len; i++) {
		if (buf[i] == sep) {
			// get part1
			if (status == 0) {
				*part1 = buf;
				*part1_len = i;
				status = 1;
			}
			// get part2
			else if (status == 1) {
				*part2 = *part1 + *part1_len + 1;
				*part2_len = (buf + i) - *part2;
				break;
			}
		}
	}

	if (*part1 && *part2) {
		if (*part2 + *part2_len + 1 > buf + len) {
			return NULL;
		}
		*part3 = *part2 + *part2_len + 1;
		*part3_len = (buf + len) - *part3;
		return buf + len;
	}

	return NULL;
}

char *uwsgi_split4(char *buf, size_t len, char sep, char **part1, size_t * part1_len, char **part2, size_t * part2_len, char **part3, size_t * part3_len, char **part4, size_t * part4_len) {

	size_t i;
	int status = 0;

	*part1 = NULL;
	*part2 = NULL;
	*part3 = NULL;
	*part4 = NULL;

	for (i = 0; i < len; i++) {
		if (buf[i] == sep) {
			// get part1
			if (status == 0) {
				*part1 = buf;
				*part1_len = i;
				status = 1;
			}
			// get part2
			else if (status == 1) {
				*part2 = *part1 + *part1_len + 1;
				*part2_len = (buf + i) - *part2;
				status = 2;
			}
			// get part3
			else if (status == 2) {
				*part3 = *part2 + *part2_len + 1;
				*part3_len = (buf + i) - *part3;
				break;
			}
		}
	}

	if (*part1 && *part2 && *part3) {
		if (*part3 + *part3_len + 1 > buf + len) {
			return NULL;
		}
		*part4 = *part3 + *part3_len + 1;
		*part4_len = (buf + len) - *part4;
		return buf + len;
	}

	return NULL;
}


char *uwsgi_netstring(char *buf, size_t len, char **netstring, size_t * netstring_len) {

	char *ptr = buf;
	char *watermark = buf + len;
	*netstring_len = 0;

	while (ptr < watermark) {
		// end of string size ?
		if (*ptr == ':') {
			*netstring_len = uwsgi_str_num(buf, ptr - buf);

			if (ptr + *netstring_len + 2 > watermark) {
				return NULL;
			}
			*netstring = ptr + 1;
			return ptr + *netstring_len + 2;
		}
		ptr++;
	}

	return NULL;
}

struct uwsgi_dyn_dict *uwsgi_dyn_dict_new(struct uwsgi_dyn_dict **dd, char *key, int keylen, char *val, int vallen) {

	struct uwsgi_dyn_dict *uwsgi_dd = *dd, *old_dd;

	if (!uwsgi_dd) {
		*dd = uwsgi_malloc(sizeof(struct uwsgi_dyn_dict));
		uwsgi_dd = *dd;
		uwsgi_dd->prev = NULL;
	}
	else {
		while (uwsgi_dd) {
			old_dd = uwsgi_dd;
			uwsgi_dd = uwsgi_dd->next;
		}

		uwsgi_dd = uwsgi_malloc(sizeof(struct uwsgi_dyn_dict));
		old_dd->next = uwsgi_dd;
		uwsgi_dd->prev = old_dd;
	}

	uwsgi_dd->key = key;
	uwsgi_dd->keylen = keylen;
	uwsgi_dd->value = val;
	uwsgi_dd->vallen = vallen;
	uwsgi_dd->hits = 0;
	uwsgi_dd->status = 0;
	uwsgi_dd->next = NULL;

	return uwsgi_dd;
}

void uwsgi_dyn_dict_del(struct uwsgi_dyn_dict *item) {

	struct uwsgi_dyn_dict *prev = item->prev;
	struct uwsgi_dyn_dict *next = item->next;

	if (prev) {
		prev->next = next;
	}

	if (next) {
		next->prev = prev;
	}

	free(item);
}

void *uwsgi_malloc_shared(size_t size) {

	void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);

	if (addr == MAP_FAILED) {
		uwsgi_log("unable to allocate %llu bytes (%lluMB)\n", (unsigned long long) size, (unsigned long long) (size / (1024 * 1024)));
		uwsgi_error("mmap()");
		exit(1);
	}

	return addr;
}

void *uwsgi_calloc_shared(size_t size) {
	void *ptr = uwsgi_malloc_shared(size);
	memset(ptr, 0, size);
	return ptr;
}


struct uwsgi_string_list *uwsgi_string_new_list(struct uwsgi_string_list **list, char *value) {

	struct uwsgi_string_list *uwsgi_string = *list, *old_uwsgi_string;

	if (!uwsgi_string) {
		*list = uwsgi_malloc(sizeof(struct uwsgi_string_list));
		uwsgi_string = *list;
	}
	else {
		while (uwsgi_string) {
			old_uwsgi_string = uwsgi_string;
			uwsgi_string = uwsgi_string->next;
		}

		uwsgi_string = uwsgi_malloc(sizeof(struct uwsgi_string_list));
		old_uwsgi_string->next = uwsgi_string;
	}

	uwsgi_string->value = value;
	uwsgi_string->len = 0;
	if (value) {
		uwsgi_string->len = strlen(value);
	}
	uwsgi_string->next = NULL;
	uwsgi_string->custom = 0;
	uwsgi_string->custom2 = 0;

	return uwsgi_string;
}

#ifdef UWSGI_PCRE
struct uwsgi_regexp_list *uwsgi_regexp_custom_new_list(struct uwsgi_regexp_list **list, char *value, char *custom) {

	struct uwsgi_regexp_list *url = *list, *old_url;

	if (!url) {
		*list = uwsgi_malloc(sizeof(struct uwsgi_regexp_list));
		url = *list;
	}
	else {
		while (url) {
			old_url = url;
			url = url->next;
		}

		url = uwsgi_malloc(sizeof(struct uwsgi_regexp_list));
		old_url->next = url;
	}

	if (uwsgi_regexp_build(value, &url->pattern, &url->pattern_extra)) {
		exit(1);
	}
	url->next = NULL;
	url->custom = 0;
	url->custom_ptr = NULL;
	url->custom_str = custom;

	return url;
}



#endif

char *uwsgi_string_get_list(struct uwsgi_string_list **list, int pos, size_t * len) {

	struct uwsgi_string_list *uwsgi_string = *list;
	int counter = 0;

	while (uwsgi_string) {
		if (counter == pos) {
			*len = uwsgi_string->len;
			return uwsgi_string->value;
		}
		uwsgi_string = uwsgi_string->next;
		counter++;
	}

	*len = 0;
	return NULL;

}


void uwsgi_string_del_list(struct uwsgi_string_list **list, struct uwsgi_string_list *item) {

	struct uwsgi_string_list *uwsgi_string = *list, *old_uwsgi_string = NULL;

	while (uwsgi_string) {
		if (uwsgi_string == item) {
			// parent instance ?
			if (old_uwsgi_string == NULL) {
				*list = uwsgi_string->next;
			}
			else {
				old_uwsgi_string->next = uwsgi_string->next;
			}

			free(uwsgi_string);
			return;
		}

		old_uwsgi_string = uwsgi_string;
		uwsgi_string = uwsgi_string->next;
	}

}

void uwsgi_sig_pause() {

	sigset_t mask;
	sigemptyset(&mask);
	sigsuspend(&mask);
}

void uwsgi_exec_command_with_args(char *cmdline) {
	char *argv[4];
	argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[2] = cmdline;
	argv[3] = NULL;
	execvp(argv[0], argv);
	uwsgi_error("execvp()");
	exit(1);
}

int uwsgi_run_command_and_wait(char *command, char *arg) {

	char *argv[4];
	int waitpid_status = 0;
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}

	if (pid > 0) {
		if (waitpid(pid, &waitpid_status, 0) < 0) {
			uwsgi_error("waitpid()");
			return -1;
		}

		return WEXITSTATUS(waitpid_status);
	}

#ifdef __linux__
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
		uwsgi_error("prctl()");
	}
#endif

	if (command == NULL) {
		argv[0] = "/bin/sh";
		argv[1] = "-c";
		argv[2] = arg;
		argv[3] = NULL;
		execvp(argv[0], argv);
	}
	else {
		argv[0] = command;
		argv[1] = arg;
		argv[2] = NULL;
		execvp(command, argv);
	}


	uwsgi_error("execvp()");
	//never here
	exit(1);
}

pid_t uwsgi_run_command(char *command, int *stdin_fd, int stdout_fd) {

	char *argv[4];

	int waitpid_status = 0;
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}

	if (pid > 0) {
		if (stdin_fd && stdin_fd[0] > -1) {
			close(stdin_fd[0]);
		}
		if (stdout_fd > -1) {
			close(stdout_fd);
		}
		if (waitpid(pid, &waitpid_status, WNOHANG) < 0) {
			uwsgi_error("waitpid()");
			return -1;
		}

		return pid;
	}

	uwsgi_close_all_sockets();

	if (stdin_fd) {
		close(stdin_fd[1]);
	}

	if (stdout_fd > -1 && stdout_fd != 1) {
		if (dup2(stdout_fd, 1) < 0) {
			uwsgi_error("dup2()");
			exit(1);
		}
	}

	if (stdin_fd && stdin_fd[0] > -1 && stdin_fd[0] != 0) {
		if (dup2(stdin_fd[0], 0) < 0) {
			uwsgi_error("dup2()");
			exit(1);
		}
	}

	if (setsid() < 0) {
		uwsgi_error("setsid()");
		exit(1);
	}

	argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[2] = command;
	argv[3] = NULL;

	execvp("/bin/sh", argv);

	uwsgi_error("execvp()");
	//never here
	exit(1);
}

int *uwsgi_attach_fd(int fd, int *count_ptr, char *code, size_t code_len) {

	struct msghdr msg;
	ssize_t len;
	char *id = NULL;

	struct iovec iov;
	struct cmsghdr *cmsg;
	int *ret;
	int i;
	int count = *count_ptr;

	void *msg_control = uwsgi_malloc(CMSG_SPACE(sizeof(int) * count));

	memset(msg_control, 0, CMSG_SPACE(sizeof(int) * count));

	if (code && code_len > 0) {
		// allocate space for code and num_sockets
		id = uwsgi_malloc(code_len + sizeof(int));
		memset(id, 0, code_len);
		iov.iov_len = code_len + sizeof(int);
	}

	iov.iov_base = id;

	memset(&msg, 0, sizeof(msg));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = msg_control;
	msg.msg_controllen = CMSG_SPACE(sizeof(int) * count);

	msg.msg_flags = 0;

	len = recvmsg(fd, &msg, 0);
	if (len <= 0) {
		uwsgi_error("recvmsg()");
		return NULL;
	}

	if (code && code_len > 0) {
		if (uwsgi_strncmp(id, code_len, code, code_len)) {
			return NULL;
		}

		if ((size_t) len == code_len + sizeof(int)) {
			memcpy(&i, id + code_len, sizeof(int));
			if (i > count) {
				*count_ptr = i;
				free(msg_control);
				free(id);
				return NULL;
			}
		}
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg)
		return NULL;

	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		return NULL;
	}

	if ((size_t) (cmsg->cmsg_len - ((char *) CMSG_DATA(cmsg) - (char *) cmsg)) > (size_t) (sizeof(int) * (count + 1))) {
		uwsgi_log("not enough space for sockets data, consider increasing it\n");
		return NULL;
	}

	ret = uwsgi_malloc(sizeof(int) * (count + 1));
	for (i = 0; i < count + 1; i++) {
		ret[i] = -1;
	}

	memcpy(ret, CMSG_DATA(cmsg), cmsg->cmsg_len - ((char *) CMSG_DATA(cmsg) - (char *) cmsg));

	free(msg_control);
	if (code && code_len > 0) {
		free(id);
	}

	return ret;
}

int uwsgi_endswith(char *str1, char *str2) {

	size_t i;
	size_t str1len = strlen(str1);
	size_t str2len = strlen(str2);
	char *ptr;

	if (str2len > str1len)
		return 0;

	ptr = (str1 + str1len) - str2len;

	for (i = 0; i < str2len; i++) {
		if (*ptr != str2[i])
			return 0;
		ptr++;
	}

	return 1;
}

void uwsgi_chown(char *filename, char *owner) {

	uid_t new_uid = -1;
	uid_t new_gid = -1;
	struct group *new_group = NULL;
	struct passwd *new_user = NULL;

	char *colon = strchr(owner, ':');
	if (colon) {
		colon[0] = 0;
	}


	if (is_a_number(owner)) {
		new_uid = atoi(owner);
	}
	else {
		new_user = getpwnam(owner);
		if (!new_user) {
			uwsgi_log("unable to find user %s\n", owner);
			exit(1);
		}
		new_uid = new_user->pw_uid;
	}

	if (colon) {
		colon[0] = ':';
		if (is_a_number(colon + 1)) {
			new_gid = atoi(colon + 1);
		}
		else {
			new_group = getgrnam(colon + 1);
			if (!new_group) {
				uwsgi_log("unable to find group %s\n", colon + 1);
				exit(1);
			}
			new_gid = new_group->gr_gid;
		}
	}

	if (chown(filename, new_uid, new_gid)) {
		uwsgi_error("chown()");
		exit(1);
	}

}

char *uwsgi_get_binary_path(char *argvzero) {

#if defined(__linux__)
	char *buf = uwsgi_calloc(PATH_MAX + 1);
	ssize_t len = readlink("/proc/self/exe", buf, PATH_MAX);
	if (len > 0) {
		return buf;
	}
	free(buf);
#elif defined(__NetBSD__)
	char *buf = uwsgi_calloc(PATH_MAX + 1);
	ssize_t len = readlink("/proc/curproc/exe", buf, PATH_MAX);
	if (len > 0) {
		return buf;
	}

	if (realpath(argvzero, buf)) {
		return buf;
	}
	free(buf);
#elif defined(__APPLE__)
	char *buf = uwsgi_malloc(uwsgi.page_size);
	uint32_t len = uwsgi.page_size;
	if (_NSGetExecutablePath(buf, &len) == 0) {
		// return only absolute path
		char *newbuf = realpath(buf, NULL);
		if (newbuf) {
			free(buf);
			return newbuf;
		}
	}
	free(buf);
#elif defined(__sun__)
	// do not free this value !!!
	char *buf = (char *) getexecname();
	if (buf) {
		// return only absolute path
		if (buf[0] == '/') {
			return buf;
		}

		char *newbuf = uwsgi_malloc(PATH_MAX + 1);
		if (realpath(buf, newbuf)) {
			return newbuf;
		}
	}
#elif defined(__FreeBSD__)
	char *buf = uwsgi_malloc(uwsgi.page_size);
	size_t len = uwsgi.page_size;
	int mib[4];
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = -1;
	if (sysctl(mib, 4, buf, &len, NULL, 0) == 0) {
		return buf;
	}
	free(buf);
#endif


	return argvzero;

}

char *uwsgi_get_line(char *ptr, char *watermark, int *size) {
	char *p = ptr;
	int count = 0;

	while (p < watermark) {
		if (*p == '\n') {
			*size = count;
			return ptr + count;
		}
		count++;
		p++;
	}

	return NULL;
}

void uwsgi_build_mime_dict(char *filename) {

	int size = 0;
	char *buf = uwsgi_open_and_read(filename, &size, 1, NULL);
	char *watermark = buf + size;

	int linesize = 0;
	char *line = buf;
	int i;
	int type_size = 0;
	int ext_start = 0;
	int found;
	int entries = 0;

	uwsgi_log("building mime-types dictionary from file %s...", filename);

	while (uwsgi_get_line(line, watermark, &linesize) != NULL) {
		found = 0;
		if (isalnum((int) line[0])) {
			// get the type size
			for (i = 0; i < linesize; i++) {
				if (isblank((int) line[i])) {
					type_size = i;
					found = 1;
					break;
				}
			}
			if (!found) {
				line += linesize + 1;
				continue;
			}
			found = 0;
			for (i = type_size; i < linesize; i++) {
				if (!isblank((int) line[i])) {
					ext_start = i;
					found = 1;
					break;
				}
			}
			if (!found) {
				line += linesize + 1;
				continue;
			}

			char *current = line + ext_start;
			int ext_size = 0;
			for (i = ext_start; i < linesize; i++) {
				if (isblank((int) line[i])) {
#ifdef UWSGI_DEBUG
					uwsgi_log("%.*s %.*s\n", ext_size, current, type_size, line);
#endif
					uwsgi_dyn_dict_new(&uwsgi.mimetypes, current, ext_size, line, type_size);
					entries++;
					ext_size = 0;
					current = NULL;
					continue;
				}
				else if (current == NULL) {
					current = line + i;
				}
				ext_size++;
			}
			if (current && ext_size > 1) {
#ifdef UWSGI_DEBUG
				uwsgi_log("%.*s %.*s\n", ext_size, current, type_size, line);
#endif
				uwsgi_dyn_dict_new(&uwsgi.mimetypes, current, ext_size, line, type_size);
				entries++;
			}

		}
		line += linesize + 1;
	}

	uwsgi_log("%d entry found\n", entries);

}

#ifdef __linux__
struct uwsgi_unshare_id {
	char *name;
	int value;
};

static struct uwsgi_unshare_id uwsgi_unshare_list[] = {
#ifdef CLONE_FILES
	{"files", CLONE_FILES},
#endif
#ifdef CLONE_FS
	{"fs", CLONE_FS},
#endif
#ifdef CLONE_NEWIPC
	{"ipc", CLONE_NEWIPC},
#endif
#ifdef CLONE_NEWNET
	{"net", CLONE_NEWNET},
#endif
#ifdef CLONE_NEWPID
	{"pid", CLONE_NEWPID},
#endif
#ifdef CLONE_NEWNS
	{"ns", CLONE_NEWNS},
	{"mount", CLONE_NEWNS},
#endif
#ifdef CLONE_SYSVSEM
	{"sysvsem", CLONE_SYSVSEM},
#endif
#ifdef CLONE_NEWUTS
	{"uts", CLONE_NEWUTS},
#endif
	{NULL, -1}
};

static int uwsgi_get_unshare_id(char *name) {

	struct uwsgi_unshare_id *uui = uwsgi_unshare_list;
	while (uui->name) {
		if (!strcmp(uui->name, name))
			return uui->value;
		uui++;
	}

	return -1;
}

void uwsgi_build_unshare(char *what) {

	char *list = uwsgi_str(what);

	char *p = strtok(list, ",");
	while (p != NULL) {
		int u_id = uwsgi_get_unshare_id(p);
		if (u_id != -1) {
			uwsgi.unshare |= u_id;
		}
		p = strtok(NULL, ",");
	}
	free(list);
}


#endif

#ifdef UWSGI_CAP
struct uwsgi_cap {
	char *name;
	cap_value_t value;
};

static struct uwsgi_cap uwsgi_cap_list[] = {
	{"chown", CAP_CHOWN},
	{"dac_override", CAP_DAC_OVERRIDE},
	{"dac_read_search", CAP_DAC_READ_SEARCH},
	{"fowner", CAP_FOWNER},
	{"fsetid", CAP_FSETID},
	{"kill", CAP_KILL},
	{"setgid", CAP_SETGID},
	{"setuid", CAP_SETUID},
	{"setpcap", CAP_SETPCAP},
	{"linux_immutable", CAP_LINUX_IMMUTABLE},
	{"net_bind_service", CAP_NET_BIND_SERVICE},
	{"net_broadcast", CAP_NET_BROADCAST},
	{"net_admin", CAP_NET_ADMIN},
	{"net_raw", CAP_NET_RAW},
	{"ipc_lock", CAP_IPC_LOCK},
	{"ipc_owner", CAP_IPC_OWNER},
	{"sys_module", CAP_SYS_MODULE},
	{"sys_rawio", CAP_SYS_RAWIO},
	{"sys_chroot", CAP_SYS_CHROOT},
	{"sys_ptrace", CAP_SYS_PTRACE},
	{"sys_pacct", CAP_SYS_PACCT},
	{"sys_admin", CAP_SYS_ADMIN},
	{"sys_boot", CAP_SYS_BOOT},
	{"sys_nice", CAP_SYS_NICE},
	{"sys_resource", CAP_SYS_RESOURCE},
	{"sys_time", CAP_SYS_TIME},
	{"sys_tty_config", CAP_SYS_TTY_CONFIG},
	{"mknod", CAP_MKNOD},
#ifdef CAP_LEASE
	{"lease", CAP_LEASE},
#endif
#ifdef CAP_AUDIT_WRITE
	{"audit_write", CAP_AUDIT_WRITE},
#endif
#ifdef CAP_AUDIT_CONTROL
	{"audit_control", CAP_AUDIT_CONTROL},
#endif
#ifdef CAP_SETFCAP
	{"setfcap", CAP_SETFCAP},
#endif
#ifdef CAP_MAC_OVERRIDE
	{"mac_override", CAP_MAC_OVERRIDE},
#endif
#ifdef CAP_MAC_ADMIN
	{"mac_admin", CAP_MAC_ADMIN},
#endif
#ifdef CAP_SYSLOG
	{"syslog", CAP_SYSLOG},
#endif
#ifdef CAP_WAKE_ALARM
	{"wake_alarm", CAP_WAKE_ALARM},
#endif
	{NULL, -1}
};

static int uwsgi_get_cap_id(char *name) {

	struct uwsgi_cap *ucl = uwsgi_cap_list;
	while (ucl->name) {
		if (!strcmp(ucl->name, name))
			return ucl->value;
		ucl++;
	}

	return -1;
}

void uwsgi_build_cap(char *what) {

	int cap_id;
	char *caps = uwsgi_str(what);
	int pos = 0;
	uwsgi.cap_count = 0;

	char *p = strtok(caps, ",");
	while (p != NULL) {
		if (is_a_number(p)) {
			uwsgi.cap_count++;
		}
		else {
			cap_id = uwsgi_get_cap_id(p);
			if (cap_id != -1) {
				uwsgi.cap_count++;
			}
		}
		p = strtok(NULL, ",");
	}
	free(caps);

	uwsgi.cap = uwsgi_malloc(sizeof(cap_value_t) * uwsgi.cap_count);

	caps = uwsgi_str(what);
	p = strtok(caps, ",");
	while (p != NULL) {
		if (is_a_number(p)) {
			cap_id = atoi(p);
		}
		else {
			cap_id = uwsgi_get_cap_id(p);
		}
		if (cap_id != -1) {
			uwsgi.cap[pos] = cap_id;
			uwsgi_log("setting capability %s [%d]\n", p, cap_id);
			pos++;
		}
		p = strtok(NULL, ",");
	}
	free(caps);

}

#endif

void uwsgi_apply_config_pass(char symbol, char *(*hook) (char *)) {

	int i, j;

	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
		int has_symbol = 0;
		int depth = 0;
		char *magic_key = NULL;
		char *magic_val = NULL;
		if (uwsgi.exported_opts[i]->value && !uwsgi.exported_opts[i]->configured) {
			for (j = 0; j < (int) strlen(uwsgi.exported_opts[i]->value); j++) {
				if (uwsgi.exported_opts[i]->value[j] == symbol) {
					has_symbol = 1;
				}
				else if (uwsgi.exported_opts[i]->value[j] == '(' && has_symbol == 1) {
					has_symbol = 2;
					depth = 0;
					magic_key = uwsgi.exported_opts[i]->value + j + 1;
				}
				else if (has_symbol > 1) {
					if (uwsgi.exported_opts[i]->value[j] == '(') {
						has_symbol++;
						depth++;
					}
					else if (uwsgi.exported_opts[i]->value[j] == ')') {
						if (depth > 0) {
							has_symbol++;
							depth--;
							continue;
						}
						if (has_symbol <= 2) {
							magic_key = NULL;
							has_symbol = 0;
							continue;
						}
#ifdef UWSGI_DEBUG
						uwsgi_log("need to interpret the %.*s tag\n", has_symbol - 2, magic_key);
#endif
						char *tmp_magic_key = uwsgi_concat2n(magic_key, has_symbol - 2, "", 0);
						magic_val = hook(tmp_magic_key);
						free(tmp_magic_key);
						if (!magic_val) {
							magic_key = NULL;
							has_symbol = 0;
							continue;
						}
						uwsgi.exported_opts[i]->value = uwsgi_concat4n(uwsgi.exported_opts[i]->value, (magic_key - 2) - uwsgi.exported_opts[i]->value, magic_val, strlen(magic_val), magic_key + (has_symbol - 1), strlen(magic_key + (has_symbol - 1)), "", 0);
#ifdef UWSGI_DEBUG
						uwsgi_log("computed new value = %s\n", uwsgi.exported_opts[i]->value);
#endif
						magic_key = NULL;
						has_symbol = 0;
						j = 0;
					}
					else {
						has_symbol++;
					}
				}
				else {
					has_symbol = 0;
				}
			}
		}
	}

}

void uwsgi_set_processname(char *name) {

#if defined(__linux__) || defined(__sun__)
	size_t amount = 0;

	// prepare for strncat
	*uwsgi.orig_argv[0] = 0;

	if (uwsgi.procname_prefix) {
		amount += strlen(uwsgi.procname_prefix);
		if ((int) amount > uwsgi.max_procname - 1)
			return;
		strncat(uwsgi.orig_argv[0], uwsgi.procname_prefix, uwsgi.max_procname - (amount + 1));
	}

	amount += strlen(name);
	if ((int) amount > uwsgi.max_procname - 1)
		return;
	strncat(uwsgi.orig_argv[0], name, (uwsgi.max_procname - amount + 1));

	if (uwsgi.procname_append) {
		amount += strlen(uwsgi.procname_append);
		if ((int) amount > uwsgi.max_procname - 1)
			return;
		strncat(uwsgi.orig_argv[0], uwsgi.procname_append, uwsgi.max_procname - (amount + 1));
	}

	// fill with spaces...
	memset(uwsgi.orig_argv[0] + amount + 1, ' ', uwsgi.max_procname - (amount));
	// end with \0
	memset(uwsgi.orig_argv[0] + amount + 1 + (uwsgi.max_procname - (amount)), '\0', 1);

#elif defined(__FreeBSD__) || defined(__NetBSD__)
	if (uwsgi.procname_prefix) {
		if (!uwsgi.procname_append) {
			setproctitle("-%s%s", uwsgi.procname_prefix, name);
		}
		else {
			setproctitle("-%s%s%s", uwsgi.procname_prefix, name, uwsgi.procname_append);
		}
	}
	else if (uwsgi.procname_append) {
		if (!uwsgi.procname_prefix) {
			setproctitle("-%s%s", name, uwsgi.procname_append);
		}
		else {
			setproctitle("-%s%s%s", uwsgi.procname_prefix, name, uwsgi.procname_append);
		}
	}
	else {
		setproctitle("-%s", name);
	}
#endif
}

// this is a wrapper for fork restoring original argv
pid_t uwsgi_fork(char *name) {


	pid_t pid = fork();
	if (pid == 0) {

		if (uwsgi.never_swap) {
			if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
				uwsgi_error("mlockall()");
			}
		}

#if defined(__linux__) || defined(__sun__)
		int i;
		for (i = 0; i < uwsgi.argc; i++) {
			strcpy(uwsgi.orig_argv[i], uwsgi.argv[i]);
		}
#endif

		if (uwsgi.auto_procname && name) {
			if (uwsgi.procname) {
				uwsgi_set_processname(uwsgi.procname);
			}
			else {
				uwsgi_set_processname(name);
			}
		}
	}

	return pid;
}

void escape_shell_arg(char *src, size_t len, char *dst) {

	size_t i;
	char *ptr = dst;

	for (i = 0; i < len; i++) {
		if (strchr("&;`'\"|*?~<>^()[]{}$\\\n", src[i])) {
			*ptr++ = '\\';
		}
		*ptr++ = src[i];
	}

	*ptr++ = 0;
}

void http_url_decode(char *buf, uint16_t * len, char *dst) {

	uint16_t i;
	int percent = 0;
	char value[2];
	size_t new_len = 0;

	char *ptr = dst;

	value[0] = '0';
	value[1] = '0';

	for (i = 0; i < *len; i++) {
		if (buf[i] == '%') {
			if (percent == 0) {
				percent = 1;
			}
			else {
				*ptr++ = '%';
				new_len++;
				percent = 0;
			}
		}
		else {
			if (percent == 1) {
				value[0] = buf[i];
				percent = 2;
			}
			else if (percent == 2) {
				value[1] = buf[i];
				*ptr++ = hex2num(value);
				percent = 0;
				new_len++;
			}
			else {
				*ptr++ = buf[i];
				new_len++;
			}
		}
	}

	*len = new_len;

}

char *uwsgi_get_var(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, uint16_t * len) {

	int i;

	for (i = 0; i < wsgi_req->var_cnt; i += 2) {
		if (!uwsgi_strncmp(key, keylen, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len)) {
			*len = wsgi_req->hvec[i + 1].iov_len;
			return wsgi_req->hvec[i + 1].iov_base;
		}
	}

	return NULL;
}

struct uwsgi_app *uwsgi_add_app(int id, uint8_t modifier1, char *mountpoint, int mountpoint_len, void *interpreter, void *callable) {

	if (id > uwsgi.max_apps) {
		uwsgi_log("FATAL ERROR: you cannot load more than %d apps in a worker\n", uwsgi.max_apps);
		exit(1);
	}

	struct uwsgi_app *wi = &uwsgi_apps[id];
	memset(wi, 0, sizeof(struct uwsgi_app));

	wi->modifier1 = modifier1;
	wi->mountpoint_len = mountpoint_len < 0xff ? mountpoint_len : (0xff - 1);
	strncpy(wi->mountpoint, mountpoint, wi->mountpoint_len);
	wi->interpreter = interpreter;
	wi->callable = callable;

	uwsgi_apps_cnt++;
	// check if we need to emulate fork() COW
	int i;
	if (uwsgi.mywid == 0) {
		for (i = 1; i <= uwsgi.numproc; i++) {
			memcpy(&uwsgi.workers[i].apps[id], &uwsgi.workers[0].apps[id], sizeof(struct uwsgi_app));
			uwsgi.workers[i].apps_cnt = uwsgi_apps_cnt;
		}
	}

	return wi;
}


char *uwsgi_check_touches(struct uwsgi_string_list *touch_list) {

	struct uwsgi_string_list *touch = touch_list;
	while (touch) {
		struct stat tr_st;
		if (stat(touch->value, &tr_st)) {
			uwsgi_log("unable to stat() %s, events will be triggered as soon as the file is created\n", touch->value);
			touch->custom = 0;
		}
		else {
			if (!touch->custom)
				touch->custom = (uint64_t) tr_st.st_mtime;
			if ((uint64_t) tr_st.st_mtime > touch->custom) {
#ifdef UWSGI_DEBUG
				uwsgi_log("[uwsgi-check-touches] modification detected on %s: %llu -> %llu\n", touch->value, (unsigned long long) touch->custom, (unsigned long long) tr_st.st_mtime);
#endif
				touch->custom = (uint64_t) tr_st.st_mtime;
				return touch->value;
			}
			touch->custom = (uint64_t) tr_st.st_mtime;
		}
		touch = touch->next;
	}

	return NULL;
}

char *uwsgi_chomp(char *str) {
	size_t i;
	for (i = 0; i < strlen(str); i++) {
		if (str[i] == '\r' || str[i] == '\n') {
			str[i] = 0;
			return str;
		}
	}

	return str;
}

char *uwsgi_tmpname(char *base, char *id) {
	char *template = uwsgi_concat3(base, "/", id);
	if (mkstemp(template) < 0) {
		free(template);
		return NULL;
	}

	return template;
}

int uwsgi_file_to_string_list(char *filename, struct uwsgi_string_list **list) {

	char line[1024];

	FILE *fh = fopen(filename, "r");
	if (fh) {
		while (fgets(line, 1024, fh)) {
			uwsgi_string_new_list(list, uwsgi_chomp(uwsgi_str(line)));
		}
		fclose(fh);
		return 1;
	}
	uwsgi_error_open(filename);
	return 0;
}

void uwsgi_setup_post_buffering() {

	if (!uwsgi.post_buffering_bufsize)
		uwsgi.post_buffering_bufsize = 8192;

	if (uwsgi.post_buffering_bufsize < uwsgi.post_buffering) {
		uwsgi.post_buffering_bufsize = uwsgi.post_buffering;
		uwsgi_log("setting request body buffering size to %d bytes\n", uwsgi.post_buffering_bufsize);
	}

}

void uwsgi_emulate_cow_for_apps(int id) {
	int i;
	// check if we need to emulate fork() COW
	if (uwsgi.mywid == 0) {
		for (i = 1; i <= uwsgi.numproc; i++) {
			memcpy(&uwsgi.workers[i].apps[id], &uwsgi.workers[0].apps[id], sizeof(struct uwsgi_app));
			uwsgi.workers[i].apps_cnt = uwsgi_apps_cnt;
		}
	}
}


void uwsgi_write_pidfile(char *pidfile_name) {
	uwsgi_log("writing pidfile to %s\n", pidfile_name);
	FILE *pidfile = fopen(pidfile_name, "w");
	if (!pidfile) {
		uwsgi_error_open(pidfile_name);
		exit(1);
	}
	if (fprintf(pidfile, "%d\n", (int) getpid()) < 0) {
		uwsgi_log("could not write pidfile.\n");
	}
	fclose(pidfile);
}

int uwsgi_manage_exception(char *type, char *value, char *repr) {

	struct uwsgi_string_list *list = NULL;

	// first manage non fatal case (like signals and alarm)....

	if (uwsgi.reload_on_exception) {
		return -1;
	}

	if (type) {
		list = uwsgi.reload_on_exception_type;
		while (list) {
			if (!strcmp(list->value, type)) {
				return -1;
			}
			list = list->next;
		}
	}

	if (value) {
		list = uwsgi.reload_on_exception_value;
		while (list) {
			if (!strcmp(list->value, value)) {
				return -1;
			}
			list = list->next;
		}
	}

	if (repr) {
		list = uwsgi.reload_on_exception_repr;
		while (list) {
			if (!strcmp(list->value, repr)) {
				return -1;
			}
			list = list->next;
		}
	}

	return 0;
}

void uwsgi_protected_close(int fd) {

	sigset_t mask, oset;
	sigfillset(&mask);
	if (sigprocmask(SIG_BLOCK, &mask, &oset)) {
		uwsgi_error("sigprocmask()");
		exit(1);
	}
	close(fd);
	if (sigprocmask(SIG_SETMASK, &oset, NULL)) {
		uwsgi_error("sigprocmask()");
		exit(1);
	}
}

ssize_t uwsgi_protected_read(int fd, void *buf, size_t len) {

	sigset_t mask, oset;
	sigfillset(&mask);
	if (sigprocmask(SIG_BLOCK, &mask, &oset)) {
		uwsgi_error("sigprocmask()");
		exit(1);
	}

	ssize_t ret = read(fd, buf, len);

	if (sigprocmask(SIG_SETMASK, &oset, NULL)) {
		uwsgi_error("sigprocmask()");
		exit(1);
	}
	return ret;
}

char *uwsgi_expand_path(char *dir, int dir_len, char *ptr) {
	char src[PATH_MAX + 1];
	memcpy(src, dir, dir_len);
	src[dir_len] = 0;
	char *dst = ptr;
	if (!dst)
		dst = uwsgi_malloc(PATH_MAX + 1);
	if (!realpath(src, dst)) {
		uwsgi_error_realpath(src);
		if (!ptr)
			free(dst);
		return NULL;
	}
	return dst;
}

#ifdef UWSGI_SSL

/*

ssl additional datas are retrieved via indexes.

You can create an index with SSL_CTX_get_ex_new_index and
set data in it with SSL_CTX_set_ex_data

*/

void uwsgi_ssl_init(void) {
	OPENSSL_config(NULL);
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	uwsgi.ssl_initialized = 1;
}

void uwsgi_ssl_info_cb(SSL const *ssl, int where, int ret) {
	if (where & SSL_CB_HANDSHAKE_DONE) {
		if (ssl->s3) {
			ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
		}
	}
}

int uwsgi_ssl_verify_callback(int ok, X509_STORE_CTX * x509_store) {
	return 1;
}

SSL_CTX *uwsgi_ssl_new_server_context(char *name, char *crt, char *key, char *ciphers, char *client_ca) {

	SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx) {
		uwsgi_log("unable to initialize ssl context\n");
		exit(1);
	}

	// this part is taken from nginx and stud, removing unneeded functionality
	// stud (for me) has made the best choice on choosing DH approach

	long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
// disable compression (if possibile)
#ifdef SSL_OP_NO_COMPRESSION
	ssloptions |= SSL_OP_NO_COMPRESSION;
#endif
	SSL_CTX_set_options(ctx, ssloptions);

// release/reuse buffers as soon as possibile
#ifdef SSL_MODE_RELEASE_BUFFERS
	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

	if (SSL_CTX_use_certificate_chain_file(ctx, crt) <= 0) {
		uwsgi_log("unable to assign ssl certificate %s\n", crt);
		exit(1);
	}

// this part is based from stud
	BIO *bio = BIO_new_file(crt, "r");
	if (bio) {
		DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
		BIO_free(bio);
		if (dh) {
			SSL_CTX_set_tmp_dh(ctx, dh);
			DH_free(dh);
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
#ifdef NID_X9_62_prime256v1
			EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
			SSL_CTX_set_tmp_ecdh(ctx, ecdh);
			EC_KEY_free(ecdh);
#endif
#endif
#endif
		}
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
		uwsgi_log("unable to assign key certificate %s\n", key);
		exit(1);
	}

	// if ciphers are specified, prefer server ciphers
	if (ciphers && strlen(ciphers) > 0) {
		if (SSL_CTX_set_cipher_list(ctx, ciphers) == 0) {
			uwsgi_log("unable to set ssl requested ciphers: %s\n", ciphers);
			exit(1);
		}

		SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	}

	// set session context (if possibile), this is required for client certificate authentication
	if (name) {
		SSL_CTX_set_session_id_context(ctx, (unsigned char *) name, strlen(name));
	}

	if (client_ca) {
		if (client_ca[0] == '!') {
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, uwsgi_ssl_verify_callback);
			client_ca++;
		}
		else {
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, uwsgi_ssl_verify_callback);
		}
		// in the future we should allow to set the verify depth
		SSL_CTX_set_verify_depth(ctx, 1);
		if (SSL_CTX_load_verify_locations(ctx, client_ca, NULL) == 0) {
			uwsgi_log("unable to set ssl verify locations for: %s\n", client_ca);
			exit(1);
		}
		STACK_OF(X509_NAME) * list = SSL_load_client_CA_file(client_ca);
		if (!list) {
			uwsgi_log("unable to load client CA certificate: %s\n", client_ca);
			exit(1);
		}

		SSL_CTX_set_client_CA_list(ctx, list);
	}


	SSL_CTX_set_info_callback(ctx, uwsgi_ssl_info_cb);

	// disable session caching by default
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

/*
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
#ifdef UWSGI_DEBUG
	uwsgi_log("[uwsgi-ssl] initialized ssl session cache: %s\n", name);
#endif
	//SSL_CTX_set_timeout
	//SSL_CTX_sess_set_cache_size
	}
*/

	return ctx;
}


char *uwsgi_rsa_sign(char *algo_key, char *message, size_t message_len, unsigned int *s_len) {

	// openssl could not be initialized
	if (!uwsgi.ssl_initialized) {
		uwsgi_ssl_init();
	}

	*s_len = 0;
	EVP_PKEY *pk = NULL;

	char *algo = uwsgi_str(algo_key);
	char *colon = strchr(algo, ':');
	if (!colon) {
		uwsgi_log("invalid RSA signature syntax, must be: <digest>:<pemfile>\n");
		free(algo);
		return NULL;
	}

	*colon = 0;
	char *keyfile = colon + 1;
	char *signature = NULL;

	FILE *kf = fopen(keyfile, "r");
	if (!kf) {
		uwsgi_error_open(keyfile);
		free(algo);
		return NULL;
	}

	if (PEM_read_PrivateKey(kf, &pk, NULL, NULL) == 0) {
		uwsgi_log("unable to load private key: %s\n", keyfile);
		free(algo);
		fclose(kf);
		return NULL;
	}

	fclose(kf);

	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	if (!ctx) {
		free(algo);
		EVP_PKEY_free(pk);
		return NULL;
	}

	const EVP_MD *md = EVP_get_digestbyname(algo);
	if (!md) {
		uwsgi_log("unknown digest algo: %s\n", algo);
		free(algo);
		EVP_PKEY_free(pk);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}

	*s_len = EVP_PKEY_size(pk);
	signature = uwsgi_malloc(*s_len);

	if (EVP_SignInit_ex(ctx, md, NULL) == 0) {
		ERR_print_errors_fp(stderr);
		free(signature);
		signature = NULL;
		*s_len = 0;
		goto clear;
	}

	if (EVP_SignUpdate(ctx, message, message_len) == 0) {
		ERR_print_errors_fp(stderr);
		free(signature);
		signature = NULL;
		*s_len = 0;
		goto clear;
	}


	if (EVP_SignFinal(ctx, (unsigned char *) signature, s_len, pk) == 0) {
		ERR_print_errors_fp(stderr);
		free(signature);
		signature = NULL;
		*s_len = 0;
		goto clear;
	}

clear:
	free(algo);
	EVP_PKEY_free(pk);
	EVP_MD_CTX_destroy(ctx);
	return signature;

}

char *uwsgi_sanitize_cert_filename(char *base, char *key, uint16_t keylen) {
	uint16_t i;
	char *filename = uwsgi_concat4n(base, strlen(base), "/", 1, key, keylen, ".pem\0", 5);

	for (i = strlen(base) + 1; i < (strlen(base) + 1) + keylen; i++) {
		if (filename[i] >= '0' && filename[i] <= '9')
			continue;
		if (filename[i] >= 'A' && filename[i] <= 'Z')
			continue;
		if (filename[i] >= 'a' && filename[i] <= 'z')
			continue;
		if (filename[i] == '.')
			continue;
		if (filename[i] == '-')
			continue;
		if (filename[i] == '_')
			continue;
		filename[i] = '_';
	}

	return filename;
}

#endif

ssize_t uwsgi_pipe(int src, int dst, int timeout) {
	char buf[8192];
	size_t written = -1;
	ssize_t len;

	for (;;) {
		int ret = uwsgi_waitfd(src, timeout);
		if (ret > 0) {
			len = read(src, buf, 8192);
			if (len == 0) {
				return written;
			}
			else if (len < 0) {
				uwsgi_error("read()");
				return -1;
			}

			size_t remains = len;
			while (remains > 0) {
				int ret = uwsgi_waitfd_write(dst, timeout);
				if (ret > 0) {
					len = write(dst, buf, remains);
					if (len > 0) {
						remains -= len;
						written += len;
					}
					else if (len == 0) {
						return written;
					}
					else {
						uwsgi_error("write()");
						return -1;
					}
				}
				else if (ret == 0) {
					goto timeout;
				}
				else {
					return -1;
				}
			}
		}
		else if (ret == 0) {
			goto timeout;
		}
		else {
			return -1;
		}
	}

	return written;
timeout:
	uwsgi_log("timeout while piping from %d to %d !!!\n", src, dst);
	return -1;
}

ssize_t uwsgi_pipe_sized(int src, int dst, size_t required, int timeout) {
	char buf[8192];
	size_t written = 0;
	ssize_t len;

	while (written < required) {
		int ret = uwsgi_waitfd(src, timeout);
		if (ret > 0) {
			len = read(src, buf, UMIN(8192, required - written));
			if (len == 0) {
				return written;
			}
			else if (len < 0) {
				uwsgi_error("read()");
				return -1;
			}

			size_t remains = len;
			while (remains > 0) {
				int ret = uwsgi_waitfd_write(dst, timeout);
				if (ret > 0) {
					len = write(dst, buf, remains);
					if (len > 0) {
						remains -= len;
						written += len;
					}
					else if (len == 0) {
						return written;
					}
					else {
						uwsgi_error("write()");
						return -1;
					}
				}
				else if (ret == 0) {
					goto timeout;
				}
				else {
					return -1;
				}
			}
		}
		else if (ret == 0) {
			goto timeout;
		}
		else {
			return -1;
		}
	}

	return written;
timeout:
	uwsgi_log("timeout while piping from %d to %d !!!\n", src, dst);
	return -1;
}


void uwsgi_set_cpu_affinity() {
	char buf[4096];
	int ret;
	int pos = 0;
	if (uwsgi.cpu_affinity) {
		int base_cpu = (uwsgi.mywid - 1) * uwsgi.cpu_affinity;
		if (base_cpu >= uwsgi.cpus) {
			base_cpu = base_cpu % uwsgi.cpus;
		}
		ret = snprintf(buf, 4096, "mapping worker %d to CPUs:", uwsgi.mywid);
		if (ret < 25) {
			uwsgi_log("unable to initialize cpu affinity !!!\n");
			exit(1);
		}
		pos += ret;
#ifdef __linux__
		cpu_set_t cpuset;
#elif defined(__FreeBSD__)
		cpuset_t cpuset;
#endif
#if defined(__linux__) || defined(__FreeBSD__)
		CPU_ZERO(&cpuset);
		int i;
		for (i = 0; i < uwsgi.cpu_affinity; i++) {
			if (base_cpu >= uwsgi.cpus)
				base_cpu = 0;
			CPU_SET(base_cpu, &cpuset);
			ret = snprintf(buf + pos, 4096 - pos, " %d", base_cpu);
			if (ret < 2) {
				uwsgi_log("unable to initialize cpu affinity !!!\n");
				exit(1);
			}
			pos += ret;
			base_cpu++;
		}
#endif
#ifdef __linux__
		if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset)) {
			uwsgi_error("sched_setaffinity()");
		}
#elif defined(__FreeBSD__)
		if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(cpuset), &cpuset)) {
			uwsgi_error("cpuset_setaffinity");
		}
#endif
		uwsgi_log("%s\n", buf);
	}

}

#ifdef UWSGI_ELF
#if defined(__linux__)
#include <elf.h>
#endif
char *uwsgi_elf_section(char *filename, char *s, size_t * len) {
	struct stat st;
	char *output = NULL;
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_error_open(filename);
		return NULL;
	}

	if (fstat(fd, &st)) {
		uwsgi_error("stat()");
		close(fd);
		return NULL;
	}

	if (st.st_size < EI_NIDENT) {
		uwsgi_log("invalid elf file: %s\n", filename);
		close(fd);
		return NULL;
	}

	char *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		uwsgi_error("mmap()");
		close(fd);
		return NULL;
	}

	if (addr[0] != ELFMAG0)
		goto clear;
	if (addr[1] != ELFMAG1)
		goto clear;
	if (addr[2] != ELFMAG2)
		goto clear;
	if (addr[3] != ELFMAG3)
		goto clear;

	if (addr[4] == ELFCLASS32) {
		// elf header
		Elf32_Ehdr *elfh = (Elf32_Ehdr *) addr;
		// first section
		Elf32_Shdr *sections = ((Elf32_Shdr *) (addr + elfh->e_shoff));
		// number of sections
		int ns = elfh->e_shnum;
		// the names table
		Elf32_Shdr *table = &sections[elfh->e_shstrndx];
		// string table session pointer
		char *names = addr + table->sh_offset;
		Elf32_Shdr *ss = NULL;
		int i;
		for (i = 0; i < ns; i++) {
			char *name = names + sections[i].sh_name;
			if (!strcmp(name, s)) {
				ss = &sections[i];
				break;
			}
		}

		if (ss) {
			*len = ss->sh_size;
			output = uwsgi_concat2n(addr + ss->sh_offset, ss->sh_size, "", 0);
		}
	}
	else if (addr[4] == ELFCLASS64) {
		// elf header
		Elf64_Ehdr *elfh = (Elf64_Ehdr *) addr;
		// first section
		Elf64_Shdr *sections = ((Elf64_Shdr *) (addr + elfh->e_shoff));
		// number of sections
		int ns = elfh->e_shnum;
		// the names table
		Elf64_Shdr *table = &sections[elfh->e_shstrndx];
		// string table session pointer
		char *names = addr + table->sh_offset;
		Elf64_Shdr *ss = NULL;
		int i;
		for (i = 0; i < ns; i++) {
			char *name = names + sections[i].sh_name;
			if (!strcmp(name, s)) {
				ss = &sections[i];
				break;
			}
		}

		if (ss) {
			*len = ss->sh_size;
			output = uwsgi_concat2n(addr + ss->sh_offset, ss->sh_size, "", 0);
		}
	}


clear:
	close(fd);
	munmap(addr, st.st_size);
	return output;
}
#endif

static void *uwsgi_thread_run(void *arg) {
	struct uwsgi_thread *ut = (struct uwsgi_thread *) arg;
	// block all signals
	sigset_t smask;
	sigfillset(&smask);
	pthread_sigmask(SIG_BLOCK, &smask, NULL);

	ut->queue = event_queue_init();
	event_queue_add_fd_read(ut->queue, ut->pipe[1]);

	ut->func(ut);
	return NULL;
}

struct uwsgi_thread *uwsgi_thread_new(void (*func) (struct uwsgi_thread *)) {

	struct uwsgi_thread *ut = uwsgi_calloc(sizeof(struct uwsgi_thread));

#if defined(SOCK_SEQPACKET) && defined(__linux__)
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ut->pipe)) {
#else
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, ut->pipe)) {
#endif
		free(ut);
		return NULL;
	}

	uwsgi_socket_nb(ut->pipe[0]);
	uwsgi_socket_nb(ut->pipe[1]);

	ut->func = func;

	pthread_attr_init(&ut->tattr);
	pthread_attr_setdetachstate(&ut->tattr, PTHREAD_CREATE_DETACHED);
	// 512K should be enough...
	pthread_attr_setstacksize(&ut->tattr, 512 * 1024);

	if (pthread_create(&ut->tid, &ut->tattr, uwsgi_thread_run, ut)) {
		uwsgi_error("pthread_create()");
		goto error;
	}

	return ut;
error:
	close(ut->pipe[0]);
	close(ut->pipe[1]);
	free(ut);
	return NULL;
}

// evaluate a math expression
#ifdef UWSGI_MATHEVAL
double uwsgi_matheval(char *expr) {
#ifdef UWSGI_DEBUG
	uwsgi_log("matheval expr = %s\n", expr);
#endif
	double ret = 0.0;
	void *e = evaluator_create(expr);
	if (!e)
		return ret;
	ret = evaluator_evaluate(e, 0, NULL, NULL);
	evaluator_destroy(e);
	return ret;
}
char *uwsgi_matheval_str(char *expr) {
	double ret = uwsgi_matheval(expr);
	return uwsgi_num2str((int) ret);
}
#endif

int uwsgi_kvlist_parse(char *src, size_t len, char list_separator, char kv_separator, ...) {
	size_t i;
	va_list ap;
	struct uwsgi_string_list *itemlist = NULL;

	char *buf = uwsgi_calloc(len + 1);

	// ok let's start splitting the string
	int escaped = 0;
	char *base = buf;
	char *ptr = buf;
	for (i = 0; i < len; i++) {
		if (src[i] == list_separator && !escaped) {
			*ptr++ = 0;
			uwsgi_string_new_list(&itemlist, base);
			base = ptr;
		}
		else if (src[i] == '\\' && !escaped) {
			escaped = 1;
		}
		else if (escaped) {
			escaped = 0;
		}
		else {
			*ptr++ = src[i];
		}
	}

	if (ptr > base) {
		uwsgi_string_new_list(&itemlist, base);
	}

	struct uwsgi_string_list *usl = itemlist;
	while (usl) {
		len = strlen(usl->value);
		char *item_buf = uwsgi_calloc(len + 1);
		base = item_buf;
		ptr = item_buf;
		escaped = 0;
		for (i = 0; i < len; i++) {
			if (usl->value[i] == kv_separator && !escaped) {
				*ptr++ = 0;
				va_start(ap, kv_separator);
				for (;;) {
					char *p = va_arg(ap, char *);
					if (!p)
						break;
					char **pp = va_arg(ap, char **);
					if (!pp)
						break;
					if (!strcmp(p, base)) {
						*pp = uwsgi_str(usl->value + i + 1);
					}
				}
				va_end(ap);
				base = ptr;
				break;
			}
			else if (usl->value[i] == '\\' && !escaped) {
				escaped = 1;
			}
			else if (escaped) {
				escaped = 0;
			}
			else {
				*ptr++ = usl->value[i];
			}
		}
		free(item_buf);
		usl = usl->next;
	}

	free(buf);
	return 0;
}

int uwsgi_send_http_stats(int fd) {

	char buf[4096];

	int ret = uwsgi_waitfd(fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
	if (ret <= 0)
		return -1;

	if (read(fd, buf, 4096) <= 0)
		return -1;

	struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);
	if (!ub)
		return -1;

	if (uwsgi_buffer_append(ub, "HTTP/1.0 200 OK\r\n", 17))
		goto error;
	if (uwsgi_buffer_append(ub, "Connection: close\r\n", 19))
		goto error;
	if (uwsgi_buffer_append(ub, "Access-Control-Allow-Origin: *\r\n", 32))
		goto error;
	if (uwsgi_buffer_append(ub, "Content-Type: application/json\r\n", 32))
		goto error;
	if (uwsgi_buffer_append(ub, "\r\n", 2))
		goto error;

	if (uwsgi_buffer_send(ub, fd))
		goto error;
	uwsgi_buffer_destroy(ub);
	return 0;

error:
	uwsgi_buffer_destroy(ub);
	return -1;
}

void uwsgi_simple_set_status(struct wsgi_request *wsgi_req, int status) {
	wsgi_req->status = status;
}

void uwsgi_simple_inc_headers(struct wsgi_request *wsgi_req) {
	wsgi_req->header_cnt++;
}

void uwsgi_simple_response_write(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, buf, len);
}

void uwsgi_simple_response_write_header(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	wsgi_req->headers_size += wsgi_req->socket->proto_write_header(wsgi_req, buf, len);
}

ssize_t uwsgi_simple_request_read(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	if (wsgi_req->post_cl == 0)
		return 0;
	if ((size_t) wsgi_req->post_pos >= wsgi_req->post_cl)
		return 0;
	size_t remains = wsgi_req->post_cl - wsgi_req->post_pos;
	remains = UMIN(len, remains);

	int fd = -1;

	if (wsgi_req->body_as_file) {
		fd = fileno((FILE *) wsgi_req->async_post);
	}
	else if (uwsgi.post_buffering > 0) {
		if (wsgi_req->post_cl > (size_t) uwsgi.post_buffering) {
			fd = fileno((FILE *) wsgi_req->async_post);
		}
	}
	else {
		fd = wsgi_req->poll.fd;
	}

	// data in memory ?
	if (fd == -1) {
		memcpy(buf, wsgi_req->post_buffering_buf + wsgi_req->post_buffering_read, remains);
		wsgi_req->post_buffering_read += remains;
		wsgi_req->post_pos += remains;
		return remains;
	}

	if (uwsgi_waitfd(fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]) <= 0) {
		uwsgi_log("error waiting for request body");
		return -1;
	}

	ssize_t rlen = read(fd, buf, remains);
	if (rlen < 0) {
		uwsgi_error("error reading request body:");
		return -1;
	}

	wsgi_req->post_pos += rlen;
	return rlen;
}

int uwsgi_plugin_modifier1(char *plugin) {
	int ret = -1;
	char *symbol_name = uwsgi_concat2(plugin, "_plugin");
	struct uwsgi_plugin *up = dlsym(RTLD_DEFAULT, symbol_name);
	if (!up)
		goto end;
	ret = up->modifier1;
end:
	free(symbol_name);
	return ret;
}
