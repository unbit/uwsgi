#include "uwsgi.h"


extern struct uwsgi_server uwsgi;

#ifdef __BIG_ENDIAN__
uint16_t uwsgi_swap16(uint16_t x) {
	return (uint16_t) ((x & 0xff) << 8 | (x & 0xff00) >> 8);
}

uint32_t uwsgi_swap32(uint32_t x) {
	x = ( (x<<8) & 0xFF00FF00 ) | ( (x>>8) & 0x00FF00FF );
	return (x>>16) | (x<<16);
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

int check_hex(char *str, int len) {
	int i;
	for(i=0;i<len;i++) {
        	if (
                	(str[i] < '0' && str[i] > '9') &&
                	(str[i] < 'a' && str[i] > 'f') &&
                	(str[i] < 'A' && str[i] > 'F')
		) {
			return 0;
		}
        }

	return 1;

}

void inc_harakiri(int sec) {
	if (uwsgi.master_process) {
		uwsgi.workers[uwsgi.mywid].harakiri += sec;
	}
	else {
		alarm(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] + sec);
	}
}

void set_harakiri(int sec) {
	if (uwsgi.master_process) {
		if (sec == 0) {
			uwsgi.workers[uwsgi.mywid].harakiri = 0;
		}
		else {
			uwsgi.workers[uwsgi.mywid].harakiri = time(NULL) + sec;
		}
	}
	else {
		alarm(sec);
	}
}

void daemonize(char *logfile) {
	pid_t pid;
	int fdin;

	pid = fork();
	if (pid < 0) {
		uwsgi_error("fork()");
		exit(1);
	}
	if (pid != 0) {
		exit(0);
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
		exit(0);
	}

	umask(0);

	/*if (chdir("/") != 0) {
	  uwsgi_error("chdir()");
	  exit(1);
	  } */


	fdin = open("/dev/null", O_RDWR);
	if (fdin < 0) {
		uwsgi_error("open()");
		exit(1);
	}

	/* stdin */
	if (dup2(fdin, 0) < 0) {
		uwsgi_error("dup2()");
		exit(1);
	}


	logto(logfile);
}

void logto(char *logfile) {

	int fd;

#ifdef UWSGI_UDP
	char *udp_port;
	struct sockaddr_in udp_addr;

	udp_port = strchr(logfile, ':');
	if (udp_port) {
		udp_port[0] = 0;
		if ( !udp_port[1] || !logfile[0] ) {
			uwsgi_log("invalid udp address\n");
			exit(1);
		}

		fd = socket(AF_INET,  SOCK_DGRAM, 0);
		if (fd < 0) {
			uwsgi_error("socket()");
			exit(1);
		}

		memset(&udp_addr, 0, sizeof(struct sockaddr_in));

		udp_addr.sin_family = AF_INET;
		udp_addr.sin_port = htons(atoi(udp_port+1));
		udp_addr.sin_addr.s_addr = inet_addr(logfile);

		if (connect(fd, (const struct sockaddr *) &udp_addr, sizeof(struct sockaddr_in)) < 0) {
			uwsgi_error("connect()");
			exit(1);
		}
	}
	else {
#endif
		fd = open(logfile, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP);
		if (fd < 0) {
			uwsgi_error("open()");
			exit(1);
		}
#ifdef UWSGI_UDP
		uwsgi.logfile = logfile;
	}
#endif


	/* stdout */
	if (fd != 1) {
		if (dup2(fd, 1) < 0) {
			uwsgi_error("dup2()");
			exit(1);
		}
		close(fd);
	}

	/* stderr */
	if (dup2(1, 2) < 0) {
		uwsgi_error("dup2()");
		exit(1);
	}
}

char *uwsgi_get_cwd() {

	int newsize = 256;
	char *cwd;

	cwd = malloc(newsize);
	if (cwd == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}

	if (getcwd(cwd, newsize) == NULL) {
		newsize = errno;
		uwsgi_log("need a bigger buffer (%d bytes) for getcwd(). doing reallocation.\n", newsize);
		free(cwd);
		cwd = malloc(newsize);
		if (cwd == NULL) {
			uwsgi_error("malloc()");
			exit(1);
		}
		if (getcwd(cwd, newsize) == NULL) {
			uwsgi_error("getcwd()");
			exit(1);
		}
	}

	return cwd;

}

void internal_server_error(int fd, char *message) {
	if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
		uwsgi.wsgi_req->headers_size = write(fd, "HTTP/1.1 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 63);
	}
	else {
		uwsgi.wsgi_req->headers_size = write(fd, "Status: 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 62);
	}
	uwsgi.wsgi_req->header_cnt = 2;

	uwsgi.wsgi_req->response_size = write(fd, "<h1>uWSGI Error</h1>", 20);
	uwsgi.wsgi_req->response_size += write(fd, message, strlen(message));
}

void uwsgi_as_root() {

#ifdef __linux__
	char *cgroup_taskfile;
	int i;
	FILE *cgroup;
	char *cgroup_opt;
#endif

	if (!getuid()) {
		uwsgi_log("uWSGI running as root, you can use --uid/--gid/--chroot options\n");

#ifdef __linux__
		if (uwsgi.cgroup) {
			if (mkdir(uwsgi.cgroup, S_IRWXU | S_IROTH | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) {
				uwsgi_log("using Linux cgroup %s\n", uwsgi.cgroup);
			}
			else {
				uwsgi_log("created Linux cgroup %s\n", uwsgi.cgroup);
			}
			cgroup_taskfile = uwsgi_concat2(uwsgi.cgroup, "/tasks");	
			cgroup = fopen(cgroup_taskfile, "w");
			if (!cgroup) {
				uwsgi_error("fopen");
				exit(1);
			}
			if (fprintf(cgroup, "%d\n", (int) getpid()) < 0) {
				uwsgi_log( "could not set cgroup\n");
				exit(1);
			}
			fclose(cgroup);
			free(cgroup_taskfile);

			for(i=0;i<uwsgi.cgroup_opt_cnt;i++) {
				cgroup_opt = strchr( uwsgi.cgroup_opt[i], '=' );
				if (!cgroup_opt) {
					cgroup_opt = strchr( uwsgi.cgroup_opt[i], ':' );
					if (!cgroup_opt) {
						uwsgi_log("invalid cgroup-opt syntax\n");
						exit(1);
					}
				}

				cgroup_opt[0] = 0;
				cgroup_opt++;

				cgroup_taskfile = uwsgi_concat3(uwsgi.cgroup, "/", uwsgi.cgroup_opt[i]);
				cgroup = fopen(cgroup_taskfile, "w");
				if (!cgroup) {
					uwsgi_error("fopen");
					exit(1);
				}
				if (fprintf(cgroup, "%s\n", cgroup_opt) < 0) {
					uwsgi_log( "could not set cgroup option %s to %s\n", uwsgi.cgroup_opt[i], cgroup_opt);
					exit(1);
				}
				fclose(cgroup);
				free(cgroup_taskfile);
			}
		}
#endif
		if (uwsgi.chroot) {
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
		if (uwsgi.gid) {
			uwsgi_log("setgid() to %d\n", uwsgi.gid);
			if (setgid(uwsgi.gid)) {
				uwsgi_error("setgid()");
				exit(1);
			}
		}
		if (uwsgi.uid) {
			uwsgi_log("setuid() to %d\n", uwsgi.uid);
			if (setuid(uwsgi.uid)) {
				uwsgi_error("setuid()");
				exit(1);
			}
		}

		if (!getuid()) {
			uwsgi_log(" *** WARNING: you are running uWSGI as root !!! (use the --uid flag) *** \n");
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

void uwsgi_close_request(struct wsgi_request *wsgi_req) {

	int waitpid_status;

	gettimeofday(&wsgi_req->end_of_request, NULL);
	uwsgi.workers[uwsgi.mywid].running_time += (double) (((double) (wsgi_req->end_of_request.tv_sec * 1000000 + wsgi_req->end_of_request.tv_usec) - (double) (wsgi_req->start_of_request.tv_sec * 1000000 + wsgi_req->start_of_request.tv_usec)) / (double) 1000.0);


	// get memory usage
	if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1)
		get_memusage();


	// close the connection with the webserver
	if (!wsgi_req->fd_closed) {
		// NOTE, if we close the socket before receiving eventually sent data, socket layer will send a RST
		close(wsgi_req->poll.fd);
	}
	uwsgi.workers[0].requests++;
	uwsgi.workers[uwsgi.mywid].requests++;

	if (uwsgi.cores > 1) {
		uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id]->requests++;
	}

	// after_request hook
	if (uwsgi.p[wsgi_req->uh.modifier1]->after_request) uwsgi.p[wsgi_req->uh.modifier1]->after_request(wsgi_req);

	// leave harakiri mode
	if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
		set_harakiri(0);
	}

	// defunct process reaper
	if (uwsgi.shared->options[UWSGI_OPTION_REAPER] == 1 || uwsgi.grunt) {
		while( waitpid(WAIT_ANY, &waitpid_status, WNOHANG) > 0);
	}
	// reset request
	memset(wsgi_req, 0, sizeof(struct wsgi_request));

	if (uwsgi.shared->options[UWSGI_OPTION_MAX_REQUESTS] > 0 && uwsgi.workers[uwsgi.mywid].requests >= uwsgi.shared->options[UWSGI_OPTION_MAX_REQUESTS]) {
		goodbye_cruel_world();
	}


}

void wsgi_req_setup(struct wsgi_request *wsgi_req, int async_id) {

	wsgi_req->poll.events = POLLIN;
	wsgi_req->app_id = uwsgi.default_app;
	wsgi_req->async_id = async_id;
#ifdef UWSGI_SENDFILE
	wsgi_req->sendfile_fd = -1;
#endif

#ifdef UWSGI_ASYNC
	wsgi_req->async_waiting_fd = -1;
#endif
	wsgi_req->hvec = uwsgi.async_hvec[wsgi_req->async_id];
	wsgi_req->buffer = uwsgi.async_buf[wsgi_req->async_id];

#ifdef UWSGI_ROUTING
	wsgi_req->ovector = uwsgi.async_ovector[wsgi_req->async_id];
#endif

	if (uwsgi.post_buffering > 0) {
		wsgi_req->post_buffering_buf = uwsgi.async_post_buf[wsgi_req->async_id];
	}

}

int wsgi_req_recv(struct wsgi_request *wsgi_req) {

	UWSGI_SET_IN_REQUEST;

	gettimeofday(&wsgi_req->start_of_request, NULL);

	if (!uwsgi_parse_response(&wsgi_req->poll, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], (struct uwsgi_header *) wsgi_req, wsgi_req->buffer)) {
		return -1;
	}

	// enter harakiri mode
	if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
		set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
	}

	wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);

	return 0;
}


int wsgi_req_simple_accept(struct wsgi_request *wsgi_req, int fd) {

	wsgi_req->poll.fd = accept(fd, (struct sockaddr *) &wsgi_req->c_addr, (socklen_t *) &wsgi_req->c_len);

	if (wsgi_req->poll.fd < 0) {
		uwsgi_error("accept()");
		return -1;
	}

	if (uwsgi.close_on_exec) {
		fcntl(wsgi_req->poll.fd, F_SETFD, FD_CLOEXEC);
	}

	return 0;
}

int wsgi_req_accept(struct wsgi_request *wsgi_req) {

	int i;
	int ret;

	ret = poll(uwsgi.sockets_poll, uwsgi.sockets_cnt, -1);

	if (ret < 0) {
		uwsgi_error("poll()");
		return -1;
	}


	for(i=0;i<uwsgi.sockets_cnt;i++) {

		if (uwsgi.sockets_poll[i].revents & POLLIN) {
			wsgi_req->poll.fd = accept(uwsgi.sockets_poll[i].fd, (struct sockaddr *) &wsgi_req->c_addr, (socklen_t *) &wsgi_req->c_len);

			if (wsgi_req->poll.fd < 0) {
				uwsgi_error("accept()");
				return -1;
			}

			if (uwsgi.close_on_exec) {
				fcntl(wsgi_req->poll.fd, F_SETFD, FD_CLOEXEC);
			}

			return 0;
		}
	}

	return -1;
}

#ifdef UWSGI_STACKLESS
inline struct wsgi_request *current_wsgi_req() {

	struct wsgi_request *wsgi_req = uwsgi.wsgi_req;

	if (uwsgi.stackless && uwsgi.async >1) {
		PyThreadState *ts = PyThreadState_GET();
		wsgi_req = find_request_by_tasklet(ts->st.current);
	}

	return wsgi_req;

}
#endif

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
}

void env_to_arg(char *src, char *dst) {
	int i;
	int val = 0;

	for(i=0;i< (int) strlen(src);i++) {
		if (src[i] == '=') {
			val = 1;
		}
		if (val) {
			dst[i] = src[i];
		}
		else {
			dst[i] = tolower( (int) src[i]);
			if (dst[i] == '_') {
				dst[i] = '-';
			}
		}
	}

	dst[strlen(src)] = 0;
}

void parse_sys_envs(char **envs) {

	struct option *lopt, *aopt;

	char **uenvs = envs;
	char *earg, *eq_pos;

	while(*uenvs) {
		if (!strncmp(*uenvs, "UWSGI_", 6)) {
			earg = malloc(strlen(*uenvs+6)+1);
			if (!earg) {
				uwsgi_error("malloc()");
				exit(1);
			}
			env_to_arg(*uenvs+6, earg);
			eq_pos = strchr(earg, '=');
			if (!eq_pos) {
				break;
			}
			eq_pos[0] = 0;

			lopt = uwsgi.long_options;

			while ((aopt = lopt)) {
				if (!aopt->name)
					break;
				if (!strcmp(earg, aopt->name)) {
					if (aopt->flag) {
						*aopt->flag = aopt->val;
					}
					else {
						if (eq_pos[1] != 0) {
							manage_opt(aopt->val, eq_pos+1);
						}
						else {
							manage_opt(aopt->val, NULL);
						}
					}
				}
				lopt++;
			}

		}
		uenvs++;
	}

}

//use this instead of fprintf to avoid buffering mess with udp logging
void uwsgi_log(const char *fmt, ...) {
	va_list ap;
	char logpkt[4096];
	int rlen = 0;

	struct timeval tv;

	if (uwsgi.logdate) {
		gettimeofday(&tv, NULL);

		memcpy( logpkt, ctime( (const time_t *) &tv.tv_sec), 24);
		memcpy( logpkt + 24, " - ", 3);

		rlen = 24 + 3;

	}

	va_start (ap, fmt);
	rlen += vsnprintf(logpkt + rlen, 4096 - rlen, fmt, ap );
	va_end(ap);

	// do not check for errors
	rlen = write(2, logpkt, rlen);
}

void uwsgi_log_verbose(const char *fmt, ...) {

	va_list ap;
	char logpkt[4096];
	int rlen = 0;

	struct timeval tv;

	gettimeofday(&tv, NULL);

	memcpy( logpkt, ctime( (const time_t *) &tv.tv_sec), 24);
	memcpy( logpkt + 24, " - ", 3);

	rlen = 24 + 3;

	va_start (ap, fmt);
	rlen += vsnprintf(logpkt + rlen, 4096 - rlen, fmt, ap );
	va_end(ap);

	// do not check for errors
	rlen = write(2, logpkt, rlen);
}

inline int uwsgi_strncmp(char *src, int slen, char *dst, int dlen) {

	if (slen != dlen) return 1;

	return memcmp(src, dst, dlen);

}

inline int uwsgi_startswith(char *src, char *what, int wlen) {

	int i;

	for(i=0;i<wlen;i++) {
		if (src[i] != what[i]) return -1;
	}
	
	return 0;
}

char *uwsgi_concatn(int c, ...) {

	va_list s;
	char *item;
	int j = c;
	char *buf;
	size_t len = 1;
	size_t tlen = 1;

	va_start( s, c);
	while(j>0) {
		item = va_arg( s, char *);
		if (item == NULL) {
			break;
		}
		len += va_arg( s, int);
		j--;
	}
	va_end( s );


	buf = malloc(len);
	if (buf == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}
	memset( buf, 0, len);

	j = c;

	len = 0;

	va_start( s, c);
	while(j>0) {
		item = va_arg( s, char *);
		if (item == NULL) {
			break;
		}
		tlen = va_arg( s, int);
		memcpy(buf + len, item, tlen);
		len += tlen;
		j--;
	}
	va_end( s );


	return buf;

}

char *uwsgi_concat2(char *one, char *two) {

	char *buf;
	size_t len = strlen(one) + strlen(two) + 1;


	buf = malloc(len);
	if (buf == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}
	buf[len-1] = 0;

	memcpy( buf, one, strlen(one));
	memcpy( buf + strlen(one) , two, strlen(two));

	return buf;

}

char *uwsgi_concat4(char *one, char *two, char *three, char *four) {

	char *buf;
	size_t len = strlen(one) + strlen(two) + strlen(three) + strlen(four) + 1;


	buf = malloc(len);
	if (buf == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}
	buf[len-1] = 0;

	memcpy( buf, one, strlen(one));
	memcpy( buf + strlen(one) , two, strlen(two));
	memcpy( buf + strlen(one) + strlen(two) , three, strlen(three));
	memcpy( buf + strlen(one) + strlen(two) + strlen(three) , four, strlen(four));

	return buf;

}


char *uwsgi_concat3(char *one, char *two, char *three) {

	char *buf;
	size_t len = strlen(one) + strlen(two) + strlen(three) + 1;


	buf = malloc(len);
	if (buf == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}
	buf[len-1] = 0;

	memcpy( buf, one, strlen(one));
	memcpy( buf + strlen(one) , two, strlen(two));
	memcpy( buf + strlen(one) + strlen(two) , three, strlen(three));

	return buf;

}

char *uwsgi_concat2n(char *one, int s1, char *two, int s2) {

	char *buf;
	size_t len = s1 + s2 + 1;


	buf = malloc(len);
	if (buf == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}
	buf[len-1] = 0;

	memcpy( buf, one, s1);
	memcpy( buf + s1, two, s2);

	return buf;

}

char *uwsgi_concat3n(char *one, int s1, char *two, int s2, char *three, int s3) {

	char *buf;
	size_t len = s1 + s2 + s3 + 1;


	buf = malloc(len);
	if (buf == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}
	buf[len-1] = 0;

	memcpy( buf, one, s1);
	memcpy( buf + s1, two, s2);
	memcpy( buf + s1 + s2, three, s3);

	return buf;

}

char *uwsgi_concat4n(char *one, int s1, char *two, int s2, char *three, int s3, char *four, int s4) {

	char *buf;
	size_t len = s1 + s2 + s3 + s4 + 1;


	buf = malloc(len);
	if (buf == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}
	buf[len-1] = 0;

	memcpy( buf, one, s1);
	memcpy( buf + s1, two, s2);
	memcpy( buf + s1 + s2, three, s3);
	memcpy( buf + s1 + s2 + s3, four, s4);

	return buf;

}



char *uwsgi_concat(int c, ... ) {

	va_list s;
	char *item;
	size_t len = 1;
	int j = c;
	char *buf;

	va_start( s, c);
	while(j>0) {
		item = va_arg( s, char *);
		if (item == NULL) {
			break;
		}
		len += (int) strlen(item);
		j--;
	}
	va_end( s );


	buf = malloc(len);
	if (buf == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}
	memset( buf, 0, len);

	j = c;

	len = 0;

	va_start( s, c);
	while(j>0) {
		item = va_arg( s, char *);
		if (item == NULL) {
			break;
		}
		memcpy(buf + len, item, strlen(item));
		len += strlen(item);	
		j--;
	}
	va_end( s );


	return buf;

}

char *uwsgi_strncopy(char *s, int len) {

	char *buf;

	buf = malloc(len + 1);
	if (buf == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}
	buf[len] = 0;

	memcpy(buf, s, len);

	return buf;

}


int uwsgi_get_app_id(char *script_name, int script_name_len) {

	int i;

	for(i=0;i<uwsgi.apps_cnt;i++) {
		if (!uwsgi.apps[i].mountpoint_len) {
			continue;
		}	
		if (!uwsgi_strncmp(uwsgi.apps[i].mountpoint, uwsgi.apps[i].mountpoint_len, script_name, script_name_len)) {
			return i;
		}
	}

	return -1;
}

int count_options(struct option *lopt) {
	struct option *aopt;
	int count = 0;

	while ( (aopt = lopt) ) {
		if (!aopt->name) break;
		count++;
		lopt++;
	}

	return count;
}

int uwsgi_read_whole_body(struct wsgi_request *wsgi_req, char *buf, size_t len) {

	size_t post_remains = wsgi_req->post_cl;
	ssize_t post_chunk;
	int ret,i;
	int upload_progress_fd = -1;
	char *upload_progress_filename = NULL;
	const char *x_progress_id = "X-Progress-ID=";
	char *xpi_ptr = (char *) x_progress_id ;
	

	wsgi_req->async_post = tmpfile();
	if (!wsgi_req->async_post) {
		uwsgi_error("tmpfile()");
		return 0;
	}

	if (uwsgi.upload_progress) {
		// first check for X-Progress-ID size
		// separator + 'X-Progress-ID' + '=' + uuid	
		if (wsgi_req->uri_len > 51) {
			for(i=0;i<wsgi_req->uri_len;i++) {
				if (wsgi_req->uri[i] == xpi_ptr[0]) {
					if (xpi_ptr[0] == '=') {
						if (wsgi_req->uri+i+36 <= wsgi_req->uri+wsgi_req->uri_len) {
							upload_progress_filename = wsgi_req->uri+i+1 ;
						}
						break;
					}
					xpi_ptr++;
				}
				else {
					xpi_ptr = (char *) x_progress_id ;
				}
			}

			// now check for valid uuid (from spec available at http://en.wikipedia.org/wiki/Universally_unique_identifier)
			if (upload_progress_filename) {

				uwsgi_log("upload progress uuid = %.*s\n", 36, upload_progress_filename);
				if (!check_hex(upload_progress_filename, 8)) goto cycle;
				if (upload_progress_filename[8] != '-') goto cycle;

				if (!check_hex(upload_progress_filename+9, 4)) goto cycle;
				if (upload_progress_filename[13] != '-') goto cycle;

				if (!check_hex(upload_progress_filename+14, 4)) goto cycle;
				if (upload_progress_filename[18] != '-') goto cycle;

				if (!check_hex(upload_progress_filename+19, 4)) goto cycle;
				if (upload_progress_filename[23] != '-') goto cycle;

				if (!check_hex(upload_progress_filename+24, 12)) goto cycle;

				upload_progress_filename = uwsgi_concat4n(uwsgi.upload_progress, strlen(uwsgi.upload_progress), "/",1,upload_progress_filename, 36, ".js", 3);
				// here we use O_EXCL to avoid eventual application bug in uuid generation/using
				upload_progress_fd = open(upload_progress_filename, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP);	
				if (upload_progress_fd < 0) {
					uwsgi_error("open()");
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
	while(post_remains > 0) {
		if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
			inc_harakiri(uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		}

		ret = poll(&wsgi_req->poll, 1, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT] * 1000);
        	if (ret < 0) {
                	uwsgi_error("poll()");
			goto end;		
        	}

		if (!ret) {
			uwsgi_log("buffering POST data timedout !!!\n");
			goto end;		
		}

		if (post_remains > len) {
			post_chunk = read(wsgi_req->poll.fd, buf, len);
		}
		else {
			post_chunk = read(wsgi_req->poll.fd, buf, post_remains);
		} 
		if (post_chunk < 0) {
			uwsgi_error("read()");
			goto end;		
		}
		if (!fwrite(buf, post_chunk, 1, wsgi_req->async_post)) {
			uwsgi_error("fwrite()");
			goto end;		
		}
		if (upload_progress_fd > -1) {
			//write json data to the upload progress file
			if (lseek(upload_progress_fd, 0, SEEK_SET)) {
				uwsgi_error("lseek()");
				goto end;		
			}
			
			// resue buf for json buffer
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

void add_exported_option(int i, char *value) {

	char *key = NULL;
	struct option *lopt, *aopt;

	if (i == 0) {
		key = value;
		value = NULL;
	}
	else {
		lopt = uwsgi.long_options;
        	while ((aopt = lopt)) {
			if (!aopt->name)
                		break;
			if (aopt->val == 0 && *aopt->flag == i) {
				key = (char *) aopt->name;
				break;
			}
			if (aopt->val == i) {
				key = (char *) aopt->name;
				break;
			}
			lopt++;
		}
	}

	//uwsgi_log("%s = %s\n", key, value);

	if (!key) return;



	if (!uwsgi.exported_opts) {
		uwsgi.exported_opts = malloc(sizeof(struct uwsgi_opt*));
		if (!uwsgi.exported_opts) {
			uwsgi_error("malloc()");
			exit(1);
		}
	}
	else {
		uwsgi.exported_opts = realloc(uwsgi.exported_opts, sizeof(struct uwsgi_opt*) * (uwsgi.exported_opts_cnt+1));
		if (!uwsgi.exported_opts) {
			uwsgi_error("realloc()");
			exit(1);
		}
	}


	uwsgi.exported_opts[uwsgi.exported_opts_cnt] = malloc(sizeof(struct uwsgi_opt));
	if (!uwsgi.exported_opts[uwsgi.exported_opts_cnt]) {
		uwsgi_error("malloc()");
		exit(1);
	}
	uwsgi.exported_opts[uwsgi.exported_opts_cnt]->key = key;
	uwsgi.exported_opts[uwsgi.exported_opts_cnt]->value = value;
	uwsgi.exported_opts_cnt++;

}

int uwsgi_waitfd(int fd, int timeout) {

	int ret;
	struct pollfd upoll[1];

	upoll[0].fd = fd;
	upoll[0].events = POLLIN;

	if (!timeout) timeout = uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT];

	timeout = timeout*1000;
	if (timeout < 0) timeout = -1;

	ret = poll(upoll, 1, timeout);

	if (ret < 0) {
		uwsgi_error("poll()");
	}

	return ret;
}
