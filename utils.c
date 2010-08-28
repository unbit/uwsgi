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

	int fd ;

#ifdef UWSGI_UDP
	char *udp_port;
	struct sockaddr_in udp_addr;

	udp_port = strchr(logfile, ':');
	if (udp_port) {
		udp_port[0] = 0 ;
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
	if (dup2(fd, 1) < 0) {
		uwsgi_error("dup2()");
		exit(1);
	}

	/* stderr */
	if (dup2(fd, 2) < 0) {
		uwsgi_error("dup2()");
		exit(1);
	}

	close(fd);
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

	if (!getuid()) {
                uwsgi_log("uWSGI running as root, you can use --uid/--gid/--chroot options\n");
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

void uwsgi_close_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int waitpid_status ;

        gettimeofday(&wsgi_req->end_of_request, NULL);
        uwsgi->workers[uwsgi->mywid].running_time += (double) (((double) (wsgi_req->end_of_request.tv_sec * 1000000 + wsgi_req->end_of_request.tv_usec) - (double) (wsgi_req->start_of_request.tv_sec * 1000000 + wsgi_req->start_of_request.tv_usec)) / (double) 1000.0);


	// get memory usage
        if (uwsgi->shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1)
        	get_memusage();


        // close the connection with the webserver
	if (!wsgi_req->fd_closed) {
		// TODO find a way to discard pending data
		close(wsgi_req->poll.fd);
	}
        uwsgi->workers[0].requests++;
        uwsgi->workers[uwsgi->mywid].requests++;


	// after_request hook
	(*uwsgi->shared->after_hooks[wsgi_req->uh.modifier1]) (uwsgi, wsgi_req);

	// leave harakiri mode
	if (uwsgi->shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
        	set_harakiri(0);
	}

	// defunct process reaper
        if (uwsgi->shared->options[UWSGI_OPTION_REAPER] == 1 || uwsgi->grunt) {
        	while( waitpid(-1, &waitpid_status, WNOHANG) > 0) ;
	}
        // reset request
	memset(wsgi_req, 0, sizeof(struct wsgi_request));

	if (uwsgi->shared->options[UWSGI_OPTION_MAX_REQUESTS] > 0 && uwsgi->workers[uwsgi->mywid].requests >= uwsgi->shared->options[UWSGI_OPTION_MAX_REQUESTS]) {
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
	wsgi_req->hvec = &uwsgi.async_hvec[wsgi_req->async_id];
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

        if (uwsgi.shared->options[UWSGI_OPTION_LOGGING]) gettimeofday(&wsgi_req->start_of_request, NULL);

	if (!uwsgi_parse_response(&wsgi_req->poll, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], (struct uwsgi_header *) wsgi_req, wsgi_req->buffer)) {
		return -1;
	}

	// enter harakiri mode
	if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
        	set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
	}

        wsgi_req->async_status = (*uwsgi.shared->hooks[wsgi_req->uh.modifier1]) (&uwsgi, wsgi_req);

	return 0;
}

int wsgi_req_accept(int fd, struct wsgi_request *wsgi_req) {

	wsgi_req->poll.fd = accept(fd, (struct sockaddr *) &wsgi_req->c_addr, (socklen_t *) &wsgi_req->c_len);

	if (wsgi_req->poll.fd < 0) {
        	uwsgi_error("accept()");
                return -1;
	}

	return 0;
}

inline struct wsgi_request *current_wsgi_req(struct uwsgi_server *uwsgi) {

	struct wsgi_request *wsgi_req = uwsgi->wsgi_req;

#ifdef UWSGI_STACKLESS
        if (uwsgi->stackless && uwsgi->async >1) {
                PyThreadState *ts = PyThreadState_GET();
                wsgi_req = find_request_by_tasklet(ts->st.current);
        }
#endif

	return wsgi_req;

}

void sanitize_args(struct uwsgi_server *uwsgi) {

#ifdef UWSGI_PROFILER
	if (uwsgi->enable_profiler) {
		uwsgi_log("*** Profiler enabled, do not use it in production environment !!! ***\n");
		uwsgi->async = 1;
	}
#endif

#ifdef UWSGI_UGREEN
#ifdef UWSGI_THREADING
	if (uwsgi->ugreen) {
                if (uwsgi->has_threads) {
                        uwsgi_log("--- python threads will be disabled in uGreen mode ---\n");
                        uwsgi->has_threads = 0;
                }
	}
#endif
#endif

	if (uwsgi->wsgi_config) {
		uwsgi->single_interpreter = 1 ;
	}

	if (uwsgi->shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
		if (!uwsgi->post_buffering) {
			 uwsgi_log(" *** WARNING: you have enabled harakiri without post buffering. Slow upload could be rejected on post-unbuffered webservers *** \n");
		}
	}

#ifdef UWSGI_HTTP
	if (uwsgi->http && !uwsgi->http_only) {
		uwsgi->vacuum = 1;
	}
#endif
}

void env_to_arg(char *src, char *dst) {
	int i;
	int val = 0 ;

	for(i=0;i<strlen(src);i++) {
		if (src[i] == '=') {
			val = 1 ;
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

void parse_sys_envs(char **envs, struct option *long_options) {

	struct option *lopt, *aopt;

	char **uenvs = envs;
	char *earg, *eq_pos ;

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
                        eq_pos[0] = 0 ;

                        lopt = long_options;

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

		rlen = 24 + 3 ;

	}

	va_start (ap, fmt);
	rlen += vsnprintf(logpkt + rlen, 4096 - rlen, fmt, ap );
	va_end(ap);

	// do not check for errors
	rlen = write(2, logpkt, rlen);
}
