#include "uwsgi.h"


extern struct uwsgi_server uwsgi;

#ifdef __BIG_ENDIAN__
uint16_t uwsgi_swap16(uint16_t x) {
	return (uint16_t) ((x & 0xff) << 8 | (x & 0xff00) >> 8);
}
#endif

void set_harakiri(int sec) {
	if (uwsgi.workers) {
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

#ifndef UNBIT

void daemonize(char *logfile) {
	pid_t pid;
	int fd, fdin;


	pid = fork();
	if (pid < 0) {
		perror("fork()");
		exit(1);
	}
	if (pid != 0) {
		exit(0);
	}

	if (setsid() < 0) {
		perror("setsid()");
		exit(1);
	}


	/* refork... */
	pid = fork();
	if (pid < 0) {
		perror("fork()");
		exit(1);
	}
	if (pid != 0) {
		exit(0);
	}

	umask(0);


	/*if (chdir("/") != 0) {
	   perror("chdir()");
	   exit(1);
	   } */


	fdin = open("/dev/null", O_RDWR);
	if (fdin < 0) {
		perror("open()");
		exit(1);
	}

	fd = open(logfile, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP);
	if (fd < 0) {
		perror("open()");
		exit(1);
	}

	/* stdin */
	if (dup2(fdin, 0) < 0) {
		perror("dup2()");
		exit(1);
	}


	/* stdout */
	if (dup2(fd, 1) < 0) {
		perror("dup2()");
		exit(1);
	}

	/* stderr */
	if (dup2(fd, 2) < 0) {
		perror("dup2()");
		exit(1);
	}

	close(fd);


}


#endif

char *uwsgi_get_cwd() {

	int newsize = 256;
	char *cwd;

	cwd = malloc(newsize);
	if (cwd == NULL) {
		perror("malloc()");
		exit(1);
	}

	if (getcwd(cwd, newsize) == NULL) {
		newsize = errno;
		fprintf(stderr, "need a bigger buffer (%d bytes) for getcwd(). doing reallocation.\n", newsize);
		free(cwd);
		cwd = malloc(newsize);
		if (cwd == NULL) {
			perror("malloc()");
			exit(1);
		}
		if (getcwd(cwd, newsize) == NULL) {
			perror("getcwd()");
			exit(1);
		}
	}

	return cwd;

}

void internal_server_error(int fd, char *message) {
#ifndef UNBIT
        if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
#endif
                uwsgi.wsgi_req->headers_size = write(fd, "HTTP/1.1 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 63);
#ifndef UNBIT
        }
        else {
                uwsgi.wsgi_req->headers_size = write(fd, "Status: 500 Internal Server Error\r\nContent-type: text/html\r\n\r\n", 62);
        }
        uwsgi.wsgi_req->header_cnt = 2;
#endif
        uwsgi.wsgi_req->response_size = write(fd, "<h1>uWSGI Error</h1>", 20);
        uwsgi.wsgi_req->response_size += write(fd, message, strlen(message));
}

void uwsgi_as_root() {

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
}

void uwsgi_close_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int waitpid_status ;

        gettimeofday(&wsgi_req->end_of_request, NULL);
        uwsgi->workers[uwsgi->mywid].running_time += (double) (((double) (wsgi_req->end_of_request.tv_sec * 1000000 + wsgi_req->end_of_request.tv_usec) - (double) (wsgi_req->start_of_request.tv_sec * 1000000 + wsgi_req->start_of_request.tv_usec)) / (double) 1000.0);


	// get memory usage
        if (uwsgi->shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1)
        	get_memusage();

        // close the connection with the webserver
        //close(wsgi_req->poll.fd);
        uwsgi->workers[0].requests++;
        uwsgi->workers[uwsgi->mywid].requests++;

	// after_request hook
	(*uwsgi->shared->after_hooks[wsgi_req->modifier]) (uwsgi, wsgi_req);


	// leave harakiri mode
	if (uwsgi->workers[uwsgi->mywid].harakiri > 0) {
        	set_harakiri(0);
	}

	// defunct process reaper
        if (uwsgi->shared->options[UWSGI_OPTION_REAPER] == 1) {
        	waitpid(-1, &waitpid_status, WNOHANG);
	}
        // reset request
	memset(wsgi_req, 0, sizeof(struct wsgi_request));

	if (uwsgi->shared->options[UWSGI_OPTION_MAX_REQUESTS] > 0 && uwsgi->workers[uwsgi->mywid].requests >= uwsgi->shared->options[UWSGI_OPTION_MAX_REQUESTS]) {
        	goodbye_cruel_world();
	}

}
