#ifdef UWSGI_SPOOLER
#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

pid_t spooler_start() {

	pid_t pid = fork();
	if (pid < 0) {
		uwsgi_error("fork()");
		exit(1);
	}
	else if (pid == 0) {
		struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
		while(uwsgi_sock) {
			close(uwsgi_sock->fd);
			uwsgi_sock = uwsgi_sock->next;
		}
		spooler();
	}
	else if (pid > 0) {
		uwsgi_log("spawned the uWSGI spooler on dir %s with pid %d\n", uwsgi.spool_dir, pid);
	}

	return pid;
}

void destroy_spool(char *file) {

	if (unlink(file)) {
        	uwsgi_error("unlink()");
                uwsgi_log("something horrible happened to the spooler. Better to kill it.\n");
                exit(1);
	}

}


int spool_request(char *filename, int rn, int core_id, char *buffer, int size) {

	struct timeval tv;
	int fd;
	struct uwsgi_header uh;

	uwsgi_lock(uwsgi.spooler_lock);

	gettimeofday(&tv, NULL);

	if (snprintf(filename, 1024, "%s/uwsgi_spoolfile_on_%s_%d_%d_%d_%llu_%llu", uwsgi.spool_dir, uwsgi.hostname, (int) getpid(), rn, core_id, (unsigned long long) tv.tv_sec, (unsigned long long) tv.tv_usec) <= 0) {
		uwsgi_unlock(uwsgi.spooler_lock);
		return 0;
	}

	fd = open(filename, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		uwsgi_error_open(filename);
		uwsgi_unlock(uwsgi.spooler_lock);
		return 0;
	}

#ifdef __sun__
	if (lockf(fd, F_LOCK, 0)) {
		uwsgi_error("lockf()");
#else
	if (flock(fd, LOCK_EX)) {
		uwsgi_error("flock()");
#endif
		close(fd);
		uwsgi_unlock(uwsgi.spooler_lock);
		return 0;
	}

	uh.modifier1 = 17;
	uh.modifier2 = 0;
	uh.pktsize = (uint16_t) size;
#ifdef __BIG_ENDIAN__
	uh.pktsize = uwsgi_swap16(uh.pktsize);
#endif

	if (write(fd, &uh, 4) != 4) {
		goto clear;
	}

	if (write(fd, buffer, size) != size) {
		goto clear;
	}

	close(fd);

	uwsgi_log("written %d bytes to spool file %s\n", size + 4, filename);
	
	uwsgi_unlock(uwsgi.spooler_lock);

	return 1;


      clear:
	uwsgi_unlock(uwsgi.spooler_lock);
	uwsgi_error("write()");
	unlink(filename);
	close(fd);
	return 0;
}



void spooler() {
	DIR *sdir;
	struct dirent *dp;
	int i, ret;


	int spool_fd;

	// prevent process blindly reading stdin to make mess
	int nullfd;

	struct uwsgi_header uh;

	char spool_buf[0xffff];

	if (chdir(uwsgi.spool_dir)) {
		uwsgi_error("chdir()");
		exit(1);
	}

	// asked by Marco Beri
#ifdef __HAIKU__
#ifdef UWSGI_DEBUG
	uwsgi_log("lowering spooler priority to %d\n", B_LOW_PRIORITY);
#endif
	set_thread_priority(find_thread(NULL), B_LOW_PRIORITY);
#else
#ifdef UWSGI_DEBUG
	uwsgi_log("lowering spooler priority to %d\n", PRIO_MAX);
#endif
	setpriority(PRIO_PROCESS, getpid(), PRIO_MAX);
#endif

	nullfd = open("/dev/null", O_RDONLY);
	if (nullfd < 0) {
		uwsgi_error_open("/dev/null");
		exit(1);
	}

	if (nullfd != 0) {
		dup2(nullfd, 0);
		close(nullfd);
	}

	for (;;) {

		sleep(uwsgi.shared->spooler_frequency);

		sdir = opendir(uwsgi.spool_dir);
		if (sdir) {
			while ((dp = readdir(sdir)) != NULL) {
				if (!strncmp("uwsgi_spoolfile_on_", dp->d_name, 19)) {
					struct stat sf_lstat;
					if (lstat(dp->d_name, &sf_lstat)) {
						continue;
					}
					if (!S_ISREG(sf_lstat.st_mode)) {
						continue;
					}
					if (!access(dp->d_name, R_OK | W_OK)) {
						uwsgi_log("managing spool request %s ...\n", dp->d_name);

						spool_fd = open(dp->d_name, O_RDONLY);
						if (spool_fd < 0) {
							uwsgi_error_open(dp->d_name);
							continue;
						}

#ifdef __sun__
						if (lockf(spool_fd, F_LOCK, 0)) {
							uwsgi_error("lockf()");
#else
						if (flock(spool_fd, LOCK_EX)) {
							uwsgi_error("flock()");
#endif
							close(spool_fd);
							continue;
						}

						if (read(spool_fd, &uh, 4) != 4) {
							uwsgi_error("read()");
							close(spool_fd);
							continue;
						}

#ifdef __BIG_ENDIAN__
						uh.pktsize = uwsgi_swap16(uh.pktsize);
#endif


						if (read(spool_fd, spool_buf, uh.pktsize) != uh.pktsize) {
							uwsgi_error("read()");
							destroy_spool(dp->d_name);	
							close(spool_fd);
							continue;
						}			
					

						close(spool_fd);

						for(i=0;i<0xff;i++) {
							if (uwsgi.p[i]->spooler) {
								ret = uwsgi.p[i]->spooler(spool_buf, uh.pktsize);
								if (ret == 0) continue;
								if (ret == -2) {

									uwsgi_log("done with task/spool %s\n", dp->d_name);
									destroy_spool(dp->d_name);	
								}
								// re-spool it
								break;	
							}
						}

					}
				}
			}
			closedir(sdir);
		}
		else {
			uwsgi_error("opendir()");
		}

	}
}


int uwsgi_request_spooler(struct wsgi_request *wsgi_req) {

	int i;
	char spool_filename[1024];

	if (uwsgi.spool_dir == NULL) {
		uwsgi_log("the spooler is inactive !!!...skip\n");
		uwsgi_send_empty_pkt(wsgi_req->poll.fd, NULL, 255, 0);
		return -1;
	}

	uwsgi_log("managing spool request...\n");
	i = spool_request(spool_filename, uwsgi.workers[0].requests + 1, wsgi_req->async_id, wsgi_req->buffer, wsgi_req->uh.pktsize);
	wsgi_req->uh.modifier1 = 255;
	wsgi_req->uh.pktsize = 0;
	if (i > 0) {
		wsgi_req->uh.modifier2 = 1;
		if (write(wsgi_req->poll.fd, wsgi_req, 4) != 4) {
			uwsgi_log("disconnected client, remove spool file.\n");
			/* client disconnect, remove spool file */
			if (unlink(spool_filename)) {
				uwsgi_error("unlink()");
				uwsgi_log("something horrible happened !!! check your spooler ASAP !!!\n");
				exit(1);
			}
		}
		return 0;
	}
	else {
		/* announce a failed spool request */
		wsgi_req->uh.modifier2 = 0;
		i = write(wsgi_req->poll.fd, wsgi_req, 4);
		if (i != 4) {
			uwsgi_error("write()");
		}
	}

	return -1;
}

#else
#warning "*** Spooler support is disabled ***"
#endif
