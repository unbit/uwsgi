#ifdef UWSGI_SPOOLER
#include "uwsgi.h"


int spool_request(struct uwsgi_server *uwsgi, char *filename, int rn, char *buffer, int size) {

	char hostname[256 + 1];
	struct timeval tv;
	int fd;
	struct uwsgi_header uh;

	if (gethostname(hostname, 256)) {
		uwsgi_error("gethostname()");
		return 0;
	}

	gettimeofday(&tv, NULL);

	hostname[256] = 0;

	if (snprintf(filename, 1024, "%s/uwsgi_spoolfile_on_%s_%d_%d_%llu_%llu", uwsgi->spool_dir, hostname, (int) getpid(), rn, (unsigned long long) tv.tv_sec, (unsigned long long) tv.tv_usec) <= 0) {
		return 0;
	}

	fd = open(filename, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		uwsgi_error("open()");
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

	uwsgi_log( "written %d bytes to spool file %s\n", size + 4, filename);

	return 1;


      clear:

	uwsgi_error("write()");
	unlink(filename);
	close(fd);
	return 0;
}

void spooler(struct uwsgi_server *uwsgi, PyObject * uwsgi_module_dict) {
	DIR *sdir;
	struct dirent *dp;
	PyObject *spooler_callable, *spool_result, *spool_tuple, *spool_env;
	int spool_fd;
	uint16_t uwstrlen;
	int rlen = 0;
	int datasize;

	// prevent process blindly reading stdin to make mess
	int nullfd;

	struct uwsgi_header uh;

	char *key;
	char *val;

	spool_tuple = PyTuple_New(1);

	if (!spool_tuple) {
		uwsgi_log( "could not create spooler tuple.\n");
		exit(1);
	}


	spool_env = PyDict_New();
	if (!spool_env) {
		uwsgi_log( "could not create spooler env.\n");
		exit(1);
	}

	if (PyTuple_SetItem(spool_tuple, 0, spool_env)) {
		PyErr_Print();
		exit(1);
	}
	
	if (chdir(uwsgi->spool_dir)) {
		uwsgi_error("chdir()");
		exit(1);
	}

	// asked by Marco Beri
	
#ifdef __HAIKU__
	uwsgi_log( "lowering spooler priority to %d\n", B_LOW_PRIORITY);
	set_thread_priority(find_thread(NULL), B_LOW_PRIORITY);
#else
	uwsgi_log( "lowering spooler priority to %d\n", PRIO_MAX);
	setpriority(PRIO_PROCESS, getpid(), PRIO_MAX);
#endif

	nullfd = open("/dev/null", O_RDONLY);
        if (nullfd < 0) {
                uwsgi_error("open()");
                exit(1);
        }

        if (nullfd != 0) {
                dup2(nullfd, 0);
		close(nullfd);
        }

	for (;;) {

		sleep(uwsgi->shared->spooler_frequency);

		sdir = opendir(uwsgi->spool_dir);
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
						uwsgi_log( "managing spool request %s ...\n", dp->d_name);

						spooler_callable = PyDict_GetItemString(uwsgi_module_dict, "spooler");
						if (!spooler_callable) {
							uwsgi_log( "you have to define uwsgi.spooler to use the spooler !!!\n");
							continue;
						}

						spool_fd = open(dp->d_name, O_RDONLY);
						if (spool_fd < 0) {
							uwsgi_error("open()");
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

						datasize = 0;

						while (datasize < uh.pktsize) {
							rlen = read(spool_fd, &uwstrlen, 2);
							if (rlen != 2) {
								uwsgi_error("read()");
								goto next_spool;
							}
							datasize += rlen;
							key = NULL;
							val = NULL;
							if (uwstrlen > 0) {
								key = malloc(uwstrlen + 1);
								if (!key) {
									uwsgi_error("malloc()");
									goto retry_later;
								}
								rlen = read(spool_fd, key, uwstrlen);
								if (rlen != uwstrlen) {
									uwsgi_error("read()");
									free(key);
									goto next_spool;
								}
								datasize += rlen;
								key[rlen] = 0;


								rlen = read(spool_fd, &uwstrlen, 2);
								if (rlen != 2) {
									uwsgi_error("read()");
									free(key);
									goto next_spool;
								}
								datasize += rlen;

								if (uwstrlen > 0) {
									val = malloc(uwstrlen + 1);
									if (!val) {
										free(key);
										uwsgi_error("malloc()");
										goto retry_later;
									}

									rlen = read(spool_fd, val, uwstrlen);
									if (rlen != uwstrlen) {
										uwsgi_error("read()");
										free(key);
										goto next_spool;
									}
									datasize += rlen;
									val[rlen] = 0;
									/* ready to add item to the dict */
								}

								if (PyDict_SetItemString(spool_env, key, PyString_FromStringAndSize(val, uwstrlen))) {
									PyErr_Print();
									free(key);
									free(val);
									goto retry_later;
								}

								free(key);
								free(val);
							}
							else {
								break;
							}
						}


						spool_result = python_call(spooler_callable, spool_tuple, 0);
						if (!spool_result) {
							PyErr_Print();
							uwsgi_log( "error detected. spool request canceled.\n");
							goto next_spool;
						}
						if (PyInt_Check(spool_result)) {
							if (PyInt_AsLong(spool_result) == 17) {
								Py_DECREF(spool_result);
								uwsgi_log( "retry this task later...\n");
								goto retry_later;
							}
						}

						Py_DECREF(spool_result);

						uwsgi_log( "done with task/spool %s\n", dp->d_name);
					      next_spool:

						if (unlink(dp->d_name)) {
							uwsgi_error("unlink");
							uwsgi_log( "something horrible happened to the spooler. Better to kill it.\n");
							exit(1);
						}
					      retry_later:
						PyDict_Clear(spool_env);
						close(spool_fd);
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

int uwsgi_request_spooler(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int i;
	char spool_filename[1024];

	if (uwsgi->spool_dir == NULL) {
		uwsgi_log( "the spooler is inactive !!!...skip\n");
		wsgi_req->uh.modifier1 = 255;
		wsgi_req->uh.pktsize = 0;
		wsgi_req->uh.modifier2 = 0;
		i = write(wsgi_req->poll.fd, wsgi_req, 4);
		if (i != 4) {
			uwsgi_error("write()");
		}
		return -1;
	}

	uwsgi_log( "managing spool request...\n");
	i = spool_request(uwsgi, spool_filename, uwsgi->workers[0].requests + 1, wsgi_req->buffer, wsgi_req->uh.pktsize);
	wsgi_req->uh.modifier1 = 255;
	wsgi_req->uh.pktsize = 0;
	if (i > 0) {
		wsgi_req->uh.modifier2 = 1;
		if (write(wsgi_req->poll.fd, wsgi_req, 4) != 4) {
			uwsgi_log( "disconnected client, remove spool file.\n");
			/* client disconnect, remove spool file */
			if (unlink(spool_filename)) {
				uwsgi_error("unlink()");
				uwsgi_log( "something horrible happened !!! check your spooler ASAP !!!\n");
				goodbye_cruel_world();
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
