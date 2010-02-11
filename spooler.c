#ifndef ROCK_SOLID
#include "uwsgi.h"

#include <dirent.h>


extern char *spool_dir;

struct uwsgi_packet_header {
	uint8_t modifier1;
	uint16_t datasize;
	uint8_t modifier2;
};


int spool_request (char *filename, int rn, char *buffer, int size) {

	char hostname[256 + 1];
	struct timeval tv;
	int fd;
	struct uwsgi_packet_header uh;

	if (gethostname (hostname, 256)) {
		perror ("gethostname()");
		return 0;
	}

	gettimeofday (&tv, NULL);

	hostname[256] = 0;

	if (snprintf (filename, 1024, "%s/uwsgi_spoolfile_on_%s_%d_%d_%llu_%llu", spool_dir, hostname, getpid (), rn, (unsigned long long) tv.tv_sec, (unsigned long long) tv.tv_usec) <= 0) {
		return 0;
	}

	fd = open (filename, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		perror ("open()");
		return 0;
	}

#ifdef __sun__
	if (lockf (fd, F_LOCK, 0)) {
		perror ("lockf()");
#else
	if (flock (fd, LOCK_EX)) {
		perror ("flock()");
#endif
		close (fd);
		return 0;
	}

	uh.modifier1 = 17;
	uh.modifier2 = 0;
	uh.datasize = (uint16_t) size;
#ifdef __BIG_ENDIAN__
	uh.datasize = uwsgi_swap16 (uh.datasize);
#endif

	if (write (fd, &uh, 4) != 4) {
		goto clear;
	}

	if (write (fd, buffer, size) != size) {
		goto clear;
	}

	close (fd);

	fprintf (stderr, "written %d bytes to spool file %s.\n", size + 4, filename);

	return 1;


      clear:

	perror ("write()");
	unlink (filename);
	close (fd);
	return 0;
}

void spooler (PyObject * uwsgi_module) {
	DIR *sdir;
	struct dirent *dp;
	PyObject *uwsgi_module_dict, *spooler_callable, *spool_result, *spool_tuple, *spool_env;
	int spool_fd;
	uint16_t uwstrlen;
	int rlen = 0;
	int datasize;

	struct uwsgi_packet_header uh;

	char *key;
	char *val;

	uwsgi_module_dict = PyModule_GetDict (uwsgi_module);
	if (!uwsgi_module_dict) {
		fprintf (stderr, "could not get uwsgi module __dict__\n");
		exit (1);
	}


	spool_tuple = PyTuple_New (1);

	if (!spool_tuple) {
		fprintf (stderr, "could not create spooler tuple.\n");
		exit (1);
	}


	spool_env = PyDict_New ();
	if (!spool_env) {
		fprintf (stderr, "could not create spooler env.\n");
		exit (1);
	}

	if (PyTuple_SetItem (spool_tuple, 0, spool_env)) {
		PyErr_Print ();
		exit (1);
	}

	if (chdir (spool_dir)) {
		perror ("chdir()");
		exit (1);
	}

	for (;;) {
		sdir = opendir (".");
		if (sdir) {
			while ((dp = readdir (sdir)) != NULL) {
				if (!strncmp ("uwsgi_spoolfile_on_", dp->d_name, 19)) {
					struct stat sf_lstat;
					if (lstat (dp->d_name, &sf_lstat)) {
						continue;
					}
					if (!S_ISREG (sf_lstat.st_mode)) {
						continue;
					}
					if (!access (dp->d_name, R_OK | W_OK)) {
						fprintf (stderr, "managing spool request %s...\n", dp->d_name);

						spooler_callable = PyDict_GetItemString (uwsgi_module_dict, "spooler");
						if (!spooler_callable) {
							fprintf (stderr, "you have to define uwsgi.spooler to use the spooler !!!\n");
							continue;
						}

						spool_fd = open (dp->d_name, O_RDONLY);
						if (spool_fd < 0) {
							perror ("open()");
							continue;
						}

#ifdef __sun__
						if (lockf (spool_fd, F_LOCK, 0)) {
							perror ("lockf()");
#else
						if (flock (spool_fd, LOCK_EX)) {
							perror ("flock()");
#endif
							close (spool_fd);
							continue;
						}

						if (read (spool_fd, &uh, 4) != 4) {
							perror ("read()");
							close (spool_fd);
							continue;
						}

#ifdef __BIG_ENDIAN__
						uh.datasize = uwsgi_swap16 (uh.datasize);
#endif

						datasize = 0;

						while (datasize < uh.datasize) {
							rlen = read (spool_fd, &uwstrlen, 2);
							if (rlen != 2) {
								perror ("read()");
								goto next_spool;
							}
							datasize += rlen;
							key = NULL;
							val = NULL;
							if (uwstrlen > 0) {
								key = malloc (uwstrlen + 1);
								if (!key) {
									perror ("malloc()");
									goto retry_later;
								}
								rlen = read (spool_fd, key, uwstrlen);
								if (rlen != uwstrlen) {
									perror ("read()");
									free (key);
									goto next_spool;
								}
								datasize += rlen;
								key[rlen] = 0;


								rlen = read (spool_fd, &uwstrlen, 2);
								if (rlen != 2) {
									perror ("read()");
									free (key);
									goto next_spool;
								}
								datasize += rlen;

								if (uwstrlen > 0) {
									val = malloc (uwstrlen + 1);
									if (!val) {
										free (key);
										perror ("malloc()");
										goto retry_later;
									}

									rlen = read (spool_fd, val, uwstrlen);
									if (rlen != uwstrlen) {
										perror ("read()");
										free (key);
										goto next_spool;
									}
									datasize += rlen;
									val[rlen] = 0;
									/* ready to add item to the dict */
								}

								if (PyDict_SetItemString (spool_env, key, PyString_FromStringAndSize (val, uwstrlen))) {
									PyErr_Print ();
									free (key);
									free (val);
									goto retry_later;
								}

								free (key);
								free (val);
							}
							else {
								break;
							}
						}


						spool_result = PyEval_CallObject (spooler_callable, spool_tuple);
						if (!spool_result) {
							PyErr_Print ();
							fprintf (stderr, "error detected. spool request canceled.\n");
							goto next_spool;
						}
						if (PyInt_Check (spool_result)) {
							if (PyInt_AsLong (spool_result) == 17) {
								Py_DECREF (spool_result);
								fprintf (stderr, "retry this task later...\n");
								goto retry_later;
							}
						}

						Py_DECREF (spool_result);

						fprintf (stderr, "done with task/spool %s\n", dp->d_name);
					      next_spool:

						if (unlink (dp->d_name)) {
							perror ("unlink");
							fprintf (stderr, "something horrible happened to the spooler. Better to kill it.\n");
							exit (1);
						}
					      retry_later:
						PyDict_Clear (spool_env);
						close (spool_fd);
					}
				}
			}
			closedir (sdir);
		}
		else {
			perror ("opendir()");
		}

		/* TODO spooler frequency user-configurable */
		sleep (5);
	}
}

int uwsgi_request_spooler (struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, char *buffer) {
	
	int i;
	char spool_filename[1024];

	if (spool_dir == NULL) {
		fprintf (stderr, "the spooler is inactive !!!...skip\n");
		wsgi_req->modifier = 255;
		wsgi_req->size = 0;
		wsgi_req->modifier_arg = 0;
		i = write (uwsgi->poll.fd, wsgi_req, 4);
		if (i != 4) {
			perror ("write()");
		}
		return -1 ;
	}

	fprintf (stderr, "managing spool request...\n");
	i = spool_request (spool_filename, uwsgi->workers[0].requests + 1, buffer, wsgi_req->size);
	wsgi_req->modifier = 255;
	wsgi_req->size = 0;
	if (i > 0) {
		wsgi_req->modifier_arg = 1;
		if (write (uwsgi->poll.fd, wsgi_req, 4) != 4) {
			fprintf (stderr, "disconnected client, remove spool file.\n");
			/* client disconnect, remove spool file */
			if (unlink (spool_filename)) {
				perror ("unlink()");
				fprintf (stderr, "something horrible happened !!! check your spooler ASAP !!!\n");
				goodbye_cruel_world ();
			}
		}
		return 0;
	}
	else {
		/* announce a failed spool request */
		wsgi_req->modifier_arg = 0;
		i = write (uwsgi->poll.fd, wsgi_req, 4);
		if (i != 4) {
			perror ("write()");
		}
	}

	return -1 ;
}

#endif
