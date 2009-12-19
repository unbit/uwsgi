#include "uwsgi.h"

#include <dirent.h>



int spool_request(char *spooldir, char *filename, int rn, char *buffer, int size) {

        char hostname[256+1];
        struct timeval tv;
	int fd;

        if (gethostname(hostname,256)) {
                perror("gethostname()");
		return 0 ;
        }

        gettimeofday(&tv, NULL);

        hostname[256] = 0 ;

        if (snprintf(filename,1024,"%s/uwsgi_spoolfile_on_%s_%d_%d_%llu_%llu", spooldir, hostname, getpid(), rn, (unsigned long long) tv.tv_sec, (unsigned long long) tv.tv_usec ) <= 0) {
		return 0;
	}

	fd = open(filename, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		perror("open()");
		return 0 ;
	}

	if (flock(fd, LOCK_EX)) {
		perror("flock()");
		close(fd);
		return 0;
	}

	fprintf(stderr,"writing %d bytes to spool file.\n",size);
	if (write(fd, buffer, size) != size) {
		goto clear ;
	}

	close(fd);

	return 1;
	

clear:

	perror("write()");
	unlink(filename);
	close(fd);
	return 0;
}

void spooler(char *spooldir, PyObject *uwsgi_module) {
	DIR *sdir ;
	struct dirent *dp;
	PyObject *uwsgi_module_dict, *spooler_callable, *spool_result, *spool_tuple, *spool_env ;
	int spool_fd ;
	uint16_t uwstrlen ;
	int rlen;

	char *key;
	char *val;

	uwsgi_module_dict = PyModule_GetDict(uwsgi_module);
        if (!uwsgi_module_dict) {
                fprintf(stderr,"could not get uwsgi module __dict__\n");
                exit(1);
        }


	spool_tuple = PyTuple_New(1);

	if (!spool_tuple) {
		fprintf(stderr,"could not create spooler tuple.\n");
		exit(1);
	}


	if (chdir(spooldir)) {
		perror("chdir()");
		exit(1);
	}

	for(;;) {
		sdir = opendir(".");
		if (sdir) {
			while((dp = readdir(sdir)) != NULL) {
#ifndef __sun__
				if (!strncmp("uwsgi_spoolfile_on_", dp->d_name, 19) && dp->d_type == DT_REG) {
#else
				if (!strncmp("uwsgi_spoolfile_on_", dp->d_name, 19)) {
					struct stat sf_lstat;
					if (lstat(dp->d_name, &sf_lstat)) {
						continue;
					}
					if (!S_ISREG(sf_lstat.st_mode)) {
						continue;
					}
#endif
					if (!access(dp->d_name, R_OK|W_OK)) {
						fprintf(stderr,"managing spool request %s...\n", dp->d_name);

						spooler_callable = PyDict_GetItemString(uwsgi_module_dict, "spooler");
						if (!spooler_callable) {
							fprintf(stderr,"you have to define uwsgi.spooler to use the spooler !!!\n");
							continue;
						}

						spool_fd = open(dp->d_name, O_RDONLY) ;
						if (flock(spool_fd, LOCK_EX)) {
							perror("flock()");
							close(spool_fd);
							continue;
						}

						if (spool_fd < 0) {
							perror("open()");
							continue;
						}	

						spool_env = PyDict_New();
						if (!spool_env) {
							PyErr_Print();	
							close(spool_fd);
							continue;
						}

						while( (rlen = read(spool_fd, &uwstrlen, 2) ) == 2) {
							key = NULL;
							val = NULL;
							if (uwstrlen > 0) {
								key = malloc(uwstrlen+1);
								if (!key) {
									perror("malloc()");
									goto retry_later;
								}
								rlen = read(spool_fd, key, uwstrlen);
								if (rlen != uwstrlen) {
									perror("read()");
									free(key);
									goto next_spool;
								}
								key[rlen] = 0 ;


								rlen = read(spool_fd, &uwstrlen, 2);
								if (rlen != 2) {
									perror("read()");
									free(key);
									goto next_spool;
								}

								if (uwstrlen > 0) {
									val = malloc(uwstrlen+1);
									if (!val) {
										free(key);
										perror("malloc()");
										goto retry_later;
									}

									rlen = read(spool_fd, val, uwstrlen);
									if (rlen != uwstrlen) {
                                                                        	perror("read()");
                                                                        	free(key);
                                                                        	goto next_spool;
                                                                	}
									val[rlen] = 0 ;
									/* ready to add item to the dict */
								}

								if (PyDict_SetItemString(spool_env, key, PyString_FromStringAndSize(val, uwstrlen))) {
									PyErr_Print();
									free(key);
									free(val);
									goto retry_later ;
								}

								free(key);
								free(val);
							}
							else {
								break;
							}
						}
						

						if (PyTuple_SetItem(spool_tuple, 0, spool_env)) {
							PyErr_Print();
							goto retry_later;
						}
						spool_result = PyEval_CallObject(spooler_callable, spool_tuple);	
						if (!spool_result) {
							PyErr_Print();
							fprintf(stderr,"error detected. spool request canceled.\n");
							goto next_spool;
						}
						if (PyInt_Check(spool_result)) {
							if (PyInt_AsLong(spool_result) == 17) {
								fprintf(stderr,"retry this task later...\n");
								goto retry_later;
							}
						}

						fprintf(stderr,"done with task/spool %s\n", dp->d_name);
next_spool:

						if (unlink(dp->d_name)) {
							perror("unlink");
							fprintf(stderr,"something horrible happened to the spooler. Better to kill it.\n");
							exit(1);
						}
retry_later:
						Py_DECREF(spool_env);
						close(spool_fd);
						Py_DECREF(spooler_callable);
					}
				}
			}
			closedir(sdir);
		}
		else {
			perror("opendir()");
		}

		/* TODO spooler frequency user-configurable */
		sleep(5);
	}
}
