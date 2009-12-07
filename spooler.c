#include "uwsgi.h"

#include <dirent.h>



int spool_request(char *host, char *port, char *spooldir, char *filename, int rn, char *buffer, int size) {

        char hostname[256+1];
        struct timeval tv;
	int fd;
	uint16_t uwstrsize;

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

	if (host != NULL) {
		uwstrsize = strlen(host) ;	
		if (write(fd, &uwstrsize, 2) != 2) {
			goto clear;
		}
		
		if (write(fd, host, uwstrsize) != uwstrsize) {
			goto clear;
		}
	}
	else {
		if (write(fd, "\0\0", 2) != 2) {
			goto clear;
		}
	}


	if (port != NULL) {
		uwstrsize = strlen(port) ;	
		if (write(fd, &uwstrsize, 2) != 2) {
			goto clear;
		}
		
		if (write(fd, port, uwstrsize) != uwstrsize) {
			goto clear;
		}
	}
	else {
		if (write(fd, "\0\0", 2) != 2) {
			goto clear;
		}
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

	char host[256+1];
	char port[6];
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
				if (!strncmp("uwsgi_spoolfile_on_", dp->d_name, 19) && dp->d_type == DT_REG) {
					if (!access(dp->d_name, R_OK|W_OK)) {
						fprintf(stderr,"managing spool request %s...\n", dp->d_name);

						spooler_callable = PyDict_GetItemString(uwsgi_module_dict, "spooler");
						if (!spooler_callable) {
							fprintf(stderr,"you have to define uwsgi.spooler to use the spooler !!!\n");
							continue;
						}

						spool_fd = open(dp->d_name, O_RDONLY) ;
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


						host[0] = 0 ;
						port[0] = 0 ;


						/* get spool host */
						rlen = read(spool_fd, &uwstrlen, 2) ;
						if (rlen != 2) {
							perror("read()");
							goto next_spool;
						}	
						if (uwstrlen > 0) {
							if (uwstrlen > 256) {
								fprintf(stderr,"invalid host for this spool file\n");	
								goto next_spool;
							}
							rlen = read(spool_fd, host, uwstrlen);
							if (rlen != uwstrlen) {
								perror("read()");
								goto next_spool;
							}
							host[rlen] = 0;
						}

						/* get spool port */
						rlen = read(spool_fd, &uwstrlen, 2) ;
						if (rlen != 2) {
							perror("read()");
							goto next_spool;
						}	
						if (uwstrlen > 0) {
							if (uwstrlen > 5) {
								fprintf(stderr,"invalid port for this spool file\n");	
								goto next_spool;
							}
							rlen = read(spool_fd, port, uwstrlen);
							if (rlen != uwstrlen) {
								perror("read()");
								goto next_spool;
							}
							port[rlen] = 0;
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
						

						if (host[0] == 0 || port[0] == 0) {
							fprintf(stderr,"CALLING the spooler callable...\n");
							if (PyTuple_SetItem(spool_tuple, 0, spool_env)) {
								PyErr_Print();
								goto retry_later;
							}
							spool_result = PyEval_CallObject(spooler_callable, spool_tuple);	
							if (!spool_result) {
								PyErr_Print();
								goto next_spool;
							}
							if (PyInt_Check(spool_result)) {
								if (PyInt_AsLong(spool_result) == 17) {
									fprintf(stderr,"retry this task later...\n");
									goto retry_later;
								}
							}

							fprintf(stderr,"done with task/spool %s\n", dp->d_name);
						}
						else {
							/* manage remote spooler connecting and copying file over the socket */
							fprintf(stderr,"sending to remote spooler...\n");
						}

next_spool:

						if (unlink(dp->d_name)) {
							perror("unlink");
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
