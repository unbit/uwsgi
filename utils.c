#include "uwsgi.h"

extern struct uwsgi_worker *workers;
extern int mywid ;

#ifdef __BIG_ENDIAN__
uint16_t uwsgi_swap16(uint16_t x) {
	return (uint16_t) ((x & 0xff) << 8 | (x & 0xff00) >> 8);
}
#endif

void set_harakiri(int sec) {
	if (workers) {
		if (sec == 0) {
			workers[mywid].harakiri = 0 ;
		}
		else {
			workers[mywid].harakiri = time(NULL) + sec ;
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
                exit(1) ;
        }
        if (pid != 0) {
                exit(0);
        }

        if (setsid() < 0) {
                perror("setsid()");
                exit(1) ;
        }


        /* refork... */
        pid = fork();
        if (pid < 0) {
                perror("fork()");
                exit(1) ;
        }
        if (pid != 0) {
                exit(0);
        }

        umask(0);


        /*if (chdir("/") != 0) {
                perror("chdir()");
                exit(1);
        }*/


        fdin = open("/dev/null", O_RDWR);
        if (fdin < 0) {
                perror("open()");
                exit(1);
        }

        fd = open(logfile, O_RDWR|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP );
        if (fd < 0) {
                perror("open()");
                exit(1);
        }

        /* stdin */
        if (dup2(fdin,0) < 0) {
                perror("dup2()");
                exit(1);
        }

	
	/* stdout */
        if (dup2(fd,1) < 0) {
                perror("dup2()");
                exit(1);
        }

        /* stderr */
        if (dup2(fd,2) < 0) {
                perror("dup2()");
                exit(1);
        }

        close(fd);


}


#endif

char * uwsgi_get_cwd() {

	int newsize = 256 ;
	char *cwd ;

	cwd = malloc(newsize);
	if (cwd == NULL) {
		perror("malloc()");
		exit(1);
	}	

	if (getcwd(cwd, newsize) == NULL) {
		newsize = errno;
		fprintf(stderr,"need a bigger buffer (%d bytes) for getcwd(). doing reallocation.\n", newsize);
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
