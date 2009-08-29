#ifndef UNBIT

#include "uwsgi.h"

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
