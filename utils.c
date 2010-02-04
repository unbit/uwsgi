#include "uwsgi.h"

#ifdef __APPLE__
#include <mach/host_info.h>
#include <mach/mach_host.h>
#endif


extern struct uwsgi_server uwsgi;

#ifdef __BIG_ENDIAN__
uint16_t uwsgi_swap16(uint16_t x) {
	return (uint16_t) ((x & 0xff) << 8 | (x & 0xff00) >> 8);
}
#endif

void set_harakiri(int sec) {
	if (uwsgi.workers) {
		if (sec == 0) {
			uwsgi.workers[uwsgi.mywid].harakiri = 0 ;
		}
		else {
			uwsgi.workers[uwsgi.mywid].harakiri = time(NULL) + sec ;
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

uint64_t get_free_memory() {

	uint64_t freemem = 0 ;

#ifdef __APPLE__
	vm_statistics_data_t page_info;
	mach_msg_type_number_t count;

	count = HOST_VM_INFO_COUNT;
	if (host_statistics (mach_host_self(), HOST_VM_INFO, (host_info_t)&page_info, &count) == KERN_SUCCESS){
		freemem += (page_info.inactive_count + page_info.free_count) * uwsgi.page_size ;		
	}
	
#elif defined(__linux__)
	/* sadly linux has no api for getting the current size of page cache. we need to parse /proc/meminfo */
	FILE *meminfo;
	
	meminfo = fopen("/proc/meminfo", "r");
	if (!meminfo) {
		perror("fopen()");
	}
	else {
		
	}
#elif defined(__FreeBSD__)
	int value ;
	size_t dlen;

	if (sysctlbyname("vm.stats.vm.v_free_count", &value, &dlen, NULL, 0) != 0) {
		perror("sysctlbyname()");
	}
	else {
		freemem += value*uwsgi.page_size ;
	}
#endif

	return freemem ;
}
