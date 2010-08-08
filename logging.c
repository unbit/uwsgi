#include "uwsgi.h"

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__)
#include <kvm.h>
#include <sys/user.h>
#elif defined(__sun__)
/* Terrible Hack !!! */
#ifndef _LP64
#undef _FILE_OFFSET_BITS
#endif
#include <procfs.h>
#define _FILE_OFFSET_BITS 64
#endif

#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/sysctl.h>
#endif

extern struct uwsgi_server uwsgi;

void log_request(struct wsgi_request *wsgi_req) {

	// optimize this (please)
	char *time_request;
	time_t microseconds, microseconds2;
	int rlen;
	int app_req = -1;
	char *msg2 = " ";
	char *via = msg2;

	char mempkt[4096];
	char logpkt[4096];

	struct iovec logvec[4] ;
	int logvecpos = 0 ;

#ifdef UWSGI_SENDFILE
	char *msg1 = " via sendfile() ";

	struct uwsgi_app *wi;

	if (wsgi_req->app_id >= 0) {
		wi = &uwsgi.wsgi_apps[wsgi_req->app_id];
		if (wi->requests > 0) {
			app_req = wi->requests;
		}
	}

	if (wsgi_req->sendfile_fd > -1 && wsgi_req->sendfile_obj == wsgi_req->async_result) { //wsgi_req->sendfile_fd_size > 0 ) {
		via = msg1;
	}
#endif

	time_request = ctime((const time_t *) &wsgi_req->start_of_request.tv_sec);
	microseconds = wsgi_req->end_of_request.tv_sec * 1000000 + wsgi_req->end_of_request.tv_usec;
	microseconds2 = wsgi_req->start_of_request.tv_sec * 1000000 + wsgi_req->start_of_request.tv_usec;

	if (uwsgi.vhost) {
		logvec[logvecpos].iov_base = wsgi_req->host ;
                logvec[logvecpos].iov_len = wsgi_req->host_len ;
                logvecpos++;

		logvec[logvecpos].iov_base = " " ;
                logvec[logvecpos].iov_len = 1 ;
                logvecpos++;
	}

	if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1) {
#ifndef UNBIT
		rlen = snprintf(mempkt, 4096, "{address space usage: %lld bytes/%lluMB} {rss usage: %llu bytes/%lluMB} ",
			(unsigned long long) uwsgi.workers[uwsgi.mywid].vsz_size, (unsigned long long ) uwsgi.workers[uwsgi.mywid].vsz_size / 1024 / 1024,
			(unsigned long long) uwsgi.workers[uwsgi.mywid].rss_size, (unsigned long long ) uwsgi.workers[uwsgi.mywid].rss_size / 1024 / 1024);
#else
		rlen = snprintf(mempkt, 4096, "{address space usage: %lld bytes/%lluMB} ",
			(unsigned long long) uwsgi.workers[uwsgi.mywid].vsz_size, (unsigned long long) uwsgi.workers[uwsgi.mywid].vsz_size / 1024 / 1024);
#endif

	
		logvec[logvecpos].iov_base = mempkt ;
		logvec[logvecpos].iov_len = rlen ;
		logvecpos++;


	}

	rlen = snprintf(logpkt, 4096, "[pid: %d|app: %d|req: %d/%llu] %.*s (%.*s) {%d vars in %d bytes} [%.*s] %.*s %.*s => generated %llu bytes in %ld msecs%s(%.*s %d) %d headers in %d bytes (%d async switches on async core %d)\n",
		uwsgi.mypid,
		wsgi_req->app_id,
		app_req,
		(unsigned long long ) uwsgi.workers[0].requests,
		wsgi_req->remote_addr_len, wsgi_req->remote_addr,
		wsgi_req->remote_user_len, wsgi_req->remote_user,
		wsgi_req->var_cnt,
		wsgi_req->uh.pktsize,
		24, time_request,
		wsgi_req->method_len, wsgi_req->method,
		wsgi_req->uri_len, wsgi_req->uri,
		(unsigned long long) wsgi_req->response_size,
		(long int) (microseconds - microseconds2) / 1000,
		via,
		wsgi_req->protocol_len, wsgi_req->protocol,
		wsgi_req->status,
		wsgi_req->header_cnt,
		wsgi_req->headers_size, 
		wsgi_req->async_switches, wsgi_req->async_id);

	logvec[logvecpos].iov_base = logpkt ;
	logvec[logvecpos].iov_len = rlen ;

	// do not check for errors
	rlen = writev(2, logvec, logvecpos+1);

}

void get_memusage() {

#ifdef UNBIT
	uwsgi.workers[uwsgi.mywid].vsz_size = syscall(356);
#elif defined(__linux__)
	FILE *procfile;
	int i;
	procfile = fopen("/proc/self/stat", "r");
	if (procfile) {
		i = fscanf(procfile, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu %lld", (unsigned long long *) &uwsgi.workers[uwsgi.mywid].vsz_size, (unsigned long long *) &uwsgi.workers[uwsgi.mywid].rss_size);
		if (i != 2) {
			uwsgi_log( "warning: invalid record in /proc/self/stat\n");
		}
		fclose(procfile);
	}
	uwsgi.workers[uwsgi.mywid].rss_size = uwsgi.workers[uwsgi.mywid].rss_size * uwsgi.page_size;
#elif defined (__sun__)
	psinfo_t info;
	int procfd ;

	procfd = open("/proc/self/psinfo", O_RDONLY);
	if (procfd >= 0) {
		if ( read(procfd, (char *) &info, sizeof(info)) > 0) {
			uwsgi.workers[uwsgi.mywid].rss_size = (uint64_t) info.pr_rssize * 1024 ;
			uwsgi.workers[uwsgi.mywid].vsz_size = (uint64_t) info.pr_size * 1024 ;
		}
		close(procfd);
	}
	
#elif defined( __APPLE__)
	/* darwin documentation says that the value are in pages, but they are bytes !!! */
	struct task_basic_info t_info;
	mach_msg_type_number_t t_size = sizeof(struct task_basic_info);

	if (task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t) & t_info, &t_size) == KERN_SUCCESS) {
		uwsgi.workers[uwsgi.mywid].rss_size = t_info.resident_size;
		uwsgi.workers[uwsgi.mywid].vsz_size = t_info.virtual_size;
	}
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__)
	kvm_t *kv;
	int cnt;

	kv = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);
	if (kv) {
#if defined(__FreeBSD__) || defined(__DragonFly__)

		struct kinfo_proc *kproc;
		kproc = kvm_getprocs(kv, KERN_PROC_PID, uwsgi.mypid, &cnt);
		if (kproc && cnt > 0) {
			uwsgi.workers[uwsgi.mywid].vsz_size = kproc->ki_size;
			uwsgi.workers[uwsgi.mywid].rss_size = kproc->ki_rssize * uwsgi.page_size;
		}
#elif defined(__NetBSD__) || defined(__OpenBSD__)
		struct kinfo_proc2 *kproc2;
		
		kproc2 = kvm_getproc2(kv, KERN_PROC_PID, uwsgi.mypid, sizeof(struct kinfo_proc2), &cnt);
		if (kproc2 && cnt > 0) {
#ifdef __OpenBSD__
			uwsgi.workers[uwsgi.mywid].vsz_size = (kproc2->p_vm_dsize + kproc2->p_vm_ssize + kproc2->p_vm_tsize) * uwsgi.page_size;
#else
			uwsgi.workers[uwsgi.mywid].vsz_size = kproc2->p_vm_msize * uwsgi.page_size;
#endif
			uwsgi.workers[uwsgi.mywid].rss_size = kproc2->p_vm_rssize * uwsgi.page_size;
		}
#endif

		kvm_close(kv);
	}

#endif
}
