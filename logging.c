#include "uwsgi.h"

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__sun__) || defined(__OpenBSD__)
#include <kvm.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#endif

extern struct uwsgi_server uwsgi;

void log_request(struct wsgi_request *wsgi_req) {
	char *time_request;
	time_t microseconds, microseconds2;


#ifdef UWSGI_SENDFILE
	char *msg1 = " via sendfile() ";
	char *msg2 = " ";
	char *via;
	static char *empty = "";

	char *first_part = empty;
	struct uwsgi_app *wi;
	int app_req = -1;

	if (wsgi_req->app_id >= 0) {
		wi = &uwsgi.wsgi_apps[wsgi_req->app_id];
		if (wi->requests > 0) {
			app_req = wi->requests;
		}
	}
	via = msg2;

	if (wsgi_req->sendfile_fd > -1) {
		via = msg1;
	}
#endif

	time_request = ctime((const time_t *) &wsgi_req->start_of_request.tv_sec);
	microseconds = wsgi_req->end_of_request.tv_sec * 1000000 + wsgi_req->end_of_request.tv_usec;
	microseconds2 = wsgi_req->start_of_request.tv_sec * 1000000 + wsgi_req->start_of_request.tv_usec;


	if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1) {
#ifndef UNBIT
		if (uwsgi.synclog) {
			snprintf(uwsgi.sync_page, uwsgi.page_size, "{address space usage: %lld bytes/%lluMB} {rss usage: %llu bytes/%lluMB} ", uwsgi.workers[uwsgi.mywid].vsz_size, uwsgi.workers[uwsgi.mywid].vsz_size / 1024 / 1024, uwsgi.workers[uwsgi.mywid].rss_size, uwsgi.workers[uwsgi.mywid].rss_size / 1024 / 1024);
			first_part = uwsgi.sync_page;
		}
		else {
			fprintf(stderr, "{address space usage: %lld bytes/%lluMB} {rss usage: %llu bytes/%lluMB} ", uwsgi.workers[uwsgi.mywid].vsz_size, uwsgi.workers[uwsgi.mywid].vsz_size / 1024 / 1024, uwsgi.workers[uwsgi.mywid].rss_size, uwsgi.workers[uwsgi.mywid].rss_size / 1024 / 1024);
		}
#else
		fprintf(stderr, "{address space usage: %lld bytes/%lluMB} ", uwsgi.workers[uwsgi.mywid].vsz_size, uwsgi.workers[uwsgi.mywid].vsz_size / 1024 / 1024);
#endif
	}

	fprintf(stderr, "%s[pid: %d|app: %d|req: %d/%llu] %.*s (%.*s) {%d vars in %d bytes} [%.*s] %.*s %.*s => generated %llu bytes in %ld msecs%s(%.*s %d) %d headers in %d bytes (%d async switches)\n",
		first_part,
		uwsgi.mypid,
		wsgi_req->app_id,
		app_req,
		uwsgi.workers[0].requests,
		wsgi_req->remote_addr_len, wsgi_req->remote_addr,
		wsgi_req->remote_user_len, wsgi_req->remote_user,
		wsgi_req->var_cnt,
		wsgi_req->size,
		24, time_request,
		wsgi_req->method_len, wsgi_req->method,
		wsgi_req->uri_len, wsgi_req->uri,
		(uint64_t) wsgi_req->response_size,
		(long int) (microseconds - microseconds2) / 1000,
		via,
		wsgi_req->protocol_len, wsgi_req->protocol,
		wsgi_req->status,
		wsgi_req->header_cnt,
		wsgi_req->headers_size, 
		wsgi_req->async_switches);


}

void get_memusage() {

#ifdef UNBIT
	uwsgi.workers[uwsgi.mywid].vsz_size = syscall(356);
#elif defined(__linux__)
	FILE *procfile;
	int i;
	procfile = fopen("/proc/self/stat", "r");
	if (procfile) {
		i = fscanf(procfile, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu %lld", &uwsgi.workers[uwsgi.mywid].vsz_size, &uwsgi.workers[uwsgi.mywid].rss_size);
		if (i != 2) {
			fprintf(stderr, "warning: invalid record in /proc/self/stat\n");
		}
		fclose(procfile);
	}
	uwsgi.workers[uwsgi.mywid].rss_size = uwsgi.workers[uwsgi.mywid].rss_size * uwsgi.page_size;
#elif defined( __APPLE__)
	/* darwin documentation says that the value are in pages, but they are bytes !!! */
	struct task_basic_info t_info;
	mach_msg_type_number_t t_size = sizeof(struct task_basic_info);

	if (task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t) & t_info, &t_size) == KERN_SUCCESS) {
		uwsgi.workers[uwsgi.mywid].rss_size = t_info.resident_size;
		uwsgi.workers[uwsgi.mywid].vsz_size = t_info.virtual_size;
	}
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__sun__) || defined(__OpenBSD__)
	kvm_t *kv;

	kv = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);
	if (kv) {
#if defined(__FreeBSD__) || defined(__DragonFly__)
		struct kinfo_proc *kproc;
		int cnt;
		kproc = kvm_getprocs(kv, KERN_PROC_PID, uwsgi.mypid, &cnt);
		if (kproc && cnt > 0) {
			uwsgi.workers[uwsgi.mywid].vsz_size = kproc->ki_size;
			uwsgi.workers[uwsgi.mywid].rss_size = kproc->ki_rssize * uwsgi.page_size;
		}
#endif

		kvm_close(kv);
	}

#endif
}
