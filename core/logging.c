#define _NO_UWSGI_RB
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

//use this instead of fprintf to avoid buffering mess with udp logging
void uwsgi_log(const char *fmt, ...) {
	va_list ap;
	char logpkt[4096];
	int rlen = 0;
	int ret;

	struct timeval tv;
	char sftime[64];
	char ctime_storage[26];
	time_t now;

	if (uwsgi.logdate) {
		if (uwsgi.log_strftime) {
			now = uwsgi_now();
			rlen = strftime(sftime, 64, uwsgi.log_strftime, localtime(&now));
			memcpy(logpkt, sftime, rlen);
			memcpy(logpkt + rlen, " - ", 3);
			rlen += 3;
		}
		else {
			gettimeofday(&tv, NULL);
#ifdef __sun__
			ctime_r((const time_t *) &tv.tv_sec, ctime_storage, 26);
#else
			ctime_r((const time_t *) &tv.tv_sec, ctime_storage);
#endif
			memcpy(logpkt, ctime_storage, 24);
			memcpy(logpkt + 24, " - ", 3);

			rlen = 24 + 3;
		}
	}

	va_start(ap, fmt);
	ret = vsnprintf(logpkt + rlen, 4096 - rlen, fmt, ap);
	va_end(ap);

	if (ret >= 4096) {
		char *tmp_buf = uwsgi_malloc(rlen + ret + 1);
		memcpy(tmp_buf, logpkt, rlen);
		va_start(ap, fmt);
		ret = vsnprintf(tmp_buf + rlen, ret + 1, fmt, ap);
		va_end(ap);
		rlen = write(2, tmp_buf, rlen + ret);
		free(tmp_buf);
		return;
	}

	rlen += ret;
	// do not check for errors
	rlen = write(2, logpkt, rlen);
}

void uwsgi_log_verbose(const char *fmt, ...) {

	va_list ap;
	char logpkt[4096];
	int rlen = 0;

	struct timeval tv;
	char sftime[64];
	time_t now;
	char ctime_storage[26];

	if (uwsgi.log_strftime) {
		now = uwsgi_now();
		rlen = strftime(sftime, 64, uwsgi.log_strftime, localtime(&now));
		memcpy(logpkt, sftime, rlen);
		memcpy(logpkt + rlen, " - ", 3);
		rlen += 3;
	}
	else {
		gettimeofday(&tv, NULL);
#ifdef __sun__
		ctime_r((const time_t *) &tv.tv_sec, ctime_storage, 26);
#else
		ctime_r((const time_t *) &tv.tv_sec, ctime_storage);
#endif
		memcpy(logpkt, ctime_storage, 24);
		memcpy(logpkt + 24, " - ", 3);

		rlen = 24 + 3;
	}



	va_start(ap, fmt);
	rlen += vsnprintf(logpkt + rlen, 4096 - rlen, fmt, ap);
	va_end(ap);

	// do not check for errors
	rlen = write(2, logpkt, rlen);
}




// create the logpipe
void create_logpipe(void) {

#if defined(SOCK_SEQPACKET) && defined(__linux__)
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, uwsgi.shared->worker_log_pipe)) {
#else
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, uwsgi.shared->worker_log_pipe)) {
#endif
		uwsgi_error("socketpair()\n");
		exit(1);
	}

	uwsgi_socket_nb(uwsgi.shared->worker_log_pipe[0]);
	uwsgi_socket_nb(uwsgi.shared->worker_log_pipe[1]);

	if (uwsgi.shared->worker_log_pipe[1] != 1) {
		if (dup2(uwsgi.shared->worker_log_pipe[1], 1) < 0) {
			uwsgi_error("dup2()");
			exit(1);
		}
	}

	if (dup2(1, 2) < 0) {
		uwsgi_error("dup2()");
		exit(1);
	}

}

#ifdef UWSGI_ZEROMQ
// the zeromq logger
ssize_t uwsgi_zeromq_logger(struct uwsgi_logger *ul, char *message, size_t len) {

	if (!ul->configured) {

		if (!ul->arg) {
			uwsgi_log_safe("invalid zeromq syntax\n");
			exit(1);
		}

		void *ctx = uwsgi_zeromq_init();

		ul->data = zmq_socket(ctx, ZMQ_PUSH);
		if (ul->data == NULL) {
			uwsgi_error_safe("zmq_socket()");
			exit(1);
		}

		if (zmq_connect(ul->data, ul->arg) < 0) {
			uwsgi_error_safe("zmq_connect()");
			exit(1);
		}

		ul->configured = 1;
	}

	zmq_msg_t msg;
	if (zmq_msg_init_size(&msg, len) == 0) {
		memcpy(zmq_msg_data(&msg), message, len);
#if ZMQ_VERSION >= ZMQ_MAKE_VERSION(3,0,0)
		zmq_sendmsg(ul->data, &msg, 0);
#else
		zmq_send(ul->data, &msg, 0);
#endif
		zmq_msg_close(&msg);
	}

	return 0;
}
#endif


// log to the specified file or udp address
void logto(char *logfile) {

	int fd;

#ifdef UWSGI_UDP
	char *udp_port;
	struct sockaddr_in udp_addr;

	udp_port = strchr(logfile, ':');
	if (udp_port) {
		udp_port[0] = 0;
		if (!udp_port[1] || !logfile[0]) {
			uwsgi_log("invalid udp address\n");
			exit(1);
		}

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0) {
			uwsgi_error("socket()");
			exit(1);
		}

		memset(&udp_addr, 0, sizeof(struct sockaddr_in));

		udp_addr.sin_family = AF_INET;
		udp_addr.sin_port = htons(atoi(udp_port + 1));
		char *resolved = uwsgi_resolve_ip(logfile);
		if (resolved) {
			udp_addr.sin_addr.s_addr = inet_addr(resolved);
		}
		else {
			udp_addr.sin_addr.s_addr = inet_addr(logfile);
		}

		if (connect(fd, (const struct sockaddr *) &udp_addr, sizeof(struct sockaddr_in)) < 0) {
			uwsgi_error("connect()");
			exit(1);
		}
	}
	else {
#endif
		if (uwsgi.log_truncate) {
			fd = open(logfile, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
		}
		else {
			fd = open(logfile, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP);
		}
		if (fd < 0) {
			uwsgi_error_open(logfile);
			exit(1);
		}
		uwsgi.logfile = logfile;

		if (uwsgi.chmod_logfile_value) {
			if (chmod(uwsgi.logfile, uwsgi.chmod_logfile_value)) {
				uwsgi_error("chmod()");
			}
		}
#ifdef UWSGI_UDP
	}
#endif


	/* stdout */
	if (fd != 1) {
		if (dup2(fd, 1) < 0) {
			uwsgi_error("dup2()");
			exit(1);
		}
		close(fd);
	}

	/* stderr */
	if (dup2(1, 2) < 0) {
		uwsgi_error("dup2()");
		exit(1);
	}
}



void uwsgi_setup_log() {

	if (uwsgi.daemonize) {
		if (uwsgi.has_emperor) {
			logto(uwsgi.daemonize);
		}
		else {
			if (!uwsgi.is_a_reload) {
				daemonize(uwsgi.daemonize);
			}
			else if (uwsgi.log_reopen) {
				logto(uwsgi.daemonize);
			}
		}
	}
	else if (uwsgi.logfile) {
		if (!uwsgi.is_a_reload || uwsgi.log_reopen) {
			logto(uwsgi.logfile);
		}
	}

}

void uwsgi_setup_log_master(void) {

	struct uwsgi_string_list *usl = uwsgi.requested_logger;
	while (usl) {
		char *id = NULL;
		char *name = usl->value;

		char *space = strchr(name, ' ');
		if (space) {
			int is_id = 1;
			int i;
			for (i = 0; i < (space - name); i++) {
				if (!isalnum(name[i])) {
					is_id = 0;
					break;
				}
			}
			if (is_id) {
				id = uwsgi_concat2n(name, space - name, "", 0);
				name = space + 1;
			}
		}

		char *colon = strchr(name, ':');
		if (colon) {
			*colon = 0;
		}

		struct uwsgi_logger *choosen_logger = uwsgi_get_logger(name);
		if (!choosen_logger) {
			uwsgi_log("unable to find logger %s\n", name);
			exit(1);
		}

		// make a copy of the logger
		struct uwsgi_logger *copy_of_choosen_logger = uwsgi_malloc(sizeof(struct uwsgi_logger));
		memcpy(copy_of_choosen_logger, choosen_logger, sizeof(struct uwsgi_logger));
		choosen_logger = copy_of_choosen_logger;
		choosen_logger->id = id;
		choosen_logger->next = NULL;

		if (colon) {
			choosen_logger->arg = colon + 1;
			// check for empty string
			if (*choosen_logger->arg == 0) {
				choosen_logger->arg = NULL;
			}
			*colon = ':';
		}

		uwsgi_append_logger(choosen_logger);

		usl = usl->next;

	}

#ifdef UWSGI_PCRE
	// set logger by its id
	struct uwsgi_regexp_list *url = uwsgi.log_route;
	while (url) {
		url->custom_ptr = uwsgi_get_logger_from_id(url->custom_str);
		url = url->next;
	}
#endif

	uwsgi.original_log_fd = dup(1);
	create_logpipe();
}

struct uwsgi_logvar *uwsgi_logvar_get(struct wsgi_request *wsgi_req, char *key, uint8_t keylen) {
	struct uwsgi_logvar *lv = wsgi_req->logvars;
	while (lv) {
		if (!uwsgi_strncmp(key, keylen, lv->key, lv->keylen)) {
			return lv;
		}
		lv = lv->next;
	}
	return NULL;
}

void uwsgi_logvar_add(struct wsgi_request *wsgi_req, char *key, uint8_t keylen, char *val, uint8_t vallen) {

	struct uwsgi_logvar *lv = uwsgi_logvar_get(wsgi_req, key, keylen);
	if (lv) {
		memcpy(lv->val, val, vallen);
		lv->vallen = vallen;
		return;
	}

	// add a new log object

	lv = wsgi_req->logvars;
	if (lv) {
		while (lv) {
			if (!lv->next) {
				lv->next = uwsgi_malloc(sizeof(struct uwsgi_logvar));
				lv = lv->next;
				break;
			}
			lv = lv->next;
		}
	}
	else {
		lv = uwsgi_malloc(sizeof(struct uwsgi_logvar));
		wsgi_req->logvars = lv;
	}

	memcpy(lv->key, key, keylen);
	lv->keylen = keylen;
	memcpy(lv->val, val, vallen);
	lv->vallen = vallen;
	lv->next = NULL;

}

void uwsgi_check_logrotate(void) {

	char message[1024];
	int need_rotation = 0;
	int need_reopen = 0;

	if (uwsgi.log_master) {
		uwsgi.shared->logsize = lseek(uwsgi.original_log_fd, 0, SEEK_CUR);
	}
	else {
		uwsgi.shared->logsize = lseek(2, 0, SEEK_CUR);
	}

	if (uwsgi.log_maxsize > 0 && uwsgi.shared->logsize > uwsgi.log_maxsize) {
		need_rotation = 1;
	}

	if (uwsgi_check_touches(uwsgi.touch_logrotate)) {
		need_rotation = 1;
	}

	if (uwsgi_check_touches(uwsgi.touch_logreopen)) {
		need_reopen = 1;
	}

	if (need_rotation) {

		char *rot_name = uwsgi.log_backupname;
		int need_free = 0;
		if (rot_name == NULL) {
			char *ts_str = uwsgi_num2str((int) uwsgi_now());
			rot_name = uwsgi_concat3(uwsgi.logfile, ".", ts_str);
			free(ts_str);
			need_free = 1;
		}
		int ret = snprintf(message, 1024, "[%d] logsize: %llu, triggering rotation to %s...\n", (int) uwsgi_now(), (unsigned long long) uwsgi.shared->logsize, rot_name);
		if (ret > 0) {
			if (write(uwsgi.original_log_fd, message, ret) != ret) {
				// very probably this will never be printed
				uwsgi_error("write()");
			}
		}
		if (rename(uwsgi.logfile, rot_name) == 0) {
			// reopen logfile dup'it and eventually gracefully reload workers;
			int fd = open(uwsgi.logfile, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
			if (fd < 0) {
				uwsgi_error_open(uwsgi.logfile);
				grace_them_all(0);
			}
			if (dup2(fd, uwsgi.original_log_fd) < 0) {
				uwsgi_error("dup2()");
				grace_them_all(0);
			}

			close(fd);

		}
		else {
			uwsgi_error("unable to rotate log: rename()");
		}
		if (need_free)
			free(rot_name);
	}
	else if (need_reopen) {
		int ret = snprintf(message, 1024, "[%d] logsize: %llu, triggering log-reopen...\n", (int) uwsgi_now(), (unsigned long long) uwsgi.shared->logsize);
		if (ret > 0) {
			if (write(uwsgi.original_log_fd, message, ret) != ret) {
				// very probably this will never be printed
				uwsgi_error("write()");
			}
		}

		// reopen logfile;
		close(uwsgi.original_log_fd);
		uwsgi.original_log_fd = open(uwsgi.logfile, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP);
		if (uwsgi.original_log_fd < 0) {
			uwsgi_error_open(uwsgi.logfile);
			grace_them_all(0);
		}
		ret = snprintf(message, 1024, "[%d] %s reopened.\n", (int) uwsgi_now(), uwsgi.logfile);
		if (ret > 0) {
			if (write(uwsgi.original_log_fd, message, ret) != ret) {
				// very probably this will never be printed
				uwsgi_error("write()");
			}
		}
		uwsgi.shared->logsize = lseek(uwsgi.original_log_fd, 0, SEEK_CUR);
	}
}


void log_request(struct wsgi_request *wsgi_req) {

	int log_it = uwsgi.shared->options[UWSGI_OPTION_LOGGING];

	if (wsgi_req->do_not_log)
		return;

	if (wsgi_req->log_this) {
		goto logit;
	}

/* conditional logging */
	if (uwsgi.shared->options[UWSGI_OPTION_LOG_ZERO] && wsgi_req->response_size == 0) {
		goto logit;
	}
	if (uwsgi.shared->options[UWSGI_OPTION_LOG_SLOW] && (uint32_t) wsgi_req_time >= uwsgi.shared->options[UWSGI_OPTION_LOG_SLOW]) {
		goto logit;
	}
	if (uwsgi.shared->options[UWSGI_OPTION_LOG_4xx] && (wsgi_req->status >= 400 && wsgi_req->status <= 499)) {
		goto logit;
	}
	if (uwsgi.shared->options[UWSGI_OPTION_LOG_5xx] && (wsgi_req->status >= 500 && wsgi_req->status <= 599)) {
		goto logit;
	}
	if (uwsgi.shared->options[UWSGI_OPTION_LOG_BIG] && (wsgi_req->response_size >= uwsgi.shared->options[UWSGI_OPTION_LOG_BIG])) {
		goto logit;
	}
	if (uwsgi.shared->options[UWSGI_OPTION_LOG_SENDFILE] && (wsgi_req->sendfile_fd > -1 && wsgi_req->sendfile_obj == wsgi_req->async_result)) {
		goto logit;
	}

	if (!log_it)
		return;

logit:

	uwsgi.logit(wsgi_req);
}

void uwsgi_logit_simple(struct wsgi_request *wsgi_req) {

	// optimize this (please)
	char time_request[26];
	int rlen;
	int app_req = -1;
	char *msg2 = " ";
	char *via = msg2;

	char mempkt[4096];
	char logpkt[4096];

	struct iovec logvec[4];
	int logvecpos = 0;

	const char *msecs = "msecs";
	const char *micros = "micros";

	char *tsize = (char *) msecs;

	char *msg1 = " via sendfile() ";
	char *msg3 = " via route() ";
	char *msg4 = " via offload() ";

	struct uwsgi_app *wi;

	if (wsgi_req->app_id >= 0) {
		wi = &uwsgi_apps[wsgi_req->app_id];
		if (wi->requests > 0) {
			app_req = wi->requests;
		}
	}

	if (wsgi_req->sendfile_fd > -1 && wsgi_req->sendfile_obj == wsgi_req->async_result) {	//wsgi_req->sendfile_fd_size > 0 ) {
		via = msg1;
	}

	// mark route() requests
	if (wsgi_req->status == -17) {
		via = msg3;
	}
	else if (wsgi_req->status == -30) {
		via = msg4;
	}

#ifdef __sun__
	ctime_r((const time_t *) &wsgi_req->start_of_request_in_sec, time_request, 26);
#else
	ctime_r((const time_t *) &wsgi_req->start_of_request_in_sec, time_request);
#endif

	uint64_t rt = wsgi_req->end_of_request - wsgi_req->start_of_request;

	if (uwsgi.log_micros) {
		tsize = (char *) micros;
	}
	else {
		rt /= 1000;
	}

	if (uwsgi.vhost) {
		logvec[logvecpos].iov_base = wsgi_req->host;
		logvec[logvecpos].iov_len = wsgi_req->host_len;
		logvecpos++;

		logvec[logvecpos].iov_base = " ";
		logvec[logvecpos].iov_len = 1;
		logvecpos++;
	}

	if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] == 1) {
#ifndef UNBIT
		rlen = snprintf(mempkt, 4096, "{address space usage: %lld bytes/%lluMB} {rss usage: %llu bytes/%lluMB} ", (unsigned long long) uwsgi.workers[uwsgi.mywid].vsz_size, (unsigned long long) uwsgi.workers[uwsgi.mywid].vsz_size / 1024 / 1024, (unsigned long long) uwsgi.workers[uwsgi.mywid].rss_size, (unsigned long long) uwsgi.workers[uwsgi.mywid].rss_size / 1024 / 1024);
#else
		rlen = snprintf(mempkt, 4096, "{address space usage: %lld bytes/%lluMB} ", (unsigned long long) uwsgi.workers[uwsgi.mywid].vsz_size, (unsigned long long) uwsgi.workers[uwsgi.mywid].vsz_size / 1024 / 1024);
#endif

		logvec[logvecpos].iov_base = mempkt;
		logvec[logvecpos].iov_len = rlen;
		logvecpos++;

	}

	rlen = snprintf(logpkt, 4096, "[pid: %d|app: %d|req: %d/%llu] %.*s (%.*s) {%d vars in %d bytes} [%.*s] %.*s %.*s => generated %llu bytes in %llu %s%s(%.*s %d) %d headers in %llu bytes (%d switches on core %d)\n", (int) uwsgi.mypid, wsgi_req->app_id, app_req, (unsigned long long) uwsgi.workers[0].requests, wsgi_req->remote_addr_len, wsgi_req->remote_addr, wsgi_req->remote_user_len, wsgi_req->remote_user, wsgi_req->var_cnt, wsgi_req->uh.pktsize, 24, time_request, wsgi_req->method_len, wsgi_req->method, wsgi_req->uri_len, wsgi_req->uri, (unsigned long long) wsgi_req->response_size, (unsigned long long) rt, tsize, via, wsgi_req->protocol_len, wsgi_req->protocol, wsgi_req->status, wsgi_req->header_cnt, (unsigned long long) wsgi_req->headers_size, wsgi_req->switches, wsgi_req->async_id);

	// not enough space for logging the request, just log a (safe) minimal message
	if (rlen > 4096) {
		rlen = snprintf(logpkt, 4096, "[pid: %d|app: %d|req: %d/%llu] 0.0.0.0 () {%d vars in %d bytes} [%.*s] - - => generated %llu bytes in %llu %s%s(- %d) %d headers in %llu bytes (%d switches on core %d)\n", (int) uwsgi.mypid, wsgi_req->app_id, app_req, (unsigned long long) uwsgi.workers[0].requests, wsgi_req->var_cnt, wsgi_req->uh.pktsize, 24, time_request, (unsigned long long) wsgi_req->response_size, (unsigned long long) rt, tsize, via, wsgi_req->status, wsgi_req->header_cnt, (unsigned long long) wsgi_req->headers_size, wsgi_req->switches, wsgi_req->async_id);
		// argh, last resort, truncate it
		if (rlen > 4096) {
			rlen = 4096;
		}
	}

	logvec[logvecpos].iov_base = logpkt;
	logvec[logvecpos].iov_len = rlen;

	// do not check for errors
	rlen = writev(2, logvec, logvecpos + 1);
}

void get_memusage(uint64_t * rss, uint64_t * vsz) {

#ifdef UNBIT
	*vsz = syscall(356);
#elif defined(__linux__)
	FILE *procfile;
	int i;
	procfile = fopen("/proc/self/stat", "r");
	if (procfile) {
		i = fscanf(procfile, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu %lld", (unsigned long long *) vsz, (unsigned long long *) rss);
		if (i != 2) {
			uwsgi_log("warning: invalid record in /proc/self/stat\n");
		}
		fclose(procfile);
	}
	*rss = *rss * uwsgi.page_size;
#elif defined (__sun__)
	psinfo_t info;
	int procfd;

	procfd = open("/proc/self/psinfo", O_RDONLY);
	if (procfd >= 0) {
		if (read(procfd, (char *) &info, sizeof(info)) > 0) {
			*rss = (uint64_t) info.pr_rssize * 1024;
			*vsz = (uint64_t) info.pr_size * 1024;
		}
		close(procfd);
	}

#elif defined(__APPLE__)
	/* darwin documentation says that the value are in pages, but they are bytes !!! */
	struct task_basic_info t_info;
	mach_msg_type_number_t t_size = sizeof(struct task_basic_info);

	if (task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t) & t_info, &t_size) == KERN_SUCCESS) {
		*rss = t_info.resident_size;
		*vsz = t_info.virtual_size;
	}
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__)
	kvm_t *kv;
	int cnt;

#if defined(__FreeBSD__)
	kv = kvm_open(NULL, "/dev/null", NULL, O_RDONLY, NULL);
#elif defined(__NetBSD__) || defined(__OpenBSD__)
	kv = kvm_open(NULL, NULL, NULL, KVM_NO_FILES, NULL);
#else
	kv = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);
#endif
	if (kv) {
#if defined(__FreeBSD__) || defined(__DragonFly__)

		struct kinfo_proc *kproc;
		kproc = kvm_getprocs(kv, KERN_PROC_PID, uwsgi.mypid, &cnt);
		if (kproc && cnt > 0) {
			*vsz = kproc->ki_size;
			*rss = kproc->ki_rssize * uwsgi.page_size;
		}
#elif defined(UWSGI_NEW_OPENBSD)
		struct kinfo_proc *kproc;
		kproc = kvm_getprocs(kv, KERN_PROC_PID, uwsgi.mypid, sizeof(struct kinfo_proc), &cnt);
		if (kproc && cnt > 0) {
			*vsz = (kproc->p_vm_dsize + kproc->p_vm_ssize + kproc->p_vm_tsize) * uwsgi.page_size;
			*rss = kproc->p_vm_rssize * uwsgi.page_size;
		}
#elif defined(__NetBSD__) || defined(__OpenBSD__)
		struct kinfo_proc2 *kproc2;

		kproc2 = kvm_getproc2(kv, KERN_PROC_PID, uwsgi.mypid, sizeof(struct kinfo_proc2), &cnt);
		if (kproc2 && cnt > 0) {
#ifdef __OpenBSD__
			*vsz = (kproc2->p_vm_dsize + kproc2->p_vm_ssize + kproc2->p_vm_tsize) * uwsgi.page_size;
#else
			*vsz = kproc2->p_vm_msize * uwsgi.page_size;
#endif
			*rss = kproc2->p_vm_rssize * uwsgi.page_size;
		}
#endif

		kvm_close(kv);
	}
#elif defined(__HAIKU__)
	area_info ai;
	int32 cookie;

	*vsz = 0;
	*rss = 0;
	while (get_next_area_info(0, &cookie, &ai) == B_OK) {
		*vsz += ai.ram_size;
		if ((ai.protection & B_WRITE_AREA) != 0) {
			*rss += ai.ram_size;
		}
	}
#endif

}

void uwsgi_register_logger(char *name, ssize_t(*func) (struct uwsgi_logger *, char *, size_t)) {

	struct uwsgi_logger *ul = uwsgi.loggers, *old_ul;

	if (!ul) {
		uwsgi.loggers = uwsgi_malloc(sizeof(struct uwsgi_logger));
		ul = uwsgi.loggers;
	}
	else {
		while (ul) {
			old_ul = ul;
			ul = ul->next;
		}

		ul = uwsgi_malloc(sizeof(struct uwsgi_logger));
		old_ul->next = ul;
	}

	ul->name = name;
	ul->func = func;
	ul->next = NULL;
	ul->configured = 0;
	ul->fd = -1;
	ul->data = NULL;


#ifdef UWSGI_DEBUG
	uwsgi_log("[uwsgi-logger] registered \"%s\"\n", ul->name);
#endif
}

void uwsgi_append_logger(struct uwsgi_logger *ul) {

	if (!uwsgi.choosen_logger) {
		uwsgi.choosen_logger = ul;
		return;
	}

	struct uwsgi_logger *ucl = uwsgi.choosen_logger;
	while (ucl) {
		if (!ucl->next) {
			ucl->next = ul;
			return;
		}
		ucl = ucl->next;
	}
}

struct uwsgi_logger *uwsgi_get_logger(char *name) {
	struct uwsgi_logger *ul = uwsgi.loggers;

	while (ul) {
		if (!strcmp(ul->name, name)) {
			return ul;
		}
		ul = ul->next;
	}

	return NULL;
}

struct uwsgi_logger *uwsgi_get_logger_from_id(char *id) {
	struct uwsgi_logger *ul = uwsgi.choosen_logger;

	while (ul) {
		if (!strcmp(ul->id, id)) {
			return ul;
		}
		ul = ul->next;
	}

	return NULL;
}


void uwsgi_logit_lf(struct wsgi_request *wsgi_req) {
	struct uwsgi_logchunk *logchunk = uwsgi.logchunks;
	ssize_t rlen = 0;
	while (logchunk) {
		int pos = logchunk->vec;
		// raw string
		if (logchunk->type == 0) {
			uwsgi.logvectors[wsgi_req->async_id][pos].iov_base = logchunk->ptr;
			uwsgi.logvectors[wsgi_req->async_id][pos].iov_len = logchunk->len;
		}
		// offsetof
		else if (logchunk->type == 1) {
			char **var = (char **) (((char *) wsgi_req) + logchunk->pos);
			uint16_t *varlen = (uint16_t *) (((char *) wsgi_req) + logchunk->pos_len);
			uwsgi.logvectors[wsgi_req->async_id][pos].iov_base = *var;
			uwsgi.logvectors[wsgi_req->async_id][pos].iov_len = *varlen;
		}
		// logvar
		else if (logchunk->type == 2) {
			struct uwsgi_logvar *lv = uwsgi_logvar_get(wsgi_req, logchunk->ptr, logchunk->len);
			if (lv) {
				uwsgi.logvectors[wsgi_req->async_id][pos].iov_base = lv->val;
				uwsgi.logvectors[wsgi_req->async_id][pos].iov_len = lv->vallen;
			}
			else {
				uwsgi.logvectors[wsgi_req->async_id][pos].iov_base = NULL;
				uwsgi.logvectors[wsgi_req->async_id][pos].iov_len = 0;
			}
		}
		// func
		else if (logchunk->type == 3) {
			rlen = logchunk->func(wsgi_req, (char **) &uwsgi.logvectors[wsgi_req->async_id][pos].iov_base);
			if (rlen > 0) {
				uwsgi.logvectors[wsgi_req->async_id][pos].iov_len = rlen;
			}
			else {
				uwsgi.logvectors[wsgi_req->async_id][pos].iov_len = 0;
			}
		}
		logchunk = logchunk->next;
	}

	// do not check for errors
	rlen = writev(2, uwsgi.logvectors[wsgi_req->async_id], uwsgi.logformat_vectors);

	// free allocated memory
	logchunk = uwsgi.logchunks;
	while (logchunk) {
		if (logchunk->free) {
			if (uwsgi.logvectors[wsgi_req->async_id][logchunk->vec].iov_len > 0) {
				free(uwsgi.logvectors[wsgi_req->async_id][logchunk->vec].iov_base);
			}
		}
		logchunk = logchunk->next;
	}
}

void uwsgi_logit_lf_strftime(struct wsgi_request *wsgi_req) {
	uwsgi_log("lf strftime\n");
}

void uwsgi_build_log_format(char *format) {
	int state = 0;
	char *ptr = format;
	char *current = ptr;
	char *logvar = NULL;
	// get the number of required iovec
	while (*ptr) {
		if (*ptr == '%') {
			if (state == 0) {
				state = 1;
			}
		}
		// start of the variable
		else if (*ptr == '(') {
			if (state == 1) {
				state = 2;
			}
		}
		// end of the variable
		else if (*ptr == ')') {
			if (logvar) {
				uwsgi_add_logchunk(1, uwsgi.logformat_vectors, logvar, ptr - logvar);
				uwsgi.logformat_vectors++;
				state = 0;
				logvar = NULL;
				current = ptr + 1;
			}
		}
		else {
			if (state == 2) {
				uwsgi_add_logchunk(0, uwsgi.logformat_vectors, current, (ptr - current) - 2);
				uwsgi.logformat_vectors++;
				logvar = ptr;
			}
			state = 0;
		}
		ptr++;
	}

	if (ptr - current > 0) {
		uwsgi_add_logchunk(0, uwsgi.logformat_vectors, current, ptr - current);
		uwsgi.logformat_vectors++;
	}

	// +1 for "\n"

	uwsgi.logformat_vectors++;

}

ssize_t uwsgi_lf_status(struct wsgi_request *wsgi_req, char **buf) {
	*buf = uwsgi_num2str(wsgi_req->status);
	return strlen(*buf);
}

ssize_t uwsgi_lf_epoch(struct wsgi_request * wsgi_req, char **buf) {
	*buf = uwsgi_num2str(uwsgi_now());
	return strlen(*buf);
}

ssize_t uwsgi_lf_ctime(struct wsgi_request * wsgi_req, char **buf) {
	*buf = uwsgi_malloc(26);
#ifdef __sun__
	ctime_r((const time_t *) &wsgi_req->start_of_request_in_sec, *buf, 26);
#else
	ctime_r((const time_t *) &wsgi_req->start_of_request_in_sec, *buf);
#endif
	return 24;
}

ssize_t uwsgi_lf_time(struct wsgi_request * wsgi_req, char **buf) {
	*buf = uwsgi_num2str(wsgi_req->start_of_request / 1000000);
	return strlen(*buf);
}



ssize_t uwsgi_lf_micros(struct wsgi_request * wsgi_req, char **buf) {
	*buf = uwsgi_num2str(wsgi_req->end_of_request - wsgi_req->start_of_request);
	return strlen(*buf);
}

ssize_t uwsgi_lf_msecs(struct wsgi_request * wsgi_req, char **buf) {
	*buf = uwsgi_num2str((wsgi_req->end_of_request - wsgi_req->start_of_request) / 1000);
	return strlen(*buf);
}


void uwsgi_add_logchunk(int variable, int pos, char *ptr, size_t len) {

	struct uwsgi_logchunk *logchunk = uwsgi.logchunks;

	if (logchunk) {
		while (logchunk) {
			if (!logchunk->next) {
				logchunk->next = uwsgi_calloc(sizeof(struct uwsgi_logchunk));
				logchunk = logchunk->next;
				break;
			}
			logchunk = logchunk->next;
		}
	}
	else {
		uwsgi.logchunks = uwsgi_calloc(sizeof(struct uwsgi_logchunk));
		logchunk = uwsgi.logchunks;
	}

	/*
	   0 -> raw test
	   1 -> offsetof variable
	   2 -> logvar
	   3 -> func
	 */

	logchunk->type = variable;
	logchunk->vec = pos;
	// normal text
	logchunk->ptr = ptr;
	logchunk->len = len;
	// variable
	if (variable) {
		if (!uwsgi_strncmp(ptr, len, "uri", 3)) {
			logchunk->pos = offsetof(struct wsgi_request, uri);
			logchunk->pos_len = offsetof(struct wsgi_request, uri_len);
		}
		else if (!uwsgi_strncmp(ptr, len, "method", 6)) {
			logchunk->pos = offsetof(struct wsgi_request, method);
			logchunk->pos_len = offsetof(struct wsgi_request, method_len);
		}
		else if (!uwsgi_strncmp(ptr, len, "user", 4)) {
			logchunk->pos = offsetof(struct wsgi_request, remote_user);
			logchunk->pos_len = offsetof(struct wsgi_request, remote_user_len);
		}
		else if (!uwsgi_strncmp(ptr, len, "addr", 4)) {
			logchunk->pos = offsetof(struct wsgi_request, remote_addr);
			logchunk->pos_len = offsetof(struct wsgi_request, remote_addr_len);
		}
		else if (!uwsgi_strncmp(ptr, len, "host", 4)) {
			logchunk->pos = offsetof(struct wsgi_request, host);
			logchunk->pos_len = offsetof(struct wsgi_request, host_len);
		}
		else if (!uwsgi_strncmp(ptr, len, "proto", 5)) {
			logchunk->pos = offsetof(struct wsgi_request, protocol);
			logchunk->pos_len = offsetof(struct wsgi_request, protocol_len);
		}
		else if (!uwsgi_strncmp(ptr, len, "status", 6)) {
			logchunk->type = 3;
			logchunk->func = uwsgi_lf_status;
			logchunk->free = 1;
		}
		else if (!uwsgi_strncmp(ptr, len, "micros", 6)) {
			logchunk->type = 3;
			logchunk->func = uwsgi_lf_micros;
			logchunk->free = 1;
		}
		else if (!uwsgi_strncmp(ptr, len, "msecs", 5)) {
			logchunk->type = 3;
			logchunk->func = uwsgi_lf_msecs;
			logchunk->free = 1;
		}
		else if (!uwsgi_strncmp(ptr, len, "time", 4)) {
			logchunk->type = 3;
			logchunk->func = uwsgi_lf_time;
			logchunk->free = 1;
		}
		else if (!uwsgi_strncmp(ptr, len, "ctime", 5)) {
			logchunk->type = 3;
			logchunk->func = uwsgi_lf_ctime;
			logchunk->free = 1;
		}
		else if (!uwsgi_strncmp(ptr, len, "epoch", 5)) {
			logchunk->type = 3;
			logchunk->func = uwsgi_lf_epoch;
			logchunk->free = 1;
		}
		// logvar
		else {
			logchunk->type = 2;
		}
	}
}
