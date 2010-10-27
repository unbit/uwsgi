#ifdef UWSGI_UGREEN

/* uGreen -> uWSGI green threads */

#include "uwsgi.h"

#define UGREEN_DEFAULT_STACKSIZE 256*1024

extern struct uwsgi_server uwsgi;

void u_green_write_all(char *data, size_t len) {

	struct wsgi_request *wsgi_req;
	int i;
	ssize_t rlen;

	for(i=0;i<uwsgi.async;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
		if (wsgi_req->async_status == UWSGI_PAUSED) {
			rlen = write(wsgi_req->poll.fd, data, len);
			if (rlen < 0) {
				uwsgi_error("write()");
				// mark core as plagued
				wsgi_req->async_plagued = 1;
			}
			else {
				wsgi_req->response_size += rlen;
			}
		}
	}
}

void u_green_unpause_all() {

	struct wsgi_request *wsgi_req;
	int i;

	for(i=0;i<uwsgi.async;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
		if (wsgi_req->async_status == UWSGI_PAUSED) {
			wsgi_req->async_status = UWSGI_AGAIN;
			wsgi_req->async_timeout = 0;
		}
	}
}


static int u_green_blocking() {
	struct wsgi_request* wsgi_req;
	int i;

	for(i=0;i<uwsgi.async;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
		if (wsgi_req->async_status != UWSGI_ACCEPTING && wsgi_req->async_status != UWSGI_PAUSED && wsgi_req->async_waiting_fd == -1 && !wsgi_req->async_timeout) {
			return 0;
		}
	}

	return -1;
}

inline static void u_green_schedule_to_main(int async_id) {

	struct wsgi_request *wsgi_req = uwsgi.wsgi_requests[async_id];

	if (wsgi_req->async_status != UWSGI_ACCEPTING) {
		if (uwsgi.shared->hook_suspend[wsgi_req->uh.modifier1]) {
			uwsgi.shared->hook_suspend[wsgi_req->uh.modifier1](wsgi_req);
		}
	}

	swapcontext(uwsgi.ugreen_contexts[async_id], &uwsgi.ugreenmain);

	if (wsgi_req->async_status != UWSGI_ACCEPTING) {
		if (uwsgi.shared->hook_resume[wsgi_req->uh.modifier1]) {
			uwsgi.shared->hook_resume[wsgi_req->uh.modifier1](wsgi_req);
		}
	}
}

inline static void u_green_schedule_to_req(struct wsgi_request *wsgi_req) {

	
	if (wsgi_req->async_status != UWSGI_ACCEPTING) {
		if (uwsgi.shared->hook_suspend[wsgi_req->uh.modifier1]) {
			uwsgi.shared->hook_suspend[wsgi_req->uh.modifier1](wsgi_req);
		}
	}

	uwsgi.wsgi_req = wsgi_req;
	uwsgi_log("SWAPCONTEXT\n");
	//wsgi_req->async_switches++;
	swapcontext(&uwsgi.ugreenmain, uwsgi.ugreen_contexts[wsgi_req->async_id] );

	uwsgi_log("RESUMED\n");

	if (wsgi_req->async_status != UWSGI_ACCEPTING) {
		if (uwsgi.shared->hook_resume[wsgi_req->uh.modifier1]) {
			uwsgi.shared->hook_resume[wsgi_req->uh.modifier1](wsgi_req);
		}
	}

}

void u_green_wait_for_fd(struct wsgi_request *wsgi_req, int fd, int etype, int timeout) {

	if (fd < 0) return;

	if (async_add(uwsgi.async_queue, fd, etype)) return;

	wsgi_req->async_waiting_fd = fd;
	wsgi_req->async_waiting_fd_type = etype;
	wsgi_req->async_timeout = time(NULL) + timeout;

	u_green_schedule_to_main(wsgi_req->async_id);

	async_del(uwsgi.async_queue, wsgi_req->async_waiting_fd, wsgi_req->async_waiting_fd_type);

	wsgi_req->async_waiting_fd = -1;
	wsgi_req->async_timeout = 0;
}

static struct wsgi_request *find_first_accepting_wsgi_req() {

	struct wsgi_request* wsgi_req;
	int i;

	uwsgi_log("FFAR\n");
	for(i=0;i<uwsgi.async;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
		if (wsgi_req->async_status == UWSGI_ACCEPTING) {
			return wsgi_req;
		}
	}

	return NULL;
}


static void u_green_request(struct wsgi_request *wsgi_req, int async_id) {


	for(;;) {
		uwsgi_log("accept()\n");
		wsgi_req_setup(wsgi_req, async_id);

		wsgi_req->async_status = UWSGI_ACCEPTING;

		u_green_schedule_to_main(async_id);

		if (wsgi_req_accept(wsgi_req)) {
			continue;
		}
		wsgi_req->async_status = UWSGI_OK;

		// check here
		u_green_schedule_to_main(async_id);

		if (wsgi_req_recv(wsgi_req)) {
			continue;
		}

		while(wsgi_req->async_status == UWSGI_AGAIN) {
			u_green_schedule_to_main(async_id);
			wsgi_req->async_status = uwsgi.shared->hook_request[wsgi_req->uh.modifier1](wsgi_req);
		}

		u_green_schedule_to_main(async_id);

		uwsgi_close_request(wsgi_req);

	}

}

void u_green_init() {

	struct wsgi_request *wsgi_req;

	volatile int i;

	uwsgi.u_stack_size = UGREEN_DEFAULT_STACKSIZE;

	if (uwsgi.ugreen_stackpages > 0) {
		uwsgi.u_stack_size = uwsgi.ugreen_stackpages * uwsgi.page_size;
	}

	uwsgi_log("initializing %d uGreen threads with stack size of %lu (%lu KB)\n", uwsgi.async, (unsigned long) uwsgi.u_stack_size,  (unsigned long) uwsgi.u_stack_size/1024);


	uwsgi.ugreen_contexts = malloc( sizeof(ucontext_t*) * uwsgi.async);
	if (!uwsgi.ugreen_contexts) {
		uwsgi_error("malloc()\n");
		exit(1);
	}


	for(i=0;i<uwsgi.async;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
		uwsgi.ugreen_contexts[i] = malloc( sizeof(ucontext_t) );
		if (!uwsgi.ugreen_contexts[i]) {
			uwsgi_error("malloc()");
			exit(1);
		}
		getcontext(uwsgi.ugreen_contexts[i]);
		uwsgi.ugreen_contexts[i]->uc_stack.ss_sp = mmap(NULL, uwsgi.u_stack_size + (uwsgi.page_size*2) , PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0) + uwsgi.page_size;

		if (!uwsgi.ugreen_contexts[i]->uc_stack.ss_sp) {
			uwsgi_error("mmap()");
			exit(1);
		}
		// set guard pages for stack
		if (mprotect(uwsgi.ugreen_contexts[i]->uc_stack.ss_sp - uwsgi.page_size, uwsgi.page_size, PROT_NONE)) {
			uwsgi_error("mprotect()");
			exit(1);
		}
		if (mprotect(uwsgi.ugreen_contexts[i]->uc_stack.ss_sp + uwsgi.u_stack_size, uwsgi.page_size, PROT_NONE)) {
			uwsgi_error("mprotect()");
			exit(1);
		}

		uwsgi.ugreen_contexts[i]->uc_stack.ss_size = uwsgi.u_stack_size;
		uwsgi.ugreen_contexts[i]->uc_link = NULL;
		makecontext(uwsgi.ugreen_contexts[i], (void (*) (void)) &u_green_request, 2, wsgi_req, i);
		wsgi_req->async_status = UWSGI_ACCEPTING;
		wsgi_req->async_id = i;
		uwsgi_log("wsgi_req %d %d\n", wsgi_req->async_id, wsgi_req->async_status);
	}

}

void u_green_expire_timeouts() {

	struct wsgi_request* wsgi_req;
	int i;
	time_t deadline = time(NULL);


	for(i=0;i<uwsgi.async;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
		if (wsgi_req->async_timeout > 0) {
			if (wsgi_req->async_timeout <= deadline) {
				wsgi_req->async_status = UWSGI_AGAIN;
				wsgi_req->async_timeout = 0;
			}
		}
	}
}

static int u_green_get_timeout() {


	struct wsgi_request* wsgi_req;
	int i;
	time_t curtime, tdelta = 0;
	int ret = 0;

	if (!uwsgi.async_running) return 0;

	for(i=0;i<uwsgi.async;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
		if (wsgi_req->async_timeout > 0) {
			if (tdelta <= 0 || tdelta > wsgi_req->async_timeout) {
				tdelta = wsgi_req->async_timeout;
			}
		}
	}

	curtime = time(NULL);

	ret = tdelta - curtime;
	if (ret > 0) {
		return ret;
	}

	return 0;
}


void u_green_loop() {

	struct wsgi_request *wsgi_req;

	int i, current = 0, timeout;

	while(uwsgi.workers[uwsgi.mywid].manage_next_request) {


		uwsgi.async_running = u_green_blocking();
		timeout = u_green_get_timeout();
		uwsgi.async_nevents = async_wait(uwsgi.async_queue, uwsgi.async_events, uwsgi.async, uwsgi.async_running, timeout);
		u_green_expire_timeouts();

		if (uwsgi.async_nevents < 0) {
			continue;
		}


		for(i=0; i<uwsgi.async_nevents;i++) {

			if ( (int) uwsgi.async_events[i].ASYNC_FD == uwsgi.sockets[0].fd) {
				wsgi_req = find_first_accepting_wsgi_req();
				if (!wsgi_req) goto cycle;
				uwsgi_log("found %d\n", wsgi_req->async_id);
				u_green_schedule_to_req(wsgi_req);
				uwsgi_log("ooops\n");
			}
			else {
				uwsgi_log("fd ready\n");
				wsgi_req = find_wsgi_req_by_fd(uwsgi.async_events[i].ASYNC_FD, -1);
				if (wsgi_req) {
					u_green_schedule_to_req(wsgi_req);
				}
				else {
					async_del(uwsgi.async_queue, uwsgi.async_events[i].ASYNC_FD, uwsgi.async_events[i].ASYNC_EV);
				}
			}

		}

cycle:

		wsgi_req = uwsgi.wsgi_requests[current];
		uwsgi_log("schedule %d %d ?\n", current, wsgi_req->async_status);
		if (wsgi_req->async_status != UWSGI_ACCEPTING && wsgi_req->async_status != UWSGI_PAUSED && wsgi_req->async_waiting_fd == -1 && !wsgi_req->async_timeout) {
			uwsgi_log("schedule !\n");
			u_green_schedule_to_req(wsgi_req);
		}
		current++;
		if (current >= uwsgi.async) current = 0;

	}


}

#endif
