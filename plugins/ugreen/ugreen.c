/* uGreen -> uWSGI green threads */

#include "../../uwsgi.h"

#ifdef __APPLE__
#define _XOPEN_SOURCE
#endif

#include <ucontext.h>

struct uwsgi_ugreen {
	int             ugreen;
        int             stackpages;
        ucontext_t      main;
        ucontext_t    **contexts;
        size_t          u_stack_size;
} ug;

#define UGREEN_DEFAULT_STACKSIZE 256*1024


extern struct uwsgi_server uwsgi;

struct option ugreen_options[] = {
	{"ugreen", no_argument, &ug.ugreen, 1},
	{"ugreen-stacksize", required_argument, 0, LONG_ARGS_UGREEN_PAGES},
	{ 0, 0, 0, 0 }
};

void u_green_loop(void);

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

inline static void u_green_schedule_to_main(struct wsgi_request *wsgi_req) {

	if (wsgi_req->async_status != UWSGI_ACCEPTING) {
		if (uwsgi.p[wsgi_req->uh.modifier1]->suspend) {
			uwsgi.p[wsgi_req->uh.modifier1]->suspend(wsgi_req);
		}
	}

	uwsgi_log("uGreen EXITING TO MAIN\n");
	swapcontext(ug.contexts[wsgi_req->async_id], &ug.main);

	uwsgi_log("uGreen RETURNED FROM MAIN\n");

	if (wsgi_req->async_status != UWSGI_ACCEPTING) {
		if (uwsgi.p[wsgi_req->uh.modifier1]->resume) {
			uwsgi.p[wsgi_req->uh.modifier1]->resume(wsgi_req);
		}
	}
}

inline static void u_green_schedule_to_req(struct wsgi_request *wsgi_req) {

	
	if (wsgi_req->async_status != UWSGI_ACCEPTING) {
		if (uwsgi.p[wsgi_req->uh.modifier1]->suspend) {
			uwsgi.p[wsgi_req->uh.modifier1]->suspend(wsgi_req);
		}
	}

	uwsgi.wsgi_req = wsgi_req;
	uwsgi_log("SWAPCONTEXT to %p\n", ug.contexts[wsgi_req->async_id]);
	//wsgi_req->async_switches++;
	swapcontext(&ug.main, ug.contexts[wsgi_req->async_id] );

	uwsgi_log("RESUMED\n");

	if (wsgi_req->async_status != UWSGI_ACCEPTING) {
		if (uwsgi.p[wsgi_req->uh.modifier1]->resume) {
			uwsgi.p[wsgi_req->uh.modifier1]->resume(wsgi_req);
		}
	}

}

void u_green_wait_for_fd(struct wsgi_request *wsgi_req, int fd, int etype, int timeout) {

	if (fd < 0) return;

	if (async_add(uwsgi.async_queue, fd, etype)) return;

	wsgi_req->async_waiting_fd = fd;
	wsgi_req->async_waiting_fd_type = etype;
	wsgi_req->async_timeout = time(NULL) + timeout;

	u_green_schedule_to_main(wsgi_req);

	async_del(uwsgi.async_queue, wsgi_req->async_waiting_fd, wsgi_req->async_waiting_fd_type);

	wsgi_req->async_waiting_fd = -1;
	wsgi_req->async_timeout = 0;
}

static struct wsgi_request *find_first_accepting_wsgi_req() {

	struct wsgi_request* wsgi_req;
	int i;

	for(i=0;i<uwsgi.async;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
		uwsgi_log("req status: %d\n",wsgi_req->async_status);
		if (wsgi_req->async_status == UWSGI_ACCEPTING) {
			return wsgi_req;
		}
	}

	return NULL;
}


static void u_green_request(struct wsgi_request *wsgi_req, int async_id) {

	uwsgi_log("request handler args %p %d\n", wsgi_req, async_id);

	for(;;) {
		uwsgi_log("accept()\n");
		wsgi_req_setup(wsgi_req, async_id);

		wsgi_req->async_status = UWSGI_ACCEPTING;

		u_green_schedule_to_main(wsgi_req);

		if (wsgi_req_accept(wsgi_req)) {
			continue;
		}

		uwsgi_log("REQUEST ACCEPTED\n");
		wsgi_req->async_status = UWSGI_OK;

		// check here
		//u_green_schedule_to_main(wsgi_req);

		if (wsgi_req_recv(wsgi_req)) {
			continue;
		}

		while(wsgi_req->async_status == UWSGI_AGAIN) {
			u_green_schedule_to_main(wsgi_req);
			wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);
		}

		u_green_schedule_to_main(wsgi_req);

		uwsgi_close_request(wsgi_req);

	}

}

int u_green_init() {

	struct wsgi_request *wsgi_req;

	volatile int i;

	ug.u_stack_size = UGREEN_DEFAULT_STACKSIZE;

	if (ug.stackpages > 0) {
		ug.u_stack_size = ug.stackpages * uwsgi.page_size;
	}

	uwsgi_log("initializing %d uGreen threads with stack size of %lu (%lu KB)\n", uwsgi.async, (unsigned long) ug.u_stack_size,  (unsigned long) ug.u_stack_size/1024);


	ug.contexts = malloc( sizeof(ucontext_t*) * uwsgi.async);
	if (!ug.contexts) {
		uwsgi_error("malloc()\n");
		exit(1);
	}


	for(i=0;i<uwsgi.async;i++) {
		wsgi_req = uwsgi.wsgi_requests[i];
		ug.contexts[i] = malloc( sizeof(ucontext_t) );
		if (!ug.contexts[i]) {
			uwsgi_error("malloc()");
			exit(1);
		}
		getcontext(ug.contexts[i]);

		ug.contexts[i]->uc_stack.ss_sp = mmap(NULL, ug.u_stack_size + (uwsgi.page_size*2) , PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0) + uwsgi.page_size;

		if (!ug.contexts[i]->uc_stack.ss_sp) {
			uwsgi_error("mmap()");
			exit(1);
		}
		// set guard pages for stack
		if (mprotect(ug.contexts[i]->uc_stack.ss_sp - uwsgi.page_size, uwsgi.page_size, PROT_NONE)) {
			uwsgi_error("mprotect()");
			exit(1);
		}
		if (mprotect(ug.contexts[i]->uc_stack.ss_sp + ug.u_stack_size, uwsgi.page_size, PROT_NONE)) {
			uwsgi_error("mprotect()");
			exit(1);
		}

		ug.contexts[i]->uc_stack.ss_size = ug.u_stack_size;

		ug.contexts[i]->uc_link = NULL;
		makecontext(ug.contexts[i], (void(*)(void)) u_green_request, 2, wsgi_req, i);
		wsgi_req->async_status = UWSGI_ACCEPTING;
		wsgi_req->async_id = i;
		uwsgi_log("wsgi_req %d %d %p\n", wsgi_req->async_id, wsgi_req->async_status, ug.contexts[i]);
	}

	uwsgi_register_loop("ugreen", u_green_loop);

	return 0;

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

	for(i=0;i<uwsgi.async;i++){
		wsgi_req = uwsgi.wsgi_requests[i];
		wsgi_req->async_status = UWSGI_ACCEPTING;
                wsgi_req->async_id = i;
	}

	uwsgi.schedule_to_main = u_green_schedule_to_main;

	uwsgi_log("FFAR: %p\n", find_first_accepting_wsgi_req());

	while(uwsgi.workers[uwsgi.mywid].manage_next_request) {

		//uwsgi_log("i am uGreen...\n");

		uwsgi.async_running = u_green_blocking();
		timeout = u_green_get_timeout();
		uwsgi.async_nevents = async_wait(uwsgi.async_queue, uwsgi.async_events, uwsgi.async, uwsgi.async_running, timeout);
		u_green_expire_timeouts();

		if (uwsgi.async_nevents < 0) {
			continue;
		}


		for(i=0; i<uwsgi.async_nevents;i++) {

			uwsgi_log("received I/O event on fd %d\n", uwsgi.async_events[i].ASYNC_FD);
			if ( (int) uwsgi.async_events[i].ASYNC_FD == uwsgi.sockets[0].fd) {
				wsgi_req = find_first_accepting_wsgi_req();
				uwsgi_log("found wsgireq at %p\n", wsgi_req);
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

int uwsgi_ugreen_manage_opt(int i, char *optarg) {

	switch(i) {
		case LONG_ARGS_UGREEN_PAGES:
                        ug.stackpages = atoi(optarg);
                        return 1;
	}

	return 0;
}

struct uwsgi_plugin ugreen_plugin = {

	.name = "ugreen",
	.init = u_green_init,
};
