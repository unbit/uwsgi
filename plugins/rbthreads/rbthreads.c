#include <uwsgi.h>
#include <ruby.h>

/*

	Author: Roberto De Ioris

	Why a loop engine ???

	The ruby 1.9/2.x threading model is very unique

	First of all we cannot attach to already spawned pthread, for this reason
	the "rbthreads" loop engine must create pthreads with rb_thread_create()

	The second reason is for how the GVL is managed.  We do not have
	functions (like in CPython) to explicitely release and acquire it.
	All happens via a function (rb_thread_call_without_gvl) calling the specified hook
	whenever the code blocks.

	Fortunately, thanks to the 1.9 async api, we can "patch" all of the server blocking parts
	with 2 simple hooks: uwsgi.wait_write_hook and uwsgi.wait_read_hook

	in addition to this we need to release the GVL in the accept() loop (but this is really easy)


*/

extern struct uwsgi_server uwsgi;

/*
	for some strange reason, some version of ruby 1.9 does not expose this declaration...
*/
void *rb_thread_call_without_gvl(void *(*func)(void *), void *data1,
                                 rb_unblock_function_t *ubf, void *data2);

struct uwsgi_rbthreads {
	int rbthreads;
	int (*orig_wait_write_hook) (int, int);
        int (*orig_wait_read_hook) (int, int);
        int (*orig_wait_milliseconds_hook) (int);
} urbts;

static struct uwsgi_option rbthreads_options[] = {
	{"rbthreads", no_argument, 0, "enable ruby native threads", uwsgi_opt_true, &urbts.rbthreads, 0},
	{"rb-threads", no_argument, 0, "enable ruby native threads", uwsgi_opt_true, &urbts.rbthreads, 0},
	{"rbthread", no_argument, 0, "enable ruby native threads", uwsgi_opt_true, &urbts.rbthreads, 0},
	{"rb-thread", no_argument, 0, "enable ruby native threads", uwsgi_opt_true, &urbts.rbthreads, 0},
        { 0, 0, 0, 0, 0, 0, 0 }
};

// this structure is passed between threads
struct uwsgi_rbthread {
	int queue;
	int core_id;
	struct wsgi_request *wsgi_req;
	// return value
	int ret;
	// fd to monitor
	int fd;
	// non-blockign timeout
	int timeout;
};

// this is called without the gvl
static void * uwsgi_rb_thread_accept(void *arg) {
	struct uwsgi_rbthread *urbt = (struct uwsgi_rbthread *) arg;
	urbt->ret = 0;
	if (wsgi_req_accept(urbt->queue, urbt->wsgi_req)) {
		urbt->ret = -1;
        }	
	return NULL;
}

static VALUE uwsgi_rb_thread_core(void *arg) {
	long core_id = (long) arg;
	struct wsgi_request *wsgi_req = &uwsgi.workers[uwsgi.mywid].cores[core_id].req;

        uwsgi_setup_thread_req(core_id, wsgi_req);

	struct uwsgi_rbthread *urbt = uwsgi_malloc(sizeof(struct uwsgi_rbthread));
        // initialize the main event queue to monitor sockets
        urbt->queue = event_queue_init();
	urbt->wsgi_req = wsgi_req;

        uwsgi_add_sockets_to_queue(urbt->queue, (int)core_id);

        if (uwsgi.signal_socket > -1) {
                event_queue_add_fd_read(urbt->queue, uwsgi.signal_socket);
                event_queue_add_fd_read(urbt->queue, uwsgi.my_signal_socket);
        }

        // ok we are ready, let's start managing requests and signals
        while (uwsgi.workers[uwsgi.mywid].manage_next_request) {

                wsgi_req_setup(wsgi_req, (int)core_id, NULL);

		rb_thread_call_without_gvl(uwsgi_rb_thread_accept, urbt, NULL, NULL);
		// accept failed ?
		if (urbt->ret) continue;

                if (wsgi_req_recv(urbt->queue, wsgi_req)) {
                        uwsgi_destroy_request(wsgi_req);
                        continue;
                }

                uwsgi_close_request(wsgi_req);
        }

	return Qnil;
}

static void rbthread_noop0() {
}

static void rbthread_noop(int core_id) {
}

static void *rbthreads_wait_fd_write_do(void *arg) {
        struct uwsgi_rbthread *urbt = (struct uwsgi_rbthread *) arg;
	urbt->ret = urbts.orig_wait_write_hook(urbt->fd, urbt->timeout);
	return NULL;
}

static int rbthreads_wait_fd_write(int fd, int timeout) {
	struct uwsgi_rbthread urbt;
	urbt.fd = fd;
	urbt.timeout = timeout;
	rb_thread_call_without_gvl(rbthreads_wait_fd_write_do, &urbt, NULL, NULL);
	return urbt.ret;
}

static void *rbthreads_wait_fd_read_do(void *arg) {
        struct uwsgi_rbthread *urbt = (struct uwsgi_rbthread *) arg;
        urbt->ret = urbts.orig_wait_read_hook(urbt->fd, urbt->timeout);
	return NULL;
}

static int rbthreads_wait_fd_read(int fd, int timeout) {
        struct uwsgi_rbthread urbt;
        urbt.fd = fd;
        urbt.timeout = timeout;
        rb_thread_call_without_gvl(rbthreads_wait_fd_read_do, &urbt, NULL, NULL);
        return urbt.ret;
}

static void *rbthreads_wait_milliseconds_do(void *arg) {
        struct uwsgi_rbthread *urbt = (struct uwsgi_rbthread *) arg;
        urbt->ret = urbts.orig_wait_milliseconds_hook(urbt->timeout);
        return NULL;
}

static int rbthreads_wait_milliseconds(int timeout) {
        struct uwsgi_rbthread urbt;
        urbt.timeout = timeout;
        rb_thread_call_without_gvl(rbthreads_wait_milliseconds_do, &urbt, NULL, NULL);
        return urbt.ret;
}


static void rbthreads_loop() {
	struct uwsgi_plugin *rup = uwsgi_plugin_get("rack");
	// disable init_thread warning
	if (rup) {
		rup->init_thread = rbthread_noop;
	}

	// override read/write nb hooks
	urbts.orig_wait_write_hook = uwsgi.wait_write_hook;
	urbts.orig_wait_read_hook = uwsgi.wait_read_hook;
	urbts.orig_wait_milliseconds_hook = uwsgi.wait_milliseconds_hook;
	uwsgi.wait_write_hook = rbthreads_wait_fd_write;
        uwsgi.wait_read_hook = rbthreads_wait_fd_read;
        uwsgi.wait_milliseconds_hook = rbthreads_wait_milliseconds;

	int i;
	for(i=1;i<uwsgi.threads;i++) {
		long y = i;
		rb_thread_create(uwsgi_rb_thread_core, (void *) y);
	}
	long y = 0;
	uwsgi_rb_thread_core((void *) y);
	// never here
}

static void rbthreads_setup() {
	uwsgi_register_loop( (char *) "rbthreads", rbthreads_loop);
}

static int rbthreads_init() {
	if (urbts.rbthreads) {
		if (uwsgi.threads < 2) {
			uwsgi_log("you have to spawn at least 2 threads for effective rbthreads support\n");
			exit(1);
		}
		struct uwsgi_plugin *rup = uwsgi_plugin_get("rack");
		// disable enable_threads warning
        	if (rup) {
                	rup->enable_threads = rbthread_noop0;
       		} 
		// set loop engine
        	uwsgi.loop = "rbthreads";
	}
	return 0;
}

struct uwsgi_plugin rbthreads_plugin = {
	.name = "rbthreads",
	.on_load = rbthreads_setup,
	.init = rbthreads_init,
	.options = rbthreads_options, 
};
