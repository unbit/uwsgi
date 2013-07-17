#include <uwsgi.h>
#include <ruby.h>

extern struct uwsgi_server uwsgi;

void *rb_thread_call_with_gvl(void *(*func)(void *), void *data1);
void *rb_thread_call_without_gvl(void *(*func)(void *), void *data1,
                                 rb_unblock_function_t *ubf, void *data2);
void *rb_thread_call_without_gvl2(void *(*func)(void *), void *data1,
                                  rb_unblock_function_t *ubf, void *data2);

struct uwsgi_rbthreads {
	int rbthreads;
} urbts;

static struct uwsgi_option rbthreads_options[] = {
	{"rbthreads", no_argument, 0, "spawn the specified number of ruby native threads", uwsgi_opt_true, &urbts.rbthreads, 0},
	{"rb-threads", no_argument, 0, "spawn the specified number of ruby native threads", uwsgi_opt_true, &urbts.rbthreads, 0},
	{"rbthread", no_argument, 0, "spawn the specified number of ruby native threads", uwsgi_opt_true, &urbts.rbthreads, 0},
	{"rb-thread", no_argument, 0, "spawn the specified number of ruby native threads", uwsgi_opt_true, &urbts.rbthreads, 0},
        { 0, 0, 0, 0, 0, 0, 0 }
};

// this structure is passed between threads
struct uwsgi_rbthread {
	int queue;
	int core_id;
	struct wsgi_request *wsgi_req;
	int ret;
};

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

        if (uwsgi.threads > 1) {
                uwsgi_setup_thread_req(core_id, wsgi_req);
        }

	struct uwsgi_rbthread *urbt = uwsgi_malloc(sizeof(struct uwsgi_rbthread));
        // initialize the main event queue to monitor sockets
        urbt->queue = event_queue_init();
	urbt->wsgi_req = wsgi_req;

        uwsgi_add_sockets_to_queue(urbt->queue, core_id);

        if (uwsgi.signal_socket > -1) {
                event_queue_add_fd_read(urbt->queue, uwsgi.signal_socket);
                event_queue_add_fd_read(urbt->queue, uwsgi.my_signal_socket);
        }

        // ok we are ready, let's start managing requests and signals
        while (uwsgi.workers[uwsgi.mywid].manage_next_request) {

                wsgi_req_setup(wsgi_req, core_id, NULL);

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

static void rbthreads_loop() {
	struct uwsgi_plugin *rup = uwsgi_plugin_get("rack");
	// disable init_thread warning
	if (rup) {
		rup->init_thread = rbthread_noop;
	}
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
