#include <uwsgi.h>

/*

	Soon before official Go 1.1, we understood supporting Go in a fork() heavy
	environment was not blessed by the Go community.

	Instead of completely dropping support for Go, we studied how the gccgo project works and we
	decided it was a better approach for uWSGI.

	This new plugin works by initializing a new "go runtime" after each fork().

	The runtime calls the Go main function (developed by the user), and pass the whole
	uWSGI control to it.
	
	the uwsgi.Run() go function directly calls the uwsgi_takeover() function (it automatically
	manages mules, spoolers and workers)

	The plugin implements goroutines too.

	On startup a goroutine is created for each socket and signals file descriptors.

	For every request a new goroutine is created too.

	The wsgi_request * structure is attached to the "closure" field of the goroutine (PAY ATTENTION)

	even if the loop engine makes use of the async mode, pthreads could be spawned all over the place.
	For such a reason a mutex is created avoiding the global wsgi_req structures to be clobbered

	Contrary to the standard way Go apps are deployed, the plugin supports loading shared libraries.
	While this is a common approach in other environments, the Go community prefers monolithic binaries.

	As always, choose the model that best suite for you. Eventually building a single uWSGI binary with your Go
	app embedded is pretty easy:

	
	CFLAGS=-DUWSGI_GCCGO_MONOLITHIC UWSGI_ADDITIONAL_SOURCES=t/go/uploadtest.go UWSGI_PROFILE=gccgo make

	or you can add the following two directives in a build profile:

	cflags = -DUWSGI_GCCGO_MONOLITHIC
	additional_sources = t/go/uploadtest.go


*/

extern struct uwsgi_server uwsgi;
struct uwsgi_plugin gccgo_plugin;

struct uwsgi_gccgo{
	// 1 if a main is loaded
	int initialized;
	struct uwsgi_string_list *libs;
	char *args;
	pthread_mutex_t wsgi_req_lock;
} ugccgo;

/*
	shortcut for enabling the "goroutines" loop engine
*/
static void uwsgi_opt_setup_goroutines(char *opt, char *value, void *foobar) {
        // set async mode
        uwsgi_opt_set_int(opt, value, &uwsgi.async);
        // set loop engine
        uwsgi.loop = "goroutines";
}

struct uwsgi_option uwsgi_gccgo_options[] = {
	{"go-load", required_argument, 0, "load a go shared library in the process address space, eventually patching main.main and __go_init_main", uwsgi_opt_add_string_list, &ugccgo.libs, 0},
	{"gccgo-load", required_argument, 0, "load a go shared library in the process address space, eventually patching main.main and __go_init_main", uwsgi_opt_add_string_list, &ugccgo.libs, 0},
	{"go-args", required_argument, 0, "set go commandline arguments", uwsgi_opt_set_str, &ugccgo.args, 0},
	{"gccgo-args", required_argument, 0, "set go commandline arguments", uwsgi_opt_set_str, &ugccgo.args, 0},
	{"goroutines", required_argument, 0, "a shortcut setting optimal options for goroutine-based apps, takes the number of max goroutines to spawn as argument", uwsgi_opt_setup_goroutines, NULL, UWSGI_OPT_THREADS},
        {0, 0, 0, 0, 0, 0, 0},

};

// no_split_stack is the key to avoid crashing !!!
void* runtime_m(void) __attribute__ ((noinline, no_split_stack));

// initialize runtime
void runtime_check(void);
void runtime_args(int, char **);
void runtime_osinit(void);
void runtime_schedinit(void);
void runtime_main(void);
void runtime_mstart(void *);

// spawn a goroutine
void *__go_go(void *, void *);

// api functions exposed
extern void uwsgigo_request(void *, void *) __asm__ ("go.uwsgi.RequestHandler");
extern void* uwsgigo_env(void *) __asm__ ("go.uwsgi.Env");
extern void* uwsgigo_env_add(void *, void *, uint16_t, void *, uint16_t) __asm__ ("go.uwsgi.EnvAdd");
extern void uwsgigo_signal_handler(void *, uint8_t) __asm__ ("go.uwsgi.SignalHandler");

// for goroutines 
void runtime_netpollinit(void);
void runtime_starttheworld(void);
void *runtime_pollOpen(int) __asm__ ("net.runtime_pollOpen");
void runtime_pollClose(void *) __asm__ ("net.runtime_pollClose");
void runtime_pollUnblock(void *) __asm__ ("net.runtime_pollUnblock");
int runtime_pollWait(void *, int) __asm__ ("net.runtime_pollWait");
void runtime_pollSetDeadline(void *, int64_t, int) __asm__ ("net.runtime_pollSetDeadline");
void runtime_gosched(void);
// the current goroutine
void *runtime_g(void);
// we use the closure field to store the wsgi_req structure
void __go_set_closure(void *);
void *__go_get_closure(void);

static void mainstart(void *arg __attribute__((unused))) {
	runtime_main();
}

#ifndef UWSGI_GCCGO_MONOLITHIC
void uwsgigo_main_main(void) __asm__ ("main.main");
void uwsgigo_main_init(void) __asm__ ("__go_init_main");
#endif

void (*uwsgigo_hook_init)(void);
void (*uwsgigo_hook_main)(void);

void uwsgigo_main_init(void) {
	uwsgigo_hook_init();
}

void uwsgigo_main_main(void) {
	uwsgigo_hook_main();
}

int uwsgi_gccgo_helper_request_body_read(struct wsgi_request *wsgi_req, char *p, uint64_t len) {
	ssize_t rlen = 0;
	char *buf = uwsgi_request_body_read(wsgi_req, len, &rlen);
	if (buf == uwsgi.empty) {
		return 0;
	}
	else if (buf == NULL) {
		return -1;
	}
	memcpy(p, buf, rlen);
	return (int) rlen;
}

int uwsgi_gccgo_helper_register_signal(uint8_t signum, char *receiver, void *handler) {
	return uwsgi_register_signal(signum, receiver, handler, gccgo_plugin.modifier1);
}

static void uwsgi_gccgo_initialize() {
	if (uwsgi.threads > 1) {
		uwsgi_log("!!! the Go runtime cannot work in multithreaded modes !!!\n");
		exit(1);
	}
#ifdef UWSGI_GCCGO_MONOLITHIC
	uwsgigo_hook_init = dlsym(RTLD_DEFAULT, "__go_init_main");
	uwsgigo_hook_main = dlsym(RTLD_DEFAULT, "main.main");
#endif
	struct uwsgi_string_list *usl = ugccgo.libs;
	while(usl) {
		void *handle = dlopen(usl->value, RTLD_NOW | RTLD_GLOBAL);
		if (!handle) {
			uwsgi_log("unable to open go shared library: %s\n", dlerror());
			exit(1);
		}
		void *g_init = dlsym(handle, "__go_init_main");
		void *g_main = dlsym(handle, "main.main");
		if (g_init && g_main) {
			uwsgigo_hook_init = g_init;
			uwsgigo_hook_main = g_main;
			uwsgi_log("[uwsgi-gccgo] loaded %s as main\n", usl->value);
		}
		else {
			uwsgi_log("[uwsgi-gccgo] loaded %s\n", usl->value);
		}
		usl = usl->next;
	}

	if (!uwsgigo_hook_init || !uwsgigo_hook_main) {
		return;
	}

	ugccgo.initialized = 1;

	// Go runtime initialization
	int argc = 0;
	if (ugccgo.args) {
        	char *argv_list = uwsgi_str(ugccgo.args);
                char *p, *ctx = NULL;
		uwsgi_foreach_token(argv_list, " ", p, ctx) {
			argc++;
                }
		free(argv_list);
        }
        runtime_check();
	if (argc > 0) {
		char **argv = uwsgi_calloc(sizeof(char *) * (argc + 2));
		char *argv_list = uwsgi_str(ugccgo.args);
		char *p, *ctx = NULL;
		int n = 0;
		uwsgi_foreach_token(argv_list, " ", p, ctx) {
			argv[n] = p;
			n++;
                }
        	runtime_args(argc, argv);
	}
	else {
		char *argv[2] = {0,0};
        	runtime_args(0, argv);
	}

        runtime_osinit();
        runtime_schedinit();
        __go_go(mainstart, NULL);
        runtime_mstart(runtime_m());
	// never here
}

static int uwsgi_gccgo_request(struct wsgi_request *wsgi_req) {
	if (!ugccgo.initialized) {
		uwsgi_log("!!! Go runtime not initialized !!!\n");
		goto end;
	}
	/* Standard GO request */
        if (!wsgi_req->uh->pktsize) {
                uwsgi_log("Empty GO request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }

	wsgi_req->async_environ = uwsgigo_env(wsgi_req);
	int i;
        for(i=0;i<wsgi_req->var_cnt;i+=2) {
                uwsgigo_env_add(wsgi_req->async_environ, wsgi_req->hvec[i].iov_base,  wsgi_req->hvec[i].iov_len, wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len);
        }
	uwsgigo_request(wsgi_req->async_environ, wsgi_req);
end:
	return UWSGI_OK;
}

static void uwsgi_gccgo_after_request(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

static int uwsgi_gccgo_signal_handler(uint8_t signum, void *handler) {
	if (!ugccgo.initialized) return -1;
        uwsgigo_signal_handler(handler, signum);
	return 0;
}

#define free_req_queue pthread_mutex_lock(&ugccgo.wsgi_req_lock);uwsgi.async_queue_unused_ptr++; uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = wsgi_req; pthread_mutex_unlock(&ugccgo.wsgi_req_lock)

static void uwsgi_gccgo_request_goroutine(void *arg) {

	struct wsgi_request *wsgi_req = (struct wsgi_request *) arg;

	// map wsgi_req to the goroutine
	__go_set_closure(wsgi_req);

	int ret,status;

        for(;;) {
                ret = uwsgi.wait_read_hook(wsgi_req->fd, uwsgi.socket_timeout);
                wsgi_req->switches++;

                if (ret <= 0) {
                        goto end;
                }

retry:
                status = wsgi_req->socket->proto(wsgi_req);
                if (status < 0) {
                        goto end;
                }
                else if (status == 0) {
                        break;
                }
		if (uwsgi_is_again()) continue;
		goto retry;
        }

#ifdef UWSGI_ROUTING
        if (uwsgi_apply_routes(wsgi_req) == UWSGI_ROUTE_BREAK) {
                goto end;
        }
#endif

        for(;;) {
                if (uwsgi.p[wsgi_req->uh->modifier1]->request(wsgi_req) <= UWSGI_OK) {
                        goto end;
                }
                wsgi_req->switches++;
		// yield
		runtime_gosched();
        }

end:
        uwsgi_close_request(wsgi_req);
        free_req_queue;
}

static struct wsgi_request *uwsgi_gccgo_current_wsgi_req(void) {
	return (struct wsgi_request *) __go_get_closure();
}

static int uwsgi_gccgo_wait_read_hook(int fd, int timeout) {
        void *pdesc = runtime_pollOpen(fd);
	int64_t t = (uwsgi_micros() * 1000LL) + (((int64_t)timeout) * 1000LL * 1000LL * 1000LL);
	runtime_pollSetDeadline(pdesc, t, 'r');
        int ret = runtime_pollWait(pdesc, 'r');
	runtime_pollUnblock(pdesc);
        runtime_pollClose(pdesc);
	if (ret == 0) return 1;
	// timeout
	if (ret == 2) return 0;
	return -1;
}

static int uwsgi_gccgo_wait_write_hook(int fd, int timeout) {
	void *pdesc = runtime_pollOpen(fd);
	int64_t t = (uwsgi_micros() * 1000LL) + (((int64_t)timeout) * 1000LL * 1000LL * 1000LL);
	runtime_pollSetDeadline(pdesc, t, 'w');
	int ret = runtime_pollWait(pdesc, 'w');	
	runtime_pollUnblock(pdesc);
	runtime_pollClose(pdesc);
	if (ret == 0) return 1;
	// timeout
	if (ret == 2) return 0;
	return -1;
}

/*
	this goroutine manages signals
*/
static void uwsgi_gccgo_signal_goroutine(void *arg) {
	int *fd = (int *) arg;
	void *pdesc = runtime_pollOpen(*fd);
	for(;;) {
		runtime_pollWait(pdesc, 'r');
retry:
		uwsgi_receive_signal(*fd, "worker", uwsgi.mywid);
		if (uwsgi_is_again()) continue;
		goto retry;
	}
}

static void uwsgi_gccgo_socket_goroutine(void *arg) {
	struct uwsgi_socket *uwsgi_sock = (struct uwsgi_socket *) arg;
	struct wsgi_request *wsgi_req = NULL;
	void *pdesc = runtime_pollOpen(uwsgi_sock->fd);
	// wait for connection
	for(;;) {
		runtime_pollWait(pdesc, 'r');	
retry:
		pthread_mutex_lock(&ugccgo.wsgi_req_lock);
		wsgi_req = find_first_available_wsgi_req();
		pthread_mutex_unlock(&ugccgo.wsgi_req_lock);

		if (wsgi_req == NULL) {
                	uwsgi_async_queue_is_full(uwsgi_now());
			// try rescheduling...
			// we do not use runtime_gosched() as we want to call the netpoll loop too
			runtime_pollUnblock(pdesc);
			runtime_pollClose(pdesc);
			pdesc = runtime_pollOpen(uwsgi_sock->fd);
			continue;
		}

		// fill wsgi_request structure
		wsgi_req_setup(wsgi_req, wsgi_req->async_id, uwsgi_sock );

		// mark core as used
		uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 1;

		// accept the connection (since uWSGI 1.5 all of the sockets are non-blocking)
		if (wsgi_req_simple_accept(wsgi_req, uwsgi_sock->fd)) {
			uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 0;
                	free_req_queue;
			if (uwsgi_is_again()) continue;
                        goto retry;
                }

		wsgi_req->start_of_request = uwsgi_micros();
		wsgi_req->start_of_request_in_sec = wsgi_req->start_of_request/1000000;

		// enter harakiri mode
		if (uwsgi.harakiri_options.workers > 0) {
                	set_harakiri(uwsgi.harakiri_options.workers);
        	}

		// spawn the new goroutine
		__go_go(uwsgi_gccgo_request_goroutine, wsgi_req);
		goto retry;
	}
}

static void uwsgi_gccgo_loop() {
	if (!ugccgo.initialized) {
		uwsgi_log("no go.main code loaded !!!\n");
		exit(1);
	}
	// initialize the log protecting the wsgi_req structures
	pthread_mutex_init(&ugccgo.wsgi_req_lock, NULL);

	// hooks
	uwsgi.current_wsgi_req = uwsgi_gccgo_current_wsgi_req;
	uwsgi.wait_write_hook = uwsgi_gccgo_wait_write_hook;
        uwsgi.wait_read_hook = uwsgi_gccgo_wait_read_hook;

	// ininitialize Go I/O loop
	runtime_netpollinit();

	if (uwsgi.signal_socket > -1) {
		__go_go(uwsgi_gccgo_signal_goroutine, &uwsgi.signal_socket);
		__go_go(uwsgi_gccgo_signal_goroutine, &uwsgi.my_signal_socket);
	}

	// start a goroutine for each socket
	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
	while(uwsgi_sock) {
		if (!uwsgi_sock->next) {
			uwsgi_gccgo_socket_goroutine(uwsgi_sock);
		}
		else {
			__go_go(uwsgi_gccgo_socket_goroutine, uwsgi_sock);
		}
		uwsgi_sock = uwsgi_sock->next;
	}

	// never here
}

static void uwsgi_gccgo_on_load() {
	uwsgi_register_loop( (char *) "go", uwsgi_gccgo_loop);
	uwsgi_register_loop( (char *) "goroutine", uwsgi_gccgo_loop);
	uwsgi_register_loop( (char *) "goroutines", uwsgi_gccgo_loop);
}

struct uwsgi_plugin gccgo_plugin = {
        .name = "gccgo",
        .modifier1 = 11,
	.options = uwsgi_gccgo_options,
	.on_load = uwsgi_gccgo_on_load,
        .request = uwsgi_gccgo_request,
        .after_request = uwsgi_gccgo_after_request,
        .post_fork = uwsgi_gccgo_initialize,
	.signal_handler = uwsgi_gccgo_signal_handler,
};
