#include <uwsgi.h>

/*

	Soon before official Go 1.1, we understand supporting Go in a fork() heavy
	environment was not blessed by the Go community.

	Instead of completely dropping support for Go, we studied how the gccgo project works and we
	decided it was a better approach for uWSGI.

	This new plugin works by initializing a new "go runtime" after each fork().

	The runtime calls the Go main function (developed by the user), and pass the whole
	uWSGI control to it.
	
	the uwsgi.Run() go function directly calls the uwsgi_takeover() function (it automatically
	manages mules, spoolers and workers)

	As well as before each core maps to a goroutine mapped to a real pthread. (goroutines called
	from your apps are native goroutines)

*/

extern struct uwsgi_server uwsgi;
struct uwsgi_plugin gccgo_plugin;

struct uwsgi_gccgo{
	struct uwsgi_string_list *libs;
	char *args;
} ugccgo;

/*
static void uwsgi_opt_setup_goroutines(char *opt, char *value, void *foobar) {
        // set async mode
        uwsgi_opt_set_int(opt, value, &uwsgi.async);
        // set loop engine
        uwsgi.loop = "goroutines";
}
*/

struct uwsgi_option uwsgi_gccgo_options[] = {
	{"go-load", required_argument, 0, "load a go shared library in the process address space, eventually patching main.main and __go_init_main", uwsgi_opt_add_string_list, &ugccgo.libs, 0},
	{"gccgo-load", required_argument, 0, "load a go shared library in the process address space, eventually patching main.main and __go_init_main", uwsgi_opt_add_string_list, &ugccgo.libs, 0},
	{"go-args", required_argument, 0, "set go commandline arguments", uwsgi_opt_set_str, &ugccgo.args, 0},
	{"gccgo-args", required_argument, 0, "set go commandline arguments", uwsgi_opt_set_str, &ugccgo.args, 0},
 //       {"goroutines", required_argument, 0, "a shortcut setting optimal options for goroutine-based apps, takes the number of goroutines to spawn as argument", uwsgi_opt_setup_goroutines, NULL, UWSGI_OPT_THREADS},
        {0, 0, 0, 0, 0, 0, 0},

};

// no_split_stack is the key to avoid crashing !!!
void* runtime_m(void) __attribute__ ((noinline, no_split_stack));

void runtime_check(void);
void runtime_args(int, char **);
void runtime_osinit(void);
void runtime_schedinit(void);
void *__go_go(void *, void *);
void runtime_main(void);
void runtime_mstart(void *);

extern void uwsgigo_request(void *, void *) __asm__ ("go.uwsgi.RequestHandler");
extern void* uwsgigo_env(void *) __asm__ ("go.uwsgi.Env");
extern void* uwsgigo_env_add(void *, void *, uint16_t, void *, uint16_t) __asm__ ("go.uwsgi.EnvAdd");
extern void uwsgigo_run_core(int) __asm__ ("go.uwsgi.RunCore");
extern void uwsgigo_signal_handler(void *, uint8_t) __asm__ ("go.uwsgi.SignalHandler");
//extern void uwsgigo_loop(void) __asm__ ("go.uwsgi.Loop");

static void mainstart(void *arg __attribute__((unused))) {
	runtime_main();
}

void uwsgigo_main_main(void) __asm__ ("main.main");
void uwsgigo_main_init(void) __asm__ ("__go_init_main");

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
	struct uwsgi_string_list *usl = ugccgo.libs;
	while(usl) {
		void *handle = dlopen(usl->value, RTLD_NOW | RTLD_GLOBAL);
		if (!handle) {
			uwsgi_log("unable to open go shared library: %s\n", dlerror());
			exit(1);
		}
		uwsgi_log("[uwsgi-gccgo] loaded %s\n", usl->value);
		uwsgigo_hook_init = dlsym(handle, "__go_init_main");
		uwsgigo_hook_main = dlsym(handle, "main.main");
		usl = usl->next;
	}

	if (!uwsgigo_hook_init || !uwsgigo_hook_main) {
		return;
	}

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
		char **argv = uwsgi_calloc(sizeof(char *) * (argc + 1));
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
        for(i=0;i<wsgi_req->var_cnt;i++) {
                uwsgigo_env_add(wsgi_req->async_environ, wsgi_req->hvec[i].iov_base,  wsgi_req->hvec[i].iov_len, wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len);
                i++;
        }
	uwsgigo_request(wsgi_req->async_environ, wsgi_req);
	return UWSGI_OK;
}

static void uwsgi_gccgo_after_request(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

static int uwsgi_gccgo_signal_handler(uint8_t signum, void *handler) {
        uwsgigo_signal_handler(handler, signum);
	return 0;
}

struct uwsgi_plugin gccgo_plugin = {
        .name = "gccgo",
        .modifier1 = 11,
	.options = uwsgi_gccgo_options,
	//.on_load = uwsgi_gccgo_on_load,
        .request = uwsgi_gccgo_request,
        .after_request = uwsgi_gccgo_after_request,
        .post_fork = uwsgi_gccgo_initialize,
	.signal_handler = uwsgi_gccgo_signal_handler,
};
