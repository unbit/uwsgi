#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_symcall {
	struct uwsgi_string_list *symcall_function_name;
	int (*symcall_function)(struct wsgi_request *);
	struct uwsgi_string_list *rpc;
	struct uwsgi_string_list *post_fork;
} usym;

struct uwsgi_plugin symcall_plugin;

static struct uwsgi_option uwsgi_symcall_options[] = {
        {"symcall", required_argument, 0, "load the specified C symbol as the symcall request handler (supports <mountpoint=func> too)", uwsgi_opt_add_string_list, &usym.symcall_function_name, 0},
        {"symcall-register-rpc", required_argument, 0, "load the specified C symbol as an RPC function (syntax: name function)", uwsgi_opt_add_string_list, &usym.rpc, 0},
        {"symcall-post-fork", required_argument, 0, "call the specified C symbol after each fork()", uwsgi_opt_add_string_list, &usym.post_fork, 0},
        {0, 0, 0, 0},
};

static void uwsgi_symcall_init(){
	struct uwsgi_string_list *usl = NULL;
	int has_mountpoints = 0;
	uwsgi_foreach(usl, usym.symcall_function_name) {
		char *func = usl->value, *mountpoint = "";
		char *equal = strchr(usl->value, '=');
		if (equal) {
			*equal = 0;
			func = equal+1;
			mountpoint = usl->value;
			has_mountpoints = 1;
		}
		usl->custom_ptr = dlsym(RTLD_DEFAULT, func);
		if (!usl->custom_ptr) {
			uwsgi_log("unable to find symbol \"%s\" in process address space\n", func);
			exit(1);
		}
		int id = uwsgi_apps_cnt;
		struct uwsgi_app *ua = uwsgi_add_app(id, symcall_plugin.modifier1, mountpoint, strlen(mountpoint), usl->custom_ptr, NULL);
		uwsgi_log("symcall app %d (mountpoint: \"%.*s\") mapped to function ptr: %p\n", id, ua->mountpoint_len, ua->mountpoint, usl->custom_ptr);
		if (equal) *equal = '=';
	}

	if (!has_mountpoints && usym.symcall_function_name) {
		usym.symcall_function = usym.symcall_function_name->custom_ptr;
	}

	uwsgi_foreach(usl, usym.rpc) {
		char *space = strchr(usl->value, ' ');
		if (!space) {
			uwsgi_log("invalid symcall RPC syntax, must be: rpcname symbol\n");
			exit(1);
		}
		*space = 0;
		void *func = dlsym(RTLD_DEFAULT, space+1);
		if (!func) {
			uwsgi_log("unable to find symbol \"%s\" in process address space\n", space+1);
			exit(1);
		}
		if (uwsgi_register_rpc(usl->value, &symcall_plugin, 0, func)) {
                	uwsgi_log("unable to register rpc function");
			exit(1);
        	}
		*space = ' ';
		usl = usl->next;
	}
}

static int uwsgi_symcall_request(struct wsgi_request *wsgi_req) {
	if (usym.symcall_function) {
		return usym.symcall_function(wsgi_req);
	}

	if (uwsgi_parse_vars(wsgi_req)) return -1;

        wsgi_req->app_id = uwsgi_get_app_id(wsgi_req, wsgi_req->appid, wsgi_req->appid_len, symcall_plugin.modifier1);
        if (wsgi_req->app_id == -1 && !uwsgi.no_default_app && uwsgi.default_app > -1) {
                if (uwsgi_apps[uwsgi.default_app].modifier1 == symcall_plugin.modifier1) {
                        wsgi_req->app_id = uwsgi.default_app;
                }
        }

        if (wsgi_req->app_id == -1) {
                uwsgi_404(wsgi_req);
                return UWSGI_OK;
        }

        struct uwsgi_app *ua = &uwsgi_apps[wsgi_req->app_id];
	if (ua->interpreter) {
		int (*func)(struct wsgi_request *) = (int (*)(struct wsgi_request *)) ua->interpreter;
		return func(wsgi_req);
	}
	return UWSGI_OK;
}


static void uwsgi_symcall_after_request(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

static uint64_t uwsgi_symcall_rpc(void *func, uint8_t argc, char **argv, uint16_t argvs[], char **buffer) {
	uint64_t (*casted_func)(uint8_t, char **, uint16_t *, char **) = (uint64_t (*)(uint8_t, char **, uint16_t *, char **)) func;
	return casted_func(argc, argv, argvs, buffer);
}

static void uwsgi_symcall_post_fork() {
	void (*func)(void);
	struct uwsgi_string_list *usl = usym.post_fork;
        while(usl) {
                func = dlsym(RTLD_DEFAULT, usl->value);
                if (!func) {
                        uwsgi_log("unable to find symbol \"%s\" in process address space\n", usl->value);
                        exit(1);
                }
		func();
                usl = usl->next;
        }
}

struct uwsgi_plugin symcall_plugin = {

        .name = "symcall",
        .modifier1 = 18,
	.options = uwsgi_symcall_options,
        .init_apps = uwsgi_symcall_init,
        .request = uwsgi_symcall_request,
        .after_request = uwsgi_symcall_after_request,
	.rpc = uwsgi_symcall_rpc,
	.post_fork = uwsgi_symcall_post_fork,

};

