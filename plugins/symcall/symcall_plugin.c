#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_symcall {
	char *symcall_function_name;
	int (*symcall_function)(struct wsgi_request *);

	struct uwsgi_string_list *rpc;
	struct uwsgi_string_list *post_fork;
} usym;

struct uwsgi_plugin symcall_plugin;

static struct uwsgi_option uwsgi_symcall_options[] = {
        {"symcall", required_argument, 0, "load the specified C symbol as the symcall request handler", uwsgi_opt_set_str, &usym.symcall_function_name, 0},
        {"symcall-register-rpc", required_argument, 0, "load the specified C symbol as an RPC function (syntax: name function)", uwsgi_opt_add_string_list, &usym.rpc, 0},
        {"symcall-post-fork", required_argument, 0, "call the specified C symbol after each fork()", uwsgi_opt_add_string_list, &usym.post_fork, 0},
        {0, 0, 0, 0},
};

static void uwsgi_symcall_init(){
	if (usym.symcall_function_name) {
		usym.symcall_function = dlsym(RTLD_DEFAULT, usym.symcall_function_name);
		if (!usym.symcall_function) {
			uwsgi_log("unable to find symbol \"%s\" in process address space\n", usym.symcall_function_name);
			exit(1);
		}
		uwsgi_log("symcall function ptr: %p\n", usym.symcall_function);
	}

	struct uwsgi_string_list *usl = usym.rpc;
	while(usl) {
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

