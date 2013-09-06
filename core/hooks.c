#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

/*

	advanced (pluggable) hooks

	they are executed before the other hooks, and can be extended by plugins

	if a plugin tries to register an hook with a name already available in the list, its function
	will be overridden

*/

struct uwsgi_hook *uwsgi_hook_by_name(char *name) {
	struct uwsgi_hook *uh = uwsgi.hooks;
	while(uh) {
		if (!strcmp(uh->name, name)) {
			return uh;
		}
		uh = uh->next;
	}
	return NULL;
}

void uwsgi_register_hook(char *name, int (*func)(char *)) {
	struct uwsgi_hook *old_uh = NULL, *uh = uwsgi.hooks;
        while(uh) {
                if (!strcmp(uh->name, name)) {
                        uh->func = func;
			return;
                }
		old_uh = uh;
		uh = uh->next;
        }

	uh = uwsgi_calloc(sizeof(struct uwsgi_hook));
	uh->name = name;
	uh->func = func;

	if (old_uh) {
		old_uh->next = uh;
	}
	else {
		uwsgi.hooks = uh;
	}
}

static int uwsgi_hook_chdir(char *arg) {
	int ret = chdir(arg);
	if (ret) {
		uwsgi_error("uwsgi_hook_chdir()");
	}
	return ret;
}

static int uwsgi_hook_exec(char *arg) {
	int ret = uwsgi_run_command_and_wait(NULL, arg);
	if (ret != 0) {
        	uwsgi_log("command \"%s\" exited with non-zero code: %d\n", arg, ret);
        }
	return ret;
}

static int uwsgi_hook_exit(char *arg) {
	int exit_code = 0;
	if (strlen(arg) > 1) {
		exit_code = atoi(arg);
	}
	exit(exit_code);
}

static int uwsgi_hook_print(char *arg) {
	char *line = uwsgi_concat2(arg, "\n");
	uwsgi_log(line);
	free(line);
	return 0;
}

static int uwsgi_hook_callint(char *arg) {
        char *space = strchr(arg, ' ');
        if (space) {
                *space = 0;
                int num = atoi(space+1);
                void (*func)(int) = dlsym(RTLD_DEFAULT, arg);
                if (!func) {
                	uwsgi_log("unable to call function \"%s(%d)\"\n", arg, num);
                        *space = ' ';
                        return -1;
		}
                *space = ' ';
                func(num);
        }
        else {
                void (*func)(void) = dlsym(RTLD_DEFAULT, arg);
                if (!func) {
                        uwsgi_log("unable to call function \"%s\"\n", arg);
                        return -1;
                }
                func();
        }
        return 0;
}


static int uwsgi_hook_call(char *arg) {
	char *space = strchr(arg, ' ');
	if (space) {
		*space = 0;
		void (*func)(char *) = dlsym(RTLD_DEFAULT, arg);
                if (!func) {
                	uwsgi_log("unable to call function \"%s(%s)\"\n", arg, space + 1);
			*space = ' ';
			return -1;
		}
		*space = ' ';
                func(space + 1);
	}
	else {
		void (*func)(void) = dlsym(RTLD_DEFAULT, arg);
                if (!func) {
                	uwsgi_log("unable to call function \"%s\"\n", arg);
			return -1;
		}
                func();
	}
	return 0;
}

static int uwsgi_hook_callintret(char *arg) {
        char *space = strchr(arg, ' ');
        if (space) {
                *space = 0;
                int num = atoi(space+1);
                int (*func)(int) = dlsym(RTLD_DEFAULT, arg);
                if (!func) {
                        uwsgi_log("unable to call function \"%s(%d)\"\n", arg, num);
                        *space = ' ';
                        return -1;
                }
                *space = ' ';
                return func(num);
        }
        int (*func)(void) = dlsym(RTLD_DEFAULT, arg);
        if (!func) {
        	uwsgi_log("unable to call function \"%s\"\n", arg);
                return -1;
        }
	return func();
}


static int uwsgi_hook_callret(char *arg) {
        char *space = strchr(arg, ' ');
        if (space) {
                *space = 0;
                int (*func)(char *) = dlsym(RTLD_DEFAULT, arg);
                if (!func) {
                        uwsgi_log("unable to call function \"%s(%s)\"\n", arg, space + 1);
                        *space = ' ';
                        return -1;
                }
                *space = ' ';
                return func(space + 1);
        }
        int (*func)(void) = dlsym(RTLD_DEFAULT, arg);
        if (!func) {
        	uwsgi_log("unable to call function \"%s\"\n", arg);
                return -1;
        }
        return func();
}


void uwsgi_register_base_hooks() {
	uwsgi_register_hook("cd", uwsgi_hook_chdir);
	uwsgi_register_hook("exec", uwsgi_hook_exec);

	uwsgi_register_hook("mount", uwsgi_mount_hook);
	uwsgi_register_hook("umount", uwsgi_umount_hook);

	uwsgi_register_hook("call", uwsgi_hook_call);
	uwsgi_register_hook("callret", uwsgi_hook_callret);

	uwsgi_register_hook("callint", uwsgi_hook_callint);
	uwsgi_register_hook("callintret", uwsgi_hook_callintret);

	// for testing
	uwsgi_register_hook("exit", uwsgi_hook_exit);
	uwsgi_register_hook("print", uwsgi_hook_print);
}

void uwsgi_hooks_run(struct uwsgi_string_list *l, char *phase, int fatal) {
	struct uwsgi_string_list *usl = NULL;
	uwsgi_foreach(usl, l) {
		char *colon = strchr(usl->value, ':');
		if (!colon) {
			uwsgi_log("invalid hook syntax, must be hook:args\n");
			exit(1);
		}
		*colon = 0;
		struct uwsgi_hook *uh = uwsgi_hook_by_name(usl->value);
		if (!uh) {
			uwsgi_log("hook not found: %s\n", usl->value);
			exit(1);
		}
		*colon = ':';

		uwsgi_log("running \"%s\" (%s)...\n", usl->value, phase);
			
		int ret = uh->func(colon+1);
		if (fatal && ret != 0) {
			exit(1);
		}
	}
}
