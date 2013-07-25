#include <uwsgi.h>

/*

	pluggable configuration system

*/

extern struct uwsgi_server uwsgi;

struct uwsgi_configurator *uwsgi_register_configurator(char *name, void (*func)(char *, char **)) {
	struct uwsgi_configurator *old_uc = NULL,*uc = uwsgi.configurators;
        while(uc) {
                if (!strcmp(uc->name, name)) {
                        return uc;
                }
                old_uc = uc;
                uc = uc->next;
        }

        uc = uwsgi_calloc(sizeof(struct uwsgi_configurator));
        uc->name = name;
        uc->func = func;

        if (old_uc) {
                old_uc->next = uc;
        }
        else {
                uwsgi.configurators = uc;
        }

        return uc;
}

int uwsgi_logic_opt_if_exists(char *key, char *value) {

        if (uwsgi_file_exists(uwsgi.logic_opt_data)) {
                add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
                return 1;
        }

        return 0;
}

int uwsgi_logic_opt_if_not_exists(char *key, char *value) {

        if (!uwsgi_file_exists(uwsgi.logic_opt_data)) {
                add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
                return 1;
        }

        return 0;
}


int uwsgi_logic_opt_for(char *key, char *value) {

        char *p = strtok(uwsgi.logic_opt_data, " ");
        while (p) {
                add_exported_option(key, uwsgi_substitute(value, "%(_)", p), 0);
                p = strtok(NULL, " ");
        }

        return 1;
}

int uwsgi_logic_opt_for_glob(char *key, char *value) {

        glob_t g;
        int i;
        if (glob(uwsgi.logic_opt_data, GLOB_MARK | GLOB_NOCHECK, NULL, &g)) {
                uwsgi_error("uwsgi_logic_opt_for_glob()");
                return 0;
        }

        for (i = 0; i < (int) g.gl_pathc; i++) {
                add_exported_option(key, uwsgi_substitute(value, "%(_)", g.gl_pathv[i]), 0);
        }

        globfree(&g);

        return 1;
}

int uwsgi_logic_opt_for_times(char *key, char *value) {

        int num = atoi(uwsgi.logic_opt_data);
        int i;
        char str_num[11];

        for (i = 1; i <= num; i++) {
                int ret = uwsgi_num2str2(i, str_num);
                // security check
                if (ret < 0 || ret > 11) {
                        exit(1);
                }
                add_exported_option(key, uwsgi_substitute(value, "%(_)", str_num), 0);
        }

        return 1;
}


int uwsgi_logic_opt_if_opt(char *key, char *value) {

        // check for env-value syntax
        char *equal = strchr(uwsgi.logic_opt_data, '=');
        if (equal)
                *equal = 0;

        char *p = uwsgi_get_exported_opt(uwsgi.logic_opt_data);
        if (equal)
                *equal = '=';

        if (p) {
                if (equal) {
                        if (strcmp(equal + 1, p))
                                return 0;
                }
                add_exported_option(key, uwsgi_substitute(value, "%(_)", p), 0);
                return 1;
        }

        return 0;
}


int uwsgi_logic_opt_if_not_opt(char *key, char *value) {

        // check for env-value syntax
        char *equal = strchr(uwsgi.logic_opt_data, '=');
        if (equal)
                *equal = 0;

        char *p = uwsgi_get_exported_opt(uwsgi.logic_opt_data);
        if (equal)
                *equal = '=';

        if (p) {
                if (equal) {
                        if (!strcmp(equal + 1, p))
                                return 0;
                }
                else {
                        return 0;
                }
        }

        add_exported_option(key, uwsgi_substitute(value, "%(_)", p), 0);
        return 1;
}



int uwsgi_logic_opt_if_env(char *key, char *value) {

        // check for env-value syntax
        char *equal = strchr(uwsgi.logic_opt_data, '=');
        if (equal)
                *equal = 0;

        char *p = getenv(uwsgi.logic_opt_data);
        if (equal)
                *equal = '=';

        if (p) {
                if (equal) {
                        if (strcmp(equal + 1, p))
                                return 0;
                }
                add_exported_option(key, uwsgi_substitute(value, "%(_)", p), 0);
                return 1;
        }

        return 0;
}


int uwsgi_logic_opt_if_not_env(char *key, char *value) {

        // check for env-value syntax
        char *equal = strchr(uwsgi.logic_opt_data, '=');
        if (equal)
                *equal = 0;

        char *p = getenv(uwsgi.logic_opt_data);
        if (equal)
                *equal = '=';

        if (p) {
                if (equal) {
                        if (!strcmp(equal + 1, p))
                                return 0;
                }
                else {
                        return 0;
                }
        }

        add_exported_option(key, uwsgi_substitute(value, "%(_)", p), 0);
        return 1;
}

int uwsgi_logic_opt_if_reload(char *key, char *value) {
        if (uwsgi.is_a_reload) {
                add_exported_option(key, value, 0);
                return 1;
        }
        return 0;
}

int uwsgi_logic_opt_if_not_reload(char *key, char *value) {
        if (!uwsgi.is_a_reload) {
                add_exported_option(key, value, 0);
                return 1;
        }
        return 0;
}

int uwsgi_logic_opt_if_file(char *key, char *value) {

        if (uwsgi_is_file(uwsgi.logic_opt_data)) {
                add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
                return 1;
        }

        return 0;
}

int uwsgi_logic_opt_if_not_file(char *key, char *value) {

        if (!uwsgi_is_file(uwsgi.logic_opt_data)) {
                add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
                return 1;
        }

        return 0;
}

int uwsgi_logic_opt_if_dir(char *key, char *value) {

        if (uwsgi_is_dir(uwsgi.logic_opt_data)) {
                add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
                return 1;
        }

        return 0;
}

int uwsgi_logic_opt_if_not_dir(char *key, char *value) {

        if (!uwsgi_is_dir(uwsgi.logic_opt_data)) {
                add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
                return 1;
        }

        return 0;
}



int uwsgi_logic_opt_if_plugin(char *key, char *value) {

        if (plugin_already_loaded(uwsgi.logic_opt_data)) {
                add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
                return 1;
        }

        return 0;
}

int uwsgi_logic_opt_if_not_plugin(char *key, char *value) {

        if (!plugin_already_loaded(uwsgi.logic_opt_data)) {
                add_exported_option(key, uwsgi_substitute(value, "%(_)", uwsgi.logic_opt_data), 0);
                return 1;
        }

        return 0;
}

int uwsgi_count_options(struct uwsgi_option *uopt) {

        struct uwsgi_option *aopt;
        int count = 0;

        while ((aopt = uopt)) {
                if (!aopt->name)
                        break;
                count++;
                uopt++;
        }

        return count;
}

struct uwsgi_option *uwsgi_opt_get(char *name) {
        struct uwsgi_option *op = uwsgi.options;

        while (op->name) {
                if (!strcmp(name, op->name)) {
                        return op;
                }
                op++;
        }

        return NULL;
}

void add_exported_option(char *key, char *value, int configured) {

	struct uwsgi_string_list *blacklist = uwsgi.blacklist;
	struct uwsgi_string_list *whitelist = uwsgi.whitelist;

	while (blacklist) {
		if (!strcmp(key, blacklist->value)) {
			uwsgi_log("uWSGI error: forbidden option \"%s\" (by blacklist)\n", key);
			exit(1);
		}
		blacklist = blacklist->next;
	}

	if (whitelist) {
		int allowed = 0;
		while (whitelist) {
			if (!strcmp(key, whitelist->value)) {
				allowed = 1;
				break;
			}
			whitelist = whitelist->next;
		}
		if (!allowed) {
			uwsgi_log("uWSGI error: forbidden option \"%s\" (by whitelist)\n", key);
			exit(1);
		}
	}

	if (uwsgi.blacklist_context) {
		if (uwsgi_list_has_str(uwsgi.blacklist_context, key)) {
			uwsgi_log("uWSGI error: forbidden option \"%s\" (by blacklist)\n", key);
			exit(1);
		}
	}

	if (uwsgi.whitelist_context) {
                if (!uwsgi_list_has_str(uwsgi.whitelist_context, key)) {
                        uwsgi_log("uWSGI error: forbidden option \"%s\" (by whitelist)\n", key);
                        exit(1);
                }
        }

	if (uwsgi.logic_opt_running)
		goto add;

	if (!strcmp(key, "end") || !strcmp(key, "endfor") || !strcmp(key, "endif")) {
		if (uwsgi.logic_opt_data) {
			free(uwsgi.logic_opt_data);
		}
		uwsgi.logic_opt = NULL;
		uwsgi.logic_opt_arg = NULL;
		uwsgi.logic_opt_cycles = 0;
		uwsgi.logic_opt_data = NULL;
	}

	if (uwsgi.logic_opt) {
		if (uwsgi.logic_opt_data) {
			free(uwsgi.logic_opt_data);
		}
		uwsgi.logic_opt_data = uwsgi_str(uwsgi.logic_opt_arg);
		uwsgi.logic_opt_cycles++;
		uwsgi.logic_opt_running = 1;
		uwsgi.logic_opt(key, value);
		uwsgi.logic_opt_running = 0;
		return;
	}

add:

	if (!uwsgi.exported_opts) {
		uwsgi.exported_opts = uwsgi_malloc(sizeof(struct uwsgi_opt *));
	}
	else {
		uwsgi.exported_opts = realloc(uwsgi.exported_opts, sizeof(struct uwsgi_opt *) * (uwsgi.exported_opts_cnt + 1));
		if (!uwsgi.exported_opts) {
			uwsgi_error("realloc()");
			exit(1);
		}
	}

	int id = uwsgi.exported_opts_cnt;
	uwsgi.exported_opts[id] = uwsgi_malloc(sizeof(struct uwsgi_opt));
	uwsgi.exported_opts[id]->key = key;
	uwsgi.exported_opts[id]->value = value;
	uwsgi.exported_opts[id]->configured = configured;
	uwsgi.exported_opts_cnt++;
	uwsgi.dirty_config = 1;

	struct uwsgi_option *op = uwsgi_opt_get(key);
	if (op) {
		// requires master ?
		if (op->flags & UWSGI_OPT_MASTER) {
			uwsgi.master_process = 1;
		}
		// requires log_master ?
		if (op->flags & UWSGI_OPT_LOG_MASTER) {
			uwsgi.master_process = 1;
			uwsgi.log_master = 1;
		}
		if (op->flags & UWSGI_OPT_REQ_LOG_MASTER) {
			uwsgi.master_process = 1;
			uwsgi.log_master = 1;
			uwsgi.req_log_master = 1;
		}
		// requires threads ?
		if (op->flags & UWSGI_OPT_THREADS) {
			uwsgi.has_threads = 1;
		}
		// requires cheaper mode ?
		if (op->flags & UWSGI_OPT_CHEAPER) {
			uwsgi.cheaper = 1;
		}
		// requires virtualhosting ?
		if (op->flags & UWSGI_OPT_VHOST) {
			uwsgi.vhost = 1;
		}
		// requires memusage ?
		if (op->flags & UWSGI_OPT_MEMORY) {
			uwsgi.force_get_memusage = 1;
		}
		// requires auto procname ?
		if (op->flags & UWSGI_OPT_PROCNAME) {
			uwsgi.auto_procname = 1;
		}
		// requires lazy ?
		if (op->flags & UWSGI_OPT_LAZY) {
			uwsgi.lazy = 1;
		}
		// requires no_initial ?
		if (op->flags & UWSGI_OPT_NO_INITIAL) {
			uwsgi.no_initial_output = 1;
		}
		// requires no_server ?
		if (op->flags & UWSGI_OPT_NO_SERVER) {
			uwsgi.no_server = 1;
		}
		// requires post_buffering ?
		if (op->flags & UWSGI_OPT_POST_BUFFERING) {
			if (!uwsgi.post_buffering)
				uwsgi.post_buffering = 4096;
		}
		// requires building mime dict ?
		if (op->flags & UWSGI_OPT_MIME) {
			uwsgi.build_mime_dict = 1;
		}
		// immediate ?
		if (op->flags & UWSGI_OPT_IMMEDIATE) {
			op->func(key, value, op->data);
			uwsgi.exported_opts[id]->configured = 1;
		}
	}
	else if (uwsgi.strict) {
		uwsgi_log("[strict-mode] unknown config directive: %s\n", key);
		exit(1);
	}

}

void uwsgi_fallback_config() {
	if (uwsgi.fallback_config && uwsgi.last_exit_code == 1) {
		uwsgi_log_verbose("!!! %s (pid: %d) exited with status %d !!!\n", uwsgi.binary_path, (int) getpid(), uwsgi.last_exit_code);
		uwsgi_log_verbose("!!! Fallback config to %s !!!\n", uwsgi.fallback_config);
		char *argv[3];
		argv[0] = uwsgi.binary_path;
		argv[1] = uwsgi.fallback_config;
		argv[2] = NULL;
        	execvp(uwsgi.binary_path, argv);
        	uwsgi_error("execvp()");
        	// never here
	}
}
