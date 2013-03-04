#include <uwsgi.h>

/*

	This is an example exception handler logging a dump of the exception packet

	It is not built by default, to discourage its usage, as it is non-thread-safe (log lines
	will be clobbered).

	You can use it as a debugger when developing true exception handlers

*/

static void uwsgi_exception_handler_log_parser_vars(char *key, uint16_t keylen, char *value, uint16_t vallen, void *data) {
	uwsgi_log("\t%.*s=%.*s\n", keylen, key, vallen, value);
}

static void uwsgi_exception_handler_log_parser_backtrace(uint16_t pos, char *value, uint16_t vallen, void *data) {
	uint16_t item = 0;
        if (pos > 0) {
                item = pos % 5;
        }

        switch(item) {
                // filename
                case 0:
			uwsgi_log("\tfilename: \"%.*s\" ", vallen, value);
                        break;
                // lineno
                case 1:
			uwsgi_log("line: %.*s ", vallen, value);
                        break;
                // function
                case 2:
			uwsgi_log("function: \"%.*s\" ", vallen, value);
                        break;
                // text
                case 3:
                        if (vallen > 0) {
				uwsgi_log("text/code: \"%.*s\" ", vallen, value);
                        }
                        break;
                // custom
                case 4:
                        if (vallen > 0) {
				uwsgi_log("custom: \"%.*s\"", vallen, value);
                        }
			uwsgi_log("\n");
                        break;
                default:
                        break;
        }

}

static void uwsgi_exception_handler_log_parser(char *key, uint16_t keylen, char *value, uint16_t vallen, void *data) {
	if (!uwsgi_strncmp(key, keylen, "vars", 4)) {
		uwsgi_log("vars:\n");
		uwsgi_hooked_parse(value, vallen, uwsgi_exception_handler_log_parser_vars, NULL);
		uwsgi_log("\n");
		return;
	}

	if (!uwsgi_strncmp(key, keylen, "backtrace", 9)) {
		uwsgi_log("backtrace:\n");
		uwsgi_hooked_parse_array(value, vallen, uwsgi_exception_handler_log_parser_backtrace, NULL);
		uwsgi_log("\n");
		return;
	}

	if (!uwsgi_strncmp(key, keylen, "class", 5)) {
		uwsgi_log("class: %.*s\n", vallen, value);
		return;
	}

	if (!uwsgi_strncmp(key, keylen, "msg", 3)) {
		uwsgi_log("msg: %.*s\n", vallen, value);
		return;
	}

	if (!uwsgi_strncmp(key, keylen, "repr", 4)) {
		uwsgi_log("repr: %.*s\n", vallen, value);
		return;
	}

	if (!uwsgi_strncmp(key, keylen, "unix", 4)) {
		uwsgi_log("unix: %.*s\n", vallen, value);
		return;
	}

	if (!uwsgi_strncmp(key, keylen, "wid", 3)) {
		uwsgi_log("wid: %.*s\n", vallen, value);
		return;
	}

	if (!uwsgi_strncmp(key, keylen, "pid", 3)) {
		uwsgi_log("pid: %.*s\n", vallen, value);
		return;
	}

	if (!uwsgi_strncmp(key, keylen, "core", 4)) {
		uwsgi_log("core: %.*s\n", vallen, value);
		return;
	}

	if (!uwsgi_strncmp(key, keylen, "node", 4)) {
		uwsgi_log("node: %.*s\n", vallen, value);
		return;
	}
}

static int uwsgi_exception_handler_log(struct uwsgi_exception_handler_instance *uehi, char *buf, size_t len) {
	uwsgi_log("\n!!! \"log\" exception handler !!!\n\n");
	uwsgi_hooked_parse(buf, len, uwsgi_exception_handler_log_parser, NULL);
	uwsgi_log("\n!!! end of \"log\" exception handler output !!!\n\n");
	return 0;
}

static void register_exception_log() {
	uwsgi_register_exception_handler("log", uwsgi_exception_handler_log);
}

struct uwsgi_plugin exception_log_plugin = {
	.name = "exception_log",
	.on_load = register_exception_log,
};
