#include <uwsgi.h>
#include <libtcc.h>

unsigned long long uwsgi_libtcc_counter = 0;

static int uwsgi_libtcc_hook(char *arg) {
	char *func_base = "uwsgi_libtcc_func";
	size_t func_len = strlen(func_base) + sizeof(UMAX64_STR);
	char *func_name = uwsgi_malloc(func_len);
	int ret = snprintf(func_name, func_len, "%s%llu", func_base, uwsgi_libtcc_counter);
	if (ret < (int) strlen(func_base) || ret >= (int) func_len) {
		free(func_name);
		return -1;
	}
	uwsgi_libtcc_counter++;
	size_t source_len = 64 + func_len + strlen(arg);
	char *source = uwsgi_malloc(source_len); 
	ret = snprintf(source, source_len, "void %s() { %s ;}", func_name, arg);
	if (ret < (int) ( strlen(func_base) + strlen(arg)) || ret >= (int) (source_len)) {
		free(func_name);
		free(source);
		return -1;
	}

	TCCState *s = tcc_new();

	if (tcc_compile_string(s, source)) goto error;
	if (tcc_relocate(s, TCC_RELOCATE_AUTO)) goto error;

	void (*func)() = tcc_get_symbol(s, func_name);
	if (!func) goto error;
	free(func_name);
	free(source);

	// call the function
	func();

	tcc_delete(s);
	return 0;

error:
	free(func_name);
	free(source);
	tcc_delete(s);
	return -1;
}

static void uwsgi_libtcc_setup() {
	uwsgi_register_hook("tcc", uwsgi_libtcc_hook);
}

struct uwsgi_plugin libtcc_plugin = {
	.name = "libtcc",
	.on_load = uwsgi_libtcc_setup,
};
