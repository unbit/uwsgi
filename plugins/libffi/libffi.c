#include <uwsgi.h>
#include <ffi.h>

ffi_type *uwsgi_libffi_get_type(char *what, size_t *skip) {
	if (!uwsgi_startswith(what, "int:", 4)) { *skip = 4; return &ffi_type_sint32;}
	if (!uwsgi_startswith(what, "sint:", 5)) { *skip = 5; return &ffi_type_sint32;}
	if (!uwsgi_startswith(what, "uint:", 5)) { *skip = 5;return &ffi_type_uint32;}
	return &ffi_type_pointer;
}

void *uwsgi_libffi_get_value(char *what, ffi_type *t) {
	if (t == &ffi_type_sint32) {
		int32_t *num = uwsgi_malloc(sizeof(int32_t));
		*num = atoi(what);
		return num;
	}
	return NULL;
}

static int uwsgi_libffi_hook(char *arg) {
	size_t argc = 0;
	size_t i;
	char **argv = uwsgi_split_quoted(arg, strlen(arg), " \t", &argc);
	if (!argc) goto end;
	
	void *func = dlsym(RTLD_DEFAULT, argv[0]);
	if (!func) goto destroy;

	ffi_cif cif;
	ffi_type **args_type = (ffi_type **) uwsgi_malloc(sizeof(ffi_type) * (argc-1));
	void **values = uwsgi_malloc(sizeof(void*) * (argc-1));
	for(i=1;i<argc;i++) {
		size_t skip = 0;
		args_type[i-1] = uwsgi_libffi_get_type(argv[i], &skip);
		void *v = uwsgi_libffi_get_value(argv[i] + skip, args_type[i-1]);
		values[i-1] = v ? v : &argv[i];
		uwsgi_log("%d = %s %p\n", i, argv[i], values[i-1]);
	}

	if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, argc-1, &ffi_type_sint64, args_type) == FFI_OK) {
		int64_t rc = 0;
		uwsgi_log("ready to call\n");
		ffi_call(&cif, func, &rc, values); 
	}

	uwsgi_log("ready to call2\n");
	for(i=0;i<(argc-1);i++) {
		char **ptr = (char **) values[i];
		if (*ptr != argv[i+1]) {
			free(values[i]);
		}
	}
	free(args_type);
	free(values);
destroy:
	for(i=0;i<argc;i++) {
		free(argv[i]);
	}
end:
	free(argv);
	return -1;
}

static void uwsgi_libffi_setup() {
	uwsgi_register_hook("ffi", uwsgi_libffi_hook);
}

struct uwsgi_plugin libffi_plugin = {
	.name = "libffi",
	.on_load = uwsgi_libffi_setup,
};
