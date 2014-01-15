#include <uwsgi.h>

#include <ruby.h>

#ifndef RUBY19
#include <st.h>
#define rb_errinfo() ruby_errinfo
#endif

#ifndef RARRAY_LEN
#define RARRAY_LEN(x) RARRAY(x)->len
#endif

#ifndef RARRAY_PTR
#define RARRAY_PTR(x) RARRAY(x)->ptr
#endif

#ifndef RSTRING_PTR
#define RSTRING_PTR(x) RSTRING(x)->ptr
#endif

#ifndef RSTRING_LEN
#define RSTRING_LEN(x) RSTRING(x)->len
#endif

struct uwsgi_rack {

        char *rails;
        char *rack;
        int gc_freq;
        uint64_t cycles;

        int call_gc;

	// why why why !!!!????!!!???
	VALUE signals_protector;
	VALUE rpc_protector;

	VALUE dollar_zero;

        VALUE dispatcher;
        VALUE rb_uwsgi_io_class;
        ID call;

	char *rbshell;
	int rb_shell_oneshot;
	int app_id;

	int unprotected;

	struct uwsgi_string_list *rbrequire;
	struct uwsgi_string_list *shared_rbrequire;
	struct uwsgi_string_list *rvm_path;

	char *gemset;

	struct uwsgi_string_list *libdir;
};

void uwsgi_rack_init_api(void);
