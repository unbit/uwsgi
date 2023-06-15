#include "uwsgi_rack.h"

extern struct uwsgi_server uwsgi;

struct uwsgi_rack ur;
struct uwsgi_plugin rack_plugin;

static void uwsgi_opt_rbshell(char *opt, char *value, void *foobar) {

        uwsgi.honour_stdin = 1;
        if (value) {
                ur.rbshell = value;
        }
        else {
                ur.rbshell = "";
        }

        if (!strcmp("rbshell-oneshot", opt)) {
                ur.rb_shell_oneshot = 1;
        }
}


struct uwsgi_option uwsgi_rack_options[] = {

        {"rails", required_argument, 0, "load a rails <= 2.x app", uwsgi_opt_set_str, &ur.rails, UWSGI_OPT_POST_BUFFERING},
        {"rack", required_argument, 0, "load a rack app", uwsgi_opt_set_str, &ur.rack, UWSGI_OPT_POST_BUFFERING},
        {"ruby-gc-freq", required_argument, 0, "set ruby GC frequency", uwsgi_opt_set_int, &ur.gc_freq, 0},
        {"rb-gc-freq", required_argument, 0, "set ruby GC frequency", uwsgi_opt_set_int, &ur.gc_freq, 0},

#ifdef RUBY19
	{"rb-lib", required_argument, 0, "add a directory to the ruby libdir search path", uwsgi_opt_add_string_list, &ur.libdir, 0},
	{"ruby-lib", required_argument, 0, "add a directory to the ruby libdir search path", uwsgi_opt_add_string_list, &ur.libdir, 0},
#endif

        {"rb-require", required_argument, 0, "import/require a ruby module/script", uwsgi_opt_add_string_list, &ur.rbrequire, 0},
        {"ruby-require", required_argument, 0, "import/require a ruby module/script", uwsgi_opt_add_string_list, &ur.rbrequire, 0},
        {"rbrequire", required_argument, 0, "import/require a ruby module/script", uwsgi_opt_add_string_list, &ur.rbrequire, 0},
        {"rubyrequire", required_argument, 0, "import/require a ruby module/script", uwsgi_opt_add_string_list, &ur.rbrequire, 0},
        {"require", required_argument, 0, "import/require a ruby module/script", uwsgi_opt_add_string_list, &ur.rbrequire, 0},

        {"shared-rb-require", required_argument, 0, "import/require a ruby module/script (shared)", uwsgi_opt_add_string_list, &ur.shared_rbrequire, 0},
        {"shared-ruby-require", required_argument, 0, "import/require a ruby module/script (shared)", uwsgi_opt_add_string_list, &ur.shared_rbrequire, 0},
        {"shared-rbrequire", required_argument, 0, "import/require a ruby module/script (shared)", uwsgi_opt_add_string_list, &ur.shared_rbrequire, 0},
        {"shared-rubyrequire", required_argument, 0, "import/require a ruby module/script (shared)", uwsgi_opt_add_string_list, &ur.shared_rbrequire, 0},
        {"shared-require", required_argument, 0, "import/require a ruby module/script (shared)", uwsgi_opt_add_string_list, &ur.shared_rbrequire, 0},

        {"gemset", required_argument, 0, "load the specified gemset (rvm)", uwsgi_opt_set_str, &ur.gemset, 0},
        {"rvm", required_argument, 0, "load the specified gemset (rvm)", uwsgi_opt_set_str, &ur.gemset, 0},

        {"rvm-path", required_argument, 0, "search for rvm in the specified directory", uwsgi_opt_add_string_list, &ur.rvm_path, 0},

        {"rbshell", optional_argument, 0, "run  a ruby/irb shell", uwsgi_opt_rbshell, NULL, 0},
        {"rbshell-oneshot", no_argument, 0, "set ruby/irb shell (one shot)", uwsgi_opt_rbshell, NULL, 0},

        {0, 0, 0, 0, 0, 0 ,0},

};

static struct uwsgi_buffer *uwsgi_ruby_exception_class(struct wsgi_request *wsgi_req) {
	VALUE err = rb_errinfo();
        VALUE e = rb_class_name(rb_class_of(err));
        struct uwsgi_buffer *ub = uwsgi_buffer_new(RSTRING_LEN(e));
        if (uwsgi_buffer_append(ub, RSTRING_PTR(e), RSTRING_LEN(e))) {
                uwsgi_buffer_destroy(ub);
                return NULL;
        }
        return ub;
}


static struct uwsgi_buffer *uwsgi_ruby_exception_msg(struct wsgi_request *wsgi_req) {
	VALUE err = rb_errinfo();
	VALUE e = rb_funcall(err, rb_intern("message"), 0, 0);
	struct uwsgi_buffer *ub = uwsgi_buffer_new(RSTRING_LEN(e));
	if (uwsgi_buffer_append(ub, RSTRING_PTR(e), RSTRING_LEN(e))) {
		uwsgi_buffer_destroy(ub);
		return NULL;
	}
	return ub;
}

static struct uwsgi_buffer *uwsgi_ruby_exception_repr(struct wsgi_request *wsgi_req) {
	struct uwsgi_buffer *ub_class = uwsgi_ruby_exception_class(wsgi_req);
	if (!ub_class) return NULL;

	struct uwsgi_buffer *ub_msg = uwsgi_ruby_exception_msg(wsgi_req);
	if (!ub_msg) {
		uwsgi_buffer_destroy(ub_class);
		return NULL;
	}

	struct uwsgi_buffer *ub = uwsgi_buffer_new(ub_class->pos + 3 + ub_msg->pos);
	if (uwsgi_buffer_append(ub, ub_msg->buf, ub_msg->pos)) goto error;
	if (uwsgi_buffer_append(ub, " (", 2)) goto error;
	if (uwsgi_buffer_append(ub, ub_class->buf, ub_class->pos)) goto error;
	if (uwsgi_buffer_append(ub, ")", 1)) goto error;

	uwsgi_buffer_destroy(ub_class);
	uwsgi_buffer_destroy(ub_msg);

	return ub;


error:
	uwsgi_buffer_destroy(ub_class);
	uwsgi_buffer_destroy(ub_msg);
	uwsgi_buffer_destroy(ub);
	return NULL;

}

// simulate ruby_error_print (this is sad... but it works well)
static void uwsgi_ruby_exception_log(struct wsgi_request *wsgi_req) {
	VALUE err = rb_errinfo();
	VALUE eclass = rb_class_name(rb_class_of(err));
	VALUE msg = rb_funcall(err, rb_intern("message"), 0, 0);
	
	VALUE ary = rb_funcall(err, rb_intern("backtrace"), 0);
        int i;
        for (i=0; i<RARRAY_LEN(ary); i++) {
		if (i == 0) {
			uwsgi_log("%s: %s (%s)\n", RSTRING_PTR(RARRAY_PTR(ary)[i]), RSTRING_PTR(msg), RSTRING_PTR(eclass));
		}
		else {
        		uwsgi_log("\tfrom %s\n", RSTRING_PTR(RARRAY_PTR(ary)[i]));
		}
        }
}

static struct uwsgi_buffer *uwsgi_ruby_backtrace(struct wsgi_request *wsgi_req) {
	VALUE err = rb_errinfo();
	VALUE ary = rb_funcall(err, rb_intern("backtrace"), 0);
	int i;
	struct uwsgi_buffer *ub = uwsgi_buffer_new(4096);
	char *filename = NULL;
	char *function = NULL;
	for (i=0; i<RARRAY_LEN(ary); i++) {
		char *bt = RSTRING_PTR(RARRAY_PTR(ary)[i]);
		// ok let's start the C dance to parse the backtrace
		char *colon = strchr(bt, ':');
		if (!colon) continue;
		filename = uwsgi_concat2n(bt, (int) (colon-bt), "", 0);
		uint16_t filename_len = colon-bt;
		colon++; if (*colon == 0) goto error;
		char *lineno_ptr = colon;
		colon = strchr(lineno_ptr, ':');
		if (!colon) goto error;
		int64_t lineno = uwsgi_str_num(lineno_ptr, (int) (colon-lineno_ptr));
		colon++; if (*colon == 0) goto error;
		colon = strchr(lineno_ptr, '`');
		if (!colon) goto error;
		colon++; if (*colon == 0) goto error;
		char *function_ptr = colon;
		char *function_end = strchr(function_ptr, '\'');
		if (!function_end) goto error;
		function = uwsgi_concat2n(function_ptr, (int) (function_end-function_ptr), "", 0);
		uint16_t function_len = function_end-function_ptr;

		if (uwsgi_buffer_u16le(ub, filename_len)) goto error;
		if (uwsgi_buffer_append(ub, filename, filename_len)) goto error;
		if (uwsgi_buffer_append_valnum(ub, lineno)) goto error;
		if (uwsgi_buffer_u16le(ub, function_len)) goto error;
		if (uwsgi_buffer_append(ub, function, function_len)) goto error;

		// in ruby we do not have text/code nor custom
		if (uwsgi_buffer_u16le(ub, 0)) goto error;
		if (uwsgi_buffer_append(ub, "", 0)) goto error;
		if (uwsgi_buffer_u16le(ub, 0)) goto error;
		if (uwsgi_buffer_append(ub, "", 0)) goto error;

		free(filename);
		filename = NULL;
		free(function);
		function = NULL;
	}

	return ub;

error:
	uwsgi_buffer_destroy(ub);

	if (filename) {
		free(filename);
	}

	if (function) {
		free(function);
	}

	return NULL;
}

VALUE rb_uwsgi_io_new(VALUE class, VALUE wr) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(wr, struct wsgi_request, wsgi_req);
	VALUE self = Data_Wrap_Struct(class , 0, 0, wsgi_req);

	rb_obj_call_init(self, 0, NULL);

	return self;

}

VALUE rb_uwsgi_io_init(int argc, VALUE *argv, VALUE self) {

	return self;
}

VALUE rb_uwsgi_io_gets(VALUE obj) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);

	ssize_t rlen = 0;

	char *buf = uwsgi_request_body_readline(wsgi_req, 0, &rlen);
	if (buf) {
		return rb_str_new(buf, rlen);
	}
	return Qnil;
}

VALUE rb_uwsgi_io_each(VALUE obj) {

	if (!rb_block_given_p())
		rb_raise(rb_eArgError, "Expected block on rack.input 'each' method");

	// yield strings chunks
	for(;;) {
		VALUE chunk = rb_uwsgi_io_gets(obj);
		if (chunk == Qnil) {
			return Qnil;
		}
		rb_yield(chunk);
	}
	// never here
	return Qnil;
}

VALUE rb_uwsgi_io_read(VALUE obj, VALUE args) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);
	long hint = 0;
	int length_given = 0;

/*
	When EOF is reached, this method returns nil if length is given and not nil, or "" if length is not given or is nil.
	If buffer is given, then the read data will be placed into buffer instead of a newly created String object.
*/

	if (RARRAY_LEN(args) > 0) {
		if (RARRAY_PTR(args)[0] != Qnil) {
			hint = NUM2LONG(RARRAY_PTR(args)[0]); 
			length_given = 1;
		}
	}

	ssize_t rlen = 0;
	char *buf = uwsgi_request_body_read(wsgi_req, hint, &rlen);
	if (buf) {
		if (length_given && buf == uwsgi.empty) {
			return Qnil;
		}
		if (RARRAY_LEN(args) > 1) {
                        rb_str_cat(RARRAY_PTR(args)[1], buf, rlen);
                }
		return rb_str_new(buf, rlen);
	}

	return Qnil;
}

VALUE rb_uwsgi_io_rewind(VALUE obj) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);
	uwsgi_request_body_seek(wsgi_req, 0);
	return Qnil;
}

#ifdef RUBY19
#ifdef RUBY_GLOBAL_SETUP
RUBY_GLOBAL_SETUP
#endif
#endif

VALUE uwsgi_require_file(VALUE arg) {
    return rb_funcall(rb_cObject, rb_intern("require"), 1, arg);
}

VALUE require_rack(VALUE arg) {
    return rb_funcall(rb_cObject, rb_intern("require"), 1, rb_str_new2("rack"));
}

VALUE require_rails(VALUE arg) {
#ifdef RUBY19
    return rb_require("./config/environment");
#else
    return rb_require("config/environment");
#endif
}

VALUE require_thin(VALUE arg) {
    return rb_funcall(rb_cObject, rb_intern("require"), 1, rb_str_new2("thin"));
}

VALUE init_rack_app(VALUE);

VALUE rack_call_rpc_handler(VALUE args) {
        VALUE rpc_args = rb_ary_entry(args, 1);
        return rb_funcall2(rb_ary_entry(args, 0), rb_intern("call"), (int) RARRAY_LEN(rpc_args), RARRAY_PTR(rpc_args));
}


uint64_t uwsgi_ruby_rpc(void *func, uint8_t argc, char **argv, uint16_t argvs[], char **buffer) {

        uint8_t i;
	VALUE rb_args = rb_ary_new2(2);
        VALUE rb_rpc_args = rb_ary_new2(argc);
        VALUE ret;
	int error = 0;
        char *rv;
        size_t rl;

	rb_ary_store(rb_args, 0, (VALUE) func);

        for (i = 0; i < argc; i++) {
                rb_ary_store(rb_rpc_args, i, rb_str_new(argv[i], argvs[i]));
        }
	rb_ary_store(rb_args, 1, rb_rpc_args);


	ret = rb_protect(rack_call_rpc_handler, rb_args, &error);

        if (error) {
		uwsgi_ruby_exception_log(NULL);
		return 0;
	}

	if (TYPE(ret) == T_STRING) {
        	rv = RSTRING_PTR(ret);
                rl = RSTRING_LEN(ret);
                if (rl > 0) {
			*buffer = uwsgi_malloc(rl);
                	memcpy(*buffer, rv, rl);
                        return rl;
                }
        }

        return 0;

}

void uwsgi_ruby_gem_set_apply(char *gemset) {

	int in_pipe[2];
	int out_pipe[2];
	size_t size;
	int waitpid_status;
	size_t i;

        if (pipe(in_pipe)) {
        	uwsgi_error("pipe()");
                exit(1);
        }

        if (pipe(out_pipe)) {
        	uwsgi_error("pipe()");
                exit(1);
        }

        pid_t pid = uwsgi_run_command("bash", in_pipe, out_pipe[1] );

	char *gemset_code = uwsgi_open_and_read(gemset, &size, 0, NULL);

	if (write(in_pipe[1], gemset_code, size) != (ssize_t) size ) {
		uwsgi_error("write()");
	}

	free(gemset_code);

	if (write(in_pipe[1], "printenv\n", 9) != 9 ) {
		uwsgi_error("write()");
	}

        close(in_pipe[1]);

	size = 0;
        char *buffer = uwsgi_read_fd(out_pipe[0], &size, 0);

        close(out_pipe[0]);

	char *ptr = buffer;


	for(i=0;i<size;i++) {
		if (buffer[i] == '\n') {
			buffer[i] = 0;
			if (putenv(ptr)) {
				uwsgi_error("putenv()");
			}
			ptr = buffer + i + 1;
		}
	}

	// do not free the buffer
        // environ will reuse it !!!
	//free(buffer);

	if (waitpid(pid, &waitpid_status, 0) <0) {
		uwsgi_error("waitpid()");
	}
}

void uwsgi_ruby_gemset(char *gemset) {

	struct uwsgi_string_list *rvm_paths = ur.rvm_path;
	while(rvm_paths) {
		char *filename = uwsgi_concat3(rvm_paths->value, "/environments/", gemset);
                if (uwsgi_file_exists(filename)) {
			uwsgi_ruby_gem_set_apply(filename);
                        free(filename);
                        return;
                }
                free(filename);
		rvm_paths = rvm_paths->next;
	}

	char *home = getenv("HOME");

	if (home) {
		char *filename = uwsgi_concat3(home, "/.rvm/environments/", gemset);
		if (uwsgi_file_exists(filename)) {
			uwsgi_ruby_gem_set_apply(filename);
			free(filename);
			return;
		}
		free(filename);
	}

	char *filename = uwsgi_concat2("/usr/local/rvm/environments/", gemset);
	if (uwsgi_file_exists(filename)) {
		uwsgi_ruby_gem_set_apply(filename);
                free(filename);
                return;
        }
        free(filename);

	uwsgi_log("ERROR: unable to load gemset %s !!!\n", gemset);
	exit(1);
	
}

static void rack_hack_dollar_zero(VALUE name, ID id, VALUE *_) {
	ur.dollar_zero = rb_obj_as_string(name);
	// From ruby 2.7 onwards this is a noop, from ruby 3.2 onwards
	// this function no longer exists
#if !defined(RUBY27)
	rb_obj_taint(ur.dollar_zero);
#endif
}

#ifndef RUBY19
void Init_stack(VALUE*);
#endif

int uwsgi_rack_init(){

#ifdef RUBY19
        int argc = 2;
        char *sargv[] = { (char *) "uwsgi", (char *) "-e0" };
        char **argv = sargv;
#endif

	if (ur.gemset) {
		uwsgi_ruby_gemset(ur.gemset);
	}

#ifdef RUBY19
	ruby_sysinit(&argc, &argv);
        RUBY_INIT_STACK
#ifdef UWSGI_RUBY_HEROKU
	uwsgi_log("*** Heroku system detected ***\n");
#endif
#ifdef RUBY_EXEC_PREFIX
	if (!strcmp(RUBY_EXEC_PREFIX, "")) {
		uwsgi_log("*** detected a ruby vm built with --enable-load-relative ***\n");
		uwsgi_log("*** if you get errors about rubygems.rb, you can:\n");
		uwsgi_log("*** 1) add a directory to the libdir search path using --ruby-libdir ***\n");
		uwsgi_log("*** 2) force the RUBY_EXEC_PREFIX with --chdir ***\n");
	}
#endif

#ifdef UWSGI_RUBY_LIBDIR
	uwsgi_string_new_list(&ur.libdir, UWSGI_RUBY_LIBDIR);
#endif
#ifdef UWSGI_RUBY_ARCHDIR
	uwsgi_string_new_list(&ur.libdir, UWSGI_RUBY_ARCHDIR);
#endif

	ruby_init();
	struct uwsgi_string_list *usl = ur.libdir;
	while(usl) {
		ruby_incpush(usl->value);
		uwsgi_log("[ruby-libdir] pushed %s\n", usl->value);
		usl = usl->next;
	}
	ruby_options(argc, argv);
#else
	ruby_init();
	VALUE dummy;
	Init_stack(&dummy);
	ruby_init_loadpath();
#endif

	ruby_show_version();

	ruby_script("uwsgi");

	ur.dollar_zero = rb_str_new2("uwsgi");
	rb_define_hooked_variable("$0", &ur.dollar_zero, 0, rack_hack_dollar_zero);
	rb_define_hooked_variable("$PROGRAM_NAME", &ur.dollar_zero, 0, rack_hack_dollar_zero);

	ur.signals_protector = rb_ary_new();
	ur.rpc_protector = rb_ary_new();
	rb_gc_register_address(&ur.signals_protector);
	rb_gc_register_address(&ur.rpc_protector);

	uwsgi_rack_init_api();	

	return 0;
}

void uwsgi_rack_preinit_apps() {

	struct uwsgi_string_list *usl = ur.shared_rbrequire;
        while(usl) {
                int error = 0;
                rb_protect( uwsgi_require_file, rb_str_new2(usl->value), &error ) ;
                if (error) {
			uwsgi_ruby_exception_log(NULL);
                }
                usl = usl->next;
        }

}

VALUE uwsgi_rb_call_new(VALUE obj) {
    return rb_funcall(obj, rb_intern("new"), 0);
}

void uwsgi_rack_init_apps(void) {

	int error;

	if (uwsgi_apps_cnt >= uwsgi.max_apps) {
                uwsgi_log("ERROR: you cannot load more than %d apps in a worker\n", uwsgi.max_apps);
		return;
        }


	ur.app_id = uwsgi_apps_cnt;
	struct uwsgi_string_list *usl = ur.rbrequire;

	time_t now = uwsgi_now();

	while(usl) {
		error = 0;
		rb_protect( uwsgi_require_file, rb_str_new2(usl->value), &error ) ;
                if (error) {
			uwsgi_ruby_exception_log(NULL);
		}
		usl = usl->next;
	}

	if (ur.rack) {
		ur.dispatcher = rb_protect(init_rack_app, rb_str_new2(ur.rack), &error);
		if (error) {
			uwsgi_ruby_exception_log(NULL);
                        exit(1);
                }
		if (ur.dispatcher == Qnil) {
			uwsgi_log("unable to find RACK entry point\n");
			exit(1);
		}
		rb_gc_register_address(&ur.dispatcher);

		goto ready;
	}
	else if (ur.rails) {
		if (chdir(ur.rails)) {
			uwsgi_error("chdir()");
			exit(1);
		}

		if (!access("config.ru", R_OK)) {
			uwsgi_log("!!! a config.ru file has been found in yor rails app, please use --rack <configfile> instead of the old --rails <app> !!!\n");
		}

		uwsgi_log("loading rails app %s\n", ur.rails);
		rb_protect( require_rails, 0, &error ) ;
		if (error) {
			uwsgi_ruby_exception_log(NULL);
			exit(1);
                }
		uwsgi_log("rails app %s ready\n", ur.rails);
		VALUE ac = rb_const_get(rb_cObject, rb_intern("ActionController"));

		ur.dispatcher = Qnil;
		if (rb_funcall(ac, rb_intern("const_defined?"), 1, ID2SYM(rb_intern("Dispatcher"))) == Qtrue) {

			VALUE ac_dispatcher = rb_const_get(ac, rb_intern("Dispatcher"));

			VALUE acd_instance_methods = rb_funcall( ac_dispatcher, rb_intern("instance_methods"), 0);

			VALUE acim_call = rb_funcall( acd_instance_methods, rb_intern("include?"), 1, ID2SYM(rb_intern("call")));

			if (acim_call == Qfalse) {
				acim_call = rb_funcall( acd_instance_methods, rb_intern("include?"), 1, rb_str_new2("call"));
			}

			if (acim_call == Qtrue) {
                        	ur.dispatcher = rb_protect(uwsgi_rb_call_new, ac_dispatcher, &error);
				if (error) {
					uwsgi_ruby_exception_log(NULL);
                        		exit(1);
				}
			}
                }

                if (ur.dispatcher == Qnil)  {
                        uwsgi_log("non-rack rails version detected...loading thin adapter...\n");
			rb_protect( require_thin, 0, &error ) ;
                	if (error) {
				uwsgi_ruby_exception_log(NULL);
                        	exit(1);
                	}
			VALUE thin_rack = rb_const_get(rb_cObject, rb_intern("Rack"));
			VALUE thin_rack_adapter = rb_const_get(thin_rack, rb_intern("Adapter"));
			VALUE thin_rack_adapter_rails = rb_const_get(thin_rack_adapter, rb_intern("Rails"));
			ur.dispatcher = rb_protect( uwsgi_rb_call_new, thin_rack_adapter_rails, &error);
			if (error) {
				uwsgi_ruby_exception_log(NULL);
                        	exit(1);
			}
                }


		if (ur.dispatcher == Qnil) {
			uwsgi_log("unable to load rails dispatcher\n");
			exit(1);
		}

		rb_gc_register_address(&ur.dispatcher);

		goto ready;
	}

	return;

ready:
	ur.call = rb_intern("call");
	if (!ur.call) {
		uwsgi_log("unable to find RACK entry point\n");
		return;
	}
	rb_gc_register_address(&ur.call);


	ur.rb_uwsgi_io_class = rb_define_class("Uwsgi_IO", rb_cObject);

	rb_gc_register_address(&ur.rb_uwsgi_io_class);

	rb_define_singleton_method(ur.rb_uwsgi_io_class, "new", rb_uwsgi_io_new, 1);
	rb_define_method(ur.rb_uwsgi_io_class, "initialize", rb_uwsgi_io_init, -1);
	rb_define_method(ur.rb_uwsgi_io_class, "gets", rb_uwsgi_io_gets, 0);
	rb_define_method(ur.rb_uwsgi_io_class, "each", rb_uwsgi_io_each, 0);
	rb_define_method(ur.rb_uwsgi_io_class, "read", rb_uwsgi_io_read, -2);
	rb_define_method(ur.rb_uwsgi_io_class, "rewind", rb_uwsgi_io_rewind, 0);

	struct uwsgi_app *ua = uwsgi_add_app(ur.app_id, rack_plugin.modifier1, (char*)"", 0, NULL, NULL);
	ua->started_at = now;
	ua->startup_time = uwsgi_now() - now;

	uwsgi_emulate_cow_for_apps(ur.app_id);
	
	if (ur.gc_freq <= 1) {
        	uwsgi_log("RACK app %d loaded in %d seconds at %p (GC frequency: AGGRESSIVE)\n", ur.app_id, (int) ua->startup_time, ur.call);
	}
	else {
        	uwsgi_log("RACK app %d loaded in %d seconds at %p (GC frequency: %d)\n", ur.app_id, (int) ua->startup_time, ur.call, ur.gc_freq);
	}

}

VALUE call_dispatch(VALUE env) {

	return rb_funcall(ur.dispatcher, ur.call, 1, env);

}

static VALUE send_body(VALUE obj, VALUE data, int argc, const VALUE *argv, VALUE blockarg) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	//uwsgi_log("sending body\n");
	if (TYPE(obj) == T_STRING) {
		uwsgi_response_write_body_do(wsgi_req, RSTRING_PTR(obj), RSTRING_LEN(obj));
	}
	else {
		uwsgi_log("UNMANAGED BODY TYPE %d\n", TYPE(obj));
	}

	return Qnil;
}

VALUE body_to_path(VALUE body) {
        return rb_funcall( body, rb_intern("to_path"), 0);
}


VALUE close_body(VALUE body) {
	return rb_funcall( body, rb_intern("close"), 0);
}

VALUE iterate_body(VALUE body) {

#ifdef RUBY19
	return rb_block_call(body, rb_intern("each"), 0, 0, send_body, 0);
#else
	return rb_iterate(rb_each, body, send_body, 0);
#endif
}

VALUE send_header(VALUE obj, VALUE headers, int argc, const VALUE *argv, VALUE blockarg) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	VALUE hkey, hval;
	
	//uwsgi_log("HEADERS %d\n", TYPE(obj));
	if (TYPE(obj) == T_ARRAY) {
		if (RARRAY_LEN(obj) >= 2) {
			hkey = rb_obj_as_string( RARRAY_PTR(obj)[0]);
			hval = rb_obj_as_string( RARRAY_PTR(obj)[1]);

		}
		else {
			goto clear;
		}
	}
	else if (TYPE(obj) == T_STRING) {
		hkey = obj;
#ifdef RUBY19
		hval = rb_hash_lookup(headers, obj);
#else
		hval = rb_hash_aref(headers, obj);
#endif
	}
	else {
		goto clear;
	}

	if (TYPE(hkey) != T_STRING || TYPE(hval) != T_STRING) {
		goto clear;
	}

	char *header_value = RSTRING_PTR(hval);
	size_t header_value_len = RSTRING_LEN(hval);
	size_t i,cnt=0;
	char *this_header = header_value;

	for(i=0;i<header_value_len;i++) {
		// multiline header, send it !!!
		if (header_value[i] == '\n') {
			uwsgi_response_add_header(wsgi_req, RSTRING_PTR(hkey), RSTRING_LEN(hkey), this_header, cnt);
			this_header += cnt+1;
			cnt = 0;
			continue;
		}
		cnt++;	
	}

	if (cnt > 0) {
		uwsgi_response_add_header(wsgi_req, RSTRING_PTR(hkey), RSTRING_LEN(hkey), this_header, cnt);
	}

clear:

	return Qnil;
}

VALUE iterate_headers(VALUE headers) {

#ifdef RUBY19
        return rb_block_call(headers, rb_intern("each"), 0, 0, send_header, headers);
#else
        return rb_iterate(rb_each, headers, send_header, headers);
#endif

}



int uwsgi_rack_request(struct wsgi_request *wsgi_req) {

	int error = 0;
	int i;
	VALUE env, ret, status, headers, body;

	if (!ur.call) {
		uwsgi_500(wsgi_req);
		uwsgi_log("--- ruby application not found ---\n");
		return -1;
	}

	/* Standard RACK request */
        if (!wsgi_req->uh->pktsize) {
                uwsgi_log("Empty RACK request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }

	wsgi_req->app_id = ur.app_id;
	uwsgi_apps[wsgi_req->app_id].requests++;

        env = rb_hash_new();
	// the following vars have to always been defined (we skip REQUEST_METHOD and PATH_INFO as they should always be available)
	rb_hash_aset(env, rb_str_new2("SCRIPT_NAME"), rb_str_new2(""));
	rb_hash_aset(env, rb_str_new2("QUERY_STRING"), rb_str_new2(""));
	rb_hash_aset(env, rb_str_new2("SERVER_NAME"), rb_str_new2(uwsgi.hostname));
	// SERVER_PORT
        char *server_port = strchr(wsgi_req->socket->name, ':');
        if (server_port) {
		rb_hash_aset(env, rb_str_new2("SERVER_PORT"), rb_str_new(server_port+1, strlen(server_port+1)));
        }
        else {
		rb_hash_aset(env, rb_str_new2("SERVER_PORT"), rb_str_new2("80"));
        }

        // fill ruby hash
        for(i=0;i<wsgi_req->var_cnt;i++) {

		// put the var only if it is not 0 size or required (rack requirement... very inefficient)
		if (wsgi_req->hvec[i+1].iov_len > 0 || 
					!uwsgi_strncmp((char *)"REQUEST_METHOD", 14, wsgi_req->hvec[i].iov_base, (int) wsgi_req->hvec[i].iov_len) ||
					!uwsgi_strncmp((char *)"SCRIPT_NAME", 11, wsgi_req->hvec[i].iov_base, (int) wsgi_req->hvec[i].iov_len) ||
					!uwsgi_strncmp((char *)"PATH_INFO", 10, wsgi_req->hvec[i].iov_base, (int) wsgi_req->hvec[i].iov_len) ||
					!uwsgi_strncmp((char *)"QUERY_STRING", 12, wsgi_req->hvec[i].iov_base, (int) wsgi_req->hvec[i].iov_len) ||
					!uwsgi_strncmp((char *)"SERVER_NAME", 11, wsgi_req->hvec[i].iov_base, (int) wsgi_req->hvec[i].iov_len) ||
					!uwsgi_strncmp((char *)"SERVER_PORT", 11, wsgi_req->hvec[i].iov_base, (int) wsgi_req->hvec[i].iov_len)
							) {
			rb_hash_aset(env, rb_str_new(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len),
					rb_str_new(wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len));

			//uwsgi_log("%.*s = %.*s\n", wsgi_req->hvec[i].iov_len, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i+1].iov_len, wsgi_req->hvec[i+1].iov_base);
		}
                i++;
        }


	VALUE rbv = rb_ary_new();
	rb_ary_store(rbv, 0, INT2NUM(1));
	rb_ary_store(rbv, 1, INT2NUM(1));
	rb_hash_aset(env, rb_str_new2("rack.version"), rbv);

	if (wsgi_req->scheme_len > 0) {
		rb_hash_aset(env, rb_str_new2("rack.url_scheme"), rb_str_new(wsgi_req->scheme, wsgi_req->scheme_len));
        }
        else if (wsgi_req->https_len > 0) {
                if (!strncasecmp(wsgi_req->https, "on", 2) || wsgi_req->https[0] == '1') {
			rb_hash_aset(env, rb_str_new2("rack.url_scheme"), rb_str_new2("https"));
                }
                else {
			rb_hash_aset(env, rb_str_new2("rack.url_scheme"), rb_str_new2("http"));
                }
        }
        else {
		rb_hash_aset(env, rb_str_new2("rack.url_scheme"), rb_str_new2("http"));
        }


	if (uwsgi.threads > 1) {
		rb_hash_aset(env, rb_str_new2("rack.multithread"), Qtrue);
	}
	else {
		rb_hash_aset(env, rb_str_new2("rack.multithread"), Qfalse);
	}

	if (uwsgi.numproc > 1) {
		rb_hash_aset(env, rb_str_new2("rack.multiprocess"), Qtrue);
	}
	else {
		rb_hash_aset(env, rb_str_new2("rack.multiprocess"), Qfalse);
	}

	rb_hash_aset(env, rb_str_new2("rack.run_once"), Qfalse);

	VALUE dws_wr = Data_Wrap_Struct(ur.rb_uwsgi_io_class, 0, 0, wsgi_req);

	rb_hash_aset(env, rb_str_new2("rack.input"), rb_funcall(ur.rb_uwsgi_io_class, rb_intern("new"), 1, dws_wr ));

	rb_hash_aset(env, rb_str_new2("rack.errors"), rb_funcall( rb_const_get(rb_cObject, rb_intern("IO")), rb_intern("new"), 2, INT2NUM(2), rb_str_new("w",1) ));

	rb_hash_aset(env, rb_str_new2("uwsgi.core"), INT2NUM(wsgi_req->async_id));
	rb_hash_aset(env, rb_str_new2("uwsgi.version"), rb_str_new2(UWSGI_VERSION));
	rb_hash_aset(env, rb_str_new2("uwsgi.node"), rb_str_new2(uwsgi.hostname));

	// remove HTTP_CONTENT_LENGTH and HTTP_CONTENT_TYPE
	rb_hash_delete(env, rb_str_new2("HTTP_CONTENT_LENGTH"));
	rb_hash_delete(env, rb_str_new2("HTTP_CONTENT_TYPE"));

	if (ur.unprotected) {
		ret = call_dispatch(env);
	}
	else {
		ret = rb_protect( call_dispatch, env, &error);
		if (error) {
			uwsgi_manage_exception(wsgi_req, uwsgi.catch_exceptions);
			goto clear;
		}
	}


	if (TYPE(ret) == T_ARRAY) {
		if (RARRAY_LEN(ret) != 3) {
			uwsgi_log("Invalid RACK response size: %ld\n", RARRAY_LEN(ret));
			return -1;
		}

		// manage Status

		status = rb_obj_as_string(RARRAY_PTR(ret)[0]);
		// get the status code

		if (uwsgi_response_prepare_headers(wsgi_req, RSTRING_PTR(status), RSTRING_LEN(status))) {
			goto clear;
		}

		headers = RARRAY_PTR(ret)[1] ;
		if (rb_respond_to( headers, rb_intern("each") )) {
			rb_protect( iterate_headers, headers, &error);
			if (error) {
				uwsgi_manage_exception(wsgi_req, uwsgi.catch_exceptions);
				goto clear;
			}
		}

		body = RARRAY_PTR(ret)[2] ;

		if (rb_respond_to( body, rb_intern("to_path") )) {
			VALUE sendfile_path = rb_protect( body_to_path, body, &error);
			if (error) {
				uwsgi_manage_exception(wsgi_req, uwsgi.catch_exceptions);
			}
			else {
				int fd = open(RSTRING_PTR(sendfile_path), O_RDONLY);
				if (fd < 0) goto clear;
				// the following function will close the descriptor
				uwsgi_response_sendfile_do(wsgi_req, fd, 0, 0);
			}
		}
		else if (rb_respond_to( body, rb_intern("each") )) {
			if (ur.unprotected) {
				iterate_body(body);
			}
			else {
				rb_protect( iterate_body, body, &error);
				if (error) {
					uwsgi_manage_exception(wsgi_req, uwsgi.catch_exceptions);
				}
			}
		}

		if (rb_respond_to( body, rb_intern("close") )) {
			//uwsgi_log("calling close\n");
			rb_protect( close_body, body, &error);
			if (error) {
				uwsgi_manage_exception(wsgi_req, uwsgi.catch_exceptions);
                        }
		}

	}
	else {
		uwsgi_500(wsgi_req);
		uwsgi_log("invalid RACK response\n");
	}

clear:

	if (ur.gc_freq <= 1 || ur.cycles%ur.gc_freq == 0) {
#ifdef UWSGI_DEBUG
			uwsgi_log("calling ruby GC\n");
#endif
			// try to limit damanges if threads are enabled...
			if (wsgi_req->async_id == 0) {
				rb_gc();
			}
	}

	ur.cycles++;

	return 0;
}

void uwsgi_rack_after_request(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

void uwsgi_rack_suspend(struct wsgi_request *wsgi_req) {
	//uwsgi_log("SUSPENDING RUBY\n");
}

void uwsgi_rack_resume(struct wsgi_request *wsgi_req) {
	//uwsgi_log("RESUMING RUBY\n");
}

VALUE init_rack_app( VALUE script ) {

	int error;

#ifndef RUBY19
	rb_require("rubygems");
#endif
        rb_protect( require_rack, 0, &error ) ;
        if (error) {
		uwsgi_ruby_exception_log(NULL);
		return Qnil;
        }

        VALUE rack = rb_const_get(rb_cObject, rb_intern("Rack"));

#ifdef RUBY19
	if (rb_funcall(rack, rb_intern("const_defined?"), 1, ID2SYM(rb_intern("BodyProxy"))) == Qtrue) {
		VALUE bodyproxy = rb_const_get(rack, rb_intern("BodyProxy"));
		// get the list of available instance_methods
		VALUE argv = Qfalse;
		VALUE methods_list = rb_class_instance_methods(1, &argv, bodyproxy);
#ifdef UWSGI_DEBUG
		uwsgi_log("%s\n", RSTRING_PTR(rb_inspect(methods_list)));
#endif
		if (rb_ary_includes(methods_list, ID2SYM(rb_intern("each"))) == Qfalse) {
			if (rb_eval_string("module Rack;class BodyProxy;def each(&block);@body.each(&block);end;end;end")) {
				if (uwsgi.mywid <= 1) {
					uwsgi_log("Rack::BodyProxy successfully patched for ruby 1.9.x\n");
				}
			}
		}
	}
#endif

        VALUE rackup = rb_funcall( rb_const_get(rack, rb_intern("Builder")), rb_intern("parse_file"), 1, script);
        if (TYPE(rackup) != T_ARRAY) {
        	uwsgi_log("unable to parse %s file\n", RSTRING_PTR(script));
                return Qnil;
        }

        if (RARRAY_LEN(rackup) < 1) {
        	uwsgi_log("invalid rack config file: %s\n", RSTRING_PTR(script));
		return Qnil;
        }

        return RARRAY_PTR(rackup)[0] ;
}

int uwsgi_rack_magic(char *mountpoint, char *lazy) {

	if (!strcmp(lazy+strlen(lazy)-3, ".ru")) {
                ur.rack = lazy;
                return 1;
        }
        else if (!strcmp(lazy+strlen(lazy)-3, ".rb")) {
                ur.rack = lazy;
                return 1;
        }


	return 0;
}

int uwsgi_rack_mount_app(char *mountpoint, char *app) {

	
	if (uwsgi_endswith(app, ".ru") || uwsgi_endswith(app, ".rb")) {
                ur.rack = app;
		uwsgi_rack_init_apps();
		return 0;
        }

        return -1;
}

VALUE run_irb(VALUE arg) {
 	rb_funcall(rb_cObject, rb_intern("require"), 1, rb_str_new2("irb"));
	VALUE irb = rb_const_get(rb_cObject, rb_intern("IRB"));
        return rb_funcall(irb, rb_intern("start"), 0);	
}

static void uwsgi_rack_hijack(void) {
	if (ur.rb_shell_oneshot && uwsgi.workers[uwsgi.mywid].hijacked_count > 0) {
                uwsgi.workers[uwsgi.mywid].hijacked = 0;
                return;
        }
        if (ur.rbshell && uwsgi.mywid == 1) {
                uwsgi.workers[uwsgi.mywid].hijacked = 1;
                uwsgi.workers[uwsgi.mywid].hijacked_count++;
                // re-map stdin to stdout and stderr if we are logging to a file
                if (uwsgi.logfile) {
                        if (dup2(0, 1) < 0) {
                                uwsgi_error("dup2()");
                        }
                        if (dup2(0, 2) < 0) {
                                uwsgi_error("dup2()");
                        }
                }
		int error = 0;
                if (ur.rbshell[0] != 0) {
			rb_eval_string(ur.rbshell);
                }
                else {
			rb_protect( run_irb, 0, &error ) ;
                	if (error) {
                        	uwsgi_ruby_exception_log(NULL);
                        	exit(1);
                	}
                }
                if (ur.rb_shell_oneshot) {
                        exit(UWSGI_DE_HIJACKED_CODE);
                }

                exit(0);
        }

}

int uwsgi_rack_mule(char *opt) {
	int error = 0;

        if (uwsgi_endswith(opt, (char *)".rb")) {
		rb_protect( uwsgi_require_file, rb_str_new2(opt), &error ) ;
                if (error) {
			uwsgi_ruby_exception_log(NULL);
			return 0;
                }
                return 1;
        }

        return 0;

}

VALUE uwsgi_rb_pfh(VALUE args) {
	
	VALUE uwsgi_rb_embedded = rb_const_get(rb_cObject, rb_intern("UWSGI"));
	if (rb_respond_to(uwsgi_rb_embedded, rb_intern("post_fork_hook"))) {
		return rb_funcall(uwsgi_rb_embedded, rb_intern("post_fork_hook"), 0);
	}
	return Qnil;
}

void uwsgi_rb_post_fork() {
	int error = 0;

        // call the post_fork_hook
	rb_protect(uwsgi_rb_pfh, 0, &error);
	if (error) {
		uwsgi_ruby_exception_log(NULL);
	}
}

VALUE uwsgi_rb_mmh(VALUE args) {
	VALUE uwsgi_rb_embedded = rb_const_get(rb_cObject, rb_intern("UWSGI"));
	return rb_funcall(uwsgi_rb_embedded, rb_intern("mule_msg_hook"), 1, args);
}

int uwsgi_rack_mule_msg(char *message, size_t len) {

	int error = 0;
	
	VALUE uwsgi_rb_embedded = rb_const_get(rb_cObject, rb_intern("UWSGI"));
        if (rb_respond_to(uwsgi_rb_embedded, rb_intern("mule_msg_hook"))) {
		VALUE arg = rb_str_new(message, len);
		rb_protect(uwsgi_rb_mmh, arg, &error);
		if (error) {
			uwsgi_ruby_exception_log(NULL);
		}
        	return 1;
	}

	return 0;
}


VALUE rack_call_signal_handler(VALUE args) {

        return rb_funcall(rb_ary_entry(args, 0), rb_intern("call"), 1, rb_ary_entry(args, 1));
}

int uwsgi_rack_signal_handler(uint8_t sig, void *handler) {

        int error = 0;


        VALUE rbhandler = (VALUE) handler;
        VALUE args = rb_ary_new2(2);
        rb_ary_store(args, 0, rbhandler);
        VALUE rbsig = INT2NUM(sig);
        rb_ary_store(args, 1, rbsig);
        rb_protect(rack_call_signal_handler, args, &error);
        if (error) {
		uwsgi_ruby_exception_log(NULL);
                rb_gc();
                return -1;
        }

        rb_gc();
        return 0;
}

VALUE uwsgi_rb_do_spooler(VALUE args) {
        VALUE uwsgi_rb_embedded = rb_const_get(rb_cObject, rb_intern("UWSGI"));
        return rb_funcall(uwsgi_rb_embedded, rb_intern("spooler"), 1, args);
}

void uwsgi_ruby_add_item(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	VALUE *spool_dict = (VALUE*) data;
	
	rb_hash_aset(*spool_dict, rb_str_new(key, keylen), rb_str_new(val, vallen));
}


int uwsgi_rack_spooler(char *filename, char *buf, uint16_t len, char *body, size_t body_len) {

	int error = 0;

        VALUE uwsgi_rb_embedded = rb_const_get(rb_cObject, rb_intern("UWSGI"));
        if (!rb_respond_to(uwsgi_rb_embedded, rb_intern("spooler"))) {
		rb_gc();
		return 0;
	}

	VALUE spool_dict = rb_hash_new();

        if (uwsgi_hooked_parse(buf, len, uwsgi_ruby_add_item, (void *) &spool_dict)) {
		rb_gc();
                // malformed packet, destroy it
                return 0;
        }

        rb_hash_aset(spool_dict, rb_str_new2("spooler_task_name"), rb_str_new2(filename));

        if (body && body_len > 0) {
                rb_hash_aset(spool_dict, rb_str_new2("body"), rb_str_new(body, body_len));
        }

        VALUE ret = rb_protect(uwsgi_rb_do_spooler, spool_dict, &error);
	if (error) {
		uwsgi_ruby_exception_log(NULL);
		rb_gc();
		return -1;
	}

        if (TYPE(ret) == T_FIXNUM) {
		rb_gc();
                return NUM2INT(ret);
        }

        // error, retry
	rb_gc();
        return -1;
}


void uwsgi_ruby_enable_native_threads() {
	uwsgi_log("DANGER: native threads do not work under ruby !!!\n");
}

void uwsgi_ruby_init_thread(int core_id) {
	uwsgi_log("DANGER: native threads do not work under ruby !!!\n");
}

void uwsgi_rack_postinit_apps(void) {
}

/*
	If the ruby VM has rb_reserved_fd_p, we avoid closign the filedescriptor needed by
	modern ruby (the Matz ones) releases.
*/
static void uwsgi_ruby_cleanup() {
	int (*uptr_rb_reserved_fd_p)(int) = dlsym(RTLD_DEFAULT, "rb_reserved_fd_p");
	if (!uptr_rb_reserved_fd_p) return;
	int i;
	for (i = 3; i < (int) uwsgi.max_fd; i++) {
		if (uptr_rb_reserved_fd_p(i)) {
			uwsgi_add_safe_fd(i);
		}
	}
}

struct uwsgi_plugin rack_plugin = {

	.name = "rack",
	.modifier1 = 7,
	.init = uwsgi_rack_init,
	.options = uwsgi_rack_options,

	.request = uwsgi_rack_request,
	.after_request = uwsgi_rack_after_request,

	.signal_handler = uwsgi_rack_signal_handler,

	.hijack_worker = uwsgi_rack_hijack,
	.post_fork = uwsgi_rb_post_fork,

	.spooler = uwsgi_rack_spooler,

	.preinit_apps = uwsgi_rack_preinit_apps,

	.init_apps = uwsgi_rack_init_apps,
	.mount_app = uwsgi_rack_mount_app,
	
	.postinit_apps = uwsgi_rack_postinit_apps,

	.magic = uwsgi_rack_magic,

	.mule = uwsgi_rack_mule,
	.mule_msg = uwsgi_rack_mule_msg,
	.rpc = uwsgi_ruby_rpc,

	.enable_threads = uwsgi_ruby_enable_native_threads,
	.init_thread = uwsgi_ruby_init_thread,

	.suspend = uwsgi_rack_suspend,
	.resume = uwsgi_rack_resume,

	.exception_class = uwsgi_ruby_exception_class,
	.exception_msg = uwsgi_ruby_exception_msg,
	.exception_repr = uwsgi_ruby_exception_repr,
	.exception_log = uwsgi_ruby_exception_log,
	.backtrace = uwsgi_ruby_backtrace,

	.master_cleanup = uwsgi_ruby_cleanup,
};

