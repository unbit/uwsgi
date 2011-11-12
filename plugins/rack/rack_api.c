#include "uwsgi_rack.h"

extern struct uwsgi_server uwsgi;

extern struct uwsgi_rack ur;

VALUE rack_uwsgi_setprocname(VALUE *class, VALUE rbname) {

	Check_Type(rbname, T_STRING);
	char *name = RSTRING_PTR(rbname);
        uwsgi_set_processname(name);

        return Qnil;
}

VALUE rack_uwsgi_mem(VALUE *class) {

        uint64_t rss=0, vsz = 0;
        VALUE ml = rb_ary_new2(2);

        get_memusage(&rss, &vsz);

	rb_ary_store(ml, 0, LONG2NUM(rss));
	rb_ary_store(ml, 1, LONG2NUM(vsz));

        return ml;

}



VALUE rack_uwsgi_cache_set(VALUE *class, VALUE rbkey, VALUE rbvalue) {


	Check_Type(rbkey, T_STRING);
	Check_Type(rbvalue, T_STRING);

        char *key = RSTRING_PTR(rbkey);
	uint64_t keylen = RSTRING_LEN(rbkey);
        char *value = RSTRING_PTR(rbvalue);
	uint64_t vallen = RSTRING_LEN(rbvalue);

        uint64_t expires = 0;

        if (vallen > uwsgi.cache_blocksize) {
                rb_raise(rb_eRuntimeError, "uWSGI cache items size must be < %llu, requested %llu bytes", (unsigned long long)uwsgi.cache_blocksize, (unsigned long long) vallen);
		return Qnil;
        }

        uwsgi_wlock(uwsgi.cache_lock);
        if (uwsgi_cache_set(key, keylen, value, vallen, expires, 0)) {
        	uwsgi_rwunlock(uwsgi.cache_lock);
		return Qnil;
        }

        uwsgi_rwunlock(uwsgi.cache_lock);
        return Qtrue;

}
VALUE rack_uwsgi_cache_update(VALUE *class, VALUE rbkey, VALUE rbvalue) {


	Check_Type(rbkey, T_STRING);
	Check_Type(rbvalue, T_STRING);

        char *key = RSTRING_PTR(rbkey);
	uint64_t keylen = RSTRING_LEN(rbkey);
        char *value = RSTRING_PTR(rbvalue);
	uint64_t vallen = RSTRING_LEN(rbvalue);

        uint64_t expires = 0;

        if (vallen > uwsgi.cache_blocksize) {
                rb_raise(rb_eRuntimeError, "uWSGI cache items size must be < %llu, requested %llu bytes", (unsigned long long)uwsgi.cache_blocksize, (unsigned long long) vallen);
		return Qnil;
        }

        uwsgi_wlock(uwsgi.cache_lock);
        if (uwsgi_cache_set(key, keylen, value, vallen, expires, UWSGI_CACHE_FLAG_UPDATE)) {
        	uwsgi_rwunlock(uwsgi.cache_lock);
		return Qnil;
        }

        uwsgi_rwunlock(uwsgi.cache_lock);
        return Qtrue;

}

VALUE rack_uwsgi_cache_set_exc(VALUE *class, VALUE rbkey, VALUE rbvalue) {
	VALUE ret;
	ret = rack_uwsgi_cache_set(class, rbkey, rbvalue);
	if (ret == Qnil) {
		rb_raise(rb_eRuntimeError, "unable to set value in uWSGI cache");
	}	
	return ret;
}

VALUE rack_uwsgi_cache_update_exc(VALUE *class, VALUE rbkey, VALUE rbvalue) {
	VALUE ret;
	ret = rack_uwsgi_cache_update(class, rbkey, rbvalue);
	if (ret == Qnil) {
		rb_raise(rb_eRuntimeError, "unable to update value in uWSGI cache");
	}	
	return ret;
}





VALUE rack_uwsgi_cache_del(VALUE *class, VALUE rbkey) {

	Check_Type(rbkey, T_STRING);

        char *key = RSTRING_PTR(rbkey);
	size_t keylen = RSTRING_LEN(rbkey);
	
        uwsgi_wlock(uwsgi.cache_lock);
        if (uwsgi_cache_del(key, keylen)) {
        	uwsgi_rwunlock(uwsgi.cache_lock);
		return Qfalse;
        }

        uwsgi_rwunlock(uwsgi.cache_lock);
        return Qtrue;

}


VALUE rack_uwsgi_cache_exists(VALUE *class, VALUE rbkey) {

	Check_Type(rbkey, T_STRING);

        char *key = RSTRING_PTR(rbkey);
	size_t keylen = RSTRING_LEN(rbkey);

        if (uwsgi_cache_exists(key, keylen)) {
                return Qtrue;
        }

        return Qfalse;

}


VALUE rack_uwsgi_cache_get(VALUE *class, VALUE rbkey) {

	Check_Type(rbkey, T_STRING);

        char *key = RSTRING_PTR(rbkey);
	size_t keylen = RSTRING_LEN(rbkey);

        uint64_t valsize;
        char *value = NULL;

        uwsgi_rlock(uwsgi.cache_lock);
        value = uwsgi_cache_get(key, keylen, &valsize);
        if (!value) {
        	uwsgi_rwunlock(uwsgi.cache_lock);
        	return Qnil;
        }
        VALUE res = rb_str_new(value, valsize);
        uwsgi_rwunlock(uwsgi.cache_lock);
        return res;

}
VALUE rack_uwsgi_cache_get_exc(VALUE *class, VALUE rbkey) {
	VALUE ret;
	ret = rack_uwsgi_cache_get(class, rbkey);
	if (ret == Qnil) {
		rb_raise(rb_eRuntimeError, "unable to get value from uWSGI cache");
	}	
	return ret;
}




VALUE rack_uwsgi_add_cron(VALUE *class, VALUE rbsignum, VALUE rbmin, VALUE rbhour, VALUE rbday, VALUE rbmon, VALUE rbweek) {

	Check_Type(rbsignum, T_FIXNUM);
	Check_Type(rbmin, T_FIXNUM);
	Check_Type(rbhour, T_FIXNUM);
	Check_Type(rbday, T_FIXNUM);
	Check_Type(rbmon, T_FIXNUM);
	Check_Type(rbweek, T_FIXNUM);

        uint8_t uwsgi_signal = NUM2INT(rbsignum);
        int minute = NUM2INT(rbmin);
        int hour = NUM2INT(rbhour);
        int day = NUM2INT(rbday);
        int month = NUM2INT(rbmon);
        int week = NUM2INT(rbweek);

        if (uwsgi_signal_add_cron(uwsgi_signal, minute, hour, day, month, week)) {
                rb_raise(rb_eRuntimeError, "unable to add cron");
                return Qnil;
        }

        return Qtrue;
}



VALUE rack_uwsgi_add_timer(VALUE *class, VALUE rbsignum, VALUE secs) {

	Check_Type(rbsignum, T_FIXNUM);
	Check_Type(secs, T_FIXNUM);

        uint8_t uwsgi_signal = NUM2INT(rbsignum);
        int seconds = NUM2INT(secs);

        if (uwsgi_add_timer(uwsgi_signal, seconds)) {
                rb_raise(rb_eRuntimeError, "unable to add timer");
                return Qnil;
        }

        return Qtrue;
}



VALUE rack_uwsgi_add_rb_timer(VALUE *class, VALUE rbsignum, VALUE secs) {

	Check_Type(rbsignum, T_FIXNUM);
	Check_Type(secs, T_FIXNUM);

        uint8_t uwsgi_signal = NUM2INT(rbsignum);
        int seconds = NUM2INT(secs);


        if (uwsgi_signal_add_rb_timer(uwsgi_signal, seconds, 0)) {
                rb_raise(rb_eRuntimeError, "unable to add rb_timer");
                return Qnil;
        }

        return Qtrue;
}



VALUE rack_uwsgi_add_file_monitor(VALUE *class, VALUE rbsignum, VALUE rbfilename) {

	Check_Type(rbsignum, T_FIXNUM);
	Check_Type(rbfilename, T_STRING);

        uint8_t uwsgi_signal = NUM2INT(rbsignum);
        char *filename = RSTRING_PTR(rbfilename);

        if (uwsgi_add_file_monitor(uwsgi_signal, filename)) {
                rb_raise(rb_eRuntimeError, "unable to add file monitor");
                return Qnil;
        }

        return Qtrue;
}


VALUE uwsgi_ruby_wait_fd_read(VALUE *class, VALUE arg1, VALUE arg2) {

	Check_Type(arg1, T_FIXNUM);
	Check_Type(arg2, T_FIXNUM);


        struct wsgi_request *wsgi_req = current_wsgi_req();

        int fd = NUM2INT(arg1);
        int timeout = NUM2INT(arg2);

        if (fd >= 0) {
                async_add_fd_read(wsgi_req, fd, timeout);
        }

        return Qtrue;
}

VALUE uwsgi_ruby_wait_fd_write(VALUE *class, VALUE arg1, VALUE arg2) {

	Check_Type(arg1, T_FIXNUM);
	Check_Type(arg2, T_FIXNUM);

        struct wsgi_request *wsgi_req = current_wsgi_req();

        int fd = NUM2INT(arg1);
        int timeout = NUM2INT(arg2);

        if (fd >= 0) {
                async_add_fd_write(wsgi_req, fd, timeout);
        }

        return Qtrue;
}



VALUE uwsgi_ruby_async_connect(VALUE *class, VALUE arg) {

	Check_Type(arg, T_STRING);

        int fd = uwsgi_connect(RSTRING_PTR(arg), 0, 1);

        return INT2FIX(fd);
}


VALUE uwsgi_ruby_async_sleep(VALUE *class, VALUE arg) {

	Check_Type(arg, T_FIXNUM);

        struct wsgi_request *wsgi_req = current_wsgi_req();
        int timeout = NUM2INT(arg);

        if (timeout >= 0) {
                async_add_timeout(wsgi_req, timeout);
        }

        return Qtrue;
}

VALUE uwsgi_ruby_masterpid(VALUE *class) {

        if (uwsgi.master_process) {
                return INT2NUM(uwsgi.workers[0].pid);
        }
        return INT2NUM(0);
}

VALUE uwsgi_ruby_suspend(VALUE *class) {

        struct wsgi_request *wsgi_req = current_wsgi_req();

        uwsgi.schedule_to_main(wsgi_req);

        return Qtrue;

}


VALUE uwsgi_ruby_signal_wait(int argc, VALUE *argv, VALUE *class) {

        struct wsgi_request *wsgi_req = current_wsgi_req();
        int wait_for_specific_signal = 0;
        uint8_t uwsgi_signal = 0;
        uint8_t received_signal;

        wsgi_req->signal_received = -1;

        if (argc > 0) {
		Check_Type(argv[0], T_FIXNUM);
                uwsgi_signal = NUM2INT(argv[0]);
                wait_for_specific_signal = 1;
        }

        if (wait_for_specific_signal) {
                received_signal = uwsgi_signal_wait(uwsgi_signal);
        }
        else {
                received_signal = uwsgi_signal_wait(-1);
        }

        wsgi_req->signal_received = received_signal;

        return Qnil;
}

VALUE uwsgi_ruby_signal_received(VALUE *class) {

        struct wsgi_request *wsgi_req = current_wsgi_req();

        return INT2NUM(wsgi_req->signal_received);
}


VALUE uwsgi_ruby_signal_registered(VALUE *class, VALUE signum) {

	Check_Type(signum, T_FIXNUM);

        uint8_t uwsgi_signal = NUM2INT(signum);

        if (uwsgi_signal_registered(uwsgi_signal)) {
                return Qtrue;
        }

        return Qfalse;
}

VALUE uwsgi_ruby_register_rpc(int argc, VALUE *argv, VALUE *class) {

        int rb_argc = 0;

        if (argc < 2) goto clear;
        if (argc > 2) {
		Check_Type(argv[2], T_FIXNUM);
                rb_argc = NUM2INT(argv[2]);
        }

	Check_Type(argv[0], T_STRING);
        char *name = RSTRING_PTR(argv[0]);
        void *func = (void *) argv[1];


        if (uwsgi_register_rpc(name, 7, rb_argc, func)) {
clear:
                rb_raise(rb_eRuntimeError, "unable to register rpc function");
                return Qnil;
        }
        rb_gc_register_address(&argv[1]);
        rb_ary_push(ur.rpc_protector, argv[1]);

        return Qtrue;
}

VALUE uwsgi_ruby_register_signal(VALUE *class, VALUE signum, VALUE sigkind, VALUE rbhandler) {

	Check_Type(signum, T_FIXNUM);
	Check_Type(sigkind, T_STRING);

        uint8_t uwsgi_signal = NUM2INT(signum);
        char *signal_kind = RSTRING_PTR(sigkind);

        if (uwsgi_register_signal(uwsgi_signal, signal_kind, (void *) rbhandler, 7)) {
                rb_raise(rb_eRuntimeError, "unable to register signal %d", uwsgi_signal);
                return Qnil;
        }

        rb_gc_register_address(&rbhandler);
        rb_ary_push(ur.signals_protector, rbhandler);

        return Qtrue;
}


VALUE uwsgi_ruby_signal(VALUE *class, VALUE signum) {

	Check_Type(signum, T_FIXNUM);

        uint8_t uwsgi_signal = NUM2INT(signum);
        ssize_t rlen;

        rlen = write(uwsgi.signal_socket, &uwsgi_signal, 1);
        if (rlen != 1) {
                uwsgi_error("write()");
        }

        return Qtrue;
}



void uwsgi_rack_init_api() {

	VALUE rb_uwsgi_embedded = rb_define_module("UWSGI");
        rb_define_module_function(rb_uwsgi_embedded, "suspend", uwsgi_ruby_suspend, 0);
        rb_define_module_function(rb_uwsgi_embedded, "masterpid", uwsgi_ruby_masterpid, 0);
        rb_define_module_function(rb_uwsgi_embedded, "async_sleep", uwsgi_ruby_async_sleep, 1);
        rb_define_module_function(rb_uwsgi_embedded, "wait_fd_read", uwsgi_ruby_wait_fd_read, 2);
        rb_define_module_function(rb_uwsgi_embedded, "wait_fd_write", uwsgi_ruby_wait_fd_write, 2);
        rb_define_module_function(rb_uwsgi_embedded, "async_connect", uwsgi_ruby_async_connect, 1);
        rb_define_module_function(rb_uwsgi_embedded, "signal", uwsgi_ruby_signal, 1);
        rb_define_module_function(rb_uwsgi_embedded, "register_signal", uwsgi_ruby_register_signal, 3);
        rb_define_module_function(rb_uwsgi_embedded, "register_rpc", uwsgi_ruby_register_rpc, -1);
        rb_define_module_function(rb_uwsgi_embedded, "signal_registered", uwsgi_ruby_signal_registered, 1);
        rb_define_module_function(rb_uwsgi_embedded, "signal_wait", uwsgi_ruby_signal_wait, -1);
        rb_define_module_function(rb_uwsgi_embedded, "signal_received", uwsgi_ruby_signal_received, 0);
        rb_define_module_function(rb_uwsgi_embedded, "add_cron", rack_uwsgi_add_cron, 6);
        rb_define_module_function(rb_uwsgi_embedded, "add_timer", rack_uwsgi_add_timer, 2);
        rb_define_module_function(rb_uwsgi_embedded, "add_rb_timer", rack_uwsgi_add_rb_timer, 2);
        rb_define_module_function(rb_uwsgi_embedded, "add_file_monitor", rack_uwsgi_add_file_monitor, 2);

        rb_define_module_function(rb_uwsgi_embedded, "setprocname", rack_uwsgi_setprocname, 1);
        rb_define_module_function(rb_uwsgi_embedded, "mem", rack_uwsgi_mem, 0);

	if (uwsgi.cache_max_items > 0) {
        	rb_define_module_function(rb_uwsgi_embedded, "cache_get", rack_uwsgi_cache_get, 1);
        	rb_define_module_function(rb_uwsgi_embedded, "cache_get!", rack_uwsgi_cache_get_exc, 1);
        	rb_define_module_function(rb_uwsgi_embedded, "cache_exists", rack_uwsgi_cache_exists, 1);
        	rb_define_module_function(rb_uwsgi_embedded, "cache_exists?", rack_uwsgi_cache_exists, 1);
        	rb_define_module_function(rb_uwsgi_embedded, "cache_del", rack_uwsgi_cache_del, 1);
        	rb_define_module_function(rb_uwsgi_embedded, "cache_set", rack_uwsgi_cache_set, 2);
        	rb_define_module_function(rb_uwsgi_embedded, "cache_set!", rack_uwsgi_cache_set_exc, 2);
        	rb_define_module_function(rb_uwsgi_embedded, "cache_update", rack_uwsgi_cache_update, 2);
        	rb_define_module_function(rb_uwsgi_embedded, "cache_update!", rack_uwsgi_cache_update_exc, 2);
	}

        VALUE uwsgi_rb_opt_hash = rb_hash_new();
        int i;
        for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
                VALUE rb_uwsgi_opt_key = rb_str_new2(uwsgi.exported_opts[i]->key);
                if ( rb_funcall(uwsgi_rb_opt_hash, rb_intern("has_key?"), 1, rb_uwsgi_opt_key) == Qtrue) {
                        VALUE rb_uwsgi_opt_item = rb_hash_aref(uwsgi_rb_opt_hash, rb_uwsgi_opt_key);
                        if (TYPE(rb_uwsgi_opt_item) == T_ARRAY) {
                                if (uwsgi.exported_opts[i]->value == NULL) {
                                        rb_ary_push(rb_uwsgi_opt_item, Qtrue);
                                }
                                else {
                                        rb_ary_push(rb_uwsgi_opt_item, rb_str_new2(uwsgi.exported_opts[i]->value));
                                }
                        }
                        else {
                                VALUE rb_uwsgi_opt_list = rb_ary_new();
                                rb_ary_push(rb_uwsgi_opt_list, rb_uwsgi_opt_item);
                                if (uwsgi.exported_opts[i]->value == NULL) {
                                        rb_ary_push(rb_uwsgi_opt_list, Qtrue);
                                }
                                else {
                                        rb_ary_push(rb_uwsgi_opt_list, rb_str_new2(uwsgi.exported_opts[i]->value));
                                }

                                rb_hash_aset(uwsgi_rb_opt_hash, rb_uwsgi_opt_key, rb_uwsgi_opt_list);
                        }
                }
                else {
                        if (uwsgi.exported_opts[i]->value == NULL) {
                                rb_hash_aset(uwsgi_rb_opt_hash, rb_uwsgi_opt_key, Qtrue);
                        }
                        else {
                                rb_hash_aset(uwsgi_rb_opt_hash, rb_uwsgi_opt_key, rb_str_new2(uwsgi.exported_opts[i]->value));
                        }
                }
        }

        rb_const_set(rb_uwsgi_embedded, rb_intern("OPT"), uwsgi_rb_opt_hash);

        rb_const_set(rb_uwsgi_embedded, rb_intern("VERSION"), rb_str_new2(UWSGI_VERSION));
        rb_const_set(rb_uwsgi_embedded, rb_intern("HOSTNAME"), rb_str_new(uwsgi.hostname, uwsgi.hostname_len));
	if (uwsgi.pidfile) {
        	rb_const_set(rb_uwsgi_embedded, rb_intern("PIDFILE"), rb_str_new2(uwsgi.pidfile));
	}

        rb_const_set(rb_uwsgi_embedded, rb_intern("NUMPROC"), INT2NUM(uwsgi.numproc));
	

}
