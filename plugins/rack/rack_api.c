#include "uwsgi_rack.h"

extern struct uwsgi_server uwsgi;

extern struct uwsgi_rack ur;
extern struct uwsgi_plugin rack_plugin;

#define uwsgi_rack_api(x, y, z) rb_define_module_function(rb_uwsgi_embedded, x, y, z)

static VALUE rack_uwsgi_metric_get(VALUE class, VALUE key) {
	Check_Type(key, T_STRING);
	int64_t value = uwsgi_metric_get(RSTRING_PTR(key), NULL);
	return LONG2NUM(value);	
}

static VALUE rack_uwsgi_metric_set(VALUE class, VALUE key, VALUE val) {
        Check_Type(key, T_STRING);
        Check_Type(val, T_FIXNUM); // should be T_BIGNUM...
        if (uwsgi_metric_set(RSTRING_PTR(key), NULL, NUM2LONG(val) )) {
		return Qnil;
	}
        return Qtrue;
}

static VALUE rack_uwsgi_metric_inc(int argc, VALUE *argv, VALUE class) {
	int64_t value = 1;
	if (argc == 0) return Qnil;
	Check_Type(argv[0], T_STRING);

	if (argc > 1) {
		Check_Type(argv[1], T_FIXNUM); // should be T_BIGNUM...
		value = NUM2LONG(argv[1]);
	}

	if (uwsgi_metric_inc(RSTRING_PTR(argv[0]), NULL, value )) {
                return Qnil;
        }
        return Qtrue;
}

static VALUE rack_uwsgi_metric_dec(int argc, VALUE *argv, VALUE class) {
        int64_t value = 1;
        if (argc == 0) return Qnil;
        Check_Type(argv[0], T_STRING);

        if (argc > 1) {
                Check_Type(argv[1], T_FIXNUM); // should be T_BIGNUM...
                value = NUM2LONG(argv[1]);
        }

        if (uwsgi_metric_dec(RSTRING_PTR(argv[0]), NULL, value )) {
                return Qnil;
        }
        return Qtrue;
}

static VALUE rack_uwsgi_metric_mul(int argc, VALUE *argv, VALUE class) {
        int64_t value = 1;
        if (argc == 0) return Qnil;
        Check_Type(argv[0], T_STRING);

        if (argc > 1) {
                Check_Type(argv[1], T_FIXNUM); // should be T_BIGNUM...
                value = NUM2LONG(argv[1]);
        }

        if (uwsgi_metric_mul(RSTRING_PTR(argv[0]), NULL, value )) {
                return Qnil;
        }
        return Qtrue;
}

static VALUE rack_uwsgi_metric_div(int argc, VALUE *argv, VALUE class) {
        int64_t value = 1;
        if (argc == 0) return Qnil;
        Check_Type(argv[0], T_STRING);

        if (argc > 1) {
                Check_Type(argv[1], T_FIXNUM); // should be T_BIGNUM...
                value = NUM2LONG(argv[1]);
        }

        if (uwsgi_metric_div(RSTRING_PTR(argv[0]), NULL, value )) {
                return Qnil;
        }
        return Qtrue;
}




static VALUE rack_uwsgi_warning(VALUE class, VALUE rbmessage) {

	Check_Type(rbmessage, T_STRING);
        char *message = RSTRING_PTR(rbmessage);
	size_t len = RSTRING_LEN(rbmessage);

        if (len > 80) {
                uwsgi_log("- warning message must be max 80 chars, it will be truncated -");
                memcpy(uwsgi.shared->warning_message, message, 80);
                uwsgi.shared->warning_message[80] = 0;
        }
        else {
                memcpy(uwsgi.shared->warning_message, message, len);
                uwsgi.shared->warning_message[len] = 0;
        }

        return Qnil;
}

static VALUE rack_uwsgi_user_harakiri(VALUE class, VALUE sec) {
        Check_Type(sec, T_FIXNUM);
	set_user_harakiri(NUM2INT(sec));
        return Qnil;
}


static VALUE rack_uwsgi_log(VALUE class, VALUE msg) {

	Check_Type(msg, T_STRING);

        uwsgi_log("%s\n", RSTRING_PTR(msg));

        return Qnil;
}

static VALUE rack_uwsgi_i_am_the_spooler(VALUE class) {
        if (uwsgi.i_am_a_spooler) {
                return Qtrue;
        }
        return Qfalse;
}

#ifdef UWSGI_SSL
static VALUE rack_uwsgi_i_am_the_lord(VALUE class, VALUE legion_name) {
	Check_Type(legion_name, T_STRING);
        if (uwsgi_legion_i_am_the_lord(RSTRING_PTR(legion_name))) {
                return Qtrue;
        }
        return Qfalse;
}
#endif

static VALUE rack_uwsgi_connection_fd(VALUE class) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
        return INT2NUM(wsgi_req->fd);
}



static VALUE rack_uwsgi_setprocname(VALUE class, VALUE rbname) {

	Check_Type(rbname, T_STRING);
	char *name = RSTRING_PTR(rbname);
        uwsgi_set_processname(name);

        return Qnil;
}

static VALUE rack_uwsgi_mem(VALUE class) {

        uint64_t rss=0, vsz = 0;
        VALUE ml = rb_ary_new2(2);

        get_memusage(&rss, &vsz);

	rb_ary_store(ml, 0, LONG2NUM(rss));
	rb_ary_store(ml, 1, LONG2NUM(vsz));

        return ml;

}

static VALUE rack_uwsgi_request_id(VALUE class) {
        return ULONG2NUM(uwsgi.workers[uwsgi.mywid].requests);
}

static VALUE rack_uwsgi_worker_id(VALUE class) {
        return INT2NUM(uwsgi.mywid);
}

static VALUE rack_uwsgi_mule_id(VALUE class) {
        return INT2NUM(uwsgi.muleid);
}

static VALUE rack_uwsgi_logsize(VALUE class) {
        return ULONG2NUM(uwsgi.shared->logsize);
}

static VALUE rack_uwsgi_mule_msg(int argc, VALUE *argv, VALUE class) {

        int fd = -1;
        int mule_id = -1;

	if (argc == 0) return Qnil;

	Check_Type(argv[0], T_STRING);

        char *message = RSTRING_PTR(argv[0]);
        size_t message_len = RSTRING_LEN(argv[0]);

        if (uwsgi.mules_cnt < 1) {
                rb_raise(rb_eRuntimeError, "no mule configured");
		return Qnil;
	}

        if (argc == 1) {
                mule_send_msg(uwsgi.shared->mule_queue_pipe[0], message, message_len);
        }
        else {
                if (TYPE(argv[1]) == T_STRING) {
                        struct uwsgi_farm *uf = get_farm_by_name(RSTRING_PTR(argv[1]));
                        if (uf == NULL) {
                                rb_raise(rb_eRuntimeError, "unknown farm");
				return Qnil;
                        }
                        fd = uf->queue_pipe[0];
                }
                else if (TYPE(argv[1]) == T_FIXNUM) {
                        mule_id = NUM2INT(argv[1]);
                        if (mule_id < 0 && mule_id > uwsgi.mules_cnt) {
                                rb_raise(rb_eRuntimeError, "invalid mule number");
				return Qnil;
                        }
                        if (mule_id == 0) {
                                fd = uwsgi.shared->mule_queue_pipe[0];
                        }
                        else {
                                fd = uwsgi.mules[mule_id-1].queue_pipe[0];
                        }
                }
                else {
                        rb_raise(rb_eRuntimeError, "invalid mule");
			return Qnil;
                }

                if (fd > -1) {
                        mule_send_msg(fd, message, message_len);
                }
        }

        return Qnil;

}



static int uwsgi_ruby_hash_mule_callback(VALUE key, VALUE val, VALUE arg_array) {
	Check_Type(key, T_SYMBOL);
	ID key_id = SYM2ID(key);
	const char *key_name = rb_id2name(key_id);

	if (!strcmp(key_name, "signals")) {
		rb_ary_store(arg_array, 0, val);
	}
	else if (!strcmp(key_name, "farms")) {
		rb_ary_store(arg_array, 1, val);
	}
	else if (!strcmp(key_name, "timeout")) {
		rb_ary_store(arg_array, 2, val);
	}
	else if (!strcmp(key_name, "buffer_size")) {
		rb_ary_store(arg_array, 3, val);
	}

	return 0;
}

static VALUE rack_uwsgi_mule_get_msg(int argc, VALUE *argv, VALUE class) {

	int manage_signals = 1;
	int manage_farms = 1;
	int timeout = -1;
	size_t buffer_size = 65536;
	ssize_t len = 0;
	char *message;

        if (uwsgi.muleid == 0) {
                rb_raise(rb_eRuntimeError, "you can receive mule messages only in a mule !!!");
		return Qnil;
        }

	if (argc > 0) {
		// 0 = manage_signals
		// 1 = manage_farms
		// 2 = timeout
		// 3 = buffer_size
		VALUE arg_array = rb_ary_new2(4);
		Check_Type(argv[0], T_HASH);
		rb_hash_foreach(argv[0], uwsgi_ruby_hash_mule_callback, arg_array);
		
		if (rb_ary_entry(arg_array, 0) == Qfalse) {
			manage_signals = 0;
		}

		if (rb_ary_entry(arg_array, 1) == Qfalse) {
			manage_farms = 0;
		}

		if (TYPE(rb_ary_entry(arg_array,2)) == T_FIXNUM) {
			timeout = NUM2INT(rb_ary_entry(arg_array,2));
		}

		if (TYPE(rb_ary_entry(arg_array,3)) == T_FIXNUM || TYPE(rb_ary_entry(arg_array,3)) == T_BIGNUM) {
			buffer_size = NUM2ULONG(rb_ary_entry(arg_array,3));
		}
		
	}

        message = uwsgi_malloc(buffer_size);

        len = uwsgi_mule_get_msg(manage_signals, manage_farms, message, buffer_size, timeout) ;

        if (len < 0) {
                free(message);
                return Qnil;
        }

        VALUE msg = rb_str_new(message, len);
        free(message);
        return msg;
}


static VALUE rack_uwsgi_lock(int argc, VALUE *argv, VALUE class) {

        int lock_num = 0;

	if (argc > 0) {
		Check_Type(argv[0], T_FIXNUM);
		lock_num = NUM2INT(argv[0]);
	}

        if (lock_num < 0 || lock_num > uwsgi.locks) {
                rb_raise(rb_eRuntimeError, "Invalid lock number");
		return Qnil;
        }

        uwsgi_lock(uwsgi.user_lock[lock_num]);
	return Qnil;
}

static VALUE rack_uwsgi_unlock(int argc, VALUE *argv, VALUE class) {

        int lock_num = 0;

	if (argc > 0) {
                Check_Type(argv[0], T_FIXNUM);
                lock_num = NUM2INT(argv[0]);
        }

        if (lock_num < 0 || lock_num > uwsgi.locks) {
                rb_raise(rb_eRuntimeError, "Invalid lock number");
                return Qnil;
        }


        uwsgi_unlock(uwsgi.user_lock[lock_num]);
	return Qnil;
}




static VALUE rack_uwsgi_cache_set(int argc, VALUE *argv, VALUE class) {

	if (argc < 2) goto error;

	Check_Type(argv[0], T_STRING);
	Check_Type(argv[1], T_STRING);

        char *key = RSTRING_PTR(argv[0]);
	uint16_t keylen = RSTRING_LEN(argv[0]);
        char *value = RSTRING_PTR(argv[1]);
	uint64_t vallen = RSTRING_LEN(argv[1]);

        uint64_t expires = 0;
	char *cache = NULL;

	if (argc > 2) {
		Check_Type(argv[2], T_FIXNUM);
		expires = NUM2INT(argv[2]);
		if (argc > 3) {
			Check_Type(argv[3], T_STRING);
			cache = RSTRING_PTR(argv[3]);
		}
	}

        if (uwsgi_cache_magic_set(key, keylen, value, vallen, expires, 0, cache)) {
		return Qnil;
        }

        return Qtrue;

error:
        rb_raise(rb_eArgError, "you need to specify a cache key and a cache value");
        return Qnil;

}

static VALUE rack_uwsgi_cache_update(int argc, VALUE *argv, VALUE class) {

        if (argc < 2) goto error;

        Check_Type(argv[0], T_STRING);
        Check_Type(argv[1], T_STRING);

        char *key = RSTRING_PTR(argv[0]);
        uint16_t keylen = RSTRING_LEN(argv[0]);
        char *value = RSTRING_PTR(argv[1]);
        uint64_t vallen = RSTRING_LEN(argv[1]);

        uint64_t expires = 0;
        char *cache = NULL;

        if (argc > 2) {
                Check_Type(argv[2], T_FIXNUM);
                expires = NUM2INT(argv[2]);
                if (argc > 3) {
                        Check_Type(argv[3], T_STRING);
                        cache = RSTRING_PTR(argv[3]);
                }
        }

        if (uwsgi_cache_magic_set(key, keylen, value, vallen, expires, UWSGI_CACHE_FLAG_UPDATE, cache)) {
                return Qnil;
        }

        return Qtrue;

error:
        rb_raise(rb_eArgError, "you need to specify a cache key and a cache value");
        return Qnil;

}


static VALUE rack_uwsgi_cache_set_exc(int argc, VALUE *argv, VALUE class) {
	VALUE ret = rack_uwsgi_cache_set(argc, argv, class);
	if (ret == Qnil) {
		rb_raise(rb_eRuntimeError, "unable to set value in uWSGI cache");
	}	
	return ret;
}

static VALUE rack_uwsgi_cache_update_exc(int argc, VALUE *argv, VALUE class) {
	VALUE ret = rack_uwsgi_cache_update(argc, argv, class);
	if (ret == Qnil) {
		rb_raise(rb_eRuntimeError, "unable to update value in uWSGI cache");
	}	
	return ret;
}

static VALUE rack_uwsgi_cache_del(int argc, VALUE *argv, VALUE class) {

        if (argc == 0) goto error;

        Check_Type(argv[0], T_STRING);
        char *key = RSTRING_PTR(argv[0]);
        uint16_t keylen = RSTRING_LEN(argv[0]);

        char *cache = NULL;

        if (argc > 1) {
                Check_Type(argv[0], T_STRING);
                cache = RSTRING_PTR(argv[0]);
        }

        if (!uwsgi_cache_magic_del(key, keylen, cache)) {
                return Qtrue;
        }

        return Qnil;

error:
        rb_raise(rb_eArgError, "you need to specify a cache key");
        return Qnil;
}

static VALUE rack_uwsgi_cache_del_exc(int argc, VALUE *argv, VALUE class) {
        VALUE ret = rack_uwsgi_cache_del(argc, argv, class);
        if (ret == Qnil) {
                rb_raise(rb_eRuntimeError, "unable to delete object from uWSGI cache");
        }
        return ret;
}



static VALUE rack_uwsgi_cache_exists(int argc, VALUE *argv, VALUE class) {

	if (argc == 0) goto error;

	Check_Type(argv[0], T_STRING);
	char *key = RSTRING_PTR(argv[0]);
        uint16_t keylen = RSTRING_LEN(argv[0]);

        char *cache = NULL;

        if (argc > 1) {
                Check_Type(argv[0], T_STRING);
                cache = RSTRING_PTR(argv[0]);
        }

        if (uwsgi_cache_magic_exists(key, keylen, cache)) {
                return Qtrue;
        }

        return Qnil;

error:
	rb_raise(rb_eArgError, "you need to specify a cache key");
	return Qnil;
}



static VALUE rack_uwsgi_cache_clear(int argc, VALUE *argv, VALUE class) {

	char *cache = NULL;

	if (argc > 0) {
		Check_Type(argv[0], T_STRING);
		cache = RSTRING_PTR(argv[0]);
	}

        if (!uwsgi_cache_magic_clear(cache)) {
                return Qtrue;
        }

        return Qnil;
}

static VALUE rack_uwsgi_cache_clear_exc(int argc, VALUE *argv, VALUE class) {
        VALUE ret = rack_uwsgi_cache_clear(argc, argv, class);
        if (ret == Qnil) {
                rb_raise(rb_eRuntimeError, "unable to clear the uWSGI cache");
        }
        return ret;
}



static VALUE rack_uwsgi_cache_get(int argc, VALUE *argv, VALUE class) {

	if (argc == 0) goto error;

	Check_Type(argv[0], T_STRING);
        char *key = RSTRING_PTR(argv[0]);
        uint16_t keylen = RSTRING_LEN(argv[0]);

	char *cache = NULL;

	if (argc > 1) {
		Check_Type(argv[1], T_STRING);
                cache = RSTRING_PTR(argv[1]);
	}

        uint64_t vallen = 0;;
        char *value = uwsgi_cache_magic_get(key, keylen, &vallen, NULL, cache);
	if (value) {
        	VALUE res = rb_str_new(value, vallen);
		free(value);
        	return res;
	}
	return Qnil;

error:
	rb_raise(rb_eArgError, "you need to specify a cache key");
	return Qnil;

}

static VALUE rack_uwsgi_cache_get_exc(int argc, VALUE *argv, VALUE class) {
	VALUE ret = rack_uwsgi_cache_get(argc, argv, class);
	if (ret == Qnil) {
		rb_raise(rb_eRuntimeError, "unable to get value from uWSGI cache");
	}	
	return ret;
}




static VALUE rack_uwsgi_add_cron(VALUE class, VALUE rbsignum, VALUE rbmin, VALUE rbhour, VALUE rbday, VALUE rbmon, VALUE rbweek) {

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



static VALUE rack_uwsgi_add_timer(VALUE class, VALUE rbsignum, VALUE secs) {

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



static VALUE rack_uwsgi_add_rb_timer(VALUE class, VALUE rbsignum, VALUE secs) {

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


static VALUE rack_uwsgi_alarm(VALUE class, VALUE alarm, VALUE msg) {

	Check_Type(alarm, T_STRING);
	Check_Type(msg, T_STRING);

	uwsgi_alarm_trigger(RSTRING_PTR(alarm), RSTRING_PTR(msg), RSTRING_LEN(msg));

	return Qnil;
}

static VALUE rack_uwsgi_add_file_monitor(VALUE class, VALUE rbsignum, VALUE rbfilename) {

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


static VALUE uwsgi_ruby_wait_fd_read(VALUE class, VALUE arg1, VALUE arg2) {

	Check_Type(arg1, T_FIXNUM);
	Check_Type(arg2, T_FIXNUM);


        struct wsgi_request *wsgi_req = current_wsgi_req();

        int fd = NUM2INT(arg1);
        int timeout = NUM2INT(arg2);

        if (async_add_fd_read(wsgi_req, fd, timeout)) {
		rb_raise(rb_eRuntimeError, "unable to add fd %d to the event queue", fd);
        }

        return Qtrue;
}

static VALUE uwsgi_ruby_wait_fd_write(VALUE class, VALUE arg1, VALUE arg2) {

	Check_Type(arg1, T_FIXNUM);
	Check_Type(arg2, T_FIXNUM);

        struct wsgi_request *wsgi_req = current_wsgi_req();

        int fd = NUM2INT(arg1);
        int timeout = NUM2INT(arg2);

        if (async_add_fd_write(wsgi_req, fd, timeout)) {
		rb_raise(rb_eRuntimeError, "unable to add fd %d to the event queue", fd);
        }

        return Qtrue;
}

static VALUE uwsgi_ruby_async_connect(VALUE class, VALUE arg) {

	Check_Type(arg, T_STRING);

        int fd = uwsgi_connect(RSTRING_PTR(arg), 0, 1);

        return INT2FIX(fd);
}


static VALUE uwsgi_ruby_async_sleep(VALUE class, VALUE arg) {

	Check_Type(arg, T_FIXNUM);

        struct wsgi_request *wsgi_req = current_wsgi_req();
        int timeout = NUM2INT(arg);

        if (timeout >= 0) {
                async_add_timeout(wsgi_req, timeout);
        }

        return Qtrue;
}

static VALUE uwsgi_ruby_masterpid(VALUE class) {

        if (uwsgi.master_process) {
                return INT2NUM(uwsgi.workers[0].pid);
        }
        return INT2NUM(0);
}

static VALUE uwsgi_ruby_suspend(VALUE class) {

        struct wsgi_request *wsgi_req = current_wsgi_req();

        uwsgi.schedule_to_main(wsgi_req);

        return Qtrue;

}


static VALUE uwsgi_ruby_signal_wait(int argc, VALUE *argv, VALUE class) {

        struct wsgi_request *wsgi_req = current_wsgi_req();
        int wait_for_specific_signal = 0;
        uint8_t uwsgi_signal = 0;
        int received_signal;

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

	if (received_signal < 0) {
		rb_raise(rb_eRuntimeError, "unable to call rpc function");
	}
	else {
        	wsgi_req->signal_received = received_signal;
	}

        return Qnil;
}

static VALUE uwsgi_ruby_signal_received(VALUE class) {

        struct wsgi_request *wsgi_req = current_wsgi_req();

        return INT2NUM(wsgi_req->signal_received);
}


static VALUE uwsgi_ruby_signal_registered(VALUE class, VALUE signum) {

	Check_Type(signum, T_FIXNUM);

        uint8_t uwsgi_signal = NUM2INT(signum);

        if (uwsgi_signal_registered(uwsgi_signal)) {
                return Qtrue;
        }

        return Qfalse;
}

static VALUE uwsgi_ruby_do_rpc(int argc, VALUE *rpc_argv, VALUE class) {

	char *node = NULL, *func;
        uint64_t size = 0;

        char *argv[256];
        uint16_t argvs[256];

        int i;


        // TODO better error reporting
        if (argc < 2)
                goto clear;


        VALUE rpc_node = rpc_argv[0];

        if (TYPE(rpc_node) == T_STRING) {
                node = RSTRING_PTR(rpc_node);
        }


        VALUE rpc_func = rpc_argv[1];

        if (TYPE(rpc_func) != T_STRING)
                goto clear;

        func = RSTRING_PTR(rpc_func);

        for (i = 0; i < (argc - 2); i++) {
                VALUE rpc_str = rpc_argv[i + 2];
                if (TYPE(rpc_str) != T_STRING)
                        goto clear;
                argv[i] = RSTRING_PTR(rpc_str);
                argvs[i] = RSTRING_LEN(rpc_str);
        }

	// response must always be freed
        char *response = uwsgi_do_rpc(node, func, argc - 2, argv, argvs, &size);
        if (response) {
                VALUE ret = rb_str_new(response, size);
                free(response);
                return ret;
        }
clear:

        rb_raise(rb_eRuntimeError, "unable to call rpc function");
        return Qnil;
}

static VALUE uwsgi_ruby_register_rpc(int argc, VALUE *argv, VALUE class) {

        int rb_argc = 0;

        if (argc < 2) goto clear;
        if (argc > 2) {
		Check_Type(argv[2], T_FIXNUM);
                rb_argc = NUM2INT(argv[2]);
        }

	Check_Type(argv[0], T_STRING);
        char *name = RSTRING_PTR(argv[0]);
        void *func = (void *) argv[1];


        if (uwsgi_register_rpc(name, &rack_plugin, rb_argc, func)) {
clear:
                rb_raise(rb_eRuntimeError, "unable to register rpc function");
                return Qnil;
        }
        rb_gc_register_address(&argv[1]);
        rb_ary_push(ur.rpc_protector, argv[1]);

        return Qtrue;
}

static VALUE uwsgi_ruby_register_signal(VALUE class, VALUE signum, VALUE sigkind, VALUE rbhandler) {

	Check_Type(signum, T_FIXNUM);
	Check_Type(sigkind, T_STRING);

        uint8_t uwsgi_signal = NUM2INT(signum);
        char *signal_kind = RSTRING_PTR(sigkind);

        if (uwsgi_register_signal(uwsgi_signal, signal_kind, (void *) rbhandler, rack_plugin.modifier1)) {
                rb_raise(rb_eRuntimeError, "unable to register signal %d", uwsgi_signal);
                return Qnil;
        }

        rb_gc_register_address(&rbhandler);
        rb_ary_push(ur.signals_protector, rbhandler);

        return Qtrue;
}


static VALUE uwsgi_ruby_signal(int argc, VALUE *argv, VALUE class) {

	if (argc < 1) {
		rb_raise(rb_eRuntimeError, "you have to specify a signum");
                return Qnil;
	}

	Check_Type(argv[0], T_FIXNUM);

        uint8_t uwsgi_signal = NUM2INT(argv[0]);

	if (argc > 1) {
		Check_Type(argv[1], T_STRING);
		char *remote = RSTRING_PTR(argv[1]);

		int ret = uwsgi_remote_signal_send(remote, uwsgi_signal);
                if (ret == 1) return Qtrue;
                if (ret == -1) {
                        rb_raise(rb_eRuntimeError, "unable to deliver signal %d to node %s", uwsgi_signal, remote);
			return Qnil;
		}
                if (ret == 0) {
                        rb_raise(rb_eRuntimeError, "node %s rejected signal %d", remote, uwsgi_signal);	
			return Qnil;
		}
	}
	else {
		uwsgi_signal_send(uwsgi.signal_socket, uwsgi_signal);
	}

        return Qtrue;
}

static int rack_uwsgi_build_spool(VALUE rbkey, VALUE rbval, VALUE argv) {
	struct uwsgi_buffer *ub = (struct uwsgi_buffer *) argv;

	if (TYPE(rbkey) != T_STRING) {
		rb_raise(rb_eRuntimeError, "spool hash must contains only strings");
		return ST_STOP;
	}

	char *key = RSTRING_PTR(rbkey); uint16_t keylen = RSTRING_LEN(rbkey);

	if (TYPE(rbval) == T_STRING) {
		char *val = RSTRING_PTR(rbval); uint16_t vallen = RSTRING_LEN(rbval);
		if (uwsgi_buffer_append_keyval(ub, key, keylen, val, vallen)) {
			rb_raise(rb_eRuntimeError, "error building the spool packet");
                	return ST_STOP;
		}
	}
	else {
		//VALUE str = rb_any_to_s(rbval);
		VALUE str = rb_funcall( rbval, rb_intern("to_s"), 0);
		if (!str) {
			rb_raise(rb_eRuntimeError, "error building the spool packet");
                        return ST_STOP;
		}
		char *val = RSTRING_PTR(str); uint16_t vallen = RSTRING_LEN(str);
		if (uwsgi_buffer_append_keyval(ub, key, keylen, val, vallen)) {
                        rb_raise(rb_eRuntimeError, "error building the spool packet");
                        return ST_STOP;
                }
	}

	return ST_CONTINUE;
}


static VALUE rack_uwsgi_send_spool(VALUE class, VALUE args) {

        char *body = NULL;
        size_t body_len= 0;

	Check_Type(args, T_HASH);

	// body
#ifdef RUBY19
       VALUE rbbody = rb_hash_lookup(args, rb_str_new2("body"));
#else
       VALUE rbbody = rb_hash_aref(args, rb_str_new2("body"));
#endif
        if (TYPE(rbbody) == T_STRING) {
        	body = RSTRING_PTR(rbbody);
		body_len = RSTRING_LEN(rbbody);
             	rb_hash_delete(args, rb_str_new2("body")); 
        }

	struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);

	rb_hash_foreach(args, rack_uwsgi_build_spool, (VALUE) ub); 

        char *filename = uwsgi_spool_request(NULL, ub->buf, ub->pos, body, body_len);

	uwsgi_buffer_destroy(ub);

        if (filename) {
		VALUE ret = rb_str_new2(filename);
		free(filename);
		return ret;
        }

        rb_raise(rb_eRuntimeError, "unable to spool job");
	return Qnil;

}

static VALUE uwsgi_ruby_websocket_handshake(int argc, VALUE *argv, VALUE class) {

        struct wsgi_request *wsgi_req = current_wsgi_req();

	char *key = NULL, *origin = NULL, *proto = NULL;
	size_t key_len = 0, origin_len = 0, proto_len = 0;

	if (argc > 0) {
        	Check_Type(argv[0], T_STRING);
        	key = RSTRING_PTR(argv[0]);
        	key_len = RSTRING_LEN(argv[0]);
		if (argc > 1) {
			Check_Type(argv[1], T_STRING);
                	origin = RSTRING_PTR(argv[1]);
                	origin_len = RSTRING_LEN(argv[1]);
			if (argc > 2) {
				Check_Type(argv[2], T_STRING);
                		proto = RSTRING_PTR(argv[2]);
                		proto_len = RSTRING_LEN(argv[2]);
			}
		}
	}

	if (uwsgi_websocket_handshake(wsgi_req, key, key_len, origin, origin_len, proto, proto_len)) {
        	rb_raise(rb_eRuntimeError, "unable to complete websocket handshake");
        }
	return Qnil;
}

static VALUE uwsgi_ruby_websocket_send(VALUE class, VALUE msg) {
	Check_Type(msg, T_STRING);
	char *message = RSTRING_PTR(msg);
	size_t message_len = RSTRING_LEN(msg);
	struct wsgi_request *wsgi_req = current_wsgi_req();
	if (uwsgi_websocket_send(wsgi_req, message, message_len)) {
                rb_raise(rb_eRuntimeError, "unable to send websocket message");
        }
	return Qnil;
}

static VALUE uwsgi_ruby_websocket_recv(VALUE class) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
        struct uwsgi_buffer *ub = uwsgi_websocket_recv(wsgi_req);
        if (!ub) {
                rb_raise(rb_eRuntimeError, "unable to receive websocket message");
		return Qnil;
        }
	VALUE ret = rb_str_new(ub->buf, ub->pos);
	uwsgi_buffer_destroy(ub);
	return ret;

}

static VALUE uwsgi_ruby_websocket_recv_nb(VALUE class) {

        struct wsgi_request *wsgi_req = current_wsgi_req();
        struct uwsgi_buffer *ub = uwsgi_websocket_recv_nb(wsgi_req);
        if (!ub) {
                rb_raise(rb_eRuntimeError, "unable to receive websocket message");
                return Qnil;
        }
        VALUE ret = rb_str_new(ub->buf, ub->pos);
        uwsgi_buffer_destroy(ub);
        return ret;

}




void uwsgi_rack_init_api() {

	VALUE rb_uwsgi_embedded = rb_define_module("UWSGI");
        uwsgi_rack_api("suspend", uwsgi_ruby_suspend, 0);
        uwsgi_rack_api("masterpid", uwsgi_ruby_masterpid, 0);
        uwsgi_rack_api("async_sleep", uwsgi_ruby_async_sleep, 1);
        uwsgi_rack_api("wait_fd_read", uwsgi_ruby_wait_fd_read, 2);
        uwsgi_rack_api("wait_fd_write", uwsgi_ruby_wait_fd_write, 2);
        uwsgi_rack_api("async_connect", uwsgi_ruby_async_connect, 1);
        uwsgi_rack_api("signal", uwsgi_ruby_signal, -1);
        uwsgi_rack_api("register_signal", uwsgi_ruby_register_signal, 3);
        uwsgi_rack_api("register_rpc", uwsgi_ruby_register_rpc, -1);
        uwsgi_rack_api("signal_registered", uwsgi_ruby_signal_registered, 1);
        uwsgi_rack_api("signal_wait", uwsgi_ruby_signal_wait, -1);
        uwsgi_rack_api("signal_received", uwsgi_ruby_signal_received, 0);
        uwsgi_rack_api("add_cron", rack_uwsgi_add_cron, 6);
        uwsgi_rack_api("add_timer", rack_uwsgi_add_timer, 2);
        uwsgi_rack_api("add_rb_timer", rack_uwsgi_add_rb_timer, 2);
        uwsgi_rack_api("add_file_monitor", rack_uwsgi_add_file_monitor, 2);

        uwsgi_rack_api("alarm", rack_uwsgi_alarm, 2);

        uwsgi_rack_api("websocket_handshake", uwsgi_ruby_websocket_handshake, -1);
        uwsgi_rack_api("websocket_send", uwsgi_ruby_websocket_send, 1);
        uwsgi_rack_api("websocket_recv", uwsgi_ruby_websocket_recv, 0);
        uwsgi_rack_api("websocket_recv_nb", uwsgi_ruby_websocket_recv_nb, 0);

        uwsgi_rack_api("setprocname", rack_uwsgi_setprocname, 1);
        uwsgi_rack_api("mem", rack_uwsgi_mem, 0);

        uwsgi_rack_api("lock", rack_uwsgi_lock, -1);
        uwsgi_rack_api("unlock", rack_uwsgi_unlock, -1);

        uwsgi_rack_api("mule_get_msg", rack_uwsgi_mule_get_msg, -1);
        uwsgi_rack_api("mule_msg", rack_uwsgi_mule_msg, -1);

        uwsgi_rack_api("request_id", rack_uwsgi_request_id, 0);
        uwsgi_rack_api("worker_id", rack_uwsgi_worker_id, 0);
        uwsgi_rack_api("mule_id", rack_uwsgi_mule_id, 0);

        uwsgi_rack_api("i_am_the_spooler", rack_uwsgi_i_am_the_spooler, 0);
        uwsgi_rack_api("send_to_spooler", rack_uwsgi_send_spool, 1);
        uwsgi_rack_api("spool", rack_uwsgi_send_spool, 1);

        uwsgi_rack_api("log", rack_uwsgi_log, 1);
        uwsgi_rack_api("logsize", rack_uwsgi_logsize, 0);

        uwsgi_rack_api("set_warning_message", rack_uwsgi_warning, 1);

        uwsgi_rack_api("set_user_harakiri", rack_uwsgi_user_harakiri, 1);

        uwsgi_rack_api("rpc", uwsgi_ruby_do_rpc, -1);


#ifdef UWSGI_SSL
	uwsgi_rack_api("i_am_the_lord", rack_uwsgi_i_am_the_lord, 1);
#endif

	uwsgi_rack_api("connection_fd", rack_uwsgi_connection_fd, 0);
	

        uwsgi_rack_api("cache_get", rack_uwsgi_cache_get, -1);
        uwsgi_rack_api("cache_get!", rack_uwsgi_cache_get_exc, -1);
        uwsgi_rack_api("cache_exists", rack_uwsgi_cache_exists, -1);
        uwsgi_rack_api("cache_exists?", rack_uwsgi_cache_exists, -1);
        uwsgi_rack_api("cache_del", rack_uwsgi_cache_del, -1);
        uwsgi_rack_api("cache_del!", rack_uwsgi_cache_del_exc, -1);
        uwsgi_rack_api("cache_set", rack_uwsgi_cache_set, -1);
        uwsgi_rack_api("cache_set!", rack_uwsgi_cache_set_exc, -1);
        uwsgi_rack_api("cache_update", rack_uwsgi_cache_update, -1);
        uwsgi_rack_api("cache_update!", rack_uwsgi_cache_update_exc, -1);
        uwsgi_rack_api("cache_clear", rack_uwsgi_cache_clear, -1);
        uwsgi_rack_api("cache_clear!", rack_uwsgi_cache_clear_exc, -1);

        uwsgi_rack_api("metric_get", rack_uwsgi_metric_get, 1);
        uwsgi_rack_api("metric_set", rack_uwsgi_metric_set, 2);
        uwsgi_rack_api("metric_inc", rack_uwsgi_metric_inc, -1);
        uwsgi_rack_api("metric_dec", rack_uwsgi_metric_dec, -1);
        uwsgi_rack_api("metric_mul", rack_uwsgi_metric_mul, -1);
        uwsgi_rack_api("metric_div", rack_uwsgi_metric_div, -1);

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

        rb_const_set(rb_uwsgi_embedded, rb_intern("SPOOL_OK"), INT2NUM(-2));
        rb_const_set(rb_uwsgi_embedded, rb_intern("SPOOL_IGNORE"), INT2NUM(0));
        rb_const_set(rb_uwsgi_embedded, rb_intern("SPOOL_RETRY"), INT2NUM(-1));

        rb_const_set(rb_uwsgi_embedded, rb_intern("VERSION"), rb_str_new2(UWSGI_VERSION));
        rb_const_set(rb_uwsgi_embedded, rb_intern("HOSTNAME"), rb_str_new(uwsgi.hostname, uwsgi.hostname_len));
	if (uwsgi.pidfile) {
        	rb_const_set(rb_uwsgi_embedded, rb_intern("PIDFILE"), rb_str_new2(uwsgi.pidfile));
	}

        rb_const_set(rb_uwsgi_embedded, rb_intern("NUMPROC"), INT2NUM(uwsgi.numproc));
	

}
