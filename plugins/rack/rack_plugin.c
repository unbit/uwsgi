#include <uwsgi.h>

#include <ruby.h>

extern char **environ;

/* statistically ordered */
static struct http_status_codes hsc[] = {

        {"200", "OK"},
        {"302", "Found"},
        {"404", "Not Found"},
        {"500", "Internal Server Error"},
        {"301", "Moved Permanently"},
        {"304", "Not Modified"},
        {"303", "See Other"},
        {"403", "Forbidden"},
        {"307", "Temporary Redirect"},
        {"401", "Unauthorized"},
        {"400", "Bad Request"},
        {"405", "Method Not Allowed"},
        {"408", "Request Timeout"},

        {"100", "Continue"},
        {"101", "Switching Protocols"},
        {"201", "Created"},
        {"202", "Accepted"},
        {"203", "Non-Authoritative Information"},
        {"204", "No Content"},
        {"205", "Reset Content"},
        {"206", "Partial Content"},
        {"300", "Multiple Choices"},
        {"305", "Use Proxy"},
        {"402", "Payment Required"},
        {"406", "Not Acceptable"},
        {"407", "Proxy Authentication Required"},
        {"409", "Conflict"},
        {"410", "Gone"},
        {"411", "Length Required"},
        {"412", "Precondition Failed"},
        {"413", "Request Entity Too Large"},
        {"414", "Request-URI Too Long"},
        {"415", "Unsupported Media Type"},
        {"416", "Requested Range Not Satisfiable"},
        {"417", "Expectation Failed"},
        {"501", "Not Implemented"},
        {"502", "Bad Gateway"},
        {"503", "Service Unavailable"},
        {"504", "Gateway Timeout"},
        {"505", "HTTP Version Not Supported"},
	{ "", NULL }, 
};


VALUE dispatcher;
VALUE rb_uwsgi_io_class;
ID call;

VALUE rb_uwsgi_io_new(VALUE class, VALUE wr) {

	struct wsgi_request *wsgi_req;
	
	Data_Get_Struct(wr, struct wsgi_request, wsgi_req);
	uwsgi_log("INITIALIZING UWSGI IO FOR FD: %d\n", wsgi_req->poll.fd);

	VALUE self = Data_Wrap_Struct(class , 0, 0, wsgi_req);
	
	rb_obj_call_init(self, 0, NULL);

	return self;
	
}

VALUE rb_uwsgi_io_init(int argc, VALUE *argv, VALUE self) {

	return self;
}

VALUE rb_uwsgi_io_gets(VALUE obj, VALUE args) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);
	
	uwsgi_log("CALLING gets !!!\n");

	return Qnil;
}

VALUE rb_uwsgi_io_each(VALUE obj, VALUE args) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);
	
	uwsgi_log("CALLING each !!!\n");

	return Qnil;
}

VALUE rb_uwsgi_io_read(VALUE obj, VALUE args) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);

	size_t len;
	
	uwsgi_log("CALLING read on %d !!!\n", wsgi_req->poll.fd);

	if (RARRAY(args)->len == 0) {
		uwsgi_log("READ ALL THE BODY (%d bytes)\n", wsgi_req->post_cl);	
		char *post_body = malloc(wsgi_req->post_cl);
		if (post_body) {
			len = read( wsgi_req->poll.fd, post_body, wsgi_req->post_cl);
			VALUE chunk = rb_str_new(post_body, wsgi_req->post_cl);
			free(post_body);
			return chunk;
		}
	}
	else if (RARRAY(args)->len > 0) {

		uwsgi_log("CHUNK SIZE: %d\n", NUM2INT( RARRAY(args)->ptr[0] ) );
	}

	return Qnil;
}

VALUE rb_uwsgi_io_rewind(VALUE obj, VALUE args) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);
	
	uwsgi_log("CALLING rewind !!!\n");

	return Qnil;
}

int uwsgi_init(struct uwsgi_server *uwsgi, char *args){

	struct http_status_codes *http_sc;

	// filling http status codes
        for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
                http_sc->message_size = strlen(http_sc->message);
        }

	ruby_init();
	ruby_init_loadpath();
	ruby_script("uwsgi");

	if (chdir("mytipo")) {
		uwsgi_error("chdir()");
	}

	rb_require("config/environment");

	uwsgi_log("ruby ready\n");

	VALUE ac = rb_const_get(rb_cObject, rb_intern("ActionController")) ;

	dispatcher = rb_funcall( rb_const_get(ac, rb_intern("Dispatcher")), rb_intern("new"), 0);

	if (dispatcher == Qnil) {
		uwsgi_log("OOOPS\n");
		exit(1);
	}
	else {
		uwsgi_log("OK %p\n", dispatcher);
	}

	rb_gc_register_address(&dispatcher);

	call = rb_intern("call");
	rb_gc_register_address(&call);


	rb_uwsgi_io_class = rb_define_class("Uwsgi_IO", rb_cObject);

	rb_gc_register_address(&rb_uwsgi_io_class);
	
	rb_define_singleton_method(rb_uwsgi_io_class, "new", rb_uwsgi_io_new, 1);
	rb_define_method(rb_uwsgi_io_class, "initialize", rb_uwsgi_io_init, -1);
	rb_define_method(rb_uwsgi_io_class, "gets", rb_uwsgi_io_gets, 0);
	rb_define_method(rb_uwsgi_io_class, "each", rb_uwsgi_io_each, 0);
	rb_define_method(rb_uwsgi_io_class, "read", rb_uwsgi_io_read, -2);
	rb_define_method(rb_uwsgi_io_class, "rewind", rb_uwsgi_io_rewind, 0);

	rb_gc_disable();

	return 0;

}

VALUE call_dispatch(VALUE env) {

	return rb_funcall(dispatcher, call, 1, env);

}

VALUE send_body(VALUE obj, VALUE fd) {

	size_t len;

	uwsgi_log("sending body\n");
	if (TYPE(obj) == T_STRING) {
		uwsgi_log("chunk is a string\n");
		len = write( NUM2INT(fd), RSTRING(obj)->ptr, RSTRING(obj)->len);
	}

	return Qnil;
}

VALUE send_header(VALUE obj, VALUE fd) {

	size_t len;
	
	uwsgi_log("SENDING HEADER: %d\n", TYPE(obj));

	if (TYPE(obj) == T_ARRAY) {
	
		if (RARRAY(obj)->len == 2) {
			VALUE hkey = rb_obj_as_string( RARRAY(obj)->ptr[0]);
			VALUE hval = rb_obj_as_string( RARRAY(obj)->ptr[1]);

			len = write( NUM2INT(fd), RSTRING(hkey)->ptr, RSTRING(hkey)->len);
			len = write( NUM2INT(fd), ": ", 2);

			len = write( NUM2INT(fd), RSTRING(hval)->ptr, RSTRING(hval)->len);
			len = write( NUM2INT(fd), "\r\n", 2);
		}
	}
	
	return Qnil;
}

static void uwsgi_ruby_exception(void) {
	
	VALUE lasterr = rb_gv_get("$!");
	VALUE message = rb_obj_as_string(lasterr);

	uwsgi_log("%s\n", RSTRING(message)->ptr);
	if(!NIL_P(ruby_errinfo)) {
		VALUE ary = rb_funcall(ruby_errinfo, rb_intern("backtrace"), 0);
		int i;
		for (i=0; i<RARRAY(ary)->len; i++) {
			uwsgi_log("%s\n", RSTRING(RARRAY(ary)->ptr[i])->ptr);
		}
	}
}

int uwsgi_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int error;
	int i;

	struct http_status_codes *http_sc;

	/* Standard RACK request */
        if (!wsgi_req->uh.pktsize) {
                uwsgi_log("Invalid RACK request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(uwsgi, wsgi_req)) {
                uwsgi_log("Invalid RACK request. skip.\n");
                return -1;
        }

        VALUE env = rb_hash_new();

        // fill ruby hash
        for(i=0;i<wsgi_req->var_cnt;i++) {

		rb_hash_aset(env, rb_str_new(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len),
				rb_str_new(wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len));
                i++;
        }

	VALUE rbv = rb_ary_new();
	rb_ary_store(rbv, 0, INT2NUM(1));
	rb_ary_store(rbv, 1, INT2NUM(1));
	rb_hash_aset(env, rb_str_new2("rack.version"), rbv);

	rb_hash_aset(env, rb_str_new2("rack.url_scheme"), rb_str_new2("http"));

	rb_hash_aset(env, rb_str_new2("rack.multithread"), Qfalse);
	rb_hash_aset(env, rb_str_new2("rack.multiprocess"), Qtrue);
	rb_hash_aset(env, rb_str_new2("rack.run_once"), Qfalse);

	VALUE dws_wr = Data_Wrap_Struct(rb_uwsgi_io_class, 0, 0, wsgi_req);
	rb_hash_aset(env, rb_str_new2("rack.input"), rb_funcall(rb_uwsgi_io_class, rb_intern("new"), 1, dws_wr ));

	
	VALUE ret = rb_protect( call_dispatch, env, &error);

	if (error) {
		uwsgi_ruby_exception();
		return -1;
	}

	if (TYPE(ret) == T_ARRAY) {
		if (RARRAY(ret)->len != 3) {
			uwsgi_log("Invalid RACK response size: %d\n", RARRAY(ret)->len);
			return -1;
		}

		// manage Status


		VALUE status = rb_obj_as_string(RARRAY(ret)->ptr[0]);
		uwsgi_log("Status: %.*s\n", RSTRING(status)->len, RSTRING(status)->ptr);
		// get the status code

		wsgi_req->hvec[0].iov_base = "HTTP/1.1 ";
        	wsgi_req->hvec[0].iov_len = 9 ;

        	wsgi_req->hvec[1].iov_base = RSTRING(status)->ptr;
        	wsgi_req->hvec[1].iov_len = 3 ;

        	wsgi_req->hvec[2].iov_base = " ";
        	wsgi_req->hvec[2].iov_len = 1 ;

        	wsgi_req->hvec[3].iov_len = 0 ;

        	for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
                	if (!strncmp(http_sc->key, RSTRING(status)->ptr, 3)) {
                        	wsgi_req->hvec[3].iov_base = http_sc->message ;
                        	wsgi_req->hvec[3].iov_len = http_sc->message_size ;
                        	break;
                	}
        	}

        	wsgi_req->hvec[4].iov_base = "\r\n";
        	wsgi_req->hvec[4].iov_len = 2 ;

		if ( (wsgi_req->response_size = writev(wsgi_req->poll.fd, wsgi_req->hvec, 5)) < 0) {
                	uwsgi_error("writev()");
        	}

		VALUE headers = RARRAY(ret)->ptr[1] ;
		if (rb_respond_to( headers, rb_intern("each") )) {

			uwsgi_log("headers respond_to each\n");
			rb_iterate( rb_each, headers, send_header, INT2NUM(wsgi_req->poll.fd)); 

		}

		uwsgi_log("wsgi_req ptr: %p\n", wsgi_req);

		write(wsgi_req->poll.fd, "\r\n", 2);

		uwsgi_log("PTR: %p\n", RARRAY(ret)->ptr[2]);

		VALUE body = RARRAY(ret)->ptr[2] ;

		//rb_gc_register_address(&body);

		if (rb_respond_to( body, rb_intern("to_path") )) {
			uwsgi_log("BODY respond_to 'to_path'\n");
		}
		else if (rb_respond_to( body, rb_intern("each") )) {
			rb_iterate( rb_each, body, send_body, INT2NUM(wsgi_req->poll.fd));
		}

		uwsgi_log("Fatto %p\n", body);
	
		if (rb_respond_to( body, rb_intern("close") )) {
			uwsgi_log("BODY respond_to 'close'\n");
		}

		uwsgi_log("Fatto 2 %p\n", wsgi_req);
	}

	rb_gc_disable();

	return 0;
}


void uwsgi_after_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	if (uwsgi->shared->options[UWSGI_OPTION_LOGGING])
                log_request(wsgi_req);
}
