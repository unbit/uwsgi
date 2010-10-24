#include "../../uwsgi.h"

#include <ruby.h>

extern char **environ;
extern struct uwsgi_server uwsgi;

#define LONG_ARGS_RACK_BASE	17000 + (7 * 100)
#define LONG_ARGS_RAILS		LONG_ARGS_RACK_BASE + 1
#define LONG_ARGS_RUBY_GC_FREQ	LONG_ARGS_RACK_BASE + 2
#define LONG_ARGS_RACK		LONG_ARGS_RACK_BASE + 3

struct uwsgi_rack {
	
	char *rails;
	char *rack;
	int gc_freq;
	uint64_t cycles;

	VALUE dispatcher;
	VALUE rb_uwsgi_io_class;
	ID call;

} ur;

struct option uwsgi_rack_options[] = {

        {"rails", required_argument, 0, LONG_ARGS_RAILS},
        {"rack", required_argument, 0, LONG_ARGS_RACK},
        {"ruby-gc-freq", required_argument, 0, LONG_ARGS_RUBY_GC_FREQ},

        {0, 0, 0, 0},

};



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



VALUE rb_uwsgi_io_new(VALUE class, VALUE wr) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(wr, struct wsgi_request, wsgi_req);
	VALUE self = Data_Wrap_Struct(class , 0, 0, wsgi_req);

	ssize_t len = uwsgi.post_buffering_bufsize;
	size_t post_remains = wsgi_req->post_cl;
	char *ptr;

	/* now the fun part:

        We will try to emulate a StringIO ruby object if http body is littler than uwsgi.post_buffering_bufsize
        otherwise we will map a *FILE object

        */

	if (!wsgi_req->post_cl) {
                return self;
	}

        if (wsgi_req->post_cl > (size_t) uwsgi.post_buffering_bufsize) {
                uwsgi_log("using file for http body storage %d\n", wsgi_req->post_cl);
                uwsgi_read_whole_body(wsgi_req, wsgi_req->post_buffering_buf, uwsgi.post_buffering_bufsize);
        }
        else {
                uwsgi_log("using memory for http body storage %d\n", wsgi_req->post_cl);
                ptr = wsgi_req->post_buffering_buf;
                while(post_remains > 0) {
                        if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
                                inc_harakiri(uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
                        }
                        if (post_remains > (size_t) uwsgi.post_buffering_bufsize) {
                                len = read(wsgi_req->poll.fd, ptr, len);
                        }
                        else {
                                len = read(wsgi_req->poll.fd, ptr, post_remains);
                        }
                        if (len < 0) {
                                uwsgi_error("read()");
                                return Qnil;
                        }
                        ptr += len;
                        post_remains -= len;
                }
                wsgi_req->buf_pos = 0;
        }

	rb_obj_call_init(self, 0, NULL);

	return self;
	
}

VALUE rb_uwsgi_io_init(int argc, VALUE *argv, VALUE self) {

	return self;
}

VALUE rb_uwsgi_io_gets(VALUE obj, VALUE args) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);
	
	// return the whole body as string
	return Qnil;
}

VALUE rb_uwsgi_io_each(VALUE obj, VALUE args) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);
	
	// yield strings chunks

	return Qnil;
}

VALUE rb_uwsgi_io_read(VALUE obj, VALUE args) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);
	VALUE chunk;
	size_t len;
	int chunk_size;


	if (!wsgi_req->post_cl) {
		return Qnil;
	}
	
	if (RARRAY(args)->len == 0) {
		//uwsgi_log("reading the whole post data\n" ) ;
		if (wsgi_req->post_cl > (size_t) uwsgi.post_buffering_bufsize) {
			char *post_body = malloc(wsgi_req->post_cl);
			if (post_body) {
				len = fread( post_body, wsgi_req->post_cl, 1, wsgi_req->async_post);
				chunk = rb_str_new(post_body, wsgi_req->post_cl);
				free(post_body);
			}
			else {
				uwsgi_error("malloc()");
				return Qnil;
			}
		}
		else {
			chunk = rb_str_new(wsgi_req->post_buffering_buf, wsgi_req->post_cl);
		}
		return chunk;
	}
	else if (RARRAY(args)->len > 0) {
		chunk_size = NUM2INT(RARRAY(args)->ptr[0]);
		//uwsgi_log("chunk reading of %d bytes\n", chunk_size ) ;
		if (wsgi_req->post_cl > (size_t) uwsgi.post_buffering_bufsize) {
			char *post_body = malloc( chunk_size ) ;
			if (post_body) {	
				len = fread( post_body, chunk_size, 1, wsgi_req->async_post );
				chunk = rb_str_new(post_body, chunk_size);
				free(post_body);
			}
			else {
				uwsgi_error("malloc()");
				return Qnil;
			}
		}
		else {	
			if (RARRAY(args)->len > 1) {
				rb_str_cat(RARRAY(args)->ptr[1], wsgi_req->post_buffering_buf+wsgi_req->buf_pos, chunk_size);
			}
			chunk = rb_str_new(wsgi_req->post_buffering_buf+wsgi_req->buf_pos, chunk_size);
			wsgi_req->buf_pos+=chunk_size;
		}

		return chunk;
	
	}

	return Qnil;
}

VALUE rb_uwsgi_io_rewind(VALUE obj, VALUE args) {

	struct wsgi_request *wsgi_req;
	Data_Get_Struct(obj, struct wsgi_request, wsgi_req);

	if (!wsgi_req->post_cl) {
		return Qnil;
	}
	
	if (wsgi_req->post_cl > (size_t) uwsgi.post_buffering_bufsize) {
		rewind(wsgi_req->async_post);
	}
	else {
		wsgi_req->buf_pos = 0;
	}
	
	return Qnil;
}

int uwsgi_rack_init(){

	struct http_status_codes *http_sc;

	// filling http status codes
        for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
                http_sc->message_size = strlen(http_sc->message);
        }

	ruby_init();
	ruby_script("uwsgi");
	ruby_init_loadpath();

	if (ur.rack) {
		rb_require("rubygems");	
		rb_funcall( rb_cObject, rb_intern("require"), 1, rb_str_new2("rack") );

		VALUE rack = rb_const_get(rb_cObject, rb_intern("Rack")) ;
		VALUE rackup = rb_funcall( rb_const_get(rack, rb_intern("Builder")), rb_intern("parse_file"), 1, rb_str_new2(ur.rack));
		if (TYPE(rackup) != T_ARRAY) {
			uwsgi_log("unable to parse %s file\n", ur.rack);
			exit(1);
		}

		if (RARRAY(rackup)->len < 1) {
			uwsgi_log("invalid rack config file: %s\n", ur.rack);
			exit(1);
		}

		ur.dispatcher = RARRAY(rackup)->ptr[0] ;

		if (ur.dispatcher == Qnil) {
			exit(1);
		}
		
	}
	else if (ur.rails) {
		if (chdir(ur.rails)) {
			uwsgi_error("chdir()");
			exit(1);
		}

		uwsgi_log("loading rails app %s\n", ur.rails);
		rb_require("config/environment");
		uwsgi_log("rails app %s ready\n", ur.rails);
		VALUE ac = rb_const_get(rb_cObject, rb_intern("ActionController")) ;

		ur.dispatcher = rb_funcall( rb_const_get(ac, rb_intern("Dispatcher")), rb_intern("new"), 0);

		if (ur.dispatcher == Qnil) {
			uwsgi_log("unable to load rails dispatcher\n");
			exit(1);
		}
	}

	rb_gc_register_address(&ur.dispatcher);

	ur.call = rb_intern("call");
	rb_gc_register_address(&ur.call);


	ur.rb_uwsgi_io_class = rb_define_class("Uwsgi_IO", rb_cObject);

	rb_gc_register_address(&ur.rb_uwsgi_io_class);
	
	rb_define_singleton_method(ur.rb_uwsgi_io_class, "new", rb_uwsgi_io_new, 1);
	rb_define_method(ur.rb_uwsgi_io_class, "initialize", rb_uwsgi_io_init, -1);
	rb_define_method(ur.rb_uwsgi_io_class, "gets", rb_uwsgi_io_gets, 0);
	rb_define_method(ur.rb_uwsgi_io_class, "each", rb_uwsgi_io_each, 0);
	rb_define_method(ur.rb_uwsgi_io_class, "read", rb_uwsgi_io_read, -2);
	rb_define_method(ur.rb_uwsgi_io_class, "rewind", rb_uwsgi_io_rewind, 0);

	//rb_gc_disable();

	return 0;

}

VALUE call_dispatch(VALUE env) {

	return rb_funcall(ur.dispatcher, ur.call, 1, env);

}

VALUE send_body(VALUE obj, VALUE fd) {

	size_t len;

	if (TYPE(obj) == T_STRING) {
		len = write( NUM2INT(fd), RSTRING(obj)->ptr, RSTRING(obj)->len);
	}
	else {
		uwsgi_log("UNMANAGED BODY TYPE %d\n", TYPE(obj));
	}

	return Qnil;
}

VALUE send_header(VALUE obj, VALUE fd) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	size_t len;
	
	if (TYPE(obj) == T_ARRAY) {
	
		if (RARRAY(obj)->len == 2) {
			VALUE hkey = rb_obj_as_string( RARRAY(obj)->ptr[0]);
			VALUE hval = rb_obj_as_string( RARRAY(obj)->ptr[1]);

			len = write( NUM2INT(fd), RSTRING(hkey)->ptr, RSTRING(hkey)->len);
			len = write( NUM2INT(fd), ": ", 2);

			len = write( NUM2INT(fd), RSTRING(hval)->ptr, RSTRING(hval)->len);
			len = write( NUM2INT(fd), "\r\n", 2);

			wsgi_req->header_cnt++;

			rb_gc_unregister_address(&hkey);
			rb_gc_unregister_address(&hval);
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

int uwsgi_rack_request(struct wsgi_request *wsgi_req) {

	int error;
	int i;

	struct http_status_codes *http_sc;

	/* Standard RACK request */
        if (!wsgi_req->uh.pktsize) {
                uwsgi_log("Invalid RACK request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                uwsgi_log("Invalid RACK request. skip.\n");
                return -1;
        }

        VALUE env = rb_hash_new();

        // fill ruby hash
        for(i=0;i<wsgi_req->var_cnt;i++) {

		// put the var only if it is not 0 size or required (rack requirement... very inefficient)
		if (wsgi_req->hvec[i+1].iov_len > 0 || 
					!uwsgi_strncmp("REQUEST_METHOD", 14, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len) ||
					!uwsgi_strncmp("SCRIPT_NAME", 11, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len) ||
					!uwsgi_strncmp("PATH_INFO", 10, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len) ||
					!uwsgi_strncmp("QUERY_STRING", 12, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len) ||
					!uwsgi_strncmp("SERVER_NAME", 11, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len) ||
					!uwsgi_strncmp("SERVER_PORT", 11, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len)
							) {
			rb_hash_aset(env, rb_str_new(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len),
					rb_str_new(wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len));
		}
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

	VALUE dws_wr = Data_Wrap_Struct(ur.rb_uwsgi_io_class, 0, 0, wsgi_req);
	rb_hash_aset(env, rb_str_new2("rack.input"), rb_funcall(ur.rb_uwsgi_io_class, rb_intern("new"), 1, dws_wr ));

	rb_hash_aset(env, rb_str_new2("rack.errors"), rb_funcall( rb_const_get(rb_cObject, rb_intern("IO")), rb_intern("new"), 2, INT2NUM(2), rb_str_new("w",1) ));

	
	VALUE ret = rb_protect( call_dispatch, env, &error);

	if (error) {
		uwsgi_ruby_exception();
		//return -1;
	}

	if (TYPE(ret) == T_ARRAY) {
		if (RARRAY(ret)->len != 3) {
			uwsgi_log("Invalid RACK response size: %d\n", RARRAY(ret)->len);
			return -1;
		}

		// manage Status


		VALUE status = rb_obj_as_string(RARRAY(ret)->ptr[0]);
		// get the status code

		wsgi_req->hvec[0].iov_base = "HTTP/1.1 ";
        	wsgi_req->hvec[0].iov_len = 9 ;

        	wsgi_req->hvec[1].iov_base = RSTRING(status)->ptr;
        	wsgi_req->hvec[1].iov_len = 3 ;

		wsgi_req->status = atoi(RSTRING(status)->ptr);

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

		if ( !(wsgi_req->response_size = writev(wsgi_req->poll.fd, wsgi_req->hvec, 5)) ) {
                	uwsgi_error("writev()");
        	}

		VALUE headers = RARRAY(ret)->ptr[1] ;
		if (rb_respond_to( headers, rb_intern("each") )) {
			rb_iterate( rb_each, headers, send_header, INT2NUM(wsgi_req->poll.fd)); 
		}

		if (write(wsgi_req->poll.fd, "\r\n", 2) != 2) {
			uwsgi_error("write()");
		}

		VALUE body = RARRAY(ret)->ptr[2] ;


		if (rb_respond_to( body, rb_intern("to_path") )) {
			VALUE sendfile_path = rb_funcall( body, rb_intern("to_path"), 0);
			wsgi_req->sendfile_fd = open(RSTRING_PTR(sendfile_path), O_RDONLY);
			wsgi_req->response_size = uwsgi_sendfile(wsgi_req);
			rb_gc_unregister_address(&sendfile_path);
			
		}
		else if (rb_respond_to( body, rb_intern("each") )) {
			rb_iterate( rb_each, body, send_body, INT2NUM(wsgi_req->poll.fd));
		}

		if (rb_respond_to( body, rb_intern("close") )) {
			rb_funcall( body, rb_intern("close"), 0);
		}

		/* unregister all the objects created */
		rb_gc_unregister_address(&status);
		rb_gc_unregister_address(&headers);
		rb_gc_unregister_address(&body);



		

	}

	rb_gc_unregister_address(&ret);

	rb_gc_unregister_address(&env);

	if (ur.gc_freq <= 1 || ur.cycles%ur.gc_freq == 0) {
		rb_gc();
	}

	ur.cycles++;

	//rb_gc_disable();

	return 0;
}


void uwsgi_rack_after_request(struct wsgi_request *wsgi_req) {

	if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
                log_request(wsgi_req);
}

int uwsgi_rack_manage_options(int i, char *optarg) {

	switch(i) {
		case LONG_ARGS_RAILS:
			ur.rails = optarg;
			return 1;
		case LONG_ARGS_RACK:
			ur.rack = optarg;
			return 1;
		case LONG_ARGS_RUBY_GC_FREQ:
			ur.gc_freq = atoi(optarg);
			return 1;
	}

	return 0;
}

struct uwsgi_plugin rack_plugin = {

        .name = "rack",
        .modifier1 = 7,
        .init = uwsgi_rack_init,
        .options = uwsgi_rack_options,
        .manage_opt = uwsgi_rack_manage_options,
        .request = uwsgi_rack_request,
        .after_request = uwsgi_rack_after_request,

};

