#include "uwsgi_rack.h"

extern struct uwsgi_server uwsgi;

struct uwsgi_rack ur;

struct option uwsgi_rack_options[] = {

        {"rails", required_argument, 0, LONG_ARGS_RAILS},
        {"rack", required_argument, 0, LONG_ARGS_RACK},
        {"ruby-gc-freq", required_argument, 0, LONG_ARGS_RUBY_GC_FREQ},

        {0, 0, 0, 0},

};

void uwsgi_ruby_exception(void) {

        VALUE lasterr = rb_gv_get("$!");
        VALUE message = rb_obj_as_string(lasterr);

        uwsgi_log("%s\n", RSTRING_PTR(message));
        if(!NIL_P(rb_errinfo())) {
                VALUE ary = rb_funcall(rb_errinfo(), rb_intern("backtrace"), 0);
                int i;
                for (i=0; i<RARRAY_LEN(ary); i++) {
                        uwsgi_log("%s\n", RSTRING_PTR(RARRAY_PTR(ary)[i]));
                }
        }
}




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

	if (wsgi_req->post_cl > (size_t) uwsgi.post_buffering) {
		//uwsgi_log("using file for http body storage %d\n", wsgi_req->post_cl);
		//RUBY_GVL_UNLOCK
		uwsgi_read_whole_body(wsgi_req, wsgi_req->post_buffering_buf, uwsgi.post_buffering_bufsize);
		//RUBY_GVL_LOCK
	}
	else {
		//RUBY_GVL_UNLOCK
		//uwsgi_log("using memory for http body storage %d\n", wsgi_req->post_cl);
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
		//RUBY_GVL_LOCK
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
	
	if (RARRAY_LEN(args) == 0) {
		//uwsgi_log("reading the whole post data\n" ) ;
		if (wsgi_req->post_cl > (size_t) uwsgi.post_buffering) {
			char *post_body = malloc(wsgi_req->post_cl);
			if (post_body) {
				//RUBY_GVL_UNLOCK
				len = fread( post_body, wsgi_req->post_cl, 1, wsgi_req->async_post);
				//RUBY_GVL_LOCK
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
	else if (RARRAY_LEN(args) > 0) {
		chunk_size = NUM2INT(RARRAY_PTR(args)[0]);
		//uwsgi_log("chunk reading of %d bytes (post_cl: %d bufsize: %d)\n", chunk_size, wsgi_req->post_cl, uwsgi.post_buffering_bufsize ) ;
		if (wsgi_req->post_cl > (size_t) uwsgi.post_buffering) {
			char *post_body = malloc( chunk_size ) ;
			if (post_body) {	
				//RUBY_GVL_UNLOCK
				len = fread( post_body, chunk_size, 1, wsgi_req->async_post );
				//uwsgi_log("read %d items\n", len);
				//RUBY_GVL_LOCK
				chunk = rb_str_new(post_body, chunk_size);
				free(post_body);
			}
			else {
				uwsgi_error("malloc()");
				return Qnil;
			}
		}
		else {	
			if (RARRAY_LEN(args) > 1) {
				rb_str_cat(RARRAY_PTR(args)[1], wsgi_req->post_buffering_buf+wsgi_req->buf_pos, chunk_size);
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

	if (wsgi_req->post_cl > (size_t) uwsgi.post_buffering) {
		//RUBY_GVL_LOCK
		rewind(wsgi_req->async_post);
		//RUBY_GVL_UNLOCK
	}
	else {
		wsgi_req->buf_pos = 0;
	}

	return Qnil;
}

#ifdef RUBY19
RUBY_GLOBAL_SETUP
#endif

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

VALUE init_rack_app(VALUE);

#ifdef RUBY19
VALUE uwsgi_ruby_fiber_yield() {
	return rb_fiber_yield(0, NULL);
}
#endif

VALUE uwsgi_ruby_suspend(VALUE *arg) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	uwsgi.schedule_to_main(wsgi_req);

	return Qtrue;
	
}

int uwsgi_rack_init(){

	struct http_status_codes *http_sc;
#ifdef RUBY19
	int argc = 2;
	char *sargv[] = { (char *) "uwsgi", (char *) "-e0" };
	char **argv = sargv;
#endif

	int error;

	// filling http status codes
        for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
                http_sc->message_size = (int) strlen(http_sc->message);
        }


#ifdef RUBY19
	ruby_sysinit(&argc, &argv);
	RUBY_INIT_STACK
	ruby_init();
	ruby_process_options(argc, argv);
#else

	ruby_init();
	ruby_init_loadpath();
#endif

	ruby_script("uwsgi");

#ifdef RUBY19
	uwsgi_register_loop( (char *) "fiber", fiber_loop);
#endif

	VALUE rb_uwsgi_embedded = rb_define_module("UWSGI");
	rb_define_module_function(rb_uwsgi_embedded, "suspend", uwsgi_ruby_suspend, 0);
#ifdef RUBY19
	rb_define_module_function(rb_uwsgi_embedded, "fiber_yield", uwsgi_ruby_fiber_yield, 0);
#endif


	if (ur.rack) {
		ur.dispatcher = rb_protect(init_rack_app, rb_str_new2(ur.rack), &error);
		if (error) {
                        uwsgi_ruby_exception();
                        exit(1);
                }
		if (ur.dispatcher == Qnil) {
			exit(1);
		}
		rb_gc_register_address(&ur.dispatcher);
	}
	else if (ur.rails) {
		if (chdir(ur.rails)) {
			uwsgi_error("chdir()");
			exit(1);
		}

		uwsgi_log("loading rails app %s\n", ur.rails);
		rb_protect( require_rails, 0, &error ) ;
		if (error) {
                	uwsgi_ruby_exception();
			exit(1);
                }
		uwsgi_log("rails app %s ready\n", ur.rails);
		VALUE ac = rb_const_get(rb_cObject, rb_intern("ActionController"));

		ur.dispatcher = rb_funcall( rb_const_get(ac, rb_intern("Dispatcher")), rb_intern("new"), 0);

		if (ur.dispatcher == Qnil) {
			uwsgi_log("unable to load rails dispatcher\n");
			exit(1);
		}
	}


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

#ifdef RUBY19
#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1) {
		rb_gc_disable();
	}
#endif
#endif

	return 0;

}

VALUE call_dispatch(VALUE env) {

	return rb_funcall(ur.dispatcher, ur.call, 1, env);

}

VALUE send_body(VALUE obj) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
	ssize_t len = 0;
	int fd = wsgi_req->poll.fd;

	//uwsgi_log("sending body\n");
	if (TYPE(obj) == T_STRING) {
		len = write( fd, RSTRING_PTR(obj), RSTRING_LEN(obj));
	}
	else {
		uwsgi_log("UNMANAGED BODY TYPE %d\n", TYPE(obj));
	}

	wsgi_req->response_size += len;

	return Qnil;
}

VALUE iterate_body(VALUE body) {

#ifdef RUBY19
	return rb_block_call(body, rb_intern("each"), 0, 0, send_body, 0);
#else
	return rb_iterate(rb_each, body, send_body, 0);
#endif

}

VALUE send_header(VALUE obj, VALUE headers) {

	struct wsgi_request *wsgi_req = current_wsgi_req();

	size_t len;
	int fd = wsgi_req->poll.fd;
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
		goto clear2;
	}

	//uwsgi_log("header: %.*s: %.*s\n", RSTRING_LEN(hkey), RSTRING_PTR(hkey), RSTRING_LEN(hval), RSTRING_PTR(hval));

	len = write( fd, RSTRING_PTR(hkey), RSTRING_LEN(hkey));
	wsgi_req->headers_size += len;
	len = write( fd, ": ", 2);
	wsgi_req->headers_size += len;

	char *header_value = RSTRING_PTR(hval);
	int header_value_len = RSTRING_LEN(hval);

	char *header_value_splitted = memchr(header_value, '\n', header_value_len);

	if (!header_value_splitted) {
		len = write( fd, header_value, header_value_len);
		wsgi_req->headers_size += len;
		len = write( fd, "\r\n", 2);
		wsgi_req->headers_size += len;
		wsgi_req->header_cnt++;
	}
	else {
		header_value_splitted[0] = 0;
		len = write( fd, header_value, header_value_splitted-header_value);
		wsgi_req->headers_size += len;
		len = write( fd, "\r\n", 2);
                wsgi_req->headers_size += len;
		wsgi_req->header_cnt++;

		header_value = header_value_splitted+1;
		header_value_len -= header_value_splitted-header_value;

		while(header_value_len && (header_value_splitted = memchr(header_value, '\n', header_value_len))) {
			header_value_splitted[0] = 0;

			len = write( fd, RSTRING_PTR(hkey), RSTRING_LEN(hkey));
        		wsgi_req->headers_size += len;
        		len = write( fd, ": ", 2);
        		wsgi_req->headers_size += len;

			len = write( fd, header_value, header_value_splitted-header_value);
			wsgi_req->headers_size += len;
			len = write( fd, "\r\n", 2);
                	wsgi_req->headers_size += len;		
                	wsgi_req->header_cnt++;

                	header_value = header_value_splitted+1;
                	header_value_len -= header_value_splitted-header_value;	
		}
	}


clear2:
	rb_gc_unregister_address(&hkey);
	rb_gc_unregister_address(&hval);

clear:

	return Qnil;
}

int uwsgi_rack_request(struct wsgi_request *wsgi_req) {

	int error;
	int i;
	VALUE env, ret, status, headers, body;

	struct http_status_codes *http_sc;

	/* Standard RACK request */
        if (!wsgi_req->uh.pktsize) {
                uwsgi_log("Invalid RACK request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                if (wsgi_req->status != 200) uwsgi_log("Invalid RACK request. skip.\n");
                return -1;
        }


	//RUBY_GVL_LOCK

        env = rb_hash_new();

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


	if (ur.unprotected) {
		ret = rb_funcall(ur.dispatcher, ur.call, 1, env);
	}
	else {
		ret = rb_protect( call_dispatch, env, &error);
	}
	
	if (error) {
		uwsgi_ruby_exception();
		//return -1;
	}

	if (TYPE(ret) == T_ARRAY) {
		if (RARRAY_LEN(ret) != 3) {
			uwsgi_log("Invalid RACK response size: %d\n", RARRAY_LEN(ret));
			return -1;
		}

		// manage Status

		status = rb_obj_as_string(RARRAY_PTR(ret)[0]);
		// get the status code

		wsgi_req->hvec[0].iov_base = wsgi_req->protocol;
        	wsgi_req->hvec[0].iov_len = wsgi_req->protocol_len ;

		wsgi_req->hvec[1].iov_base = (char *) " ";
        	wsgi_req->hvec[1].iov_len = 1 ;

        	wsgi_req->hvec[2].iov_base = RSTRING_PTR(status);
        	wsgi_req->hvec[2].iov_len = 3 ;

		wsgi_req->status = atoi(RSTRING_PTR(status));

        	wsgi_req->hvec[3].iov_base = (char *) " ";
        	wsgi_req->hvec[3].iov_len = 1 ;

        	wsgi_req->hvec[4].iov_len = 0 ;

        	for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
                	if (!strncmp(http_sc->key, RSTRING_PTR(status), 3)) {
                        	wsgi_req->hvec[4].iov_base = (char *) http_sc->message ;
                        	wsgi_req->hvec[4].iov_len = http_sc->message_size ;
                        	break;
                	}
        	}

        	wsgi_req->hvec[5].iov_base = (char *) "\r\n";
        	wsgi_req->hvec[5].iov_len = 2 ;

		//RUBY_GVL_UNLOCK
		if ( !(wsgi_req->headers_size = writev(wsgi_req->poll.fd, wsgi_req->hvec, 6)) ) {
                	uwsgi_error("writev()");
        	}
		//RUBY_GVL_LOCK

		headers = RARRAY_PTR(ret)[1] ;
		if (rb_respond_to( headers, rb_intern("each") )) {
			rb_iterate( rb_each, headers, send_header, headers); 
		}

		//RUBY_GVL_UNLOCK
		if (write(wsgi_req->poll.fd, "\r\n", 2) != 2) {
			uwsgi_error("write()");
		}
		//RUBY_GVL_LOCK

		body = RARRAY_PTR(ret)[2] ;

		if (rb_respond_to( body, rb_intern("to_path") )) {
			VALUE sendfile_path = rb_funcall( body, rb_intern("to_path"), 0);
			wsgi_req->sendfile_fd = open(RSTRING_PTR(sendfile_path), O_RDONLY);
			//RUBY_GVL_UNLOCK
			wsgi_req->response_size = uwsgi_sendfile(wsgi_req);
			if (wsgi_req->response_size > 0) {
				while(wsgi_req->response_size < wsgi_req->sendfile_fd_size) {
					uwsgi_log("sendfile_fd_size = %d\n", wsgi_req->sendfile_fd_size);
					wsgi_req->response_size += uwsgi_sendfile(wsgi_req);
				}
			}
			//RUBY_GVL_LOCK;
			rb_gc_unregister_address(&sendfile_path);

		}
		else if (rb_respond_to( body, rb_intern("each") )) {
			if (ur.unprotected) {
#ifdef RUBY19
        			rb_block_call(body, rb_intern("each"), 0, 0, send_body, 0);
#else
        			rb_iterate(rb_each, body, send_body, 0);
#endif
			}
			else {
				rb_protect( iterate_body, body, &error);
				if (error) {
					uwsgi_ruby_exception();
				}
			}
		}

		if (rb_respond_to( body, rb_intern("close") )) {
			//uwsgi_log("calling close\n");
			rb_funcall( body, rb_intern("close"), 0);
		}

//fine:

		/* unregister all the objects created */
	
		rb_gc_unregister_address(&status);
		rb_gc_unregister_address(&headers);
		rb_gc_unregister_address(&body);

	}


	rb_gc_unregister_address(&ret);

	rb_gc_unregister_address(&env);

	if (ur.gc_freq <= 1 || ur.cycles%ur.gc_freq == 0) {
#ifdef RUBY19
#ifdef UWSGI_THREADING
		if (uwsgi.threads > 1) {
			if (wsgi_req->async_id == 0) {
				rb_gc_enable();
				rb_gc();
				rb_gc_disable();
			}
		}
		else {
#endif
#endif
			//uwsgi_log("calling ruby GC\n");
			rb_gc();
#ifdef RUBY19
#ifdef UWSGI_THREADING
		}
#endif
#endif
	}

	//RUBY_GVL_UNLOCK

	ur.cycles++;



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

void uwsgi_rack_suspend(struct wsgi_request *wsgi_req) {

	uwsgi_log("SUSPENDING RUBY\n");
}

void uwsgi_rack_resume(struct wsgi_request *wsgi_req) {

	uwsgi_log("RESUMING RUBY\n");
}

void uwsgi_rack_enable_threads(void) {

	pthread_mutex_init(&ur.gvl, NULL);
}

void uwsgi_rack_init_thread(int core_id) {
	// thread initialization
}

VALUE init_rack_app( VALUE script ) {

	int error;

#ifndef RUBY19
	rb_require("rubygems");
#endif
        rb_protect( require_rack, 0, &error ) ;
        if (error) {
        	uwsgi_ruby_exception();
		return Qnil;
        }

        VALUE rack = rb_const_get(rb_cObject, rb_intern("Rack"));
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

int uwsgi_rack_xml(char *node, char *content) {

	int error;

	if (!strcmp("rack", node)) {
		ur.dispatcher = rb_protect(init_rack_app, rb_str_new2(content), &error);
		if (ur.dispatcher != Qnil) {
			rb_gc_register_address(&ur.dispatcher);
			uwsgi_log("Rack application ready\n");
			return 1;
		}
        }

	return 0;
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

/*
int uwsgi_rack_mount_app(char *mountpoint, char *app) {

	
        if ( !strcmp(what+strlen(what)-3, ".ru") || !strcmp(what+strlen(what)-3, ".rb")) {
                return = uwsgi_rack_load(mountpoint, what);
        }

        return -1;
}
*/

struct uwsgi_plugin rack_plugin = {

	.name = "rack",
	.modifier1 = 7,
	.init = uwsgi_rack_init,
	.options = uwsgi_rack_options,
	.manage_opt = uwsgi_rack_manage_options,
	.request = uwsgi_rack_request,
	.after_request = uwsgi_rack_after_request,

	//.mount_app = uwsgi_rack_mount_app,
	.manage_xml = uwsgi_rack_xml,

	.magic = uwsgi_rack_magic,

	.suspend = uwsgi_rack_suspend,
	.resume = uwsgi_rack_resume,
#ifdef RUBY19
#ifdef UWSGI_THREADING
	.enable_threads = uwsgi_rack_enable_threads,
	.init_thread = uwsgi_rack_init_thread,
#endif
#endif
};

