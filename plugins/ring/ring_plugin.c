#include <jvm.h>

/*

	Clojure/ring JVM handler

	to run a ring app you need to load the clojure jar, a clojure script and specify a namspace:handler app

	./uwsgi --http :9090 --http-modifier1 8 --http-modifier2 1 --jvm-classpath clojuretest/lib/clojure-1.3.0.jar --ring-load clojuretest/src/clojuretest/core.clj --ring-app clojuretest.core:handler

	TODO
		app mountpoints
		check if loading compiled classes works

*/

#define UWSGI_JVM_REQUEST_HANDLER_RING	1

extern struct uwsgi_jvm ujvm;

struct uwsgi_ring {
	struct uwsgi_string_list *scripts;
	char *app;
	jobject handler;
	jobject keyword;
	jobject into;
	// invoke with 1 arg
	jmethodID invoke1;
	// invoke with 2 args
	jmethodID invoke2;

	jclass Associative;
	jclass PersistentArrayMap;

} uring;

static struct uwsgi_option uwsgi_ring_options[] = {
        {"ring-load", required_argument, 0, "load the specified clojure script", uwsgi_opt_add_string_list, &uring.scripts, 0},
        {"clojure-load", required_argument, 0, "load the specified clojure script", uwsgi_opt_add_string_list, &uring.scripts, 0},
        {"ring-app", required_argument, 0, "map the specified ring application (syntax namespace:function)", uwsgi_opt_set_str, &uring.app, 0},
        {0, 0, 0, 0},
};

static jobject uwsgi_ring_invoke1(jobject o, jobject arg1) {
	return uwsgi_jvm_call_object(o, uring.invoke1, arg1);
}

static jobject uwsgi_ring_invoke2(jobject o, jobject arg1, jobject arg2) {
	return uwsgi_jvm_call_object(o, uring.invoke2, arg1, arg2);
}

// here we create a PersistentArrayMap empty object (we use that for clojure "into")
static jobject uwsgi_ring_associative() {
        // optimization
        static jmethodID mid = 0;

        if (!mid) {
                mid = uwsgi_jvm_get_method_id(uring.PersistentArrayMap, "<init>", "()V");
                if (!mid) return NULL;
        }

        jobject o = (*ujvm_env)->NewObject(ujvm_env, uring.PersistentArrayMap, mid);
        if (uwsgi_jvm_exception()) {
                return NULL;
        }
        return o;
}

// create a new clojure keyword
static jobject uwsgi_ring_keyword(char *key, size_t len) {
	jobject j_key = uwsgi_jvm_str(key, len);
	if (!j_key) return NULL;
	jobject kw = uwsgi_ring_invoke1(uring.keyword, j_key);
	uwsgi_jvm_local_unref(j_key);
	return kw;
}

// add a string item to the ring request map
static int uwsgi_ring_request_item_add(jobject hm, char *key, size_t keylen, char *value, size_t vallen) {
	jobject j_key = uwsgi_ring_keyword(key, keylen);
	if (!j_key) return -1;

	jobject j_value = uwsgi_jvm_str(value, vallen);
	if (!j_value) {
		uwsgi_jvm_local_unref(j_key);
		return -1;
	}

	int ret = uwsgi_jvm_hashmap_put(hm, j_key, j_value);
	uwsgi_jvm_local_unref(j_key);
	uwsgi_jvm_local_unref(j_value);
	return ret;	
}

static int uwsgi_ring_request_item_add_body(jobject hm, char *key, size_t keylen) {
        jobject j_key = uwsgi_ring_keyword(key, keylen);
        if (!j_key) return -1;

        jobject j_value = uwsgi_jvm_request_body_input_stream();
        if (!j_value) {
                uwsgi_jvm_local_unref(j_key);
                return -1;
        }

        int ret = uwsgi_jvm_hashmap_put(hm, j_key, j_value);
        uwsgi_jvm_local_unref(j_key);
        uwsgi_jvm_local_unref(j_value);
        return ret;
}


// add a keyword item to the ring request map
static int uwsgi_ring_request_item_add_keyword(jobject hm, char *key, size_t keylen, char *value, size_t vallen) {
        jobject j_key = uwsgi_ring_keyword(key, keylen);
        if (!j_key) return -1;
	
	char *lc_value = uwsgi_malloc(vallen);
	char *ptr = lc_value;
	size_t i;
	for(i=0;i<vallen;i++) {
		*ptr++= tolower((int) value[i]);
	}

        jobject j_value = uwsgi_ring_keyword(lc_value, vallen);
	free(lc_value);
        if (!j_value) {
                uwsgi_jvm_local_unref(j_key);
                return -1;
        }

        int ret = uwsgi_jvm_hashmap_put(hm, j_key, j_value);
        uwsgi_jvm_local_unref(j_key);
        uwsgi_jvm_local_unref(j_value);
        return ret;
}

static int uwsgi_ring_request_item_add_num(jobject hm, char *key, size_t keylen, long num) {
        jobject j_key = uwsgi_ring_keyword(key, keylen);
        if (!j_key) return -1;

	jobject j_value = uwsgi_jvm_num(num);
        if (!j_value) {
                uwsgi_jvm_local_unref(j_key);
                return -1;
        }

        int ret = uwsgi_jvm_hashmap_put(hm, j_key, j_value);
        uwsgi_jvm_local_unref(j_key);
        uwsgi_jvm_local_unref(j_value);
        return ret;
}



// get the iterator from an Associative object
static jobject uwsgi_ring_Associative_iterator(jobject o) {
	jclass c = uwsgi_jvm_class_from_object(o);
	if (!c) return NULL;
	jmethodID mid = uwsgi_jvm_get_method_id(c, "entrySet", "()Ljava/util/Set;");
	uwsgi_jvm_local_unref(c);
	if (!mid) return NULL;
	jobject set = uwsgi_jvm_call_object(o, mid);
	if (!set) return NULL;
	jobject iter = uwsgi_jvm_iterator(set);
	uwsgi_jvm_local_unref(set);
	return iter;
}

static jobject uwsgi_ring_Associative_get(jobject o, jobject key) {
	jclass c = uwsgi_jvm_class_from_object(o);
        if (!c) return NULL;
        jmethodID mid = uwsgi_jvm_get_method_id(c, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
        uwsgi_jvm_local_unref(c);
        if (!mid) return NULL;
        return uwsgi_jvm_call_object(o, mid, key);
}

// get an item from the ring response map
static jobject uwsgi_ring_response_get(jobject r, char *name, size_t len) {
	jobject j_key = uwsgi_ring_keyword(name, len);
        if (!j_key) return NULL;

	jobject item = uwsgi_ring_Associative_get(r, j_key);
	uwsgi_jvm_local_unref(j_key);
	return item;
}

// the request handler
static int uwsgi_ring_request(struct wsgi_request *wsgi_req) {
	char status_str[1];
	jobject request = NULL;
	jobject response = NULL;
	jobject entries = NULL;
	jobject r_status = NULL;
	jobject r_headers = NULL;
	jobject r_body = NULL;

	jobject hm = uwsgi_jvm_hashmap();
	if (!hm) return -1;

	jobject empty_request = uwsgi_ring_associative();
	if (!empty_request) {
		uwsgi_jvm_local_unref(hm);
		return -1;
	}

	if (uwsgi_ring_request_item_add_keyword(hm, "request-method", 14, wsgi_req->method, wsgi_req->method_len)) goto end;
	if (uwsgi_ring_request_item_add(hm, "uri", 3, wsgi_req->uri, wsgi_req->uri_len)) goto end;
	if (uwsgi_ring_request_item_add(hm, "server-name", 11, wsgi_req->host, wsgi_req->host_len)) goto end;
	if (uwsgi_ring_request_item_add(hm, "remote-addr", 11, wsgi_req->remote_addr, wsgi_req->remote_addr_len)) goto end;
	if (wsgi_req->query_string_len > 0) {
		if (uwsgi_ring_request_item_add(hm, "query-string", 12, wsgi_req->query_string, wsgi_req->query_string_len)) goto end;
	}
	if (wsgi_req->content_type_len) {
		if (uwsgi_ring_request_item_add(hm, "content-type", 12, wsgi_req->content_type, wsgi_req->content_type_len)) goto end;
	}

	if (wsgi_req->post_cl > 0) {
		if (uwsgi_ring_request_item_add_num(hm, "content-length", 14, wsgi_req->post_cl)) goto end;
	}

	// add :body input stream
	if (uwsgi_ring_request_item_add_body(hm, "body", 4)) goto end;

	// convert the HashMap to Associative
	request = uwsgi_ring_invoke2(uring.into, empty_request, hm);
	if (!request) goto end;

	response = uwsgi_ring_invoke1(uring.handler, request);
	if (!response) goto end;

	if (!uwsgi_jvm_object_is_instance(response, uring.Associative)) {
		uwsgi_log("invalid ring response type, need to implement: clojure.lang.Associative\n");
		goto end;
	}
	
	r_status = uwsgi_ring_response_get(response, "status", 6);
	if (!r_status) goto end;

	if (!uwsgi_jvm_object_is_instance(r_status, ujvm.long_class) && !uwsgi_jvm_object_is_instance(r_status, ujvm.int_class)) {
		uwsgi_log("invalid ring response status type, must be: java.lang.Long\n");
		goto end;
	}


	long n_status = uwsgi_jvm_number2c(r_status);
	if (n_status == -1) goto end;

	if (uwsgi_num2str2(n_status, status_str) != 3) {
		goto end;
	}

	if (uwsgi_response_prepare_headers(wsgi_req, status_str, 3)) goto end;

	r_headers = uwsgi_ring_response_get(response, "headers", 7);
	if (!r_headers) goto end;

	if (!uwsgi_jvm_object_is_instance(r_headers, uring.Associative)) {
		uwsgi_log("invalid ring response headers type, need to implement: clojure.lang.Associative\n");
		goto end;
	}

	entries = uwsgi_ring_Associative_iterator(r_headers);
	if (!entries) goto end;

	int error = 0;
	while(uwsgi_jvm_iterator_hasNext(entries)) {
		jobject hh = NULL, h_key = NULL, h_value = NULL;

		hh = uwsgi_jvm_iterator_next(entries);
		if (!hh) { error = 1 ; goto clear;}
		h_key = uwsgi_jvm_getKey(hh);
		if (!h_key) { error = 1 ; goto clear;}
		h_value = uwsgi_jvm_getValue(hh);
		if (!h_value) { error = 1 ; goto clear;}

		if (!uwsgi_jvm_object_is_instance(h_key, ujvm.str_class)) {
			uwsgi_log("headers key must be java/lang/String !!!\n");
			error = 1 ; goto clear;
		}

		// check for string
		if (uwsgi_jvm_object_is_instance(h_value, ujvm.str_class)) {
			char *c_h_key = uwsgi_jvm_str2c(h_key);
			uint16_t c_h_keylen = uwsgi_jvm_strlen(h_key);
			char *c_h_value = uwsgi_jvm_str2c(h_value);
                        uint16_t c_h_vallen = uwsgi_jvm_strlen(h_value);
			int ret = uwsgi_response_add_header(wsgi_req, c_h_key, c_h_keylen, c_h_value, c_h_vallen);
			uwsgi_jvm_release_chars(h_key, c_h_key);
			uwsgi_jvm_release_chars(h_value, c_h_value);
			if (ret) error = 1;
			goto clear;
		}

		// check for collection
		jobject values = uwsgi_jvm_auto_iterator(h_value);
		if (values) {
			while(uwsgi_jvm_iterator_hasNext(values)) {
				jobject hh_value = uwsgi_jvm_iterator_next(values);
				if (!uwsgi_jvm_object_is_instance(hh_value, ujvm.str_class)) {
                        		uwsgi_log("headers value must be java/lang/String !!!\n");
					uwsgi_jvm_local_unref(hh_value);
					uwsgi_jvm_local_unref(values);
					error = 1 ; goto clear;
                		}
				char *c_h_key = uwsgi_jvm_str2c(h_key);
				uint16_t c_h_keylen = uwsgi_jvm_strlen(h_key);
				char *c_h_value = uwsgi_jvm_str2c(hh_value);
				uint16_t c_h_vallen = uwsgi_jvm_strlen(hh_value);
				int ret = uwsgi_response_add_header(wsgi_req, c_h_key, c_h_keylen, c_h_value, c_h_vallen);
				uwsgi_jvm_release_chars(h_key, c_h_key);
				uwsgi_jvm_release_chars(hh_value, c_h_value);
				uwsgi_jvm_local_unref(hh_value);
				if (ret) { uwsgi_jvm_local_unref(values); error = 1 ; goto clear;}
			}
			uwsgi_jvm_local_unref(values);
			goto clear;
		}
		uwsgi_log("unsupported header value !!! (must be java/lang/String or collection/seq)\n");
		error = 1;
clear:
		if (h_value)
		uwsgi_jvm_local_unref(h_value);
		if (h_key)
		uwsgi_jvm_local_unref(h_key);
		if (hh)
		uwsgi_jvm_local_unref(hh);
		if (error) goto end;
	}

	r_body = uwsgi_ring_response_get(response, "body", 4);
        if (!r_body) goto end;


        if (uwsgi_jvm_object_is_instance(r_body, ujvm.str_class)) {
		char *c_body = uwsgi_jvm_str2c(r_body);
		size_t c_body_len = uwsgi_jvm_strlen(r_body);
		uwsgi_response_write_body_do(wsgi_req, c_body, c_body_len);
		uwsgi_jvm_release_chars(r_body, c_body);
		goto end;
        }

	jobject chunks = uwsgi_jvm_auto_iterator(r_body);
	if (chunks) {
		while(uwsgi_jvm_iterator_hasNext(chunks)) {
			jobject chunk = uwsgi_jvm_iterator_next(chunks);
			if (!chunk) goto done;
			if (!uwsgi_jvm_object_is_instance(chunk, ujvm.str_class)) {
                        	uwsgi_log("body iSeq item must be java/lang/String !!!\n");
				uwsgi_jvm_local_unref(chunk);
                                goto done;
                        }
			char *c_body = uwsgi_jvm_str2c(chunk);
                	size_t c_body_len = uwsgi_jvm_strlen(chunk);
                	int ret = uwsgi_response_write_body_do(wsgi_req, c_body, c_body_len);
                	uwsgi_jvm_release_chars(chunk, c_body);
			uwsgi_jvm_local_unref(chunk);
			if (ret) goto done;
		}
done:
		uwsgi_jvm_local_unref(chunks);
		goto end;
	}

	if (uwsgi_jvm_object_is_instance(r_body, ujvm.file_class)) {
		jobject j_filename = uwsgi_jvm_filename(r_body);
		if (!j_filename) goto end;
		char *c_filename = uwsgi_jvm_str2c(j_filename);
		int fd = open(c_filename, O_RDONLY);
		if (fd < 0) {
			uwsgi_error("clojure/ring->open()");
			goto done2;
		}
		uwsgi_response_sendfile_do(wsgi_req, fd, 0, 0);
done2:
		uwsgi_jvm_release_chars(j_filename, c_filename);
		uwsgi_jvm_local_unref(j_filename);
		goto end;
	}

	if (uwsgi_jvm_object_is_instance(r_body, ujvm.input_stream_class)) {
		uwsgi_jvm_consume_input_stream(wsgi_req, 8192, r_body);
		goto end;
	}

	uwsgi_log("unsupported clojure/ring body type\n");
end:
	// destroy the request map and the response
	uwsgi_jvm_local_unref(hm);
	uwsgi_jvm_local_unref(empty_request);
	if (request) {
		uwsgi_jvm_local_unref(request);
	}
	if (entries) {
		uwsgi_jvm_local_unref(entries);
	}
	if (r_status) {
		uwsgi_jvm_local_unref(r_status);
	}
	if (r_headers) {
		uwsgi_jvm_local_unref(r_headers);
	}
	if (r_body) {
		uwsgi_jvm_local_unref(r_body);
	}
	if (response) {
		uwsgi_jvm_local_unref(response);
	}
	return UWSGI_OK;
}

static int uwsgi_ring_setup() {
	uwsgi_log("loading clojure environment...\n");

	jclass clojure = uwsgi_jvm_class("clojure/lang/RT");
	if (!clojure) {
		exit(1);
	}

	jclass clojure_var_class = uwsgi_jvm_class("clojure/lang/Var");
	if (!clojure_var_class) {
		exit(1);
	}

	uring.Associative = uwsgi_jvm_class("clojure/lang/Associative");
        if (!uring.Associative) {
                exit(1);
        }

	// we use that for allocating the empty associative passed to "into"
	uring.PersistentArrayMap = uwsgi_jvm_class("clojure/lang/PersistentArrayMap");
        if (!uring.PersistentArrayMap) {
                exit(1);
        }

	jmethodID clojure_loadresourcescript = uwsgi_jvm_get_static_method_id(clojure, "loadResourceScript", "(Ljava/lang/String;)V");
	if (!clojure_loadresourcescript) {
		exit(1);
	}

	struct uwsgi_string_list *usl = uring.scripts;
	while(usl) {
		if (uwsgi_jvm_call_static(clojure, clojure_loadresourcescript, uwsgi_jvm_str(usl->value, 0))) {
			exit(1);	
		}
		usl = usl->next;
	}

	jmethodID clojure_var = uwsgi_jvm_get_static_method_id(clojure, "var", "(Ljava/lang/String;Ljava/lang/String;)Lclojure/lang/Var;");
	if (!clojure_var) {
		exit(1);
	}

	uring.keyword = uwsgi_jvm_call_object_static(clojure, clojure_var, uwsgi_jvm_str("clojure.core", 0), uwsgi_jvm_str("keyword", 0));
	if (!uring.keyword) {
		exit(1);
	}

	uring.into = uwsgi_jvm_call_object_static(clojure, clojure_var, uwsgi_jvm_str("clojure.core", 0), uwsgi_jvm_str("into", 0));
	if (!uring.into) {
		exit(1);
	}

	char *namespace = uwsgi_str(uring.app);
	char *colon = strchr(namespace, ':');
	if (!colon) {
		uwsgi_log("invalid ring application namespace/handler\n");
		exit(1);
	}
	*colon = 0;
	uring.handler = uwsgi_jvm_call_object_static(clojure, clojure_var, uwsgi_jvm_str(namespace, 0), uwsgi_jvm_str(colon+1, 0));
	if (!uring.handler) {
		exit(1);
	} 

	uring.invoke1 = uwsgi_jvm_get_method_id(clojure_var_class, "invoke", "(Ljava/lang/Object;)Ljava/lang/Object;");
	if (!uring.invoke1) {
		exit(1);
	}

	uring.invoke2 = uwsgi_jvm_get_method_id(clojure_var_class, "invoke", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
	if (!uring.invoke2) {
		exit(1);
	}

	uwsgi_log("clojure/ring app loaded\n");
	return 0;
}

static int uwsgi_ring_init() {
	
	if (!uring.app) return 0;

	if (uwsgi_jvm_register_request_handler(UWSGI_JVM_REQUEST_HANDLER_RING, uwsgi_ring_setup, uwsgi_ring_request)) {
		exit(1);
	}

	return 0;
}

struct uwsgi_plugin ring_plugin = {
	.name = "ring",
	.options = uwsgi_ring_options,
	.init = uwsgi_ring_init,
};
