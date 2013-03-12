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

static int uwsgi_ring_request_header_add(jobject hm, char *key, size_t keylen, char *value, size_t vallen) {
	size_t i;
	char *lkey = uwsgi_malloc(keylen);
	char *ptr = lkey;
	for(i=0;i<keylen;i++) {
		if (key[i] == '_') {
			*ptr++= '-';
		}
		else {
			*ptr++= tolower((int) key[i]);
		}
	}

	jobject j_key = uwsgi_jvm_str(lkey, keylen);
	free(lkey);
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

static int uwsgi_ring_request_item_add_obj(jobject hm, char *key, size_t keylen, jobject o) {
        jobject j_key = uwsgi_ring_keyword(key, keylen);
        if (!j_key) return -1;

        int ret = uwsgi_jvm_hashmap_put(hm, j_key, o);
        uwsgi_jvm_local_unref(j_key);
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
	char status_str[11];
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

	// *** REQUEST GENERATION ***

	if (uwsgi_ring_request_item_add_keyword(hm, "request-method", 14, wsgi_req->method, wsgi_req->method_len)) goto end;
	if (uwsgi_ring_request_item_add(hm, "uri", 3, wsgi_req->path_info, wsgi_req->path_info_len)) goto end;
	if (uwsgi_ring_request_item_add(hm, "server-name", 11, wsgi_req->host, wsgi_req->host_len)) goto end;

	// server-port is required !!!
	uint16_t server_port_len = 0;
	char *server_port = uwsgi_get_var(wsgi_req, "SERVER_PORT", 11, &server_port_len);
	if (!server_port) goto end;

	if (uwsgi_ring_request_item_add_num(hm, "server-port", 11, uwsgi_str_num(server_port, server_port_len))) goto end;

	if (wsgi_req->scheme_len > 0) {
		if (uwsgi_ring_request_item_add_keyword(hm, "scheme", 6, wsgi_req->scheme, wsgi_req->scheme_len)) goto end;
	}
	else {
		if (uwsgi_ring_request_item_add_keyword(hm, "scheme", 6, "http", 4)) goto end;
	}

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

	// generate :headers
	jobject req_headers = uwsgi_jvm_hashmap();
	if (!req_headers) goto end;

	int i;
	for(i=0;i<wsgi_req->var_cnt;i++) {
		char *hk = wsgi_req->hvec[i].iov_base;
		uint16_t hk_l = wsgi_req->hvec[i].iov_len;
		char *hv = wsgi_req->hvec[i+1].iov_base;
                uint16_t hv_l = wsgi_req->hvec[i+1].iov_len;
		if (!uwsgi_starts_with(hk, hk_l, "HTTP_", 5)) {
			if (uwsgi_ring_request_header_add(req_headers,hk+5,hk_l-5, hv, hv_l)) goto hend;
		}
		else if (!uwsgi_strncmp(hk, hk_l, "CONTENT_TYPE", 12)) {
			if (uwsgi_ring_request_header_add(req_headers,hk,hk_l, hv, hv_l)) goto hend;
		}
		else if (!uwsgi_strncmp(hk, hk_l, "CONTENT_LENGTH", 14)) {
			if (uwsgi_ring_request_header_add(req_headers, hk,hk_l, hv, hv_l)) goto hend;
		}
		i++;
	}

	jobject h_empty_request = uwsgi_ring_associative();
	if (!h_empty_request) goto hend;

	// convert the req_headers HashMap to Associative
        jobject clj_req_headers = uwsgi_ring_invoke2(uring.into, h_empty_request, req_headers);
	if (!clj_req_headers) {
		uwsgi_jvm_local_unref(h_empty_request);
		goto hend;
	}
	uwsgi_jvm_local_unref(h_empty_request);

	// add :headers
	if (uwsgi_ring_request_item_add_obj(hm, "headers", 7, clj_req_headers)) {
		uwsgi_jvm_local_unref(clj_req_headers);
hend:
		uwsgi_jvm_local_unref(req_headers);
		goto end;
	}
	uwsgi_jvm_local_unref(clj_req_headers);
	uwsgi_jvm_local_unref(req_headers);

	// add :body input stream
	if (uwsgi_ring_request_item_add_body(hm, "body", 4)) goto end;

	// *** END OF REQUEST GENERATION ***

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

	if (uwsgi_jvm_iterator_to_response_headers(wsgi_req, entries)) {
		goto end;
	}

	r_body = uwsgi_ring_response_get(response, "body", 4);
        if (!r_body) goto end;

	if (uwsgi_jvm_object_to_response_body(wsgi_req, r_body)) {
		uwsgi_log("unsupported clojure/ring body type\n");
	}
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
	char *colon = strchr(namespace, '/');
	if (!colon) {
		colon = strchr(namespace, ':');
		if (!colon) {
			uwsgi_log("invalid ring application namespace/handler\n");
			exit(1);
		}
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
