#include <jvm.h>

#define UWSGI_JVM_REQUEST_HANDLER_RING	1

struct uwsgi_ring {
	char *app;
	jobject handler;
	jobject keyword;
	// invoke with 1 arg
	jmethodID invoke1;
	// invoke with 2 args
	jmethodID invoke2;

	jclass PersistentArrayMap;
	jmethodID PersistentArrayMap_get;
	jmethodID PersistentArrayMap_entrySet;
} uring;

static struct uwsgi_option uwsgi_ring_options[] = {
        {"ring-app", required_argument, 0, "load the specified clojure/ring application", uwsgi_opt_set_str, &uring.app, 0},
        {0, 0, 0, 0},
};

static jobject uwsgi_ring_invoke1(jobject o, jobject arg1) {
	return uwsgi_jvm_call_object(o, uring.invoke1, arg1);
}

static jobject uwsgi_ring_keyword(char *key, size_t len) {
	jobject j_key = uwsgi_jvm_str(key, len);
	char *cn = uwsgi_jvm_str2c( uwsgi_jvm_object_class_name(j_key) );
	uwsgi_log("response type = %s\n", cn);
	if (!j_key) return NULL;
	return uwsgi_ring_invoke1(uring.keyword, j_key);
}

static int uwsgi_ring_request_item_add(jobject hm, char *key, size_t keylen, char *value, size_t vallen) {
	jobject j_key = uwsgi_ring_keyword(key, keylen);
	if (!j_key) return -1;

	jobject j_value = uwsgi_jvm_str(value, vallen);
	if (!j_value) return -1;

	return uwsgi_jvm_hashmap_put(hm, j_key, j_value);
}

static jobject uwsgi_ring_PersistentArrayMap_get(jobject pam, jobject key) {
	return uwsgi_jvm_call_object(pam, uring.PersistentArrayMap_get, key);
}

static jobject uwsgi_ring_PersistentArrayMap_iterator(jobject pam) {
	jobject set = uwsgi_jvm_call_object(pam, uring.PersistentArrayMap_entrySet);
	if (!set) return NULL;
	return uwsgi_jvm_iterator(set);
}

static jobject uwsgi_ring_response_get(jobject r, char *name, size_t len) {
	jobject j_key = uwsgi_ring_keyword(name, len);
        if (!j_key) return NULL;

	return uwsgi_ring_PersistentArrayMap_get(r, j_key);
}

static jobject uwsgi_ring_header_get(jobject headers, jobject key) {
	return uwsgi_ring_PersistentArrayMap_get(headers, key);
}

static int uwsgi_ring_request(struct wsgi_request *wsgi_req) {
	uwsgi_log("managing ring request\n");
	jobject hm = uwsgi_jvm_hashmap();
	if (!hm) return -1;

	if (uwsgi_ring_request_item_add(hm, "request-method", 14, wsgi_req->method, wsgi_req->method_len)) goto error;
	if (uwsgi_ring_request_item_add(hm, "uri", 3, wsgi_req->uri, wsgi_req->uri_len)) goto error;

	jobject response = uwsgi_ring_invoke1(uring.handler, hm);
	if (!response) goto error;

	if (!uwsgi_jvm_object_is_instance(response, uring.PersistentArrayMap)) {
		uwsgi_log("invalid ring response type, must be: clojure.lang.PersistentArrayMap\n");
		goto error;
	}
	
	jobject r_status = uwsgi_ring_response_get(response, "status", 6);
	if (!r_status) goto error;

	jobject r_headers = uwsgi_ring_response_get(response, "headers", 7);
	if (!r_headers) goto error;

	char *cn = uwsgi_jvm_str2c( uwsgi_jvm_object_class_name(r_headers) );
	uwsgi_log("headers type = %s\n", cn);

	cn = uwsgi_jvm_str2c( uwsgi_jvm_object_class_name(r_status) );
	uwsgi_log("status type = %s\n", cn);

	jobject entries = uwsgi_ring_PersistentArrayMap_iterator(r_headers);
	if (!entries) goto error;

	while(uwsgi_jvm_iterator_hasNext(entries)) {
		jobject hh = uwsgi_jvm_iterator_next(entries);
		uwsgi_log("hh = %p\n", hh);
	}
	jobject ct = uwsgi_ring_header_get(r_headers, uwsgi_jvm_str("Content-Type", 0));
	if (!ct) {
		uwsgi_log("oops\n");
		goto error;
	}

	uwsgi_log("type = %s\n", uwsgi_jvm_str2c(ct));

	return UWSGI_OK;

error:
	// destroy the hashmap
	return -1;
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

	uring.PersistentArrayMap = uwsgi_jvm_class("clojure/lang/PersistentArrayMap");
        if (!uring.PersistentArrayMap) {
                exit(1);
        }

	jmethodID clojure_loadresourcescript = uwsgi_jvm_get_static_method_id(clojure, "loadResourceScript", "(Ljava/lang/String;)V");
	if (!clojure_loadresourcescript) {
		exit(1);
	}

	if (uwsgi_jvm_call_static(clojure, clojure_loadresourcescript, uwsgi_jvm_str(uring.app, 0))) {
		exit(1);	
	}

	jmethodID clojure_var = uwsgi_jvm_get_static_method_id(clojure, "var", "(Ljava/lang/String;Ljava/lang/String;)Lclojure/lang/Var;");
	if (!clojure_var) {
		exit(1);
	}

	uring.PersistentArrayMap_get = uwsgi_jvm_get_method_id(uring.PersistentArrayMap, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
	if (!uring.PersistentArrayMap_get) {
		exit(1);
	}

	uring.PersistentArrayMap_entrySet = uwsgi_jvm_get_method_id(uring.PersistentArrayMap, "entrySet", "()Ljava/util/Set;");
	if (!uring.PersistentArrayMap_entrySet) {
		exit(1);
	}

	char *ns = "clojuretest.core";
	char *func = "handler";
	uring.handler = uwsgi_jvm_call_object_static(clojure, clojure_var, uwsgi_jvm_str(ns, 0), uwsgi_jvm_str(func, 0));
	if (!uring.handler) {
		exit(1);
	} 

	ns = "clojure.core";
	func = "keyword";
	uring.keyword = uwsgi_jvm_call_object_static(clojure, clojure_var, uwsgi_jvm_str(ns, 0), uwsgi_jvm_str(func, 0));
	if (!uring.keyword) {
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
