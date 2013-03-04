#include <jvm.h>

#define UWSGI_JVM_REQUEST_HANDLER_RING	1

extern struct uwsgi_jvm ujvm;

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

	jclass PersistentVector;
	jclass PersistentList;
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

static int uwsgi_ring_request(struct wsgi_request *wsgi_req) {
	char status_str[1];
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

	if (!uwsgi_jvm_object_is_instance(r_status, ujvm.long_class) && !uwsgi_jvm_object_is_instance(r_status, ujvm.int_class)) {
		uwsgi_log("invalid ring response status type, must be: java.lang.Long\n");
		goto error;
	}

	long n_status = uwsgi_jvm_number2c(r_status);
	if (n_status == -1) goto error;

	if (uwsgi_num2str2(n_status, status_str) != 3) {
		goto error;
	}

	if (uwsgi_response_prepare_headers(wsgi_req, status_str, 3)) goto error;

	jobject r_headers = uwsgi_ring_response_get(response, "headers", 7);
	if (!r_headers) goto error;

	if (!uwsgi_jvm_object_is_instance(r_headers, uring.PersistentArrayMap)) {
		uwsgi_log("invalid ring response headers type, must be: clojure.lang.PersistentArrayMap\n");
		goto error;
	}

	jobject entries = uwsgi_ring_PersistentArrayMap_iterator(r_headers);
	if (!entries) goto error;

	while(uwsgi_jvm_iterator_hasNext(entries)) {
		jobject hh = uwsgi_jvm_iterator_next(entries);
		if (!hh) goto error;
		jobject h_key = uwsgi_jvm_getKey(hh);
		if (!h_key) goto error;
		jobject h_value = uwsgi_jvm_getValue(hh);
		if (!h_value) goto error;

		if (!uwsgi_jvm_object_is_instance(h_key, ujvm.str_class)) {
			uwsgi_log("headers key must be java/lang/String !!!\n");
			goto error;
		}

		if (uwsgi_jvm_object_is_instance(h_value, ujvm.str_class)) {
			char *c_h_key = uwsgi_jvm_str2c(h_key);
			uint16_t c_h_keylen = uwsgi_jvm_strlen(h_key);
			char *c_h_value = uwsgi_jvm_str2c(h_value);
                        uint16_t c_h_vallen = uwsgi_jvm_strlen(h_value);
			int ret = uwsgi_response_add_header(wsgi_req, c_h_key, c_h_keylen, c_h_value, c_h_vallen);
			uwsgi_jvm_release_chars(h_key, c_h_key);
			uwsgi_jvm_release_chars(h_value, c_h_value);
			if (ret) goto error;	
		}
		else if (uwsgi_jvm_object_is_instance(h_value, uring.PersistentVector) || uwsgi_jvm_object_is_instance(h_value, uring.PersistentList)) {
			jobject values = uwsgi_jvm_auto_iterator(h_value);
			if (!values) goto error;
			while(uwsgi_jvm_iterator_hasNext(values)) {
				jobject hh_value = uwsgi_jvm_iterator_next(values);
				if (!uwsgi_jvm_object_is_instance(hh_value, ujvm.str_class)) {
                        		uwsgi_log("headers value must be java/lang/String !!!\n");
                        		goto error;
                		}
				char *c_h_key = uwsgi_jvm_str2c(h_key);
				uint16_t c_h_keylen = uwsgi_jvm_strlen(h_key);
				char *c_h_value = uwsgi_jvm_str2c(hh_value);
				uint16_t c_h_vallen = uwsgi_jvm_strlen(hh_value);
				int ret = uwsgi_response_add_header(wsgi_req, c_h_key, c_h_keylen, c_h_value, c_h_vallen);
				uwsgi_jvm_release_chars(h_key, c_h_key);
				uwsgi_jvm_release_chars(hh_value, c_h_value);
				if (ret) goto error;
			}
		}
		else {
			uwsgi_log("unsupported header value !!! (must be java/lang/String, clojure/lang/PersistentVector or clojure/lang/PersistentList)\n");
			goto error;
		}
	}

	jobject r_body = uwsgi_ring_response_get(response, "body", 4);
        if (!r_body) goto error;

        if (uwsgi_jvm_object_is_instance(r_body, ujvm.str_class)) {
		char *c_body = uwsgi_jvm_str2c(r_body);
		size_t c_body_len = uwsgi_jvm_strlen(r_body);
		uwsgi_response_write_body_do(wsgi_req, c_body, c_body_len);
		uwsgi_jvm_release_chars(r_body, c_body);
		return UWSGI_OK;
        }

	jobject chunks = uwsgi_jvm_auto_iterator(r_body);
	if (chunks) {
		while(uwsgi_jvm_iterator_hasNext(chunks)) {
			jobject chunk = uwsgi_jvm_iterator_next(chunks);
			if (!uwsgi_jvm_object_is_instance(chunk, ujvm.str_class)) {
                        	uwsgi_log("body iSeq item must be java/lang/String !!!\n");
                                goto error;
                        }
			char *c_body = uwsgi_jvm_str2c(chunk);
                	size_t c_body_len = uwsgi_jvm_strlen(chunk);
                	int ret = uwsgi_response_write_body_do(wsgi_req, c_body, c_body_len);
                	uwsgi_jvm_release_chars(chunk, c_body);
			if (ret) goto error;
		}
		return UWSGI_OK;
	}

	if (uwsgi_jvm_object_is_instance(r_body, ujvm.file_class)) {
		jobject j_filename = uwsgi_jvm_filename(r_body);
		if (!j_filename) goto error;
		char *c_filename = uwsgi_jvm_str2c(j_filename);
		int fd = open(c_filename, O_RDONLY);
		if (fd < 0) {
			uwsgi_error("clojure/ring->open()");
			goto error;
		}
		uwsgi_response_sendfile_do(wsgi_req, fd, 0, 0);
		uwsgi_log("sendfile fd = %d\n", fd);
		uwsgi_jvm_release_chars(j_filename, c_filename);
		return UWSGI_OK;
	}

	uwsgi_log("unsupported clojure/ring body type\n");
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

	uring.PersistentVector = uwsgi_jvm_class("clojure/lang/PersistentVector");
        if (!uring.PersistentVector) {
                exit(1);
        }

	uring.PersistentList = uwsgi_jvm_class("clojure/lang/PersistentList");
        if (!uring.PersistentList) {
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
