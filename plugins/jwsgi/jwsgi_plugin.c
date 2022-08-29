#include <jvm.h>

extern struct uwsgi_server uwsgi;
extern struct uwsgi_jvm ujvm;

#define UWSGI_JVM_REQUEST_HANDLER_JWSGI	0

struct uwsgi_jwsgi {
	char *app;
	jmethodID app_mid;
	jclass app_class;
	jobject app_instance;
} ujwsgi;

static struct uwsgi_option uwsgi_jwsgi_options[] = {
        {"jwsgi", required_argument, 0, "load the specified JWSGI application (syntax class:method)", uwsgi_opt_set_str, &ujwsgi.app, 0},
        {0, 0, 0, 0},
};

static int uwsgi_jwsgi_add_request_item(jobject hm, char *key, uint16_t key_len, char *value, uint16_t value_len) {
	jobject j_key = uwsgi_jvm_str(key, key_len);
	if (!j_key) return -1;

	jobject j_value = NULL;
	// avoid clobbering vars
	if (value_len > 0) {
		j_value = uwsgi_jvm_str(value, value_len);
	}
	else {
		char *tmp = uwsgi_str("");
		j_value = uwsgi_jvm_str(tmp, 0);
		free(tmp);
	}
	if (!j_value) {
		uwsgi_jvm_local_unref(j_value);
		return -1;
	}

	int ret = uwsgi_jvm_hashmap_put(hm, j_key, j_value);
	uwsgi_jvm_local_unref(j_key);
	uwsgi_jvm_local_unref(j_value);
	return ret;
}

static int uwsgi_jwsgi_add_request_input(jobject hm, char *key, uint16_t key_len) {
	jobject j_key = uwsgi_jvm_str(key, key_len);
        if (!j_key) return -1;

        jobject j_value = uwsgi_jvm_request_body_input_stream();
        if (!j_value) {
                uwsgi_jvm_local_unref(j_value);
                return -1;
        }

        int ret = uwsgi_jvm_hashmap_put(hm, j_key, j_value);
        uwsgi_jvm_local_unref(j_key);
        uwsgi_jvm_local_unref(j_value);
        return ret;
}

static int uwsgi_jwsgi_request(struct wsgi_request *wsgi_req) {
	char status_str[11];
	jobject hm = NULL;
	jobject response = NULL;
	jobject r_status = NULL;
	jobject r_headers = NULL;
	jobject r_headers_entries = NULL;
	jobject r_body = NULL;

	hm = uwsgi_jvm_hashmap();
	if (!hm) return -1;

	int i;
	for(i=0;i<wsgi_req->var_cnt;i+=2) {
                char *hk = wsgi_req->hvec[i].iov_base;
                uint16_t hk_l = wsgi_req->hvec[i].iov_len;
                char *hv = wsgi_req->hvec[i+1].iov_base;
                uint16_t hv_l = wsgi_req->hvec[i+1].iov_len;
		if (uwsgi_jwsgi_add_request_item(hm, hk, hk_l, hv, hv_l)) goto end;
	}

	if (uwsgi_jwsgi_add_request_input(hm, "jwsgi.input", 11)) goto end;

	if (!ujwsgi.app_instance) {
		response = uwsgi_jvm_call_object_static(ujwsgi.app_class, ujwsgi.app_mid, hm);
	}
	else {
		response = uwsgi_jvm_call_object(ujwsgi.app_instance, ujwsgi.app_mid, hm);
	}
	if (!response) goto end;

	if (uwsgi_jvm_array_len(response) != 3) {
		uwsgi_log("invalid JWSGI response object\n");
		goto end;
	}

	r_status = uwsgi_jvm_array_get(response, 0);
	if (!r_status) goto end;

	long n_status = uwsgi_jvm_number2c(r_status);
        if (n_status == -1) goto end;

	if (uwsgi_num2str2(n_status, status_str) != 3) {
                goto end;
        }

	if (uwsgi_response_prepare_headers(wsgi_req, status_str, 3)) goto end;

	r_headers = uwsgi_jvm_array_get(response, 1);
	if (!r_headers) goto end;

	// get entrySet
	r_headers_entries = uwsgi_jvm_entryset(r_headers);	
	if (!r_headers_entries) goto end;

	// get iterator
	jobject values = uwsgi_jvm_auto_iterator(r_headers_entries);
	if (values) {
		int ret = uwsgi_jvm_iterator_to_response_headers(wsgi_req, values);
		uwsgi_jvm_local_unref(values);
		if (ret) goto end;
	}
	else {
		uwsgi_log("unsupported response headers type !!! (must be java/util/HashMap)\n");
		goto end;
	}

	r_body = uwsgi_jvm_array_get(response, 2);
	if (!r_body) goto end;

	if (uwsgi_jvm_object_to_response_body(wsgi_req, r_body)) {
		uwsgi_log("unsupported JWSGI response body type\n");
	}

end:
	if (r_status) uwsgi_jvm_local_unref(r_status);
	if (r_headers_entries) uwsgi_jvm_local_unref(r_headers_entries);
	if (r_headers) uwsgi_jvm_local_unref(r_headers);
	if (r_body) uwsgi_jvm_local_unref(r_body);

	if (response) {
		uwsgi_jvm_local_unref(response);
	}
	uwsgi_jvm_local_unref(hm);
	return UWSGI_OK;
}

static int uwsgi_jwsgi_setup() {

	char *app = uwsgi_str(ujwsgi.app);

	char *method = "application";
	char *colon = strchr(app, ':');

	if (colon) {
		*colon = 0;
		method = colon + 1;
	}

	ujwsgi.app_class = uwsgi_jvm_class(app);
	if (!ujwsgi.app_class) {
		exit(1);
	}

	ujwsgi.app_mid = uwsgi_jvm_get_static_method_id_quiet(ujwsgi.app_class, method, "(Ljava/util/HashMap;)[Ljava/lang/Object;");
	if (uwsgi_jvm_exception() || !ujwsgi.app_mid) {
                jmethodID mid = uwsgi_jvm_get_method_id(ujwsgi.app_class, "<init>", "()V");
                if (uwsgi_jvm_exception() || !mid) exit(1);
        	ujwsgi.app_instance = (*ujvm_env)->NewObject(ujvm_env, ujwsgi.app_class, mid);
        	if (uwsgi_jvm_exception() || !ujwsgi.app_instance) {
			exit(1);
        	}
		ujwsgi.app_mid = uwsgi_jvm_get_method_id(ujwsgi.app_class, method, "(Ljava/util/HashMap;)[Ljava/lang/Object;");
        	if (uwsgi_jvm_exception() || !ujwsgi.app_mid) {
			exit(1);
        	}
	}

	uwsgi_log("JWSGI app \"%s\" loaded\n", ujwsgi.app);
	return 0;
}

static int uwsgi_jwsgi_init() {

        if (!ujwsgi.app) return 0;

        if (uwsgi_jvm_register_request_handler(UWSGI_JVM_REQUEST_HANDLER_JWSGI, uwsgi_jwsgi_setup, uwsgi_jwsgi_request)) {
                exit(1);
        }

        return 0;
}


struct uwsgi_plugin jwsgi_plugin = {
        .name = "jwsgi",
        .options = uwsgi_jwsgi_options,
        .init = uwsgi_jwsgi_init,
};
