#include "../jvm/jvm.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_jvm ujvm;

void uwsgi_jwsgi_init(void) {


}

int uwsgi_jwsgi_request(struct wsgi_request *wsgi_req) {

	jmethodID jmid;
	int i;
	jobject env;
	jobject hkey, hval;
	jobject response;

	jobject status;
	jobject headers, header;
	jobject body;

	jclass hc;

	jmethodID hh_size, hh_get;
	int hlen;

	if (!wsgi_req->uh.pktsize) {
                uwsgi_log("Invalid JWSGI request. skip.\n");
                return -1;
        }


        if (uwsgi_parse_vars(wsgi_req)) {
                uwsgi_log("Invalid JWSGI request. skip.\n");
                return -1;
        }

	
	jmid = uwsgi_jvm_get_static_method_id(ujvm.main_class, "jwsgi", "(Ljava/util/Hashtable;)[Ljava/lang/Object;");

	uwsgi_log("jwsgi method id = %d\n", jmid);

	env = uwsgi_jvm_ht_new();
	uwsgi_jvm_exception();

	for(i=0;i<wsgi_req->var_cnt;i++) {
		
		uwsgi_jvm_ht_put(env,
				uwsgi_jvm_str_new(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len),
				uwsgi_jvm_str_new(wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len)
				);

		// check if something is going wrong during hashtable fill
		uwsgi_jvm_exception();

                i++;
        }

	uwsgi_log("env created\n");
	
	uwsgi_jvm_ht_put(env, uwsgi_jvm_str("jwsgi.input"), uwsgi_jvm_fd(wsgi_req->poll.fd));

	uwsgi_log("jwsgi.input created\n");
	
	response = (*ujvm.env)->CallObjectMethod(ujvm.env, ujvm.main_class, jmid, env);
	uwsgi_jvm_exception();

	uwsgi_log("RESPONSE SIZE %d\n", (*ujvm.env)->GetArrayLength(ujvm.env, response));

	status = uwsgi_jvm_array_get(response, 0);
	uwsgi_jvm_exception();

	wsgi_req->headers_size += write(wsgi_req->poll.fd, wsgi_req->protocol, wsgi_req->protocol_len);
	wsgi_req->headers_size += write(wsgi_req->poll.fd, " ", 1);
	wsgi_req->headers_size += write(wsgi_req->poll.fd, uwsgi_jvm_str2c(status), uwsgi_jvm_strlen2c(status));
	wsgi_req->headers_size += write(wsgi_req->poll.fd, "\r\n", 2);

	
	headers = uwsgi_jvm_array_get(response, 1);
	hc = uwsgi_jvm_get_object_class(headers);
	hh_size = uwsgi_jvm_get_method_id(hc, "size","()I");
	hh_get = uwsgi_jvm_get_method_id(hc, "get","(I)Ljava/lang/Object;");

	hlen = (*ujvm.env)->CallIntMethod(ujvm.env, headers, hh_size);

	for(i=0;i<hlen;i++) {
		header = (*ujvm.env)->CallObjectMethod(ujvm.env, headers, hh_get, i);
		hkey = uwsgi_jvm_array_get(header, 0);		
		hval = uwsgi_jvm_array_get(header, 1);		

		wsgi_req->headers_size += write(wsgi_req->poll.fd, uwsgi_jvm_str2c(hkey), uwsgi_jvm_strlen2c(hkey));
		wsgi_req->headers_size += write(wsgi_req->poll.fd, ": ", 2);
		wsgi_req->headers_size += write(wsgi_req->poll.fd, uwsgi_jvm_str2c(hval), uwsgi_jvm_strlen2c(hval));
		wsgi_req->headers_size += write(wsgi_req->poll.fd, "\r\n", 2);
	}

	wsgi_req->headers_size += write(wsgi_req->poll.fd, "\r\n", 2);

	body = uwsgi_jvm_array_get(response, 2);

	wsgi_req->response_size = write(wsgi_req->poll.fd, (*ujvm.env)->GetStringUTFChars(ujvm.env, body, NULL), (*ujvm.env)->GetStringUTFLength(ujvm.env, body));

	return 1;
}

void uwsgi_jwsgi_after_request(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

struct uwsgi_plugin jwsgi_plugin = {

	.name = "jwsgi",
	.modifier1 = 8,
	.request = uwsgi_jwsgi_request,
	.after_request = uwsgi_jwsgi_after_request,
};
