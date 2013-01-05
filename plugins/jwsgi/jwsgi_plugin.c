#include "../jvm/jvm.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_jvm ujvm;

static int MAX_LREFS = 16;

void uwsgi_jwsgi_init(void) {

}

int uwsgi_jwsgi_request(struct wsgi_request *wsgi_req) {

    jmethodID jmid;
    int i;
    jobject env;
    jobject key, val;
    jobject response;

    jobject status;
    jobject headers, header;
    jobject body;

    const char* body_str;
    const char* status_str;
    const char* hkey_str;
    const char* hval_str;

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

    uwsgi_jvm_begin(MAX_LREFS);

    uwsgi_log("main class = %s\n", ujvm.string_main);

    jmid = uwsgi_jvm_method_static(ujvm.class_main, "jwsgi", "(Ljava/util/Hashtable;)[Ljava/lang/Object;");
    uwsgi_jvm_ok();

    uwsgi_log("jwsgi method id = %d\n", jmid);

    env = uwsgi_jvm_hashtable();
    uwsgi_jvm_ok();

    int cnt = wsgi_req->var_cnt;
    for(i=0;i<cnt;i++) {

        uwsgi_jvm_begin(MAX_LREFS);

        key = uwsgi_jvm_string_from(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len);
        val = uwsgi_jvm_string_from(wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len);
        uwsgi_jvm_hashtable_put(env, key, val);
        uwsgi_jvm_ok();

        uwsgi_jvm_end();

        i++;
    }

    uwsgi_log("env created\n");

    jobject fd = uwsgi_jvm_fd(wsgi_req->poll.fd);
    uwsgi_jvm_hashtable_put(env, ujvm.jwsgi_input, fd);

    uwsgi_log("jwsgi.input created\n");

    response = uwsgi_jvm_call(ujvm.class_main, jmid, env);
    uwsgi_jvm_ok();

    uwsgi_log("RESPONSE SIZE %d\n", uwsgi_jvm_arraylen(response));

    uwsgi_jvm_begin(MAX_LREFS);

    uwsgi_log("getting status\n");
    status = uwsgi_jvm_array_get(response, 0);
    uwsgi_jvm_ok();

    status_str = uwsgi_jvm_utf8chars(uwsgi_jvm_tostring(status));
    uwsgi_log("status: %s\n", status_str);

    wsgi_req->headers_size += write(wsgi_req->poll.fd, wsgi_req->protocol, wsgi_req->protocol_len);
    wsgi_req->headers_size += write(wsgi_req->poll.fd, " ", 1);
    wsgi_req->headers_size += write(wsgi_req->poll.fd, status_str, uwsgi_jvm_utf8len(status));
    wsgi_req->headers_size += write(wsgi_req->poll.fd, "\r\n", 2);

    uwsgi_log("getting headers\n");
    headers = uwsgi_jvm_array_get(response, 1);

    hc = uwsgi_jvm_class_of(headers);
    hh_size = uwsgi_jvm_method(hc, "size","()I");
    hh_get = uwsgi_jvm_method(hc, "get","(I)Ljava/lang/Object;");

    hlen = uwsgi_jvm_call_int(headers, hh_size);
    uwsgi_log("headers length: %i\n", hlen);

    for(i=0;i<hlen;i++) {

        uwsgi_jvm_begin(MAX_LREFS);

        uwsgi_log("before getting header @ %i\n", i);
        header = uwsgi_jvm_call(headers, hh_get, i);
        if (header != NULL ) {
            uwsgi_log("after getting header\n");
            uwsgi_log("size of header = %i\n", uwsgi_jvm_arraylen(header));

            key = uwsgi_jvm_array_get(header, 0);
            val = uwsgi_jvm_array_get(header, 1);
            uwsgi_jvm_println(key);
            uwsgi_jvm_println(val);

            hkey_str = uwsgi_jvm_utf8chars(key);
            hval_str = uwsgi_jvm_utf8chars(val);
            uwsgi_log("header: %s=%s\n", hkey_str, hval_str);

            wsgi_req->headers_size += write(wsgi_req->poll.fd, hkey_str, uwsgi_jvm_utf8len(key));
            wsgi_req->headers_size += write(wsgi_req->poll.fd, ": ", 2);
            wsgi_req->headers_size += write(wsgi_req->poll.fd, hval_str, uwsgi_jvm_utf8len(val));
            wsgi_req->headers_size += write(wsgi_req->poll.fd, "\r\n", 2);

            uwsgi_jvm_release_utf8chars(key, hkey_str);
            uwsgi_jvm_release_utf8chars(val, hval_str);
            uwsgi_jvm_delete(key);
            uwsgi_jvm_delete(val);
        }

        uwsgi_jvm_end();
    }

    wsgi_req->headers_size += write(wsgi_req->poll.fd, "\r\n", 2);

    body = uwsgi_jvm_array_get(response, 2);
    body_str = uwsgi_jvm_utf8chars(body);
    wsgi_req->response_size = write(wsgi_req->poll.fd, body_str, uwsgi_jvm_utf8len(body));

    uwsgi_log("releasing status string: %s\n", status_str);
    uwsgi_jvm_release_utf8chars(status, status_str);
    uwsgi_log("releasing body string: %s\n", body_str);
    uwsgi_jvm_release_utf8chars(body, body_str);

    uwsgi_jvm_end();

    uwsgi_jvm_end();

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
