/**

Ring Spec
from https://github.com/ring-clojure/ring/blob/master/SPEC

=== Ring Spec (1.1)
Ring is defined in terms of handlers, middleware, adapters, requests maps, and
response maps, each of which are described below.


== Handlers
Ring handlers constitute the core logic of the web application. Handlers are
implemented as Clojure functions that process a given request map to generate
and return a response map.


== Middleware
Ring middleware augments the functionality of handlers by invoking them in the
process of generating responses. Typically middleware will be implemented as a
higher-order function that takes one or more handlers and configuration options
as arguments and returns a new handler with the desired compound behavior.


== Adapters
Handlers are run via Ring adapters, which are in turn responsible for
implementing the HTTP protocol and abstracting the handlers that they run from
the details of the protocol.

Adapters are implemented as functions of two arguments: a handler and an options
map. The options map provides any needed configuration to the adapter, such as
the port on which to run.

Once initialized, adapters receive HTTP requests, parse them to construct an
request map, and then invoke their handler with this request map as an
argument. Once the handler returns a response map, the adapter uses it to
construct and send an HTTP response to the client.


== Request Map
A request map is a Clojure map containing at least the following keys and
corresponding values:

:server-port
  (Required, Integer)
  The port on which the request is being handled.

:server-name
  (Required, String)
  The resolved server name, or the server IP address.

:remote-addr
  (Required, String)
  The IP address of the client or the last proxy that sent the request.

:uri
  (Required, String)
  The request URI. Must start with "/".

:query-string
  (Optional, String)
  The query string, if present.

:scheme
  (Required, Keyword)
  The transport protocol, must be one of :http or :https.

:request-method
  (Required, Keyword)
  The HTTP request method, must be one of :get, :head, :options, :put, :post, or
  :delete.

:content-type
  (Optional, String)
  The MIME type of the request body, if known.

:content-length
  (Optional, Integer)
  The number of bytes in the request body, if known.

:character-encoding
  (Optional, String)
  The name of the character encoding used in the request body, if known.

:ssl-client-cert
  (Optional, X509Certificate)
  The SSL client certificate, if supplied.

:headers
  (Required, IPersistentMap)
  A Clojure map of downcased header name Strings to corresponding header value
  Strings.

:body
  (Optional, InputStream)
  An InputStream for the request body, if present.


== Response Map
A response map is a Clojure map containing at least the following keys and corresponding values:

:status
  (Required, Integer)
  The HTTP status code, must be greater than or equal to 100.

:headers
  (Required, IPersistentMap)
  A Clojure map of HTTP header names to header values. These values may be
  either Strings, in which case one name/value header will be sent in the
  HTTP response, or a seq of Strings, in which case a name/value header will be
  sent for each such String value.

:body
  (Optional, {String, ISeq, File, InputStream})
  A representation of the response body, if a response body is appropriate for
  the response's status code. The respond body is handled according to its type:
  String:
    Contents are sent to the client as-is.
  ISeq:
    Each element of the seq is sent to the client as a string.
  File:
    Contents at the specified location are sent to the client. The server may
    use an optimized method to send the file if such a method is available.
  InputStream:
    Contents are consumed from the stream and sent to the client. When the
    stream is exhausted, it is .close'd.

 */

#include <string.h>
#include "../jvm/jvm.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_jvm ujvm;

char *entrance_point;
char *entrance_script;
char *entrance_function;

struct uwsgi_option uwsgi_ring_options[] = {
        {"ring", required_argument, 0, "load the specified clojure-ring entrance point, eg. a.b.c:x", uwsgi_opt_set_str, &entrance_point, 0},
        {"ring-classpath", required_argument, 0, "add the specified directory or jar for the clojure classpath", uwsgi_opt_add_string_list, &ujvm.classpath, 0},
        {0, 0, 0, 0},
};

int MAX_LREFS = 16;

jclass cRT;
jclass cVAR;

jmethodID mLOAD;
jmethodID mVAR;

jobject oSCRIPT;
jobject oNAME;

jobject oHANDLER;
jmethodID mINVOKE;

char* uwsgi_ring_reqkey(char* key) {
}

char* uwsgi_ring_respkey(char* key) {
}

jobject uwsgi_ring_map_new() {
}

void uwsgi_ring_map_put() {
}

void uwsgi_ring_init(void) {

    if ((*ujvm.env)->PushLocalFrame(ujvm.env, MAX_LREFS) < 0) {
        uwsgi_log("ring can not allocate frame!");
        return -1;
    }

    cRT   = (*ujvm.env)->NewLocalRef(ujvm.env, uwsgi_jvm_get_class("clojure/lang/RT"));
    cVAR  = (*ujvm.env)->NewLocalRef(ujvm.env, uwsgi_jvm_get_class("clojure/lang/Var"));

    mLOAD = uwsgi_jvm_get_static_method_id(cRT, "loadResourceScript", "(Ljava/lang/String;)V;");
    mVAR  = uwsgi_jvm_get_static_method_id(cRT, "var", "(Ljava/lang/String;Ljava/lang/String;)Lclojure/lang/Var;");

    entrance_script = strtok(entrance_point, ":");
    if (entrance_script != NULL) {
        oSCRIPT = uwsgi_jvm_str(entrance_script);
        entrance_function = strtok(NULL, ":");
        oNAME = uwsgi_jvm_str(entrance_function);
    } else {
        entrance_function = "";
    }

    if (mLOAD && mVAR && oSCRIPT && oNAME) {
        (*ujvm.env)->CallStaticVoidMethod(ujvm.env, cRT, mLOAD, oSCRIPT);
        uwsgi_jvm_exception();
        oHANDLER = (*ujvm.env)->CallStaticMethod(ujvm.env, cRT, mVAR, oNAME);
        uwsgi_jvm_exception();
        mINVOKE = uwsgi_jvm_get_method_id(oHANDLER, "invoke", "(Ljava/lang/Object;)Ljava/lang/Object;");
    }

    (*ujvm.env)->PopLocalFrame(ujvm.env, NULL);

}

int uwsgi_ring_request(struct wsgi_request *wsgi_req) {

    jobject request_map;
    jobject key, val;
    jobject response;
    jobject status;
    jobject headers, header;
    jobject body;

    const char* status_str;
    const char* key_str;
    const char* val_str;
    const char* body_str;

    int i, hlen;

    if (!wsgi_req->uh.pktsize) {
        uwsgi_log("Invalid RING request. skip.\n");
        return -1;
    }

    if (uwsgi_parse_vars(wsgi_req)) {
        uwsgi_log("Invalid RING request. skip.\n");
        return -1;
    }

    if ((*ujvm.env)->PushLocalFrame(ujvm.env, MAX_LREFS) < 0) {
        uwsgi_log("ring can not allocate frame!");
        return -1;
    }

    request_map = uwsgi_ring_map_new();
    uwsgi_jvm_exception();

    int cnt = wsgi_req->var_cnt;
    for(i=0;i<cnt;i++) {

        if ((*ujvm.env)->PushLocalFrame(ujvm.env, MAX_LREFS) < 0) {
            uwsgi_log("ring can not allocate frame!");
            return -1;
        }

        hkey = uwsgi_jvm_str_new(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len);
        hval = uwsgi_jvm_str_new(wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len);
        uwsgi_ring_map_put(request_map, hkey, hval);
        uwsgi_jvm_exception();

        (*ujvm.env)->PopLocalFrame(ujvm.env, NULL);

        i++;
    }

    uwsgi_log("request map created\n");

    uwsgi_ring_map_put(env, uwsgi_jvm_str("uwsgi.ring.input"), uwsgi_jvm_fd(wsgi_req->poll.fd));

    uwsgi_log("ring.input created\n");

    response = (*ujvm.env)->CallObjectMethod(ujvm.env, oHANDLER, oINVOKE, request_map);
    uwsgi_jvm_exception();

    if ((*ujvm.env)->PushLocalFrame(ujvm.env, MAX_LREFS) < 0) {
        uwsgi_log("ring can not allocate frame!");
        return -1;
    }

    status = uwsgi_jvm_tostring(uwsgi_ring_map_get(response, "status"));
    uwsgi_jvm_exception();

    status_str = uwsgi_jvm_str2c(status);
    wsgi_req->headers_size += write(wsgi_req->poll.fd, wsgi_req->protocol, wsgi_req->protocol_len);
    wsgi_req->headers_size += write(wsgi_req->poll.fd, " ", 1);
    wsgi_req->headers_size += write(wsgi_req->poll.fd, status_str, uwsgi_jvm_strlen2c(status));
    wsgi_req->headers_size += write(wsgi_req->poll.fd, "\r\n", 2);
    (*ujvm.env)->ReleaseStringUTFChars(ujvm.env, status, status_str);

    headers = uwsgi_ring_map_get(response, "headers");

    hc = uwsgi_jvm_get_object_class(headers);
    hh_size = uwsgi_jvm_get_method_id(hc, "size","()I");
    hh_get = uwsgi_jvm_get_method_id(hc, "get","(I)Ljava/lang/Object;");

    hlen = (*ujvm.env)->CallIntMethod(ujvm.env, headers, hh_size);

    for(i=0;i<hlen;i++) {

        if ((*ujvm.env)->PushLocalFrame(ujvm.env, MAX_LREFS) < 0) {
            uwsgi_log("ring can not allocate frame!");
            return -1;
        }

        header = (*ujvm.env)->CallObjectMethod(ujvm.env, headers, hh_get, i);
        hkey = uwsgi_jvm_array_get(header, 0);
        hval = uwsgi_jvm_array_get(header, 1);
        hkey_str = uwsgi_jvm_str2c(hkey);
        hval_str = uwsgi_jvm_str2c(hval);

        wsgi_req->headers_size += write(wsgi_req->poll.fd, hkey_str, uwsgi_jvm_strlen2c(hkey));
        wsgi_req->headers_size += write(wsgi_req->poll.fd, ": ", 2);
        wsgi_req->headers_size += write(wsgi_req->poll.fd, hval_str, uwsgi_jvm_strlen2c(hval));
        wsgi_req->headers_size += write(wsgi_req->poll.fd, "\r\n", 2);

        (*ujvm.env)->ReleaseStringUTFChars(ujvm.env, hkey, hkey_str);
        (*ujvm.env)->ReleaseStringUTFChars(ujvm.env, hval, hval_str);

        (*ujvm.env)->PopLocalFrame(ujvm.env, NULL);
    }

    wsgi_req->headers_size += write(wsgi_req->poll.fd, "\r\n", 2);

    body = uwsgi_ring_map_get(response, "body");

    body_str = (*ujvm.env)->GetStringUTFChars(ujvm.env, body, NULL);
    wsgi_req->response_size = write(wsgi_req->poll.fd, body_str, (*ujvm.env)->GetStringUTFLength(ujvm.env, body));
    (*ujvm.env)->ReleaseStringUTFChars(ujvm.env, body, status_str);

    (*ujvm.env)->PopLocalFrame(ujvm.env, NULL);

    (*ujvm.env)->PopLocalFrame(ujvm.env, NULL);

    return 1;
}

void uwsgi_ring_after_request(struct wsgi_request *wsgi_req) {
    log_request(wsgi_req);
}

struct uwsgi_plugin ring_plugin = {

    .name = "ring",
    .modifier1 = 8,
    .options = uwsgi_ring_options,
    .init_apps = uwsgi_ring_init,
    .after_request = uwsgi_ring_after_request,
    .after_request = uwsgi_ring_after_request,
};
