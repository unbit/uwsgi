#include <jvm.h>

/*

	Servlet 2.5 JVM handler

*/

#define UWSGI_JVM_REQUEST_HANDLER_SERVLET	2

extern struct uwsgi_jvm ujvm;

struct uwsgi_servlet {
} uservlet;

static struct uwsgi_option uwsgi_servlet_options[] = {
        {0, 0, 0, 0},
};

// the request handler
static int uwsgi_servlet_request(struct wsgi_request *wsgi_req) {
	return UWSGI_OK;
}

static int uwsgi_servlet_setup() {
	uwsgi_log("loading servlet environment...\n");

	jclass servlet = uwsgi_jvm_class("org/apache/jasper/servlet/JspServlet");
	uwsgi_log("jclass = %p\n", servlet);

	jmethodID mid = uwsgi_jvm_get_method_id(servlet, "<init>", "()V");
        if (uwsgi_jvm_exception() || !mid) exit(1);
        jobject instance = (*ujvm_env)->NewObject(ujvm_env, servlet, mid);
	if (uwsgi_jvm_exception() || !instance) exit(1);

	uwsgi_log("done\n");

	jclass uwsgi_servlet_config = uwsgi_jvm_class("uWSGIServletConfig");
	mid = uwsgi_jvm_get_method_id(uwsgi_servlet_config, "<init>", "()V");
	jobject config = (*ujvm_env)->NewObject(ujvm_env, uwsgi_servlet_config, mid);

	mid = uwsgi_jvm_get_method_id(servlet, "init", "(Ljavax/servlet/ServletConfig;)V");
	uwsgi_jvm_call_object(instance, mid, config );

	uwsgi_log("SERVLET initialized\n");

	jclass uwsgi_request = uwsgi_jvm_class("uWSGIServletRequest");
	jclass uwsgi_response = uwsgi_jvm_class("uWSGIServletResponse");

	uwsgi_log("%p %p\n", uwsgi_request, uwsgi_response);

	mid = uwsgi_jvm_get_method_id(uwsgi_request , "<init>", "()V");
	if (uwsgi_jvm_exception() || !mid) exit(1);
	jobject request = (*ujvm_env)->NewObject(ujvm_env, uwsgi_request, mid);

	mid = uwsgi_jvm_get_method_id(uwsgi_response , "<init>", "()V");
	if (uwsgi_jvm_exception() || !mid) exit(1);
	jobject response = (*ujvm_env)->NewObject(ujvm_env, uwsgi_response, mid);

	uwsgi_log("%p %p\n", request, response);

	mid = uwsgi_jvm_get_method_id(servlet, "service", "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V");
	if (uwsgi_jvm_exception() || !mid) exit(1);

	uwsgi_jvm_call_object(instance, mid, request, response);

	uwsgi_log("done\n");

	mid = uwsgi_jvm_get_method_id(uwsgi_response, "flushBuffer", "()V");
	if (uwsgi_jvm_exception() || !mid) exit(1);
	uwsgi_jvm_call_object(response, mid);

	uwsgi_log("servlet loaded\n");
	return 0;
}

static int uwsgi_servlet_init() {
	
	if (uwsgi_jvm_register_request_handler(UWSGI_JVM_REQUEST_HANDLER_SERVLET, uwsgi_servlet_setup, uwsgi_servlet_request)) {
		exit(1);
	}

	return 0;
}

struct uwsgi_plugin servlet_plugin = {
	.name = "servlet",
	.options = uwsgi_servlet_options,
	.init = uwsgi_servlet_init,
};
