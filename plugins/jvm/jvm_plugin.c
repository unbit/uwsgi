#include "jvm.h"

/*

with javap -s -p <class>
you can get method signatures

This plugin is the core for all of the JVM-based ones

*/

extern struct uwsgi_server uwsgi;
struct uwsgi_plugin jvm_plugin;

JNIEXPORT jint JNICALL uwsgi_jvm_api_worker_id(JNIEnv *env, jclass c) {
	return uwsgi.mywid;
}

JNIEXPORT void JNICALL uwsgi_jvm_api_register_signal(JNIEnv *env, jclass c, jint signum, jstring target, jobject handler) {
	char *t = uwsgi_jvm_str2c(target);
	if (uwsgi_register_signal(signum, t, uwsgi_jvm_ref(handler), jvm_plugin.modifier1)) {
		uwsgi_jvm_throw("unable to register signal handler");
	}
}

JNIEXPORT void JNICALL uwsgi_jvm_api_register_rpc(JNIEnv *env, jclass c, jstring name, jobject func) {
	char *n = uwsgi_jvm_str2c(name);
	if (uwsgi_register_rpc(n, jvm_plugin.modifier1, 0, uwsgi_jvm_ref(func))) {
		uwsgi_jvm_throw("unable to register rpc function");
	}
}

static JNINativeMethod uwsgi_jvm_api_methods[] = {
	{"register_signal", "(ILjava/lang/String;Luwsgi$SignalHandler;)V", (void *) &uwsgi_jvm_api_register_signal},
	{"register_rpc", "(Ljava/lang/String;Luwsgi$RpcFunction;)V", (void *) &uwsgi_jvm_api_register_rpc},
	{"worker_id", "()I", (void *) &uwsgi_jvm_api_worker_id},
};

struct uwsgi_jvm ujvm;

static struct uwsgi_option uwsgi_jvm_options[] = {
        {"jvm-main-class", required_argument, 0, "load the specified class and call its main() function", uwsgi_opt_add_string_list, &ujvm.main_classes, 0},
        {"jvm-class", required_argument, 0, "load the specified class", uwsgi_opt_add_string_list, &ujvm.classes, 0},
        {"jvm-classpath", required_argument, 0, "add the specified directory to the classpath", uwsgi_opt_add_string_list, &ujvm.classpath, 0},
        {0, 0, 0, 0},
};

// returns 0 if ok, -1 on exception
int uwsgi_jvm_exception(void) {

	if ((*ujvm.env)->ExceptionOccurred(ujvm.env)) {
        	(*ujvm.env)->ExceptionDescribe(ujvm.env);
        	(*ujvm.env)->ExceptionClear(ujvm.env);
		return -1;
	}
	return 0;
}

void uwsgi_jvm_clear_exception() {
	if ((*ujvm.env)->ExceptionOccurred(ujvm.env)) {
		(*ujvm.env)->ExceptionClear(ujvm.env);
	}
}

// load/find/get a class
jclass uwsgi_jvm_class(char *name) {

	jclass my_class = (*ujvm.env)->FindClass(ujvm.env, name);

	if (uwsgi_jvm_exception()) {
		return NULL;
	}

	return my_class;
	return uwsgi_jvm_ref(my_class);
}

// returns the method id, given the method name and its signature
jmethodID uwsgi_jvm_get_method_id(jclass cls, char *name, char *signature) {
	return (*ujvm.env)->GetMethodID(ujvm.env, cls, name, signature);
}

// returns the static method id, given the method name and its signature
jmethodID uwsgi_jvm_get_static_method_id(jclass cls, char *name, char *signature) {
	return (*ujvm.env)->GetStaticMethodID(ujvm.env, cls, name, signature);
}

jobject uwsgi_jvm_ref(jobject obj) {
	return (*ujvm.env)->NewGlobalRef(ujvm.env, obj);
}

void uwsgi_jvm_unref(jobject obj) {
	(*ujvm.env)->DeleteLocalRef(ujvm.env, obj);
}

jobject uwsgi_jvm_str(char *str, size_t len) {
	jobject new_str;
	if (len > 0) {
		char *tmp = uwsgi_concat2n(str, len, "", 0);
		new_str = (*ujvm.env)->NewStringUTF(ujvm.env, tmp);	
		free(tmp);
	}
	else {
		new_str = (*ujvm.env)->NewStringUTF(ujvm.env, str);
	}
	
	return new_str;
}

int uwsgi_jvm_call_static(jclass c, jmethodID mid, ...) {
	va_list args;
	va_start(args, mid);
	(*ujvm.env)->CallStaticVoidMethod(ujvm.env, c, mid, args);
	va_end(args);
        return uwsgi_jvm_exception();
}

int uwsgi_jvm_call(jobject o, jmethodID mid, ...) {
	va_list args;
	va_start(args, mid);
        (*ujvm.env)->CallVoidMethodV(ujvm.env, o, mid, args);
	va_end(args);
        return uwsgi_jvm_exception();
}

jobject uwsgi_jvm_call_objectA(jobject o, jmethodID mid, jvalue *args) {
	jobject ret = (*ujvm.env)->CallObjectMethodA(ujvm.env, o, mid, args);
	if (uwsgi_jvm_exception()) {
		return NULL;
	}	
	return ret;
}

void uwsgi_jvm_throw(char *message) {
	(*ujvm.env)->ThrowNew(ujvm.env, ujvm.runtime_exception, message);
}

static int uwsgi_jvm_init(void) {

	return 0;
}

static void uwsgi_jvm_create(void) {

	JavaVM *jvm;
	JavaVMOption options[1];

        ujvm.vm_args.version = JNI_VERSION_1_2;

        JNI_GetDefaultJavaVMInitArgs(&ujvm.vm_args);

        options[0].optionString = "-Djava.class.path=.";

        char *old_cp = NULL ;
        struct uwsgi_string_list *cp = ujvm.classpath;
        while(cp) {
                if (old_cp) {
                        options[0].optionString = uwsgi_concat3(old_cp, ":", cp->value);
                        free(old_cp);
                }
                else {
                        options[0].optionString = uwsgi_concat3(options[0].optionString, ":", cp->value);
                }
                old_cp = options[0].optionString ;
                cp = cp->next;
        }

        ujvm.vm_args.options  = options;
        ujvm.vm_args.nOptions = 1;

	if (JNI_CreateJavaVM(&jvm, (void **) &ujvm.env, &ujvm.vm_args)) {
		uwsgi_log("unable to initialize the JVM\n");
		exit(1);
	}

	char *java_version = NULL;
	jvmtiEnv *jvmti;
	if ((*jvm)->GetEnv(jvm, (void **)&jvmti, JVMTI_VERSION) == JNI_OK) {
		(*jvmti)->GetSystemProperty(jvmti, "java.vm.version", &java_version);
	}

	if (java_version) {
		uwsgi_log("JVM %s initialized at %p\n", java_version, ujvm.env);
	}
	else {
		uwsgi_log("JVM initialized at %p\n", ujvm.env);
	}

	ujvm.str_class = uwsgi_jvm_class("java/lang/String");
	if (!ujvm.str_class) exit(1);

	ujvm.runtime_exception = uwsgi_jvm_class("java/lang/RuntimeException");
	if (!ujvm.runtime_exception) exit(1);

	jclass uwsgi_class = uwsgi_jvm_class("uwsgi");
	if (!uwsgi_class) {
		exit(1);
	}
	(*ujvm.env)->RegisterNatives(ujvm.env, uwsgi_class, uwsgi_jvm_api_methods, sizeof(uwsgi_jvm_api_methods)/sizeof(uwsgi_jvm_api_methods[0]));
	if (uwsgi_jvm_exception()) {
		exit(1);
	}

	jclass uwsgi_signal_handler_class = uwsgi_jvm_class("uwsgi$SignalHandler");
	if (!uwsgi_signal_handler_class) exit(1);
	ujvm.api_signal_handler_mid = uwsgi_jvm_get_method_id(uwsgi_signal_handler_class, "function", "(I)V");
	if (!ujvm.api_signal_handler_mid) exit(1);

	jclass uwsgi_rpc_function_class = uwsgi_jvm_class("uwsgi$RpcFunction");
	if (!uwsgi_rpc_function_class) exit(1);
	ujvm.api_rpc_function_mid = uwsgi_jvm_get_method_id(uwsgi_rpc_function_class, "function", "([Ljava/lang/String;)Ljava/lang/String;");
	if (!ujvm.api_rpc_function_mid) exit(1);

	struct uwsgi_string_list *usl = ujvm.main_classes;
	while(usl) {
		jclass c = uwsgi_jvm_class(usl->value);
		if (!c) {
			exit(1);
		}
		jmethodID mid = uwsgi_jvm_get_static_method_id(c, "main", "([Ljava/lang/String;)V");
		if (!mid) {
			uwsgi_jvm_clear_exception();
			mid = uwsgi_jvm_get_static_method_id(c, "main", "()V");
		}
		if (!mid) {
			uwsgi_log("unable to find main() method in class \"%s\"\n", usl->value);
			exit(1);
		}
		if (uwsgi_jvm_call_static(c, mid)) {
			exit(1);
		}
		usl = usl->next;
	}

}

// get the raw body of a java string
char *uwsgi_jvm_str2c(jobject obj) {
    return (char *) (*ujvm.env)->GetStringUTFChars(ujvm.env, obj, NULL);
}

// return the size of a java string (UTF8)
size_t uwsgi_jvm_strlen(jobject obj) {
	return (*ujvm.env)->GetStringUTFLength(ujvm.env, obj);
}

static int uwsgi_jvm_signal_handler(uint8_t signum, void *handler) {
	long l_signum = signum;
	return uwsgi_jvm_call(handler, ujvm.api_signal_handler_mid, (void *) l_signum);
}

// route request to the specific JVM plugin (identified by modifier2)
static int uwsgi_jvm_request(struct wsgi_request *wsgi_req) {
	return UWSGI_OK;
}

void uwsgi_jvm_release_chars(jobject o, char *str) {
	(*ujvm.env)->ReleaseStringUTFChars(ujvm.env, o, str);
}

static uint16_t uwsgi_jvm_rpc(void *func, uint8_t argc, char **argv, uint16_t argvs[], char *buffer) {
	jvalue *args = uwsgi_calloc(sizeof(jvalue) * argc+1);	
	uint8_t i;
	for(i=0;i<argc;i++) {
		args[i] = (jvalue) uwsgi_jvm_str(argv[i], argvs[i]);
	}
	jobject ret = uwsgi_jvm_call_objectA(func, ujvm.api_rpc_function_mid, args);
	free(args);
	if (ret == NULL) {
		goto end;
	}
	size_t rlen = uwsgi_jvm_strlen(ret);
	if (rlen <= 0xffff) {
		char *b = uwsgi_jvm_str2c(ret);
		memcpy(buffer, b, rlen);
		uwsgi_jvm_release_chars(ret, b);
		(*ujvm.env)->DeleteLocalRef(ujvm.env, ret);
		return rlen;
	}
end:
	(*ujvm.env)->DeleteLocalRef(ujvm.env, ret);
	return 0;
}

struct uwsgi_plugin jvm_plugin = {
	.name = "jvm",
	.modifier1 = 8,

	.request = uwsgi_jvm_request,

	.init = uwsgi_jvm_init,
	.options = uwsgi_jvm_options,

	.post_fork = uwsgi_jvm_create,

	.signal_handler = uwsgi_jvm_signal_handler,
	.rpc = uwsgi_jvm_rpc,
};


