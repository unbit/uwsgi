#include <uwsgi.h>
#include <jni.h>
#include <jvmti.h>

struct uwsgi_jvm {

	JavaVM *vm;
	JavaVMInitArgs vm_args;

	pthread_key_t env;

        struct uwsgi_string_list *classpath;
        struct uwsgi_string_list *classes;
        struct uwsgi_string_list *main_classes;

	jclass str_class;
	jclass runtime_exception;

	jmethodID api_signal_handler_mid;
	jmethodID api_rpc_function_mid;
};

#define ujvm_env ((JNIEnv*)pthread_getspecific(ujvm.env))

jclass uwsgi_jvm_class(char *);
jobject uwsgi_jvm_ref(jobject);
void uwsgi_jvm_unref(jobject);
int uwsgi_jvm_call_static(jclass, jmethodID, ...);
int uwsgi_jvm_call(jobject, jmethodID, ...);

void uwsgi_jvm_clear_exception(void);
char *uwsgi_jvm_str2c(jobject);

void uwsgi_jvm_throw(char *);

jobject uwsgi_jvm_call_objectA(jobject o, jmethodID mid, jvalue *);
void uwsgi_jvm_release_chars(jobject, char *);
