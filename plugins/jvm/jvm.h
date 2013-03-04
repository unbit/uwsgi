#include <uwsgi.h>
#include <jni.h>
#include <jvmti.h>

/*
 *  Structures
 */

struct uwsgi_jvm {

    JavaVM *vm;
    JavaVMInitArgs vm_args;

    pthread_key_t env;

    struct uwsgi_string_list *classpath;
    struct uwsgi_string_list *classes;
    struct uwsgi_string_list *main_classes;

    jclass str_class;
    jclass hashmap_class;
    jclass set_class;
    jclass iterator_class;
    jclass runtime_exception;

    jmethodID api_signal_handler_mid;
    jmethodID api_rpc_function_mid;

    int (*request_handlers[UMAX8])(struct wsgi_request *);
    int (*request_handlers_setup[UMAX8])(void);
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

int uwsgi_jvm_register_request_handler(uint8_t, int (*)(void), int (*)(struct wsgi_request *));
jmethodID uwsgi_jvm_get_static_method_id(jclass, char *, char *);

jobject uwsgi_jvm_str(char *, size_t);
jobject uwsgi_jvm_hashmap(void);
int uwsgi_jvm_hashmap_put(jobject, jobject, jobject);

jobject uwsgi_jvm_call_object(jobject, jmethodID, ...);
jobject uwsgi_jvm_call_object_static(jclass, jmethodID, ...);
jmethodID uwsgi_jvm_get_method_id(jclass, char *, char *);
jclass uwsgi_jvm_class_from_object(jobject);

jobject uwsgi_jvm_object_class_name(jobject);
int uwsgi_jvm_object_is_instance(jobject, jclass);
jobject uwsgi_jvm_hashmap_get(jobject, jobject);

int uwsgi_jvm_iterator_hasNext(jobject);
jobject uwsgi_jvm_iterator_next(jobject);

jobject uwsgi_jvm_iterator(jobject);

