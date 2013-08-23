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
        struct uwsgi_string_list *opts;

	jclass request_body_class;

	jclass str_class;
	jclass str_array_class;
	jclass long_class;
	jclass int_class;
	jclass byte_class;
	jclass bytearray_class;
	jclass input_stream_class;
	jclass file_class;
	jclass hashmap_class;
	jclass list_class;
	jclass set_class;
	jclass iterator_class;
	jclass bool_class;

	jclass runtime_exception;
	jclass io_exception;

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
int uwsgi_jvm_exception(void);
char *uwsgi_jvm_str2c(jobject);

void uwsgi_jvm_throw(char *);
void uwsgi_jvm_throw_io(char *);

jobject uwsgi_jvm_call_objectA(jobject o, jmethodID mid, jvalue *);
void uwsgi_jvm_release_chars(jobject, char *);

int uwsgi_jvm_register_request_handler(uint8_t, int (*)(void), int (*)(struct wsgi_request *));
jmethodID uwsgi_jvm_get_static_method_id(jclass, char *, char *);
jmethodID uwsgi_jvm_get_static_method_id_quiet(jclass, char *, char *);

jobject uwsgi_jvm_str(char *, size_t);
jobject uwsgi_jvm_hashmap(void);
int uwsgi_jvm_hashmap_put(jobject, jobject, jobject);
int uwsgi_jvm_hashmap_has(jobject, jobject);

jobject uwsgi_jvm_list(void);
int uwsgi_jvm_list_add(jobject, jobject);

jobject uwsgi_jvm_call_object(jobject, jmethodID, ...);
jobject uwsgi_jvm_call_object_static(jclass, jmethodID, ...);
jmethodID uwsgi_jvm_get_method_id(jclass, char *, char *);
jmethodID uwsgi_jvm_get_method_id_quiet(jclass, char *, char *);
jclass uwsgi_jvm_class_from_object(jobject);

jobject uwsgi_jvm_object_class_name(jobject);
int uwsgi_jvm_object_is_instance(jobject, jclass);
jobject uwsgi_jvm_hashmap_get(jobject, jobject);

int uwsgi_jvm_iterator_hasNext(jobject);
jobject uwsgi_jvm_iterator_next(jobject);

jobject uwsgi_jvm_iterator(jobject);
jobject uwsgi_jvm_auto_iterator(jobject);

jobject uwsgi_jvm_getKey(jobject);
jobject uwsgi_jvm_getValue(jobject);

size_t uwsgi_jvm_strlen(jobject);
long uwsgi_jvm_number2c(jobject);

long uwsgi_jvm_int2c(jobject);
long uwsgi_jvm_long2c(jobject);

jobject uwsgi_jvm_filename(jobject);
void uwsgi_jvm_local_unref(jobject);
int uwsgi_jvm_call_bool(jobject, jmethodID, ...);

int uwsgi_jvm_consume_input_stream(struct wsgi_request *, size_t, jobject);
jobject uwsgi_jvm_num(long);
jobject uwsgi_jvm_request_body_input_stream(void);
jobject uwsgi_jvm_bool(long);

size_t uwsgi_jvm_array_len(jobject);
jobject uwsgi_jvm_array_get(jobject, long);

int uwsgi_jvm_iterator_to_response_headers(struct wsgi_request *, jobject);
jobject uwsgi_jvm_entryset(jobject);

int uwsgi_jvm_object_to_response_body(struct wsgi_request *, jobject);

jobject uwsgi_jvm_bytearray(char *, size_t);
char *uwsgi_jvm_bytearray2c(jobject);
void uwsgi_jvm_release_bytearray(jobject, char *);

jobject uwsgi_jvm_to_string(jobject);
