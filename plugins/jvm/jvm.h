#include <uwsgi.h>
#include <jni.h>
#include <jvmti.h>

struct uwsgi_jvm {

        JNIEnv  *env;

        struct uwsgi_string_list *classpath;
        struct uwsgi_string_list *classes;
        struct uwsgi_string_list *main_classes;

	jclass str_class;
};


jclass uwsgi_jvm_class(char *);
jobject uwsgi_jvm_ref(jobject);
void uwsgi_jvm_unref(jobject);
int uwsgi_jvm_call_static(jclass, jmethodID);

void uwsgi_jvm_clear_exception(void);
