#include "../../uwsgi.h"
#include <jni.h>

struct uwsgi_jvm {

        struct uwsgi_string_list *classpath;

        JNIEnv  *env;
        char *class;
        jclass main_class;

	jclass str_class;
	jclass ht_class;
	jclass fd_class;
};


jmethodID uwsgi_jvm_get_method_id(jclass, char *, char *);
jmethodID uwsgi_jvm_get_static_method_id(jclass, char *, char *);
jclass uwsgi_jvm_get_class(char *);
jclass uwsgi_jvm_get_object_class(jobject);
int uwsgi_jvm_exception(void);

jobject uwsgi_jvm_str_new(char *, int );
jobject uwsgi_jvm_str(char *);

jobject uwsgi_jvm_array_get(jobject , int );
jobject uwsgi_jvm_ht_new(void);
jobject uwsgi_jvm_ht_put(jobject, jobject, jobject);

jobject uwsgi_jvm_fd(int);

char *uwsgi_jvm_str2c(jobject);
int uwsgi_jvm_strlen2c(jobject);
