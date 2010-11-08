#include "../../uwsgi.h"
#include <jni.h>

#define MAX_CLASSPATH 64

#define LONG_ARGS_JVM_BASE      17000 + (300 * 100)
#define LONG_ARGS_JVM_CLASS     LONG_ARGS_JVM_BASE + 1
#define LONG_ARGS_JVM_CLASSPATH LONG_ARGS_JVM_BASE + 2

struct uwsgi_jvm {

        char *classpath[MAX_CLASSPATH];
        int classpath_cnt;

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
