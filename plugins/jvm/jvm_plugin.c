#include "../../uwsgi.h";
#include <jni.h>

#define MAX_CLASSPATH 64

#define LONG_ARGS_JVM_BASE      17000 + (300 * 100)
#define LONG_ARGS_JVM_CLASS     LONG_ARGS_JVM_BASE + 1
#define LONG_ARGS_JVM_CLASSPATH LONG_ARGS_JVM_BASE + 2

struct uwsgi_jvm {

	char *classpath[MAX_CLASSPATH];
	int classpath_cnt;

	JNIEnv	*env;
	char *class;
	jclass main_class;

} ujvm;

struct option uwsgi_jvm_options[] = {
        {"jvm-main-class", required_argument, 0, LONG_ARGS_JVM_CLASS},
        {"jvm-classpath", required_argument, 0, LONG_ARGS_JVM_CLASSPATH},
        {0, 0, 0, 0},
};

int uwsgi_jvm_exception(void) {

	if ((*ujvm.env)->ExceptionOccurred(ujvm.env)) {
                (*ujvm.env)->ExceptionDescribe(ujvm.env);
                (*ujvm.env)->ExceptionClear(ujvm.env);
                return 1;
        }
	
	return 0;
}

jclass uwsgi_jvm_get_class(char *name) {

	jclass my_class = (*ujvm.env)->FindClass(ujvm.env, name);
	
	if (uwsgi_jvm_exception()) {
		return NULL;
        }

	return my_class;
}

jmethodID uwsgi_jvm_get_method_id(jclass cls, char *name, char *signature) {

	jmethodID mid;

	mid = (*ujvm.env)->GetMethodID(ujvm.env, cls, name, signature);

	return mid;
}

jmethodID uwsgi_jvm_get_static_method_id(jclass cls, char *name, char *signature) {

	jmethodID mid;

	mid = (*ujvm.env)->GetStaticMethodID(ujvm.env, cls, name, signature);

	return mid;
}

int jvm_init(void) {

        jint res;
        JavaVM          *jvm;
        JavaVMInitArgs  vm_args;
        JavaVMOption    options[1];
	jmethodID mmid;

	int i;
	char *old_cp = NULL ;


        vm_args.version = JNI_VERSION_1_2;

        JNI_GetDefaultJavaVMInitArgs(&vm_args);

        options[0].optionString = "-Djava.class.path=.";

	if (ujvm.classpath_cnt > 0) {
		for(i=0;i<ujvm.classpath_cnt;i++) {
			if (old_cp) {
				options[0].optionString = uwsgi_concat3(old_cp, ":", ujvm.classpath[i]);
				free(old_cp);
			}	
			else {
				options[0].optionString = uwsgi_concat3(options[0].optionString, ":", ujvm.classpath[i]);
			}
			old_cp = options[0].optionString ;
		}
	}

        vm_args.options  = options;
        vm_args.nOptions = 1;

        res = JNI_CreateJavaVM(&jvm, (void **) &ujvm.env, &vm_args);

	if (res) {
		uwsgi_log("unable to initialize JVM\n");
		exit(1);
	}

	uwsgi_log("JVM initialized\n");

	if (ujvm.class) {
		ujvm.main_class = uwsgi_jvm_get_class(ujvm.class);
		if (!ujvm.main_class) {
			exit(1);
		}

		mmid = uwsgi_jvm_get_static_method_id(ujvm.main_class, "main", "([Ljava/lang/String;)V");
		if (mmid) {
			(*ujvm.env)->CallStaticVoidMethod(ujvm.env, ujvm.main_class, mmid);
			uwsgi_jvm_exception();
		}
	}

	return 1;

}


int uwsgi_jvm_manage_opt(int i, char *optarg) {

	switch(i) {
		case LONG_ARGS_JVM_CLASS:
			ujvm.class = optarg;
			return 1;
		case LONG_ARGS_JVM_CLASSPATH:
                	if (ujvm.classpath_cnt < MAX_CLASSPATH) {
                        	ujvm.classpath[ujvm.classpath_cnt] = optarg;
                                ujvm.classpath_cnt++;
                        }
                        else {
                        	uwsgi_log( "you can specify at most %d --jvm-classpath options\n", MAX_CLASSPATH);
                        }
                        return 1;
	}

	return 0;
}

struct uwsgi_plugin jvm_plugin = {

	.name = "jvm",
	.init = jvm_init,
	.options = uwsgi_jvm_options,
	.manage_opt = uwsgi_jvm_manage_opt,
};


