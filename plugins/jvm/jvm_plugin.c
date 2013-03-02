#include "jvm.h"

/*

with javap -s -p <class>
you can get method signatures

This plugin is the core for all of the JVM-based ones

*/

extern struct uwsgi_server uwsgi;

JNIEXPORT jint JNICALL uwsgi_jvm_api_worker_id(JNIEnv *env) {
	return uwsgi.mywid;
}

JNIEXPORT void JNICALL uwsgi_jvm_api_hello(JNIEnv *env, jclass c) {
	uwsgi_log("AAAA\n");
}

static JNINativeMethod uwsgi_jvm_api_methods[] = {
	{"worker_id", "()I", (void *) &uwsgi_jvm_api_worker_id},
	{"hello", "()V", (void *) &uwsgi_jvm_api_hello},
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
	return (*ujvm.env)->NewLocalRef(ujvm.env, obj);
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
	
	return uwsgi_jvm_ref(new_str);
}

int uwsgi_jvm_call_static(jclass c, jmethodID mid) {
	(*ujvm.env)->CallStaticVoidMethod(ujvm.env, c, mid);
        return uwsgi_jvm_exception();
}

static int uwsgi_jvm_init(void) {

	JavaVM *jvm;
	JavaVMInitArgs vm_args;
	JavaVMOption options[1];

	vm_args.version = JNI_VERSION_1_2;

	JNI_GetDefaultJavaVMInitArgs(&vm_args);

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

	vm_args.options  = options;
	vm_args.nOptions = 1;

	if (JNI_CreateJavaVM(&jvm, (void **) &ujvm.env, &vm_args)) {
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

	jclass uwsgi_class = uwsgi_jvm_class("uwsgi");
	if (!uwsgi_class) {
		exit(1);
	}
	(*ujvm.env)->RegisterNatives(ujvm.env, uwsgi_class, uwsgi_jvm_api_methods, sizeof(uwsgi_jvm_api_methods)/sizeof(uwsgi_jvm_api_methods[0]));
	if (uwsgi_jvm_exception()) {
		exit(1);
	}

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
/*
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

    ujvm.str_class = uwsgi_jvm_get_class("java/lang/String");
    ujvm.ht_class = uwsgi_jvm_get_class("java/util/Hashtable");
*/

	return 1;

}

// get the raw body of a java string
char *uwsgi_jvm_str2c(jobject obj) {
    return (char *) (*ujvm.env)->GetStringUTFChars(ujvm.env, obj, NULL);
}

// return the size of a java string (UTF8)
size_t uwsgi_jvm_strlen(jobject obj) {
	return (*ujvm.env)->GetStringUTFLength(ujvm.env, obj);
}

struct uwsgi_plugin jvm_plugin = {
	.name = "jvm",
	.init = uwsgi_jvm_init,
	.options = uwsgi_jvm_options,
};


