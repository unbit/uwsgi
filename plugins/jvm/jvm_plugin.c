#include "jvm.h"

/*

with javap -s -p <class>
you can get method signatures

This plugin is the core for all of the JVM-based ones

*/

struct uwsgi_jvm ujvm;

struct uwsgi_option uwsgi_jvm_options[] = {
        {"jvm-main-class", required_argument, 0, "load the specified class", uwsgi_opt_set_str, &ujvm.class, 0},
        {"jvm-classpath", required_argument, 0, "add the specified directory to the classpath", uwsgi_opt_add_string_list, &ujvm.classpath, 0},
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

jclass uwsgi_jvm_get_object_class(jobject obj) {
	return (*ujvm.env)->GetObjectClass(ujvm.env, obj);
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

jobject uwsgi_jvm_str_new(char *str, int len) {

	jbyteArray ba;
	static jmethodID str_new_mid = 0;

	if (!str_new_mid) {
		str_new_mid = uwsgi_jvm_get_method_id(ujvm.str_class, "<init>", "([BLjava/lang/String;)V");
	}

	ba = (*ujvm.env)->NewByteArray(ujvm.env, len);
        (*ujvm.env)->SetByteArrayRegion(ujvm.env, ba, 0, len, (jbyte *) str);
        return (*ujvm.env)->NewObject(ujvm.env, ujvm.str_class, str_new_mid, ba,
        		(*ujvm.env)->NewStringUTF(ujvm.env, "UTF-8"));
}

jobject uwsgi_jvm_str(char *str) {
	return (*ujvm.env)->NewStringUTF(ujvm.env, str);
}


int jvm_init(void) {

        jint res;
        JavaVM          *jvm;
        JavaVMInitArgs  vm_args;
        JavaVMOption    options[1];
	jmethodID mmid;

	char *old_cp = NULL ;


        vm_args.version = JNI_VERSION_1_2;

        JNI_GetDefaultJavaVMInitArgs(&vm_args);

        options[0].optionString = "-Djava.class.path=.";

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

	ujvm.str_class = uwsgi_jvm_get_class("java/lang/String");
	ujvm.ht_class = uwsgi_jvm_get_class("java/util/Hashtable");
	ujvm.fd_class = uwsgi_jvm_get_class("java/io/FileDescriptor");

	return 1;

}

jobject uwsgi_jvm_array_get(jobject obj, int index) {
	return (*ujvm.env)->GetObjectArrayElement(ujvm.env, obj, index);
}

jobject uwsgi_jvm_ht_new() {
	static jmethodID htimid = 0;

	if (!htimid) {
		htimid = uwsgi_jvm_get_method_id(ujvm.ht_class, "<init>", "()V");
	}

	return (*ujvm.env)->NewObject(ujvm.env, ujvm.ht_class, htimid);
}

jobject uwsgi_jvm_ht_put(jobject obj, jobject key, jobject val) {
	
	static jmethodID htpmid = 0 ;

	if (!htpmid) {
		htpmid = uwsgi_jvm_get_method_id(ujvm.ht_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
	}

        return (*ujvm.env)->CallObjectMethod(ujvm.env, obj, htpmid, key, val);
}

jobject uwsgi_jvm_fd(int fd) {

	jobject fd_obj;
	static jmethodID fd_mid = 0;
	static jfieldID fd_field = 0 ;

	if (!fd_mid) {
		fd_mid = uwsgi_jvm_get_method_id( ujvm.fd_class, "<init>", "()V");	
	}

        fd_obj = (*ujvm.env)->NewObject(ujvm.env, ujvm.fd_class, fd_mid);

	if (!fd_field) {
        	fd_field = (*ujvm.env)->GetFieldID(ujvm.env, ujvm.fd_class, "fd", "I");
	}

        (*ujvm.env)->SetIntField(ujvm.env, fd_obj, fd_field, fd);

	return fd_obj;
}

char *uwsgi_jvm_str2c(jobject obj) {

	return (char *) (*ujvm.env)->GetStringUTFChars(ujvm.env, obj, NULL);
}

int uwsgi_jvm_strlen2c(jobject obj) {

	return (*ujvm.env)->GetStringUTFLength(ujvm.env, obj);
}

struct uwsgi_plugin jvm_plugin = {

	.name = "jvm",
	.init = jvm_init,
	.options = uwsgi_jvm_options,
};


