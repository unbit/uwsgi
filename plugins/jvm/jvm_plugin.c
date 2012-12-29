/**
 * uWSGI JVM plugin
 *
 * This plugin is the core for all of the JVM-based ones.
 * It provides various wrappers and helper for JVM-based projects.
 *
 */

/*
 *
 * Hints: with javap -s -p <class>
 *        you can get method signatures
 */

#include "jvm.h"

/*
 * Structures
 */

uwsgi_jvm ujvm;

struct uwsgi_option uwsgi_jvm_options[] = {

        {"jvm-main-class", required_argument, 0, "load the specified class", uwsgi_opt_set_str, &ujvm.str_main, 0},
        {"jvm-classpath", required_argument, 0, "add the specified directory to the classpath", uwsgi_opt_add_string_list, &ujvm.classpath, 0},
        {0, 0, 0, 0},

};

jboolean uwsgi_jvm_equal(uwsgi_jvm * pjvm, jobject obj1, jobject obj2) {

    jclass clazz = uwsgi_jvm_class_of(pjvm, obj1);
    jmethodID eq = uwsgi_jvm_method(pjvm, clazz, "equals", "(Ljava/lang/Object;)Z");

    return uwsgi_jvm_call_boolean(pjvm, obj1, eq, obj2);

}

jstring uwsgi_jvm_tostring(uwsgi_jvm * pjvm, jobject obj) {

    jclass clazz = uwsgi_jvm_class_of(pjvm, obj);
    uwsgi_jvm_default_handle(pjvm);

    jmethodID tostring = uwsgi_jvm_method(pjvm, clazz, "toString", "()Ljava/lang/String;");

    return (jstring)uwsgi_jvm_call(pjvm, obj, tostring);

}

jstring uwsgi_jvm_string_from(uwsgi_jvm * pjvm, char * chars, int length) {

    const char * UTF8 = "UTF-8";
    static jmethodID construct = 0;

    if(!construct) {

        construct = uwsgi_jvm_method(pjvm, pjvm->class_string, "<init>", "([BLjava/lang/String;)V");

    }

    jobject utf8 = uwsgi_jvm_utf8(pjvm, UTF8);

    jbyteArray array = uwsgi_jvm_array_byte(pjvm, length);
    uwsgi_jvm_array_set_region_byte(pjvm, array, 0, length, (jbyte *) chars);
    jobject result = uwsgi_jvm_new(pjvm, pjvm->class_string, construct, array, utf8);
    uwsgi_jvm_default_handle(pjvm);

    return result;

}

const jchar * uwsgi_jvm_tostrchars(uwsgi_jvm * pjvm, jobject obj) {

    return uwsgi_jvm_strchars(pjvm, uwsgi_jvm_tostring(pjvm, obj));

}

const char * uwsgi_jvm_toutf8chars(uwsgi_jvm * pjvm, jobject obj) {

    return uwsgi_jvm_utf8chars(pjvm, uwsgi_jvm_tostring(pjvm, obj));

}

jobject uwsgi_jvm_hashtable(uwsgi_jvm * pjvm) {

    static jmethodID construct = 0;

    if (!construct) {

        construct = uwsgi_jvm_method(pjvm, pjvm->class_hashtable, "<init>", "()V");

    }

    return uwsgi_jvm_new(pjvm, pjvm->class_hashtable, construct);
}

jint uwsgi_jvm_hashtable_size(uwsgi_jvm * pjvm, jobject obj) {

    static jmethodID size = 0 ;

    if (!size) {

        size = uwsgi_jvm_method(pjvm, pjvm->class_hashtable, "size", "()I");

    }

    return uwsgi_jvm_call_int(pjvm, obj, size);
}

jobject uwsgi_jvm_hashtable_get(uwsgi_jvm * pjvm, jobject obj, jobject key) {

    static jmethodID get = 0 ;

    if (!get) {

        get = uwsgi_jvm_method(pjvm, pjvm->class_hashtable, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");

    }

    return uwsgi_jvm_call(pjvm, obj, get, key);
}

jobject uwsgi_jvm_hashtable_put(uwsgi_jvm * pjvm, jobject obj, jobject key, jobject val) {

    static jmethodID put = 0 ;

    if (!put) {

        put = uwsgi_jvm_method(pjvm, pjvm->class_hashtable, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    }

    return uwsgi_jvm_call(pjvm, obj, put, key, val);
}

jobject uwsgi_jvm_fd(uwsgi_jvm * pjvm, int fd) {

    static jmethodID mid_fd = 0;
    static jfieldID fid_fd = 0;

    jobject obj_fd;

    if (!mid_fd) {

        mid_fd = uwsgi_jvm_method(pjvm,  pjvm->class_file_descriptor, "<init>", "()V");

    }

    if (!fid_fd) {

        fid_fd = uwsgi_jvm_field(pjvm, pjvm->class_file_descriptor, "fd", "I");

    }

    obj_fd = uwsgi_jvm_new(pjvm, pjvm->class_file_descriptor, mid_fd);

    uwsgi_jvm_set_int(pjvm, obj_fd, fid_fd, fd);

    return obj_fd;
}

jobject uwsgi_jvm_in(uwsgi_jvm * pjvm) {

    static jclass system;
    static jfieldID fld_in = 0;

    if(!fld_in) {

        system = uwsgi_jvm_class_for(&ujvm, "java/lang/System");
        fld_in = uwsgi_jvm_field_static(pjvm, system, "in", "Ljava/io/InputStream;");

    }

    return uwsgi_jvm_get_static(pjvm, system, fld_in);

}

jobject uwsgi_jvm_out(uwsgi_jvm * pjvm) {

    static jclass system;
    static jfieldID fld_out = 0;

    if(!fld_out) {

        system = uwsgi_jvm_class_for(&ujvm, "java/lang/System");
        fld_out = uwsgi_jvm_field_static(pjvm, system, "out", "Ljava/io/PrintStream;");

    }

    return uwsgi_jvm_get_static(pjvm, system, fld_out);

}

jobject uwsgi_jvm_err(uwsgi_jvm * pjvm) {

    static jclass system;
    static jfieldID fld_err = 0;

    if(!fld_err) {

        system = uwsgi_jvm_class_for(&ujvm, "java/lang/System");
        fld_err = uwsgi_jvm_field_static(pjvm, system, "err", "Ljava/io/PrintStream;");

    }

    return uwsgi_jvm_get_static(pjvm, system, fld_err);

}

void uwsgi_jvm_print(uwsgi_jvm * pjvm, jstring msg) {

    static jclass stream;
    static jmethodID print = 0;

    if(!print) {

        stream = uwsgi_jvm_class_for(&ujvm, "java/io/PrintStream");
        print = uwsgi_jvm_method(pjvm, stream, "print", "(Ljava/lang/String;)V");

    }

    uwsgi_jvm_call(pjvm, uwsgi_jvm_out(pjvm), print, msg);

}

void uwsgi_jvm_println(uwsgi_jvm * pjvm, jstring msg) {

    static jclass stream;
    static jmethodID print = 0;

    if(!print) {

        stream = uwsgi_jvm_class_for(&ujvm, "java/io/PrintStream");
        print = uwsgi_jvm_method(pjvm, stream, "println", "(Ljava/lang/String;)V");

    }

    uwsgi_jvm_call(pjvm, uwsgi_jvm_out(pjvm), print, msg);

}

// JVM initialization

int jvm_init(void) {

    jint res;
    JavaVM          *jvm;
    JavaVMInitArgs  vm_args;
    JavaVMOption    options[1];
    jmethodID       mid_main;

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

    ujvm.class_string = uwsgi_jvm_class_for(&ujvm, "java/lang/String");
    uwsgi_log("JVM String class initialized\n");
    ujvm.class_hashtable  = uwsgi_jvm_class_for(&ujvm, "java/util/Hashtable");
    uwsgi_log("JVM Hashtable class initialized\n");
    ujvm.class_file_descriptor  = uwsgi_jvm_class_for(&ujvm, "java/io/FileDescriptor");
    uwsgi_log("JVM FileDescriptor class initialized\n");

    const char * UTF8 = "UTF-8";
    jobject utf8 = uwsgi_jvm_utf8(&ujvm, UTF8);
    uwsgi_jvm_println(&ujvm, utf8);

    if (ujvm.str_main) {
        ujvm.class_main = uwsgi_jvm_class_for(&ujvm, ujvm.str_main);
        if (!ujvm.class_main) {
            exit(1);
        }

        mid_main = uwsgi_jvm_method_static(&ujvm, ujvm.class_main, "main", "([Ljava/lang/String;)V");
        if (mid_main) {
            uwsgi_jvm_call_static(&ujvm, ujvm.class_main, mid_main);
            uwsgi_jvm_default_handle(&ujvm);
        }
    }

    return 1;
}

struct uwsgi_plugin jvm_plugin = {

    .name = "jvm",
    .init = jvm_init,
    .options = uwsgi_jvm_options,
};


