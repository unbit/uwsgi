/**
 * uWSGI JVM plugin
 *
 * This plugin is the core for all of the JVM-based ones.
 * It provides various wrappers and helper for JVM-based projects.
 *
 */

#include <stdarg.h>
#include "../../uwsgi.h"
#include <jni.h>

/*
 *  Structures
 */

typedef struct {

    struct uwsgi_string_list * classpath;

    JNIEnv * env;

    char *   str_main;
    jclass   class_main;

    jclass class_string;
    jclass class_hashtable;
    jclass class_file_descriptor;

} uwsgi_jvm;

/*  Inline JNI wrappers and helpers
 *
 *  - General wrappers and helpers
 *
 *  static inline jboolean  uwsgi_jvm_begin(uwsgi_jvm *, jint);
 *  static inline jboolean  uwsgi_jvm_ensure(uwsgi_jvm *, jint);
 *  static inline jobject   uwsgi_jvm_claim(uwsgi_jvm *, jobject);
 *  static inline void      uwsgi_jvm_delete(uwsgi_jvm *, jobject);
 *  static inline void      uwsgi_jvm_end(uwsgi_jvm *);
 */

static inline jboolean uwsgi_jvm_begin(uwsgi_jvm * pjvm, jint max_ref_count) {

    if ((*(pjvm->env))->PushLocalFrame(pjvm->env, max_ref_count) < 0) {

        uwsgi_log("jwsgi can not allocate frame!");
        return JNI_TRUE;

    }

    return JNI_FALSE;

}

static inline jboolean uwsgi_jvm_ensure(uwsgi_jvm * pjvm, jint max_ref_count) {

    if ((*(pjvm->env))->EnsureLocalCapacity(pjvm->env, max_ref_count) < 0) {

        uwsgi_log("jwsgi can not allocate frame!");
        return JNI_TRUE;

    }

    return JNI_FALSE;

}

static inline jobject uwsgi_jvm_claim(uwsgi_jvm * pjvm, jobject obj) {

    return (*(pjvm->env))->NewLocalRef(pjvm->env, obj);

}

static inline void uwsgi_jvm_delete(uwsgi_jvm * pjvm, jobject obj) {

    (*(pjvm->env))->DeleteLocalRef(pjvm->env, obj);

}

static inline void uwsgi_jvm_end(uwsgi_jvm * pjvm) {

    (*(pjvm->env))->PopLocalFrame(pjvm->env, NULL);

}

/*  Inline JNI wrappers and helpers
 *
 *  - excpetion wrappers and helpers
 *
 *  static inline jint      uwsgi_jvm_throw(uwsgi_jvm *, jthowable);
 *  static inline jint      uwsgi_jvm_throw_new(uwsgi_jvm *, jclass, const char *);
 *  static inline void      uwsgi_jvm_fatal(uwsgi_jvm *, const char *);
 *  static inline jthowable uwsgi_jvm_catch(uwsgi_jvm *);
 *  static inline void      uwsgi_jvm_describe(uwsgi_jvm *);
 *  static inline void      uwsgi_jvm_clear(uwsgi_jvm *);
 *  static inline jint      uwsgi_jvm_defalt_handle(uwsgi_jvm *);
 */

static inline jint uwsgi_jvm_throw(uwsgi_jvm * pjvm, jthrowable obj) {

     return (*(pjvm->env))->Throw(pjvm->env, obj);

}

static inline jint uwsgi_jvm_throw_new(uwsgi_jvm * pjvm, jclass clazz, const char * msg) {

    return (*(pjvm->env))->ThrowNew(pjvm->env, clazz, msg);

}

static inline void uwsgi_jvm_fatal(uwsgi_jvm * pjvm, const char * msg) {

    (*(pjvm->env))->FatalError(pjvm->env, msg);

}

static inline jthrowable uwsgi_jvm_catch(uwsgi_jvm * pjvm) {

     return (*(pjvm->env))->ExceptionOccurred(pjvm->env);

}

static inline void uwsgi_jvm_describe(uwsgi_jvm * pjvm) {

    (*(pjvm->env))->ExceptionDescribe(pjvm->env);

}

static inline void uwsgi_jvm_clear(uwsgi_jvm * pjvm) {

    (*(pjvm->env))->ExceptionClear(pjvm->env);

}

static inline jint uwsgi_jvm_default_handle(uwsgi_jvm * pjvm) {

    if (uwsgi_jvm_catch(pjvm)) {

        uwsgi_jvm_describe(pjvm);
        uwsgi_jvm_clear(pjvm);

        return JNI_ERR;
    }

    return JNI_OK;

}

/*  Inline JNI wrappers and helpers
 *
 *  - class wrappers and helpers
 *
 *  static inline jclass    uwsgi_jvm_class_for(uwsgi_jvm *, char *);
 *  static inline jclass    uwsgi_jvm_class_of(uwsgi_jvm *, jobject);
 *  static inline jclass    uwsgi_jvm_super(uwsgi_jvm *, jclass);
 *  static inline jboolean  uwsgi_jvm_assignable(uwsgi_jvm *, jclass, jclass);
 */

static inline jclass uwsgi_jvm_class_for(uwsgi_jvm * pjvm, char * name) {

    jclass clazz = (*(pjvm->env))->FindClass(pjvm->env, name);

    if (uwsgi_jvm_default_handle(pjvm)) {
        return NULL;
    }

    return clazz;

}

static inline jclass uwsgi_jvm_class_of(uwsgi_jvm * pjvm, jobject obj) {

    return (*(pjvm->env))->GetObjectClass(pjvm->env, obj);

}

static inline jclass uwsgi_jvm_super(uwsgi_jvm * pjvm, jclass clazz) {

    return (*(pjvm->env))->GetSuperclass(pjvm->env, clazz);

}

static inline jboolean uwsgi_jvm_assignable(uwsgi_jvm * pjvm, jclass sub, jclass sup) {

    return (*(pjvm->env))->IsAssignableFrom(pjvm->env, sub, sup);

}

/*  Inline JNI wrappers and helpers
 *
 *  - field and method wrappers
 *
 *  static inline jfieldID  uwsgi_jvm_field(uwsgi_jvm *, jclass, char *, char *);
 *  static inline jfieldID  uwsgi_jvm_field_static(uwsgi_jvm *, jclass, char *, char *);
 *  static inline jmethodID uwsgi_jvm_method(uwsgi_jvm *, jclass, char *, char *);
 *  static inline jmethodID uwsgi_jvm_method_static(uwsgi_jvm *, jclass, char *, char *);
 */

static inline jfieldID uwsgi_jvm_field(uwsgi_jvm * pjvm, jclass clazz, char * name, char * sig) {

    return (*(pjvm->env))->GetFieldID(pjvm->env, clazz, name, sig);

}

static inline jfieldID uwsgi_jvm_field_static(uwsgi_jvm * pjvm, jclass clazz, char * name, char * sig) {

    return (*(pjvm->env))->GetStaticFieldID(pjvm->env, clazz, name, sig);

}

static inline jmethodID uwsgi_jvm_method(uwsgi_jvm * pjvm, jclass clazz, char * name, char * sig) {

    return (*(pjvm->env))->GetMethodID(pjvm->env, clazz, name, sig);

}

static inline jmethodID uwsgi_jvm_method_static(uwsgi_jvm * pjvm, jclass clazz, char * name, char * sig) {

    return (*(pjvm->env))->GetStaticMethodID(pjvm->env, clazz, name, sig);

}

/*  Inline JNI wrappers and helpers
 *
 *  - object wrappers
 *
 *  static inline jobject   uwsgi_jvm_new(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline jboolean  uwsgi_jvm_same(uwsgi_jvm *, jobject, jobject);
 *  static inline jboolean  uwsgi_jvm_is_a(uwsgi_jvm *, jobject, jclass);
 */

static inline jobject uwsgi_jvm_new(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->NewObject(pjvm->env, clazz, methodID, args);

}

static inline jboolean uwsgi_jvm_same(uwsgi_jvm * pjvm, jobject obj1, jobject obj2) {

    return (*(pjvm->env))->IsSameObject(pjvm->env, obj1, obj2);

}

static inline jboolean uwsgi_jvm_is_a(uwsgi_jvm * pjvm, jobject obj, jclass clazz) {

    return (*(pjvm->env))->IsInstanceOf(pjvm->env, obj, clazz);

}

/*  Inline JNI wrappers and helpers
 *
 *  - object field read
 *
 *  static inline jobject   uwsgi_jvm_get(uwsgi_jvm *, jobject, jfieldID);
 *  static inline jboolean  uwsgi_jvm_get_boolean(uwsgi_jvm *, jobject, jfieldID);
 *  static inline jbyte     uwsgi_jvm_get_byte(uwsgi_jvm *, jobject, jfieldID);
 *  static inline jchar     uwsgi_jvm_get_char(uwsgi_jvm *, jobject, jfieldID);
 *  static inline jshort    uwsgi_jvm_get_short(uwsgi_jvm *, jobject, jfieldID);
 *  static inline jint      uwsgi_jvm_get_int(uwsgi_jvm *, jobject, jfieldID);
 *  static inline jlong     uwsgi_jvm_get_long(uwsgi_jvm *, jobject, jfieldID);
 *  static inline jfloat    uwsgi_jvm_get_float(uwsgi_jvm *, jobject, jfieldID);
 *  static inline jdouble   uwsgi_jvm_get_double(uwsgi_jvm *, jobject, jfieldID);
 *  static inline jstring   uwsgi_jvm_get_string(uwsgi_jvm *, jobject, jfieldID);
 *  static inline char *    uwsgi_jvm_get_utf8(uwsgi_jvm *, jobject, jfieldID);
 */

static inline jobject uwsgi_jvm_get(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return (*(pjvm->env))->GetObjectField(pjvm->env, obj, fieldID);

}

static inline jboolean uwsgi_jvm_get_boolean(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return (*(pjvm->env))->GetBooleanField(pjvm->env, obj, fieldID);

}

static inline jbyte uwsgi_jvm_get_byte(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return (*(pjvm->env))->GetByteField(pjvm->env, obj, fieldID);

}

static inline jchar uwsgi_jvm_get_char(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return (*(pjvm->env))->GetCharField(pjvm->env, obj, fieldID);

}

static inline jshort uwsgi_jvm_get_short(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return (*(pjvm->env))->GetShortField(pjvm->env, obj, fieldID);

}

static inline jint uwsgi_jvm_get_int(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return (*(pjvm->env))->GetIntField(pjvm->env, obj, fieldID);

}

static inline jlong uwsgi_jvm_get_long(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return (*(pjvm->env))->GetLongField(pjvm->env, obj, fieldID);

}

static inline jfloat uwsgi_jvm_get_float(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return (*(pjvm->env))->GetFloatField(pjvm->env, obj, fieldID);

}

static inline jdouble uwsgi_jvm_get_double(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return (*(pjvm->env))->GetDoubleField(pjvm->env, obj, fieldID);

}

static inline jstring uwsgi_jvm_get_string(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return (jstring)((*(pjvm->env))->GetObjectField(pjvm->env, obj, fieldID));

}

static inline char * uwsgi_jvm_get_utf8(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID) {

    return NULL; //TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - object field write
 *
 *  static inline void    uwsgi_jvm_set(uwsgi_jvm *, jobject, jfieldID, jobject);
 *  static inline void    uwsgi_jvm_set_boolean(uwsgi_jvm *, jobject, jfieldID, jboolean);
 *  static inline void    uwsgi_jvm_set_byte(uwsgi_jvm *, jobject, jfieldID, jbyte);
 *  static inline void    uwsgi_jvm_set_char(uwsgi_jvm *, jobject, jfieldID, jchar);
 *  static inline void    uwsgi_jvm_set_short(uwsgi_jvm *, jobject, jfieldID, jshort);
 *  static inline void    uwsgi_jvm_set_int(uwsgi_jvm *, jobject, jfieldID, jint);
 *  static inline void    uwsgi_jvm_set_long(uwsgi_jvm *, jobject, jfieldID, jlong);
 *  static inline void    uwsgi_jvm_set_float(uwsgi_jvm *, jobject, jfieldID, jfloat);
 *  static inline void    uwsgi_jvm_set_double(uwsgi_jvm *, jobject, jfieldID, jdouble);
 *  static inline void    uwsgi_jvm_set_string(uwsgi_jvm *, jobject, jfieldID, jstring);
 *  static inline void    uwsgi_jvm_set_utf8(uwsgi_jvm *, jobject, jfieldID, char *);
 */

static inline void uwsgi_jvm_set(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, jobject val) {

    (*(pjvm->env))->SetObjectField(pjvm->env, obj, fieldID, val);

}

static inline void uwsgi_jvm_set_boolean(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, jboolean val) {

    (*(pjvm->env))->SetBooleanField(pjvm->env, obj, fieldID, val);

}

static inline void uwsgi_jvm_set_byte(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, jbyte val) {

    (*(pjvm->env))->SetByteField(pjvm->env, obj, fieldID, val);

}

static inline void uwsgi_jvm_set_char(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, jchar val) {

    (*(pjvm->env))->SetCharField(pjvm->env, obj, fieldID, val);

}

static inline void uwsgi_jvm_set_short(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, jshort val) {

    (*(pjvm->env))->SetShortField(pjvm->env, obj, fieldID, val);

}

static inline void uwsgi_jvm_set_int(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, jint val) {

    (*(pjvm->env))->SetIntField(pjvm->env, obj, fieldID, val);

}

static inline void uwsgi_jvm_set_long(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, jlong val) {

    (*(pjvm->env))->SetLongField(pjvm->env, obj, fieldID, val);

}

static inline void uwsgi_jvm_set_float(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, jfloat val) {

    (*(pjvm->env))->SetFloatField(pjvm->env, obj, fieldID, val);

}

static inline void uwsgi_jvm_set_double(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, jdouble val) {

    (*(pjvm->env))->SetDoubleField(pjvm->env, obj, fieldID, val);

}

static inline void uwsgi_jvm_set_string(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, jstring val) {

    (*(pjvm->env))->SetObjectField(pjvm->env, obj, fieldID, val);

}

static inline void uwsgi_jvm_set_utf8(uwsgi_jvm * pjvm, jobject obj, jfieldID fieldID, char * val) {

    //TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - class field read
 *
 *  static inline jobject   uwsgi_jvm_get_static(uwsgi_jvm *, jclass, jfieldID);
 *  static inline jboolean  uwsgi_jvm_get_static_boolean(uwsgi_jvm *, jclass, jfieldID);
 *  static inline jbyte     uwsgi_jvm_get_static_byte(uwsgi_jvm *, jclass, jfieldID);
 *  static inline jchar     uwsgi_jvm_get_static_char(uwsgi_jvm *, jclass, jfieldID);
 *  static inline jshort    uwsgi_jvm_get_static_short(uwsgi_jvm *, jclass, jfieldID);
 *  static inline jint      uwsgi_jvm_get_static_int(uwsgi_jvm *, jclass, jfieldID);
 *  static inline jlong     uwsgi_jvm_get_static_long(uwsgi_jvm *, jclass, jfieldID);
 *  static inline jfloat    uwsgi_jvm_get_static_float(uwsgi_jvm *, jclass, jfieldID);
 *  static inline jdouble   uwsgi_jvm_get_static_double(uwsgi_jvm *, jclass, jfieldID);
 *  static inline jstring   uwsgi_jvm_get_static_string(uwsgi_jvm *, jclass, jfieldID);
 *  static inline char *    uwsgi_jvm_get_static_utf8(uwsgi_jvm *, jclass, jfieldID);
 */

static inline jobject uwsgi_jvm_get_static(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return (*(pjvm->env))->GetStaticObjectField(pjvm->env, clazz, fieldID);

}

static inline jboolean uwsgi_jvm_get_static_boolean(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return (*(pjvm->env))->GetStaticBooleanField(pjvm->env, clazz, fieldID);

}

static inline jbyte uwsgi_jvm_get_static_byte(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return (*(pjvm->env))->GetStaticByteField(pjvm->env, clazz, fieldID);

}

static inline jchar uwsgi_jvm_get_static_char(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return (*(pjvm->env))->GetStaticCharField(pjvm->env, clazz, fieldID);

}

static inline jshort uwsgi_jvm_get_static_short(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return (*(pjvm->env))->GetStaticShortField(pjvm->env, clazz, fieldID);

}

static inline jint uwsgi_jvm_get_static_int(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return (*(pjvm->env))->GetStaticIntField(pjvm->env, clazz, fieldID);

}

static inline jlong uwsgi_jvm_get_static_long(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return (*(pjvm->env))->GetStaticLongField(pjvm->env, clazz, fieldID);

}

static inline jfloat uwsgi_jvm_get_static_float(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return (*(pjvm->env))->GetStaticFloatField(pjvm->env, clazz, fieldID);

}

static inline jdouble uwsgi_jvm_get_static_double(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return (*(pjvm->env))->GetStaticDoubleField(pjvm->env, clazz, fieldID);

}

static inline jstring uwsgi_jvm_get_static_string(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return (jstring)((*(pjvm->env))->GetStaticObjectField(pjvm->env, clazz, fieldID));

}

static inline char * uwsgi_jvm_get_static_utf8(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID) {

    return NULL; //TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - class field write
 *
 *  static inline void    uwsgi_jvm_set_static(uwsgi_jvm *, jclass, jfieldID, jobject);
 *  static inline void    uwsgi_jvm_set_static_boolean(uwsgi_jvm *, jclass, jfieldID, jboolean);
 *  static inline void    uwsgi_jvm_set_static_byte(uwsgi_jvm *, jclass, jfieldID, jbyte);
 *  static inline void    uwsgi_jvm_set_static_char(uwsgi_jvm *, jclass, jfieldID, jchar);
 *  static inline void    uwsgi_jvm_set_static_short(uwsgi_jvm *, jclass, jfieldID, jshort);
 *  static inline void    uwsgi_jvm_set_static_int(uwsgi_jvm *, jclass, jfieldID, jint);
 *  static inline void    uwsgi_jvm_set_static_long(uwsgi_jvm *, jclass, jfieldID, jlong);
 *  static inline void    uwsgi_jvm_set_static_float(uwsgi_jvm *, jclass, jfieldID, jfloat);
 *  static inline void    uwsgi_jvm_set_static_double(uwsgi_jvm *, jclass, jfieldID, jdouble);
 *  static inline void    uwsgi_jvm_set_static_string(uwsgi_jvm *, jclass, jfieldID, jstring);
 *  static inline void    uwsgi_jvm_set_static_utf8(uwsgi_jvm *, jclass, jfieldID, char *);
 */

static inline void uwsgi_jvm_set_static(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, jobject val) {

    (*(pjvm->env))->SetStaticObjectField(pjvm->env, clazz, fieldID, val);

}

static inline void uwsgi_jvm_set_static_boolean(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, jboolean val) {

    (*(pjvm->env))->SetStaticBooleanField(pjvm->env, clazz, fieldID, val);

}

static inline void uwsgi_jvm_set_static_byte(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, jbyte val) {

    (*(pjvm->env))->SetStaticByteField(pjvm->env, clazz, fieldID, val);

}

static inline void uwsgi_jvm_set_static_char(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, jchar val) {

    (*(pjvm->env))->SetStaticCharField(pjvm->env, clazz, fieldID, val);

}

static inline void uwsgi_jvm_set_static_short(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, jshort val) {

    (*(pjvm->env))->SetStaticShortField(pjvm->env, clazz, fieldID, val);

}

static inline void uwsgi_jvm_set_static_int(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, jint val) {

    (*(pjvm->env))->SetStaticIntField(pjvm->env, clazz, fieldID, val);

}

static inline void uwsgi_jvm_set_static_long(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, jlong val) {

    (*(pjvm->env))->SetStaticLongField(pjvm->env, clazz, fieldID, val);

}

static inline void uwsgi_jvm_set_static_float(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, jfloat val) {

    (*(pjvm->env))->SetStaticFloatField(pjvm->env, clazz, fieldID, val);

}

static inline void uwsgi_jvm_set_static_double(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, jdouble val) {

    (*(pjvm->env))->SetStaticDoubleField(pjvm->env, clazz, fieldID, val);

}

static inline void uwsgi_jvm_set_static_string(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, jstring val) {

    (*(pjvm->env))->SetStaticObjectField(pjvm->env, clazz, fieldID, val);

}

static inline void uwsgi_jvm_set_static_utf8(uwsgi_jvm * pjvm, jclass clazz, jfieldID fieldID, char * val) {

    //TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - object method call
 *
 *  static inline jobject   uwsgi_jvm_call(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline jboolean  uwsgi_jvm_call_boolean(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline jint      uwsgi_jvm_call_byte(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline jchar     uwsgi_jvm_call_char(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline jshort    uwsgi_jvm_call_short(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline jint      uwsgi_jvm_call_int(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline jlong     uwsgi_jvm_call_long(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline jfloat    uwsgi_jvm_call_float(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline jdouble   uwsgi_jvm_call_double(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline void      uwsgi_jvm_call_void(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline jstring   uwsgi_jvm_call_string(uwsgi_jvm *, jobject, jmethodID, ...);
 *  static inline char *    uwsgi_jvm_call_utf8(uwsgi_jvm *, jobject, jmethodID, ...);
 */

static inline jobject uwsgi_jvm_call(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallObjectMethod(pjvm->env, obj, methodID, args);

}

static inline jboolean uwsgi_jvm_call_boolean(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallBooleanMethod(pjvm->env, obj, methodID, args);

}

static inline jint uwsgi_jvm_call_byte(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallByteMethod(pjvm->env, obj, methodID, args);

}

static inline jchar uwsgi_jvm_call_char(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallCharMethod(pjvm->env, obj, methodID, args);

}

static inline jshort uwsgi_jvm_call_short(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallShortMethod(pjvm->env, obj, methodID, args);

}

static inline jint uwsgi_jvm_call_int(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallIntMethod(pjvm->env, obj, methodID, args);

}

static inline jlong uwsgi_jvm_call_long(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallLongMethod(pjvm->env, obj, methodID, args);

}

static inline jfloat uwsgi_jvm_call_float(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallFloatMethod(pjvm->env, obj, methodID, args);

}

static inline jdouble uwsgi_jvm_call_double(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallDoubleMethod(pjvm->env, obj, methodID, args);

}

static inline void uwsgi_jvm_call_void(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    (*(pjvm->env))->CallVoidMethod(pjvm->env, obj, methodID, args);

}

static inline jstring uwsgi_jvm_call_string(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (jstring)(*(pjvm->env))->CallObjectMethod(pjvm->env, obj, methodID, args);

}

static inline char * uwsgi_jvm_call_utf8(uwsgi_jvm * pjvm, jobject obj, jmethodID methodID, ...) {

    return NULL; // TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - direct object method call
 *
 *  static inline jobject   uwsgi_jvm_call_direct(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline jboolean  uwsgi_jvm_call_direct_boolean(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline jint      uwsgi_jvm_call_direct_byte(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline jchar     uwsgi_jvm_call_direct_char(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline jshort    uwsgi_jvm_call_direct_short(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline jint      uwsgi_jvm_call_direct_int(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline jlong     uwsgi_jvm_call_direct_long(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline jfloat    uwsgi_jvm_call_direct_float(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline jdouble   uwsgi_jvm_call_direct_double(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline void      uwsgi_jvm_call_direct_void(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline jstring   uwsgi_jvm_call_direct_string(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 *  static inline char *    uwsgi_jvm_call_direct_utf8(uwsgi_jvm *, jobject, jclass, jmethodID, ...);
 */

static inline jobject uwsgi_jvm_call_direct(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallNonvirtualObjectMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline jboolean uwsgi_jvm_call_direct_boolean(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallNonvirtualBooleanMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline jint uwsgi_jvm_call_direct_byte(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallNonvirtualByteMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline jchar uwsgi_jvm_call_direct_char(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallNonvirtualCharMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline jshort uwsgi_jvm_call_direct_short(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallNonvirtualShortMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline jint uwsgi_jvm_call_direct_int(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallNonvirtualIntMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline jlong uwsgi_jvm_call_direct_long(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallNonvirtualLongMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline jfloat uwsgi_jvm_call_direct_float(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallNonvirtualFloatMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline jdouble uwsgi_jvm_call_direct_double(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallNonvirtualDoubleMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline void uwsgi_jvm_call_direct_void(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    (*(pjvm->env))->CallNonvirtualVoidMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline jstring uwsgi_jvm_call_direct_string(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (jstring)(*(pjvm->env))->CallNonvirtualObjectMethod(pjvm->env, obj, clazz, methodID, args);

}

static inline char * uwsgi_jvm_call_direct_utf8(uwsgi_jvm * pjvm, jobject obj, jclass clazz, jmethodID methodID, ...) {

    return NULL; // TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - class method call
 *
 *  static inline jobject   uwsgi_jvm_call_static(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline jboolean  uwsgi_jvm_call_static_boolean(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline jint      uwsgi_jvm_call_static_byte(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline jchar     uwsgi_jvm_call_static_char(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline jshort    uwsgi_jvm_call_static_short(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline jint      uwsgi_jvm_call_static_int(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline jlong     uwsgi_jvm_call_static_long(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline jfloat    uwsgi_jvm_call_static_float(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline jdouble   uwsgi_jvm_call_static_double(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline void      uwsgi_jvm_call_static_void(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline jstring   uwsgi_jvm_call_static_string(uwsgi_jvm *, jclass, jmethodID, ...);
 *  static inline char *    uwsgi_jvm_call_static_utf8(uwsgi_jvm *, jclass, jmethodID, ...);
 */

static inline jclass uwsgi_jvm_call_static(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallStaticObjectMethod(pjvm->env, clazz, methodID, args);

}

static inline jboolean uwsgi_jvm_call_static_boolean(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallStaticBooleanMethod(pjvm->env, clazz, methodID, args);

}

static inline jint uwsgi_jvm_call_static_byte(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallStaticByteMethod(pjvm->env, clazz, methodID, args);

}

static inline jchar uwsgi_jvm_call_static_char(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallStaticCharMethod(pjvm->env, clazz, methodID, args);

}

static inline jshort uwsgi_jvm_call_static_short(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallStaticShortMethod(pjvm->env, clazz, methodID, args);

}

static inline jint uwsgi_jvm_call_static_int(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallStaticIntMethod(pjvm->env, clazz, methodID, args);

}

static inline jlong uwsgi_jvm_call_static_long(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallStaticLongMethod(pjvm->env, clazz, methodID, args);

}

static inline jfloat uwsgi_jvm_call_static_float(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallStaticFloatMethod(pjvm->env, clazz, methodID, args);

}

static inline jdouble uwsgi_jvm_call_static_double(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*(pjvm->env))->CallStaticDoubleMethod(pjvm->env, clazz, methodID, args);

}

static inline void uwsgi_jvm_call_static_void(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    (*(pjvm->env))->CallStaticVoidMethod(pjvm->env, clazz, methodID, args);

}

static inline jstring uwsgi_jvm_call_static_string(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (jstring)(*(pjvm->env))->CallStaticObjectMethod(pjvm->env, clazz, methodID, args);

}

static inline char * uwsgi_jvm_call_static_utf8(uwsgi_jvm * pjvm, jclass clazz, jmethodID methodID, ...) {

    return NULL; // TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - string wrapper
 *
 * static inline jstring   uwsgi_jvm_string(uwsgi_jvm * pjvm, jchar *, jsize);
 * static inline jsize     uwsgi_jvm_strlen(uwsgi_jvm * pjvm, jstring);
 * static inline const jchar * uwsgi_jvm_strchars(uwsgi_jvm * pjvm, jstring);
 * static inline void      uwsgi_jvm_release_strchars(uwsgi_jvm * pjvm, jstring, const jchar *);
 * static inline jstring   uwsgi_jvm_utf8(uwsgi_jvm * pjvm, char *);
 * static inline jsize     uwsgi_jvm_utf8len(uwsgi_jvm * pjvm, jstring);
 * static inline const char *  uwsgi_jvm_utf8chars(uwsgi_jvm * pjvm, jstring);
 * static inline void      uwsgi_jvm_release_utf8chars(uwsgi_jvm * pjvm, jstring, const char *);
 */

static inline jstring uwsgi_jvm_string(uwsgi_jvm * pjvm, jchar * unicode, jsize len) {

    return (*(pjvm->env))->NewString(pjvm->env, unicode, len);

}

static inline jsize uwsgi_jvm_strlen(uwsgi_jvm * pjvm, jstring str) {

    return (*(pjvm->env))->GetStringLength(pjvm->env, str);

}

static inline const jchar * uwsgi_jvm_strchars(uwsgi_jvm * pjvm, jstring str) {

    return (*(pjvm->env))->GetStringChars(pjvm->env, str, NULL);

}

static inline void uwsgi_jvm_release_strchars(uwsgi_jvm * pjvm, jstring str, const jchar * chars) {

    (*(pjvm->env))->ReleaseStringChars(pjvm->env, str, chars);

}

static inline jstring uwsgi_jvm_utf8(uwsgi_jvm * pjvm, const char * utf) {

    return (*(pjvm->env))->NewStringUTF(pjvm->env, utf);

}

static inline jsize uwsgi_jvm_utf8len(uwsgi_jvm * pjvm, jstring str) {

    return (*(pjvm->env))->GetStringUTFLength(pjvm->env, str);

}

static inline const char * uwsgi_jvm_utf8chars(uwsgi_jvm * pjvm, jstring str) {

    return (*(pjvm->env))->GetStringUTFChars(pjvm->env, str, NULL);

}

static inline void uwsgi_jvm_release_utf8chars(uwsgi_jvm * pjvm, jstring str, const char * chars) {

    (*(pjvm->env))->ReleaseStringUTFChars(pjvm->env, str, chars);

}


/*  Inline JNI wrappers and helpers
 *
 *  - array general operation wrapper
 *
 *  static inline jsize         uwsgi_jvm_arraylen(uwsgi_jvm *, jarray);
 */

static inline jsize uwsgi_jvm_arraylen(uwsgi_jvm * pjvm, jarray array) {

    return  (*(pjvm->env))->GetArrayLength(pjvm->env, array);

}

/*  Inline JNI wrappers and helpers
 *
 *  - array creation wrapper
 *
 *  static inline jobjectArray  uwsgi_jvm_array(uwsgi_jvm *, jclass, jsize, jobject);
 *  static inline jbooleanArray uwsgi_jvm_array_boolean(uwsgi_jvm *, jsize);
 *  static inline jbyteArray    uwsgi_jvm_array_byte(uwsgi_jvm *, jsize);
 *  static inline jcharArray    uwsgi_jvm_array_char(uwsgi_jvm *, jsize);
 *  static inline jshortArray   uwsgi_jvm_array_short(uwsgi_jvm *, jsize);
 *  static inline jintArray     uwsgi_jvm_array_int(uwsgi_jvm *, jsize);
 *  static inline jlongArray    uwsgi_jvm_array_long(uwsgi_jvm *, jsize);
 *  static inline jfloatArray   uwsgi_jvm_array_float(uwsgi_jvm *, jsize);
 *  static inline jdoubleArray  uwsgi_jvm_array_double(uwsgi_jvm *, jsize);
 */

static inline jobjectArray  uwsgi_jvm_array(uwsgi_jvm * pjvm, jclass clazz, jsize len, jobject init) {

    return  (*(pjvm->env))->NewObjectArray(pjvm->env, len, clazz, init);

}

static inline jbooleanArray uwsgi_jvm_array_boolean(uwsgi_jvm * pjvm, jsize len) {

    return  (*(pjvm->env))->NewBooleanArray(pjvm->env, len);

}

static inline jbyteArray uwsgi_jvm_array_byte(uwsgi_jvm * pjvm, jsize len) {

    return  (*(pjvm->env))->NewByteArray(pjvm->env, len);

}

static inline jcharArray uwsgi_jvm_array_char(uwsgi_jvm * pjvm, jsize len) {

    return  (*(pjvm->env))->NewCharArray(pjvm->env, len);

}

static inline jshortArray uwsgi_jvm_array_short(uwsgi_jvm * pjvm, jsize len) {

    return  (*(pjvm->env))->NewShortArray(pjvm->env, len);

}

static inline jintArray uwsgi_jvm_array_int(uwsgi_jvm * pjvm, jsize len) {

    return  (*(pjvm->env))->NewIntArray(pjvm->env, len);

}

static inline jlongArray uwsgi_jvm_array_long(uwsgi_jvm * pjvm, jsize len) {

    return  (*(pjvm->env))->NewLongArray(pjvm->env, len);

}

static inline jfloatArray uwsgi_jvm_array_float(uwsgi_jvm * pjvm, jsize len) {

    return  (*(pjvm->env))->NewFloatArray(pjvm->env, len);

}

static inline jdoubleArray uwsgi_jvm_array_double(uwsgi_jvm * pjvm, jsize len) {

    return  (*(pjvm->env))->NewDoubleArray(pjvm->env, len);

}

/*  Inline JNI wrappers and helpers
 *
 *  - object array access wrapper
 *
 *  static inline jobject  uwsgi_jvm_array_get(uwsgi_jvm *, jobjectArray, jsize);
 *  static inline void uwsgi_jvm_array_set(uwsgi_jvm *, jobjectArray, jsize, jobject);
 */

static inline jobject  uwsgi_jvm_array_get(uwsgi_jvm * pjvm, jobjectArray array, jsize index) {

    return  (*(pjvm->env))->GetObjectArrayElement(pjvm->env, array, index);

}

static inline void uwsgi_jvm_array_set(uwsgi_jvm * pjvm, jobjectArray array, jsize index, jobject val) {

    (*(pjvm->env))->SetObjectArrayElement(pjvm->env, array, index, val);

}

/*  Inline JNI wrappers and helpers
 *
 *  - array get region wrapper
 *
 *  static inline void uwsgi_jvm_array_get_region_boolean(uwsgi_jvm *, jbooleanArray, jsize, jsize, jboolean *);
 *  static inline void uwsgi_jvm_array_get_region_byte(uwsgi_jvm *, jbyteArray, jsize, jsize, jbyte *);
 *  static inline void uwsgi_jvm_array_get_region_char(uwsgi_jvm *, jcharArray, jsize, jsize, jchar *);
 *  static inline void uwsgi_jvm_array_get_region_short(uwsgi_jvm *, jshortArray, jsize, jsize, jshort *);
 *  static inline void uwsgi_jvm_array_get_region_int(uwsgi_jvm *, jintArray, jsize, jsize, jint *);
 *  static inline void uwsgi_jvm_array_get_region_long(uwsgi_jvm *, jlongArray, jsize, jsize, jlong *);
 *  static inline void uwsgi_jvm_array_get_region_float(uwsgi_jvm *, jfloatArray, jsize, jsize, jfloat *);
 *  static inline void uwsgi_jvm_array_get_region_double(uwsgi_jvm *, jdoubleArray, jsize, jsize, jdouble *);
 */

static inline void uwsgi_jvm_array_get_region_boolean(uwsgi_jvm * pjvm, jbooleanArray array, jsize start, jsize len, jboolean * buf) {

    (*(pjvm->env))->GetBooleanArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_get_region_byte(uwsgi_jvm * pjvm, jbyteArray array, jsize start, jsize len, jbyte * buf) {

    (*(pjvm->env))->GetByteArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_get_region_char(uwsgi_jvm * pjvm, jcharArray array, jsize start, jsize len, jchar * buf) {

    (*(pjvm->env))->GetCharArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_get_region_short(uwsgi_jvm * pjvm, jshortArray array, jsize start, jsize len, jshort * buf) {

    (*(pjvm->env))->GetShortArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_get_region_int(uwsgi_jvm * pjvm, jintArray array, jsize start, jsize len, jint * buf) {

    (*(pjvm->env))->GetIntArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_get_region_long(uwsgi_jvm * pjvm, jlongArray array, jsize start, jsize len, jlong * buf) {

    (*(pjvm->env))->GetLongArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_get_region_float(uwsgi_jvm * pjvm, jfloatArray array, jsize start, jsize len, jfloat * buf) {

    (*(pjvm->env))->GetFloatArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_get_region_double(uwsgi_jvm * pjvm, jdoubleArray array, jsize start, jsize len, jdouble * buf) {

    (*(pjvm->env))->GetDoubleArrayRegion(pjvm->env, array, start, len, buf);

}

/*  Inline JNI wrappers and helpers
 *
 *  - array set region wrapper
 *
 *  static inline void uwsgi_jvm_array_set_region_boolean(uwsgi_jvm *, jbooleanArray, jsize, jsize, jboolean *);
 *  static inline void uwsgi_jvm_array_set_region_byte(uwsgi_jvm *, jbyteArray, jsize, jsize, jbyte *);
 *  static inline void uwsgi_jvm_array_set_region_char(uwsgi_jvm *, jcharArray, jsize, jsize, jchar *);
 *  static inline void uwsgi_jvm_array_set_region_short(uwsgi_jvm *, jshortArray, jsize, jsize, jshort *);
 *  static inline void uwsgi_jvm_array_set_region_int(uwsgi_jvm *, jintArray, jsize, jsize, jint *);
 *  static inline void uwsgi_jvm_array_set_region_long(uwsgi_jvm *, jlongArray, jsize, jsize, jlong *);
 *  static inline void uwsgi_jvm_array_set_region_float(uwsgi_jvm *, jfloatArray, jsize, jsize, jfloat *);
 *  static inline void uwsgi_jvm_array_set_region_double(uwsgi_jvm *, jdoubleArray, jsize, jsize, jdouble *);
 */

static inline void uwsgi_jvm_array_set_region_boolean(uwsgi_jvm * pjvm, jbooleanArray array, jsize start, jsize len, jboolean * buf) {

    (*(pjvm->env))->SetBooleanArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_set_region_byte(uwsgi_jvm * pjvm, jbyteArray array, jsize start, jsize len, jbyte * buf) {

    (*(pjvm->env))->SetByteArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_set_region_char(uwsgi_jvm * pjvm, jcharArray array, jsize start, jsize len, jchar * buf) {

    (*(pjvm->env))->SetCharArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_set_region_short(uwsgi_jvm * pjvm, jshortArray array, jsize start, jsize len, jshort * buf) {

    (*(pjvm->env))->SetShortArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_set_region_int(uwsgi_jvm * pjvm, jintArray array, jsize start, jsize len, jint * buf) {

    (*(pjvm->env))->SetIntArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_set_region_long(uwsgi_jvm * pjvm, jlongArray array, jsize start, jsize len, jlong * buf) {

    (*(pjvm->env))->SetLongArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_set_region_float(uwsgi_jvm * pjvm, jfloatArray array, jsize start, jsize len, jfloat * buf) {

    (*(pjvm->env))->SetFloatArrayRegion(pjvm->env, array, start, len, buf);

}

static inline void uwsgi_jvm_array_set_region_double(uwsgi_jvm * pjvm, jdoubleArray array, jsize start, jsize len, jdouble * buf) {

    (*(pjvm->env))->SetDoubleArrayRegion(pjvm->env, array, start, len, buf);

}

/*  Inline JNI wrappers and helpers
 *
 *  - java2c array converting wrapper
 *
 *  static inline jboolean * uwsgi_jvm_array_elems_boolean(uwsgi_jvm *, jbooleanArray);
 *  static inline jbyte *    uwsgi_jvm_array_elems_byte(uwsgi_jvm *, jbyteArray);
 *  static inline jchar *    uwsgi_jvm_array_elems_char(uwsgi_jvm *, jcharArray);
 *  static inline jshort *   uwsgi_jvm_array_elems_short(uwsgi_jvm *, jshortArray);
 *  static inline jint *     uwsgi_jvm_array_elems_int(uwsgi_jvm *, jintArray);
 *  static inline jlong *    uwsgi_jvm_array_elems_long(uwsgi_jvm *, jlongArray);
 *  static inline jfloat *   uwsgi_jvm_array_elems_float(uwsgi_jvm *, jfloatArray);
 *  static inline jdouble *  uwsgi_jvm_array_elems_double(uwsgi_jvm *, jdoubleArray);
 */

static inline jboolean * uwsgi_jvm_array_elems_boolean(uwsgi_jvm * pjvm, jbooleanArray array) {

    return  (*(pjvm->env))->GetBooleanArrayElements(pjvm->env, array, NULL);

}

static inline jbyte * uwsgi_jvm_array_elems_byte(uwsgi_jvm * pjvm, jbyteArray array) {

    return  (*(pjvm->env))->GetByteArrayElements(pjvm->env, array, NULL);

}

static inline jchar * uwsgi_jvm_array_elems_char(uwsgi_jvm * pjvm, jcharArray array) {

    return  (*(pjvm->env))->GetCharArrayElements(pjvm->env, array, NULL);

}

static inline jshort * uwsgi_jvm_array_elems_short(uwsgi_jvm * pjvm, jshortArray array) {

    return  (*(pjvm->env))->GetShortArrayElements(pjvm->env, array, NULL);

}

static inline jint * uwsgi_jvm_array_elems_int(uwsgi_jvm * pjvm, jintArray array) {

    return  (*(pjvm->env))->GetIntArrayElements(pjvm->env, array, NULL);

}

static inline jlong * uwsgi_jvm_array_elems_long(uwsgi_jvm * pjvm, jlongArray array) {

    return  (*(pjvm->env))->GetLongArrayElements(pjvm->env, array, NULL);

}

static inline jfloat * uwsgi_jvm_array_elems_float(uwsgi_jvm * pjvm, jfloatArray array) {

    return  (*(pjvm->env))->GetFloatArrayElements(pjvm->env, array, NULL);

}

static inline jdouble * uwsgi_jvm_array_elems_double(uwsgi_jvm * pjvm, jdoubleArray array) {

    return  (*(pjvm->env))->GetDoubleArrayElements(pjvm->env, array, NULL);

}


/*  Inline JNI wrappers and helpers
 *
 *  - array release wrapper
 *
 *  static inline void     uwsgi_jvm_array_release_boolean(uwsgi_jvm *, jbooleanArray, jboolean *, jint);
 *  static inline void     uwsgi_jvm_array_release_byte(uwsgi_jvm *, jbyteArray, jbyte *, jint);
 *  static inline void     uwsgi_jvm_array_release_char(uwsgi_jvm *, jcharArray, jchar *, jint);
 *  static inline void     uwsgi_jvm_array_release_short(uwsgi_jvm *, jshortArray, jshort *, jint);
 *  static inline void     uwsgi_jvm_array_release_int(uwsgi_jvm *, jintArray, jint *, jint);
 *  static inline void     uwsgi_jvm_array_release_long(uwsgi_jvm *, jlongArray, jlong *, jint);
 *  static inline void     uwsgi_jvm_array_release_float(uwsgi_jvm *, jfloatArray, jfloat *, jint);
 *  static inline void     uwsgi_jvm_array_release_double(uwsgi_jvm *, jdoubleArray, jdouble *, jint);
 */

static inline void uwsgi_jvm_array_release_boolean(uwsgi_jvm * pjvm, jbooleanArray array, jboolean * elems, jint mode) {

    (*(pjvm->env))->ReleaseBooleanArrayElements(pjvm->env, array, elems, mode);

}

static inline void uwsgi_jvm_array_release_byte(uwsgi_jvm * pjvm, jbyteArray array, jbyte * elems, jint mode) {

    (*(pjvm->env))->ReleaseByteArrayElements(pjvm->env, array, elems, mode);

}

static inline void uwsgi_jvm_array_release_char(uwsgi_jvm * pjvm, jcharArray array, jchar * elems, jint mode) {

    (*(pjvm->env))->ReleaseCharArrayElements(pjvm->env, array, elems, mode);

}

static inline void uwsgi_jvm_array_release_short(uwsgi_jvm * pjvm, jshortArray array, jshort * elems, jint mode) {

    (*(pjvm->env))->ReleaseShortArrayElements(pjvm->env, array, elems, mode);

}

static inline void uwsgi_jvm_array_release_int(uwsgi_jvm * pjvm, jintArray array, jint * elems, jint mode) {

    (*(pjvm->env))->ReleaseIntArrayElements(pjvm->env, array, elems, mode);

}

static inline void uwsgi_jvm_array_release_long(uwsgi_jvm * pjvm, jlongArray array, jlong * elems, jint mode) {

    (*(pjvm->env))->ReleaseLongArrayElements(pjvm->env, array, elems, mode);

}

static inline void uwsgi_jvm_array_release_float(uwsgi_jvm * pjvm, jfloatArray array, jfloat * elems, jint mode) {

    (*(pjvm->env))->ReleaseFloatArrayElements(pjvm->env, array, elems, mode);

}

static inline void uwsgi_jvm_array_release_double(uwsgi_jvm * pjvm, jdoubleArray array, jdouble * elems, jint mode) {

    (*(pjvm->env))->ReleaseDoubleArrayElements(pjvm->env, array, elems, mode);

}

/*  JNI helpers
 *
 *  - object helpers
 */

jboolean  uwsgi_jvm_equal(uwsgi_jvm * pjvm, jobject, jobject);
jstring   uwsgi_jvm_tostring(uwsgi_jvm * pjvm, jobject);
jstring   uwsgi_jvm_string_from(uwsgi_jvm * pjvm, char *, int length);
const jchar * uwsgi_jvm_tostrchars(uwsgi_jvm * pjvm, jobject);
const char *  uwsgi_jvm_toutf8chars(uwsgi_jvm * pjvm, jobject);

/*  JNI helpers
 *
 *  - Hashtable helpers
 */

jobject uwsgi_jvm_hashtable(uwsgi_jvm * pjvm);
jsize   uwsgi_jvm_hashtable_size(uwsgi_jvm * pjvm, jobject);
jobject uwsgi_jvm_hashtable_get(uwsgi_jvm * pjvm, jobject, jobject);
jobject uwsgi_jvm_hashtable_put(uwsgi_jvm * pjvm, jobject, jobject, jobject);

/*  JNI helpers
 *
 *  - FileDescriptor
 */

jobject uwsgi_jvm_fd(uwsgi_jvm * pjvm, int);

/*  JNI helpers
 *
 *  - System.out
 */

jobject uwsgi_jvm_in(uwsgi_jvm * pjvm);
jobject uwsgi_jvm_out(uwsgi_jvm * pjvm);
jobject uwsgi_jvm_err(uwsgi_jvm * pjvm);
void uwsgi_jvm_print(uwsgi_jvm * pjvm, jstring);
void uwsgi_jvm_println(uwsgi_jvm * pjvm, jstring);



