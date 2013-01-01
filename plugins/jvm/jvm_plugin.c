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

struct uwsgi_jvm ujvm;

struct uwsgi_option uwsgi_jvm_options[] = {

    {"jvm-main-class", required_argument, 0, "load the specified class", uwsgi_opt_set_str, &ujvm.string_main, 0},
    {"jvm-classpath", required_argument, 0, "add the specified directory to the classpath", uwsgi_opt_add_string_list, &ujvm.classpath, 0},
    {0, 0, 0, 0},

};

int MAX_LREFS = 16;

/*  Inline JNI wrappers and helpers
 *
 *  - General wrappers and helpers
 *
 *  jboolean  uwsgi_jvm_begin(jint);
 *  jboolean  uwsgi_jvm_ensure(jint);
 *  jobject   uwsgi_jvm_claim(jobject);
 *  void      uwsgi_jvm_delete(jobject);
 *  void      uwsgi_jvm_end(uwsgi_jvm *);
 */

jboolean uwsgi_jvm_begin(jint max_ref_count) {

    if ((*ujvm.env)->PushLocalFrame(ujvm.env, max_ref_count) < 0) {

        uwsgi_log("jwsgi can not allocate frame!");
        return JNI_TRUE;

    }

    return JNI_FALSE;

}

jboolean uwsgi_jvm_ensure(jint max_ref_count) {

    if ((*ujvm.env)->EnsureLocalCapacity(ujvm.env, max_ref_count) < 0) {

        uwsgi_log("jwsgi can not allocate frame!");
        return JNI_TRUE;

    }

    return JNI_FALSE;

}

jobject uwsgi_jvm_claim(jobject obj) {

    return (*ujvm.env)->NewLocalRef(ujvm.env, obj);

}

void uwsgi_jvm_delete(jobject obj) {

    (*ujvm.env)->DeleteLocalRef(ujvm.env, obj);

}

void uwsgi_jvm_end() {

    (*ujvm.env)->PopLocalFrame(ujvm.env, NULL);

}

/*  Inline JNI wrappers and helpers
 *
 *  - excpetion wrappers and helpers
 *
 *  jint       uwsgi_jvm_throw(jthrowable);
 *  jint       uwsgi_jvm_throw_new(jclass, const char *);
 *  void       uwsgi_jvm_fatal(const char *);
 *  jthrowable uwsgi_jvm_catch(uwsgi_jvm *);
 *  void       uwsgi_jvm_describe(uwsgi_jvm *);
 *  void       uwsgi_jvm_clear(uwsgi_jvm *);
 *  jint       uwsgi_jvm_defalt_handle(uwsgi_jvm *);
 */

jint uwsgi_jvm_throw(jthrowable obj) {

     return (*ujvm.env)->Throw(ujvm.env, obj);

}

jint uwsgi_jvm_throw_new(jclass clazz, const char * msg) {

    return (*ujvm.env)->ThrowNew(ujvm.env, clazz, msg);

}

void uwsgi_jvm_fatal(const char * msg) {

    (*ujvm.env)->FatalError(ujvm.env, msg);

}

jthrowable uwsgi_jvm_catch() {

     return (*ujvm.env)->ExceptionOccurred(ujvm.env);

}

void uwsgi_jvm_describe() {

    (*ujvm.env)->ExceptionDescribe(ujvm.env);

}

void uwsgi_jvm_clear() {

    (*ujvm.env)->ExceptionClear(ujvm.env);

}

jint uwsgi_jvm_ok() {

    if (uwsgi_jvm_catch()) {

        uwsgi_jvm_describe();
        uwsgi_jvm_clear();

        return JNI_ERR;
    }

    return JNI_OK;

}

/*  Inline JNI wrappers and helpers
 *
 *  - class wrappers and helpers
 *
 *  jclass    uwsgi_jvm_class_for(char *);
 *  jclass    uwsgi_jvm_class_of(jobject);
 *  jclass    uwsgi_jvm_super(jclass);
 *  jboolean  uwsgi_jvm_assignable(jclass, jclass);
 */

jclass uwsgi_jvm_class_for(char * name) {

    jclass clazz = (*ujvm.env)->FindClass(ujvm.env, name);

    if (uwsgi_jvm_ok()) {
        return NULL;
    }

    return uwsgi_jvm_claim(clazz);

}

jclass uwsgi_jvm_class_of(jobject obj) {

    return uwsgi_jvm_claim((*ujvm.env)->GetObjectClass(ujvm.env, obj));

}

jclass uwsgi_jvm_super(jclass clazz) {

    return uwsgi_jvm_claim((*ujvm.env)->GetSuperclass(ujvm.env, clazz));

}

jboolean uwsgi_jvm_assignable(jclass sub, jclass sup) {

    return (*ujvm.env)->IsAssignableFrom(ujvm.env, sub, sup);

}

/*  Inline JNI wrappers and helpers
 *
 *  - field and method wrappers
 *
 *  jfieldID  uwsgi_jvm_field(jclass, char *, char *);
 *  jfieldID  uwsgi_jvm_field_static(jclass, char *, char *);
 *  jmethodID uwsgi_jvm_method(jclass, char *, char *);
 *  jmethodID uwsgi_jvm_method_static(jclass, char *, char *);
 */

jfieldID uwsgi_jvm_field(jclass clazz, char * name, char * sig) {

    return (*ujvm.env)->GetFieldID(ujvm.env, clazz, name, sig);

}

jfieldID uwsgi_jvm_field_static(jclass clazz, char * name, char * sig) {

    return (*ujvm.env)->GetStaticFieldID(ujvm.env, clazz, name, sig);

}

jmethodID uwsgi_jvm_method(jclass clazz, char * name, char * sig) {

    return (*ujvm.env)->GetMethodID(ujvm.env, clazz, name, sig);

}

jmethodID uwsgi_jvm_method_static(jclass clazz, char * name, char * sig) {

    return (*ujvm.env)->GetStaticMethodID(ujvm.env, clazz, name, sig);

}

/*  Inline JNI wrappers and helpers
 *
 *  - object wrappers
 *
 *  jobject   uwsgi_jvm_new(jclass, jmethodID, ...);
 *  jboolean  uwsgi_jvm_same(jobject, jobject);
 *  jboolean  uwsgi_jvm_is_a(jobject, jclass);
 */

jobject uwsgi_jvm_new(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return uwsgi_jvm_claim((*ujvm.env)->NewObject(ujvm.env, clazz, methodID, args));

}

jboolean uwsgi_jvm_same(jobject obj1, jobject obj2) {

    return (*ujvm.env)->IsSameObject(ujvm.env, obj1, obj2);

}

jboolean uwsgi_jvm_is_a(jobject obj, jclass clazz) {

    return (*ujvm.env)->IsInstanceOf(ujvm.env, obj, clazz);

}

/*  Inline JNI wrappers and helpers
 *
 *  - object field read
 *
 *  jobject   uwsgi_jvm_get(jobject, jfieldID);
 *  jboolean  uwsgi_jvm_get_boolean(jobject, jfieldID);
 *  jbyte     uwsgi_jvm_get_byte(jobject, jfieldID);
 *  jchar     uwsgi_jvm_get_char(jobject, jfieldID);
 *  jshort    uwsgi_jvm_get_short(jobject, jfieldID);
 *  jint      uwsgi_jvm_get_int(jobject, jfieldID);
 *  jlong     uwsgi_jvm_get_long(jobject, jfieldID);
 *  jfloat    uwsgi_jvm_get_float(jobject, jfieldID);
 *  jdouble   uwsgi_jvm_get_double(jobject, jfieldID);
 *  jstring   uwsgi_jvm_get_string(jobject, jfieldID);
 *  char *    uwsgi_jvm_get_utf8(jobject, jfieldID);
 */

jobject uwsgi_jvm_get(jobject obj, jfieldID fieldID) {

    return uwsgi_jvm_claim((*ujvm.env)->GetObjectField(ujvm.env, obj, fieldID));

}

jboolean uwsgi_jvm_get_boolean(jobject obj, jfieldID fieldID) {

    return (*ujvm.env)->GetBooleanField(ujvm.env, obj, fieldID);

}

jbyte uwsgi_jvm_get_byte(jobject obj, jfieldID fieldID) {

    return (*ujvm.env)->GetByteField(ujvm.env, obj, fieldID);

}

jchar uwsgi_jvm_get_char(jobject obj, jfieldID fieldID) {

    return (*ujvm.env)->GetCharField(ujvm.env, obj, fieldID);

}

jshort uwsgi_jvm_get_short(jobject obj, jfieldID fieldID) {

    return (*ujvm.env)->GetShortField(ujvm.env, obj, fieldID);

}

jint uwsgi_jvm_get_int(jobject obj, jfieldID fieldID) {

    return (*ujvm.env)->GetIntField(ujvm.env, obj, fieldID);

}

jlong uwsgi_jvm_get_long(jobject obj, jfieldID fieldID) {

    return (*ujvm.env)->GetLongField(ujvm.env, obj, fieldID);

}

jfloat uwsgi_jvm_get_float(jobject obj, jfieldID fieldID) {

    return (*ujvm.env)->GetFloatField(ujvm.env, obj, fieldID);

}

jdouble uwsgi_jvm_get_double(jobject obj, jfieldID fieldID) {

    return (*ujvm.env)->GetDoubleField(ujvm.env, obj, fieldID);

}

jstring uwsgi_jvm_get_string(jobject obj, jfieldID fieldID) {

    return (jstring)(uwsgi_jvm_get(obj, fieldID));

}

char * uwsgi_jvm_get_utf8(jobject obj, jfieldID fieldID) {

    return NULL; //TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - object field write
 *
 *  void    uwsgi_jvm_set(jobject, jfieldID, jobject);
 *  void    uwsgi_jvm_set_boolean(jobject, jfieldID, jboolean);
 *  void    uwsgi_jvm_set_byte(jobject, jfieldID, jbyte);
 *  void    uwsgi_jvm_set_char(jobject, jfieldID, jchar);
 *  void    uwsgi_jvm_set_short(jobject, jfieldID, jshort);
 *  void    uwsgi_jvm_set_int(jobject, jfieldID, jint);
 *  void    uwsgi_jvm_set_long(jobject, jfieldID, jlong);
 *  void    uwsgi_jvm_set_float(jobject, jfieldID, jfloat);
 *  void    uwsgi_jvm_set_double(jobject, jfieldID, jdouble);
 *  void    uwsgi_jvm_set_string(jobject, jfieldID, jstring);
 *  void    uwsgi_jvm_set_utf8(jobject, jfieldID, char *);
 */

void uwsgi_jvm_set(jobject obj, jfieldID fieldID, jobject val) {

    (*ujvm.env)->SetObjectField(ujvm.env, obj, fieldID, val);

}

void uwsgi_jvm_set_boolean(jobject obj, jfieldID fieldID, jboolean val) {

    (*ujvm.env)->SetBooleanField(ujvm.env, obj, fieldID, val);

}

void uwsgi_jvm_set_byte(jobject obj, jfieldID fieldID, jbyte val) {

    (*ujvm.env)->SetByteField(ujvm.env, obj, fieldID, val);

}

void uwsgi_jvm_set_char(jobject obj, jfieldID fieldID, jchar val) {

    (*ujvm.env)->SetCharField(ujvm.env, obj, fieldID, val);

}

void uwsgi_jvm_set_short(jobject obj, jfieldID fieldID, jshort val) {

    (*ujvm.env)->SetShortField(ujvm.env, obj, fieldID, val);

}

void uwsgi_jvm_set_int(jobject obj, jfieldID fieldID, jint val) {

    (*ujvm.env)->SetIntField(ujvm.env, obj, fieldID, val);

}

void uwsgi_jvm_set_long(jobject obj, jfieldID fieldID, jlong val) {

    (*ujvm.env)->SetLongField(ujvm.env, obj, fieldID, val);

}

void uwsgi_jvm_set_float(jobject obj, jfieldID fieldID, jfloat val) {

    (*ujvm.env)->SetFloatField(ujvm.env, obj, fieldID, val);

}

void uwsgi_jvm_set_double(jobject obj, jfieldID fieldID, jdouble val) {

    (*ujvm.env)->SetDoubleField(ujvm.env, obj, fieldID, val);

}

void uwsgi_jvm_set_string(jobject obj, jfieldID fieldID, jstring val) {

    (*ujvm.env)->SetObjectField(ujvm.env, obj, fieldID, val);

}

void uwsgi_jvm_set_utf8(jobject obj, jfieldID fieldID, char * val) {

    //TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - class field read
 *
 *  jobject   uwsgi_jvm_get_static(jclass, jfieldID);
 *  jboolean  uwsgi_jvm_get_static_boolean(jclass, jfieldID);
 *  jbyte     uwsgi_jvm_get_static_byte(jclass, jfieldID);
 *  jchar     uwsgi_jvm_get_static_char(jclass, jfieldID);
 *  jshort    uwsgi_jvm_get_static_short(jclass, jfieldID);
 *  jint      uwsgi_jvm_get_static_int(jclass, jfieldID);
 *  jlong     uwsgi_jvm_get_static_long(jclass, jfieldID);
 *  jfloat    uwsgi_jvm_get_static_float(jclass, jfieldID);
 *  jdouble   uwsgi_jvm_get_static_double(jclass, jfieldID);
 *  jstring   uwsgi_jvm_get_static_string(jclass, jfieldID);
 *  char *    uwsgi_jvm_get_static_utf8(jclass, jfieldID);
 */

jobject uwsgi_jvm_get_static(jclass clazz, jfieldID fieldID) {

    return uwsgi_jvm_claim((*ujvm.env)->GetStaticObjectField(ujvm.env, clazz, fieldID));

}

jboolean uwsgi_jvm_get_static_boolean(jclass clazz, jfieldID fieldID) {

    return (*ujvm.env)->GetStaticBooleanField(ujvm.env, clazz, fieldID);

}

jbyte uwsgi_jvm_get_static_byte(jclass clazz, jfieldID fieldID) {

    return (*ujvm.env)->GetStaticByteField(ujvm.env, clazz, fieldID);

}

jchar uwsgi_jvm_get_static_char(jclass clazz, jfieldID fieldID) {

    return (*ujvm.env)->GetStaticCharField(ujvm.env, clazz, fieldID);

}

jshort uwsgi_jvm_get_static_short(jclass clazz, jfieldID fieldID) {

    return (*ujvm.env)->GetStaticShortField(ujvm.env, clazz, fieldID);

}

jint uwsgi_jvm_get_static_int(jclass clazz, jfieldID fieldID) {

    return (*ujvm.env)->GetStaticIntField(ujvm.env, clazz, fieldID);

}

jlong uwsgi_jvm_get_static_long(jclass clazz, jfieldID fieldID) {

    return (*ujvm.env)->GetStaticLongField(ujvm.env, clazz, fieldID);

}

jfloat uwsgi_jvm_get_static_float(jclass clazz, jfieldID fieldID) {

    return (*ujvm.env)->GetStaticFloatField(ujvm.env, clazz, fieldID);

}

jdouble uwsgi_jvm_get_static_double(jclass clazz, jfieldID fieldID) {

    return (*ujvm.env)->GetStaticDoubleField(ujvm.env, clazz, fieldID);

}

jstring uwsgi_jvm_get_static_string(jclass clazz, jfieldID fieldID) {

    return (jstring)(uwsgi_jvm_get_static(clazz, fieldID));

}

char * uwsgi_jvm_get_static_utf8(jclass clazz, jfieldID fieldID) {

    return NULL; //TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - class field write
 *
 *  void    uwsgi_jvm_set_static(jclass, jfieldID, jobject);
 *  void    uwsgi_jvm_set_static_boolean(jclass, jfieldID, jboolean);
 *  void    uwsgi_jvm_set_static_byte(jclass, jfieldID, jbyte);
 *  void    uwsgi_jvm_set_static_char(jclass, jfieldID, jchar);
 *  void    uwsgi_jvm_set_static_short(jclass, jfieldID, jshort);
 *  void    uwsgi_jvm_set_static_int(jclass, jfieldID, jint);
 *  void    uwsgi_jvm_set_static_long(jclass, jfieldID, jlong);
 *  void    uwsgi_jvm_set_static_float(jclass, jfieldID, jfloat);
 *  void    uwsgi_jvm_set_static_double(jclass, jfieldID, jdouble);
 *  void    uwsgi_jvm_set_static_string(jclass, jfieldID, jstring);
 *  void    uwsgi_jvm_set_static_utf8(jclass, jfieldID, char *);
 */

void uwsgi_jvm_set_static(jclass clazz, jfieldID fieldID, jobject val) {

    (*ujvm.env)->SetStaticObjectField(ujvm.env, clazz, fieldID, val);

}

void uwsgi_jvm_set_static_boolean(jclass clazz, jfieldID fieldID, jboolean val) {

    (*ujvm.env)->SetStaticBooleanField(ujvm.env, clazz, fieldID, val);

}

void uwsgi_jvm_set_static_byte(jclass clazz, jfieldID fieldID, jbyte val) {

    (*ujvm.env)->SetStaticByteField(ujvm.env, clazz, fieldID, val);

}

void uwsgi_jvm_set_static_char(jclass clazz, jfieldID fieldID, jchar val) {

    (*ujvm.env)->SetStaticCharField(ujvm.env, clazz, fieldID, val);

}

void uwsgi_jvm_set_static_short(jclass clazz, jfieldID fieldID, jshort val) {

    (*ujvm.env)->SetStaticShortField(ujvm.env, clazz, fieldID, val);

}

void uwsgi_jvm_set_static_int(jclass clazz, jfieldID fieldID, jint val) {

    (*ujvm.env)->SetStaticIntField(ujvm.env, clazz, fieldID, val);

}

void uwsgi_jvm_set_static_long(jclass clazz, jfieldID fieldID, jlong val) {

    (*ujvm.env)->SetStaticLongField(ujvm.env, clazz, fieldID, val);

}

void uwsgi_jvm_set_static_float(jclass clazz, jfieldID fieldID, jfloat val) {

    (*ujvm.env)->SetStaticFloatField(ujvm.env, clazz, fieldID, val);

}

void uwsgi_jvm_set_static_double(jclass clazz, jfieldID fieldID, jdouble val) {

    (*ujvm.env)->SetStaticDoubleField(ujvm.env, clazz, fieldID, val);

}

void uwsgi_jvm_set_static_string(jclass clazz, jfieldID fieldID, jstring val) {

    (*ujvm.env)->SetStaticObjectField(ujvm.env, clazz, fieldID, val);

}

void uwsgi_jvm_set_static_utf8(jclass clazz, jfieldID fieldID, char * val) {

    //TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - object method call
 *
 *  jobject   uwsgi_jvm_call(jobject, jmethodID, ...);
 *  jboolean  uwsgi_jvm_call_boolean(jobject, jmethodID, ...);
 *  jint      uwsgi_jvm_call_byte(jobject, jmethodID, ...);
 *  jchar     uwsgi_jvm_call_char(jobject, jmethodID, ...);
 *  jshort    uwsgi_jvm_call_short(jobject, jmethodID, ...);
 *  jint      uwsgi_jvm_call_int(jobject, jmethodID, ...);
 *  jlong     uwsgi_jvm_call_long(jobject, jmethodID, ...);
 *  jfloat    uwsgi_jvm_call_float(jobject, jmethodID, ...);
 *  jdouble   uwsgi_jvm_call_double(jobject, jmethodID, ...);
 *  void      uwsgi_jvm_call_void(jobject, jmethodID, ...);
 *  jstring   uwsgi_jvm_call_string(jobject, jmethodID, ...);
 *  char *    uwsgi_jvm_call_utf8(jobject, jmethodID, ...);
 */

jobject uwsgi_jvm_call(jobject obj, jmethodID methodID, ...) {

    va_list args;

    return uwsgi_jvm_claim((*ujvm.env)->CallObjectMethod(ujvm.env, obj, methodID, args));

}

jboolean uwsgi_jvm_call_boolean(jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallBooleanMethod(ujvm.env, obj, methodID, args);

}

jint uwsgi_jvm_call_byte(jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallByteMethod(ujvm.env, obj, methodID, args);

}

jchar uwsgi_jvm_call_char(jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallCharMethod(ujvm.env, obj, methodID, args);

}

jshort uwsgi_jvm_call_short(jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallShortMethod(ujvm.env, obj, methodID, args);

}

jint uwsgi_jvm_call_int(jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallIntMethod(ujvm.env, obj, methodID, args);

}

jlong uwsgi_jvm_call_long(jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallLongMethod(ujvm.env, obj, methodID, args);

}

jfloat uwsgi_jvm_call_float(jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallFloatMethod(ujvm.env, obj, methodID, args);

}

jdouble uwsgi_jvm_call_double(jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallDoubleMethod(ujvm.env, obj, methodID, args);

}

void uwsgi_jvm_call_void(jobject obj, jmethodID methodID, ...) {

    va_list args;

    (*ujvm.env)->CallVoidMethod(ujvm.env, obj, methodID, args);

}

jstring uwsgi_jvm_call_string(jobject obj, jmethodID methodID, ...) {

    va_list args;

    return (jstring)(uwsgi_jvm_call(obj, methodID, args));

}

char * uwsgi_jvm_call_utf8(jobject obj, jmethodID methodID, ...) {

    return NULL; // TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - direct object method call
 *
 *  jobject   uwsgi_jvm_call_direct(jobject, jclass, jmethodID, ...);
 *  jboolean  uwsgi_jvm_call_direct_boolean(jobject, jclass, jmethodID, ...);
 *  jint      uwsgi_jvm_call_direct_byte(jobject, jclass, jmethodID, ...);
 *  jchar     uwsgi_jvm_call_direct_char(jobject, jclass, jmethodID, ...);
 *  jshort    uwsgi_jvm_call_direct_short(jobject, jclass, jmethodID, ...);
 *  jint      uwsgi_jvm_call_direct_int(jobject, jclass, jmethodID, ...);
 *  jlong     uwsgi_jvm_call_direct_long(jobject, jclass, jmethodID, ...);
 *  jfloat    uwsgi_jvm_call_direct_float(jobject, jclass, jmethodID, ...);
 *  jdouble   uwsgi_jvm_call_direct_double(jobject, jclass, jmethodID, ...);
 *  void      uwsgi_jvm_call_direct_void(jobject, jclass, jmethodID, ...);
 *  jstring   uwsgi_jvm_call_direct_string(jobject, jclass, jmethodID, ...);
 *  char *    uwsgi_jvm_call_direct_utf8(jobject, jclass, jmethodID, ...);
 */

jobject uwsgi_jvm_call_direct(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return uwsgi_jvm_claim((*ujvm.env)->CallNonvirtualObjectMethod(ujvm.env, obj, clazz, methodID, args));

}

jboolean uwsgi_jvm_call_direct_boolean(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallNonvirtualBooleanMethod(ujvm.env, obj, clazz, methodID, args);

}

jint uwsgi_jvm_call_direct_byte(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallNonvirtualByteMethod(ujvm.env, obj, clazz, methodID, args);

}

jchar uwsgi_jvm_call_direct_char(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallNonvirtualCharMethod(ujvm.env, obj, clazz, methodID, args);

}

jshort uwsgi_jvm_call_direct_short(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallNonvirtualShortMethod(ujvm.env, obj, clazz, methodID, args);

}

jint uwsgi_jvm_call_direct_int(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallNonvirtualIntMethod(ujvm.env, obj, clazz, methodID, args);

}

jlong uwsgi_jvm_call_direct_long(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallNonvirtualLongMethod(ujvm.env, obj, clazz, methodID, args);

}

jfloat uwsgi_jvm_call_direct_float(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallNonvirtualFloatMethod(ujvm.env, obj, clazz, methodID, args);

}

jdouble uwsgi_jvm_call_direct_double(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallNonvirtualDoubleMethod(ujvm.env, obj, clazz, methodID, args);

}

void uwsgi_jvm_call_direct_void(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    (*ujvm.env)->CallNonvirtualVoidMethod(ujvm.env, obj, clazz, methodID, args);

}

jstring uwsgi_jvm_call_direct_string(jobject obj, jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (jstring)(uwsgi_jvm_call_direct(obj, clazz, methodID, args));

}

char * uwsgi_jvm_call_direct_utf8(jobject obj, jclass clazz, jmethodID methodID, ...) {

    return NULL; // TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - class method call
 *
 *  jobject   uwsgi_jvm_call_static(jclass, jmethodID, ...);
 *  jboolean  uwsgi_jvm_call_static_boolean(jclass, jmethodID, ...);
 *  jint      uwsgi_jvm_call_static_byte(jclass, jmethodID, ...);
 *  jchar     uwsgi_jvm_call_static_char(jclass, jmethodID, ...);
 *  jshort    uwsgi_jvm_call_static_short(jclass, jmethodID, ...);
 *  jint      uwsgi_jvm_call_static_int(jclass, jmethodID, ...);
 *  jlong     uwsgi_jvm_call_static_long(jclass, jmethodID, ...);
 *  jfloat    uwsgi_jvm_call_static_float(jclass, jmethodID, ...);
 *  jdouble   uwsgi_jvm_call_static_double(jclass, jmethodID, ...);
 *  void      uwsgi_jvm_call_static_void(jclass, jmethodID, ...);
 *  jstring   uwsgi_jvm_call_static_string(jclass, jmethodID, ...);
 *  char *    uwsgi_jvm_call_static_utf8(jclass, jmethodID, ...);
 */

jclass uwsgi_jvm_call_static(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return uwsgi_jvm_claim((*ujvm.env)->CallStaticObjectMethod(ujvm.env, clazz, methodID, args));

}

jboolean uwsgi_jvm_call_static_boolean(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallStaticBooleanMethod(ujvm.env, clazz, methodID, args);

}

jint uwsgi_jvm_call_static_byte(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallStaticByteMethod(ujvm.env, clazz, methodID, args);

}

jchar uwsgi_jvm_call_static_char(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallStaticCharMethod(ujvm.env, clazz, methodID, args);

}

jshort uwsgi_jvm_call_static_short(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallStaticShortMethod(ujvm.env, clazz, methodID, args);

}

jint uwsgi_jvm_call_static_int(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallStaticIntMethod(ujvm.env, clazz, methodID, args);

}

jlong uwsgi_jvm_call_static_long(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallStaticLongMethod(ujvm.env, clazz, methodID, args);

}

jfloat uwsgi_jvm_call_static_float(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallStaticFloatMethod(ujvm.env, clazz, methodID, args);

}

jdouble uwsgi_jvm_call_static_double(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (*ujvm.env)->CallStaticDoubleMethod(ujvm.env, clazz, methodID, args);

}

void uwsgi_jvm_call_static_void(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    (*ujvm.env)->CallStaticVoidMethod(ujvm.env, clazz, methodID, args);

}

jstring uwsgi_jvm_call_static_string(jclass clazz, jmethodID methodID, ...) {

    va_list args;

    return (jstring)(uwsgi_jvm_call_static(clazz, methodID, args));

}

char * uwsgi_jvm_call_static_utf8(jclass clazz, jmethodID methodID, ...) {

    return NULL; // TODO

}

/*  Inline JNI wrappers and helpers
 *
 *  - string wrapper
 *
 * jstring   uwsgi_jvm_string(jchar *, jsize);
 * jsize     uwsgi_jvm_strlen(jstring);
 * const jchar * uwsgi_jvm_strchars(jstring);
 * void      uwsgi_jvm_release_strchars(jstring, const jchar *);
 * jstring   uwsgi_jvm_utf8(char *);
 * jsize     uwsgi_jvm_utf8len(jstring);
 * const char *  uwsgi_jvm_utf8chars(jstring);
 * void      uwsgi_jvm_release_utf8chars(jstring, const char *);
 */

jstring uwsgi_jvm_string(jchar * unicode, jsize len) {

    return uwsgi_jvm_claim((*ujvm.env)->NewString(ujvm.env, unicode, len));

}

jsize uwsgi_jvm_strlen(jstring str) {

    return (*ujvm.env)->GetStringLength(ujvm.env, str);

}

const jchar * uwsgi_jvm_strchars(jstring str) {

    return (*ujvm.env)->GetStringChars(ujvm.env, str, NULL);

}

void uwsgi_jvm_release_strchars(jstring str, const jchar * chars) {

    (*ujvm.env)->ReleaseStringChars(ujvm.env, str, chars);

}

jstring uwsgi_jvm_utf8(const char * utf) {

    return (*ujvm.env)->NewStringUTF(ujvm.env, utf);

}

jsize uwsgi_jvm_utf8len(jstring str) {

    return (*ujvm.env)->GetStringUTFLength(ujvm.env, str);

}

const char * uwsgi_jvm_utf8chars(jstring str) {

    return (*ujvm.env)->GetStringUTFChars(ujvm.env, str, NULL);

}

void uwsgi_jvm_release_utf8chars(jstring str, const char * chars) {

    (*ujvm.env)->ReleaseStringUTFChars(ujvm.env, str, chars);

}


/*  Inline JNI wrappers and helpers
 *
 *  - array general operation wrapper
 *
 *  jsize         uwsgi_jvm_arraylen(jarray);
 */

jsize uwsgi_jvm_arraylen(jarray array) {

    return  (*ujvm.env)->GetArrayLength(ujvm.env, array);

}

/*  Inline JNI wrappers and helpers
 *
 *  - array creation wrapper
 *
 *  jobjectArray  uwsgi_jvm_array(jclass, jsize, jobject);
 *  jbooleanArray uwsgi_jvm_array_boolean(jsize);
 *  jbyteArray    uwsgi_jvm_array_byte(jsize);
 *  jcharArray    uwsgi_jvm_array_char(jsize);
 *  jshortArray   uwsgi_jvm_array_short(jsize);
 *  jintArray     uwsgi_jvm_array_int(jsize);
 *  jlongArray    uwsgi_jvm_array_long(jsize);
 *  jfloatArray   uwsgi_jvm_array_float(jsize);
 *  jdoubleArray  uwsgi_jvm_array_double(jsize);
 */

jobjectArray  uwsgi_jvm_array(jclass clazz, jsize len, jobject init) {

    return  uwsgi_jvm_claim((*ujvm.env)->NewObjectArray(ujvm.env, len, clazz, init));

}

jbooleanArray uwsgi_jvm_array_boolean(jsize len) {

    return  uwsgi_jvm_claim((*ujvm.env)->NewBooleanArray(ujvm.env, len));

}

jbyteArray uwsgi_jvm_array_byte(jsize len) {

    return  uwsgi_jvm_claim((*ujvm.env)->NewByteArray(ujvm.env, len));

}

jcharArray uwsgi_jvm_array_char(jsize len) {

    return  uwsgi_jvm_claim((*ujvm.env)->NewCharArray(ujvm.env, len));

}

jshortArray uwsgi_jvm_array_short(jsize len) {

    return  uwsgi_jvm_claim((*ujvm.env)->NewShortArray(ujvm.env, len));

}

jintArray uwsgi_jvm_array_int(jsize len) {

    return  uwsgi_jvm_claim((*ujvm.env)->NewIntArray(ujvm.env, len));

}

jlongArray uwsgi_jvm_array_long(jsize len) {

    return  uwsgi_jvm_claim((*ujvm.env)->NewLongArray(ujvm.env, len));

}

jfloatArray uwsgi_jvm_array_float(jsize len) {

    return  uwsgi_jvm_claim((*ujvm.env)->NewFloatArray(ujvm.env, len));

}

jdoubleArray uwsgi_jvm_array_double(jsize len) {

    return  uwsgi_jvm_claim((*ujvm.env)->NewDoubleArray(ujvm.env, len));

}

/*  Inline JNI wrappers and helpers
 *
 *  - object array access wrapper
 *
 *  jobject  uwsgi_jvm_array_get(jobjectArray, jsize);
 *  void uwsgi_jvm_array_set(jobjectArray, jsize, jobject);
 */

jobject  uwsgi_jvm_array_get(jobjectArray array, jsize index) {

    return  uwsgi_jvm_claim((*ujvm.env)->GetObjectArrayElement(ujvm.env, array, index));

}

void uwsgi_jvm_array_set(jobjectArray array, jsize index, jobject val) {

    (*ujvm.env)->SetObjectArrayElement(ujvm.env, array, index, val);

}

/*  Inline JNI wrappers and helpers
 *
 *  - array get region wrapper
 *
 *  void uwsgi_jvm_array_get_region_boolean(jbooleanArray, jsize, jsize, jboolean *);
 *  void uwsgi_jvm_array_get_region_byte(jbyteArray, jsize, jsize, jbyte *);
 *  void uwsgi_jvm_array_get_region_char(jcharArray, jsize, jsize, jchar *);
 *  void uwsgi_jvm_array_get_region_short(jshortArray, jsize, jsize, jshort *);
 *  void uwsgi_jvm_array_get_region_int(jintArray, jsize, jsize, jint *);
 *  void uwsgi_jvm_array_get_region_long(jlongArray, jsize, jsize, jlong *);
 *  void uwsgi_jvm_array_get_region_float(jfloatArray, jsize, jsize, jfloat *);
 *  void uwsgi_jvm_array_get_region_double(jdoubleArray, jsize, jsize, jdouble *);
 */

void uwsgi_jvm_array_get_region_boolean(jbooleanArray array, jsize start, jsize len, jboolean * buf) {

    (*ujvm.env)->GetBooleanArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_get_region_byte(jbyteArray array, jsize start, jsize len, jbyte * buf) {

    (*ujvm.env)->GetByteArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_get_region_char(jcharArray array, jsize start, jsize len, jchar * buf) {

    (*ujvm.env)->GetCharArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_get_region_short(jshortArray array, jsize start, jsize len, jshort * buf) {

    (*ujvm.env)->GetShortArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_get_region_int(jintArray array, jsize start, jsize len, jint * buf) {

    (*ujvm.env)->GetIntArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_get_region_long(jlongArray array, jsize start, jsize len, jlong * buf) {

    (*ujvm.env)->GetLongArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_get_region_float(jfloatArray array, jsize start, jsize len, jfloat * buf) {

    (*ujvm.env)->GetFloatArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_get_region_double(jdoubleArray array, jsize start, jsize len, jdouble * buf) {

    (*ujvm.env)->GetDoubleArrayRegion(ujvm.env, array, start, len, buf);

}

/*  Inline JNI wrappers and helpers
 *
 *  - array set region wrapper
 *
 *  void uwsgi_jvm_array_set_region_boolean(jbooleanArray, jsize, jsize, jboolean *);
 *  void uwsgi_jvm_array_set_region_byte(jbyteArray, jsize, jsize, jbyte *);
 *  void uwsgi_jvm_array_set_region_char(jcharArray, jsize, jsize, jchar *);
 *  void uwsgi_jvm_array_set_region_short(jshortArray, jsize, jsize, jshort *);
 *  void uwsgi_jvm_array_set_region_int(jintArray, jsize, jsize, jint *);
 *  void uwsgi_jvm_array_set_region_long(jlongArray, jsize, jsize, jlong *);
 *  void uwsgi_jvm_array_set_region_float(jfloatArray, jsize, jsize, jfloat *);
 *  void uwsgi_jvm_array_set_region_double(jdoubleArray, jsize, jsize, jdouble *);
 */

void uwsgi_jvm_array_set_region_boolean(jbooleanArray array, jsize start, jsize len, jboolean * buf) {

    (*ujvm.env)->SetBooleanArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_set_region_byte(jbyteArray array, jsize start, jsize len, jbyte * buf) {

    (*ujvm.env)->SetByteArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_set_region_char(jcharArray array, jsize start, jsize len, jchar * buf) {

    (*ujvm.env)->SetCharArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_set_region_short(jshortArray array, jsize start, jsize len, jshort * buf) {

    (*ujvm.env)->SetShortArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_set_region_int(jintArray array, jsize start, jsize len, jint * buf) {

    (*ujvm.env)->SetIntArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_set_region_long(jlongArray array, jsize start, jsize len, jlong * buf) {

    (*ujvm.env)->SetLongArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_set_region_float(jfloatArray array, jsize start, jsize len, jfloat * buf) {

    (*ujvm.env)->SetFloatArrayRegion(ujvm.env, array, start, len, buf);

}

void uwsgi_jvm_array_set_region_double(jdoubleArray array, jsize start, jsize len, jdouble * buf) {

    (*ujvm.env)->SetDoubleArrayRegion(ujvm.env, array, start, len, buf);

}

/*  Inline JNI wrappers and helpers
 *
 *  - java2c array converting wrapper
 *
 *  jboolean * uwsgi_jvm_array_elems_boolean(jbooleanArray);
 *  jbyte *    uwsgi_jvm_array_elems_byte(jbyteArray);
 *  jchar *    uwsgi_jvm_array_elems_char(jcharArray);
 *  jshort *   uwsgi_jvm_array_elems_short(jshortArray);
 *  jint *     uwsgi_jvm_array_elems_int(jintArray);
 *  jlong *    uwsgi_jvm_array_elems_long(jlongArray);
 *  jfloat *   uwsgi_jvm_array_elems_float(jfloatArray);
 *  jdouble *  uwsgi_jvm_array_elems_double(jdoubleArray);
 */

jboolean * uwsgi_jvm_array_elems_boolean(jbooleanArray array) {

    return  (*ujvm.env)->GetBooleanArrayElements(ujvm.env, array, NULL);

}

jbyte * uwsgi_jvm_array_elems_byte(jbyteArray array) {

    return  (*ujvm.env)->GetByteArrayElements(ujvm.env, array, NULL);

}

jchar * uwsgi_jvm_array_elems_char(jcharArray array) {

    return  (*ujvm.env)->GetCharArrayElements(ujvm.env, array, NULL);

}

jshort * uwsgi_jvm_array_elems_short(jshortArray array) {

    return  (*ujvm.env)->GetShortArrayElements(ujvm.env, array, NULL);

}

jint * uwsgi_jvm_array_elems_int(jintArray array) {

    return  (*ujvm.env)->GetIntArrayElements(ujvm.env, array, NULL);

}

jlong * uwsgi_jvm_array_elems_long(jlongArray array) {

    return  (*ujvm.env)->GetLongArrayElements(ujvm.env, array, NULL);

}

jfloat * uwsgi_jvm_array_elems_float(jfloatArray array) {

    return  (*ujvm.env)->GetFloatArrayElements(ujvm.env, array, NULL);

}

jdouble * uwsgi_jvm_array_elems_double(jdoubleArray array) {

    return  (*ujvm.env)->GetDoubleArrayElements(ujvm.env, array, NULL);

}


/*  Inline JNI wrappers and helpers
 *
 *  - array release wrapper
 *
 *  void     uwsgi_jvm_array_release_boolean(jbooleanArray, jboolean *, jint);
 *  void     uwsgi_jvm_array_release_byte(jbyteArray, jbyte *, jint);
 *  void     uwsgi_jvm_array_release_char(jcharArray, jchar *, jint);
 *  void     uwsgi_jvm_array_release_short(jshortArray, jshort *, jint);
 *  void     uwsgi_jvm_array_release_int(jintArray, jint *, jint);
 *  void     uwsgi_jvm_array_release_long(jlongArray, jlong *, jint);
 *  void     uwsgi_jvm_array_release_float(jfloatArray, jfloat *, jint);
 *  void     uwsgi_jvm_array_release_double(jdoubleArray, jdouble *, jint);
 */

void uwsgi_jvm_array_release_boolean(jbooleanArray array, jboolean * elems, jint mode) {

    (*ujvm.env)->ReleaseBooleanArrayElements(ujvm.env, array, elems, mode);

}

void uwsgi_jvm_array_release_byte(jbyteArray array, jbyte * elems, jint mode) {

    (*ujvm.env)->ReleaseByteArrayElements(ujvm.env, array, elems, mode);

}

void uwsgi_jvm_array_release_char(jcharArray array, jchar * elems, jint mode) {

    (*ujvm.env)->ReleaseCharArrayElements(ujvm.env, array, elems, mode);

}

void uwsgi_jvm_array_release_short(jshortArray array, jshort * elems, jint mode) {

    (*ujvm.env)->ReleaseShortArrayElements(ujvm.env, array, elems, mode);

}

void uwsgi_jvm_array_release_int(jintArray array, jint * elems, jint mode) {

    (*ujvm.env)->ReleaseIntArrayElements(ujvm.env, array, elems, mode);

}

void uwsgi_jvm_array_release_long(jlongArray array, jlong * elems, jint mode) {

    (*ujvm.env)->ReleaseLongArrayElements(ujvm.env, array, elems, mode);

}

void uwsgi_jvm_array_release_float(jfloatArray array, jfloat * elems, jint mode) {

    (*ujvm.env)->ReleaseFloatArrayElements(ujvm.env, array, elems, mode);

}

void uwsgi_jvm_array_release_double(jdoubleArray array, jdouble * elems, jint mode) {

    (*ujvm.env)->ReleaseDoubleArrayElements(ujvm.env, array, elems, mode);

}


jboolean uwsgi_jvm_equal(jobject obj1, jobject obj2) {

    jclass clazz = uwsgi_jvm_class_of(obj1);
    jmethodID eq = uwsgi_jvm_method(clazz, "equals", "(Ljava/lang/Object;)Z");

    return uwsgi_jvm_call_boolean(obj1, eq, obj2);

}

jstring uwsgi_jvm_tostring(jobject obj) {

    jclass clazz = uwsgi_jvm_class_of(obj);
    uwsgi_jvm_ok();

    jmethodID tostring = uwsgi_jvm_method(clazz, "toString", "()Ljava/lang/String;");

    return (jstring)uwsgi_jvm_call(obj, tostring);

}

jstring uwsgi_jvm_string_from(char * chars, int length) {

    const char * UTF8 = "UTF-8";
    static jmethodID construct = 0;

    if(!construct) {

        construct = uwsgi_jvm_method(ujvm.class_string, "<init>", "([BLjava/lang/String;)V");

    }

    jobject utf8 = uwsgi_jvm_utf8(UTF8);
    jbyteArray array = uwsgi_jvm_array_byte(length);
    uwsgi_jvm_array_set_region_byte(array, 0, length, (jbyte *) chars);

    jobject result = uwsgi_jvm_new(ujvm.class_string, construct, array, utf8);
    uwsgi_jvm_ok();

    return result;

}

const jchar * uwsgi_jvm_tostrchars(jobject obj) {

    return uwsgi_jvm_strchars(uwsgi_jvm_tostring(obj));

}

const char * uwsgi_jvm_toutf8chars(jobject obj) {

    return uwsgi_jvm_utf8chars(uwsgi_jvm_tostring(obj));

}

jobject uwsgi_jvm_hashtable() {

    static jmethodID construct = 0;

    if (!construct) {

        construct = uwsgi_jvm_method(ujvm.class_hashtable, "<init>", "()V");

    }

    return uwsgi_jvm_new(ujvm.class_hashtable, construct);
}

jint uwsgi_jvm_hashtable_size(jobject obj) {

    static jmethodID size = 0 ;

    if (!size) {

        size = uwsgi_jvm_method(ujvm.class_hashtable, "size", "()I");

    }

    return uwsgi_jvm_call_int(obj, size);
}

jobject uwsgi_jvm_hashtable_get(jobject obj, jobject key) {

    static jmethodID get = 0 ;

    if (!get) {

        get = uwsgi_jvm_method(ujvm.class_hashtable, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");

    }

    return uwsgi_jvm_call(obj, get, key);
}

jobject uwsgi_jvm_hashtable_put(jobject obj, jobject key, jobject val) {

    static jmethodID put = 0 ;

    if (!put) {

        put = uwsgi_jvm_method(ujvm.class_hashtable, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    }

    return uwsgi_jvm_call(obj, put, key, val);
}

jobject uwsgi_jvm_fd(int fd) {

    static jmethodID mid_fd = 0;
    static jfieldID fid_fd = 0;

    jobject obj_fd;

    if (!mid_fd) {

        mid_fd = uwsgi_jvm_method(ujvm.class_file_descriptor, "<init>", "()V");

    }

    if (!fid_fd) {

        fid_fd = uwsgi_jvm_field(ujvm.class_file_descriptor, "fd", "I");

    }

    obj_fd = uwsgi_jvm_new(ujvm.class_file_descriptor, mid_fd);

    uwsgi_jvm_set_int(obj_fd, fid_fd, fd);

    return obj_fd;
}

jobject uwsgi_jvm_in() {

    static jclass system;
    static jfieldID fld_in = 0;

    if(!fld_in) {

        system = uwsgi_jvm_class_for("java/lang/System");
        fld_in = uwsgi_jvm_field_static(system, "in", "Ljava/io/InputStream;");

    }

    return uwsgi_jvm_get_static(system, fld_in);

}

jobject uwsgi_jvm_out() {

    static jclass system;
    static jfieldID fld_out = 0;

    if(!fld_out) {

        system = uwsgi_jvm_class_for("java/lang/System");
        fld_out = uwsgi_jvm_field_static(system, "out", "Ljava/io/PrintStream;");

    }

    return uwsgi_jvm_get_static(system, fld_out);

}

jobject uwsgi_jvm_err() {

    static jclass system;
    static jfieldID fld_err = 0;

    if(!fld_err) {

        system = uwsgi_jvm_class_for("java/lang/System");
        fld_err = uwsgi_jvm_field_static(system, "err", "Ljava/io/PrintStream;");

    }

    return uwsgi_jvm_get_static(system, fld_err);

}

void uwsgi_jvm_print(jstring msg) {

    static jclass stream;
    static jmethodID print = 0;

    if(!print) {

        stream = uwsgi_jvm_class_for("java/io/PrintStream");
        print = uwsgi_jvm_method(stream, "print", "(Ljava/lang/String;)V");

    }

    uwsgi_jvm_call(uwsgi_jvm_out(), print, msg);

}

void uwsgi_jvm_println(jstring msg) {

    static jclass stream;
    static jmethodID println = 0;

    if(!println) {

        stream = uwsgi_jvm_class_for("java/io/PrintStream");
        println = uwsgi_jvm_method(stream, "println", "(Ljava/lang/String;)V");

    }

    uwsgi_jvm_call(uwsgi_jvm_out(), println, msg);

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

    uwsgi_jvm_begin(MAX_LREFS);

    ujvm.class_string = uwsgi_jvm_class_for("java/lang/String");
    uwsgi_log("JVM String class initialized\n");
    ujvm.class_hashtable  = uwsgi_jvm_class_for("java/util/Hashtable");
    uwsgi_log("JVM Hashtable class initialized\n");
    ujvm.class_file_descriptor  = uwsgi_jvm_class_for("java/io/FileDescriptor");
    uwsgi_log("JVM FileDescriptor class initialized\n");

    uwsgi_jvm_end();

    uwsgi_jvm_begin(MAX_LREFS);

    if (ujvm.string_main) {
        uwsgi_log(ujvm.string_main);
        ujvm.class_main = uwsgi_jvm_class_for(ujvm.string_main);
        if (!ujvm.class_main) {
            uwsgi_log(" can not be found!\n");
            exit(1);
        }

        mid_main = uwsgi_jvm_method_static(ujvm.class_main, "main", "([Ljava/lang/String;)V");
        if (mid_main) {
            uwsgi_jvm_call_static(ujvm.class_main, mid_main);
            uwsgi_jvm_ok();
        }
    }

    uwsgi_jvm_end();

    uwsgi_jvm_begin(MAX_LREFS);

    uwsgi_jvm_println(uwsgi_jvm_utf8("UTF-8"));

    uwsgi_jvm_end();

    return 1;
}

struct uwsgi_plugin jvm_plugin = {

    .name = "jvm",
    .init = jvm_init,
    .options = uwsgi_jvm_options,
};


