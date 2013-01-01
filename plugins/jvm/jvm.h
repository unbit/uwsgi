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

struct uwsgi_jvm {

    struct uwsgi_string_list * classpath;

    JNIEnv * env;

    char *   string_main;
    jclass   class_main;

    jclass class_string;
    jclass class_hashtable;
    jclass class_file_descriptor;

};

jboolean      uwsgi_jvm_begin(jint);
jboolean      uwsgi_jvm_ensure(jint);
jobject       uwsgi_jvm_claim(jobject);
void          uwsgi_jvm_delete(jobject);
void          uwsgi_jvm_end();
jint          uwsgi_jvm_throw(jthrowable);
jint          uwsgi_jvm_throw_new(jclass, const char *);
void          uwsgi_jvm_fatal(const char *);
jthrowable    uwsgi_jvm_catch();
void          uwsgi_jvm_describe();
void          uwsgi_jvm_clear();
jint          uwsgi_jvm_ok();
jclass        uwsgi_jvm_class_for(char *);
jclass        uwsgi_jvm_class_of(jobject);
jclass        uwsgi_jvm_super(jclass);
jboolean      uwsgi_jvm_assignable(jclass, jclass);
jfieldID      uwsgi_jvm_field(jclass, char *, char *);
jfieldID      uwsgi_jvm_field_static(jclass, char *, char *);
jmethodID     uwsgi_jvm_method(jclass, char *, char *);
jmethodID     uwsgi_jvm_method_static(jclass, char *, char *);
jobject       uwsgi_jvm_new(jclass, jmethodID, ...);
jboolean      uwsgi_jvm_same(jobject, jobject);
jboolean      uwsgi_jvm_is_a(jobject, jclass);
jobject       uwsgi_jvm_get(jobject, jfieldID);
jboolean      uwsgi_jvm_get_boolean(jobject, jfieldID);
jbyte         uwsgi_jvm_get_byte(jobject, jfieldID);
jchar         uwsgi_jvm_get_char(jobject, jfieldID);
jshort        uwsgi_jvm_get_short(jobject, jfieldID);
jint          uwsgi_jvm_get_int(jobject, jfieldID);
jlong         uwsgi_jvm_get_long(jobject, jfieldID);
jfloat        uwsgi_jvm_get_float(jobject, jfieldID);
jdouble       uwsgi_jvm_get_double(jobject, jfieldID);
jstring       uwsgi_jvm_get_string(jobject, jfieldID);
char *        uwsgi_jvm_get_utf8(jobject, jfieldID);
void          uwsgi_jvm_set(jobject, jfieldID, jobject);
void          uwsgi_jvm_set_boolean(jobject, jfieldID, jboolean);
void          uwsgi_jvm_set_byte(jobject, jfieldID, jbyte);
void          uwsgi_jvm_set_char(jobject, jfieldID, jchar);
void          uwsgi_jvm_set_short(jobject, jfieldID, jshort);
void          uwsgi_jvm_set_int(jobject, jfieldID, jint);
void          uwsgi_jvm_set_long(jobject, jfieldID, jlong);
void          uwsgi_jvm_set_float(jobject, jfieldID, jfloat);
void          uwsgi_jvm_set_double(jobject, jfieldID, jdouble);
void          uwsgi_jvm_set_string(jobject, jfieldID, jstring);
void          uwsgi_jvm_set_utf8(jobject, jfieldID, char *);
jobject       uwsgi_jvm_get_static(jclass, jfieldID);
jboolean      uwsgi_jvm_get_static_boolean(jclass, jfieldID);
jbyte         uwsgi_jvm_get_static_byte(jclass, jfieldID);
jchar         uwsgi_jvm_get_static_char(jclass, jfieldID);
jshort        uwsgi_jvm_get_static_short(jclass, jfieldID);
jint          uwsgi_jvm_get_static_int(jclass, jfieldID);
jlong         uwsgi_jvm_get_static_long(jclass, jfieldID);
jfloat        uwsgi_jvm_get_static_float(jclass, jfieldID);
jdouble       uwsgi_jvm_get_static_double(jclass, jfieldID);
jstring       uwsgi_jvm_get_static_string(jclass, jfieldID);
char *        uwsgi_jvm_get_static_utf8(jclass, jfieldID);
void          uwsgi_jvm_set_static(jclass, jfieldID, jobject);
void          uwsgi_jvm_set_static_boolean(jclass, jfieldID, jboolean);
void          uwsgi_jvm_set_static_byte(jclass, jfieldID, jbyte);
void          uwsgi_jvm_set_static_char(jclass, jfieldID, jchar);
void          uwsgi_jvm_set_static_short(jclass, jfieldID, jshort);
void          uwsgi_jvm_set_static_int(jclass, jfieldID, jint);
void          uwsgi_jvm_set_static_long(jclass, jfieldID, jlong);
void          uwsgi_jvm_set_static_float(jclass, jfieldID, jfloat);
void          uwsgi_jvm_set_static_double(jclass, jfieldID, jdouble);
void          uwsgi_jvm_set_static_string(jclass, jfieldID, jstring);
void          uwsgi_jvm_set_static_utf8(jclass, jfieldID, char *);
jobject       uwsgi_jvm_call(jobject, jmethodID, ...);
jboolean      uwsgi_jvm_call_boolean(jobject, jmethodID, ...);
jint          uwsgi_jvm_call_byte(jobject, jmethodID, ...);
jchar         uwsgi_jvm_call_char(jobject, jmethodID, ...);
jshort        uwsgi_jvm_call_short(jobject, jmethodID, ...);
jint          uwsgi_jvm_call_int(jobject, jmethodID, ...);
jlong         uwsgi_jvm_call_long(jobject, jmethodID, ...);
jfloat        uwsgi_jvm_call_float(jobject, jmethodID, ...);
jdouble       uwsgi_jvm_call_double(jobject, jmethodID, ...);
void          uwsgi_jvm_call_void(jobject, jmethodID, ...);
jstring       uwsgi_jvm_call_string(jobject, jmethodID, ...);
char *        uwsgi_jvm_call_utf8(jobject, jmethodID, ...);
jobject       uwsgi_jvm_call_direct(jobject, jclass, jmethodID, ...);
jboolean      uwsgi_jvm_call_direct_boolean(jobject, jclass, jmethodID, ...);
jint          uwsgi_jvm_call_direct_byte(jobject, jclass, jmethodID, ...);
jchar         uwsgi_jvm_call_direct_char(jobject, jclass, jmethodID, ...);
jshort        uwsgi_jvm_call_direct_short(jobject, jclass, jmethodID, ...);
jint          uwsgi_jvm_call_direct_int(jobject, jclass, jmethodID, ...);
jlong         uwsgi_jvm_call_direct_long(jobject, jclass, jmethodID, ...);
jfloat        uwsgi_jvm_call_direct_float(jobject, jclass, jmethodID, ...);
jdouble       uwsgi_jvm_call_direct_double(jobject, jclass, jmethodID, ...);
void          uwsgi_jvm_call_direct_void(jobject, jclass, jmethodID, ...);
jstring       uwsgi_jvm_call_direct_string(jobject, jclass, jmethodID, ...);
char *        uwsgi_jvm_call_direct_utf8(jobject, jclass, jmethodID, ...);
jobject       uwsgi_jvm_call_static(jclass, jmethodID, ...);
jboolean      uwsgi_jvm_call_static_boolean(jclass, jmethodID, ...);
jint          uwsgi_jvm_call_static_byte(jclass, jmethodID, ...);
jchar         uwsgi_jvm_call_static_char(jclass, jmethodID, ...);
jshort        uwsgi_jvm_call_static_short(jclass, jmethodID, ...);
jint          uwsgi_jvm_call_static_int(jclass, jmethodID, ...);
jlong         uwsgi_jvm_call_static_long(jclass, jmethodID, ...);
jfloat        uwsgi_jvm_call_static_float(jclass, jmethodID, ...);
jdouble       uwsgi_jvm_call_static_double(jclass, jmethodID, ...);
void          uwsgi_jvm_call_static_void(jclass, jmethodID, ...);
jstring       uwsgi_jvm_call_static_string(jclass, jmethodID, ...);
char *        uwsgi_jvm_call_static_utf8(jclass, jmethodID, ...);
jstring       uwsgi_jvm_string(jchar *, jsize);
jsize         uwsgi_jvm_strlen(jstring);
const jchar * uwsgi_jvm_strchars(jstring);
void          uwsgi_jvm_release_strchars(jstring, const jchar *);
jstring       uwsgi_jvm_utf8(const char *);
jsize         uwsgi_jvm_utf8len(jstring);
const char *  uwsgi_jvm_utf8chars(jstring);
void          uwsgi_jvm_release_utf8chars(jstring, const char *);
jsize         uwsgi_jvm_arraylen(jarray);
jobjectArray  uwsgi_jvm_array(jclass, jsize, jobject);
jbooleanArray uwsgi_jvm_array_boolean(jsize);
jbyteArray    uwsgi_jvm_array_byte(jsize);
jcharArray    uwsgi_jvm_array_char(jsize);
jshortArray   uwsgi_jvm_array_short(jsize);
jintArray     uwsgi_jvm_array_int(jsize);
jlongArray    uwsgi_jvm_array_long(jsize);
jfloatArray   uwsgi_jvm_array_float(jsize);
jdoubleArray  uwsgi_jvm_array_double(jsize);
jobject       uwsgi_jvm_array_get(jobjectArray, jsize);
void          uwsgi_jvm_array_set(jobjectArray, jsize, jobject);
void          uwsgi_jvm_array_get_region_boolean(jbooleanArray, jsize, jsize, jboolean *);
void          uwsgi_jvm_array_get_region_byte(jbyteArray, jsize, jsize, jbyte *);
void          uwsgi_jvm_array_get_region_char(jcharArray, jsize, jsize, jchar *);
void          uwsgi_jvm_array_get_region_short(jshortArray, jsize, jsize, jshort *);
void          uwsgi_jvm_array_get_region_int(jintArray, jsize, jsize, jint *);
void          uwsgi_jvm_array_get_region_long(jlongArray, jsize, jsize, jlong *);
void          uwsgi_jvm_array_get_region_float(jfloatArray, jsize, jsize, jfloat *);
void          uwsgi_jvm_array_get_region_double(jdoubleArray, jsize, jsize, jdouble *);
void          uwsgi_jvm_array_set_region_boolean(jbooleanArray, jsize, jsize, jboolean *);
void          uwsgi_jvm_array_set_region_byte(jbyteArray, jsize, jsize, jbyte *);
void          uwsgi_jvm_array_set_region_char(jcharArray, jsize, jsize, jchar *);
void          uwsgi_jvm_array_set_region_short(jshortArray, jsize, jsize, jshort *);
void          uwsgi_jvm_array_set_region_int(jintArray, jsize, jsize, jint *);
void          uwsgi_jvm_array_set_region_long(jlongArray, jsize, jsize, jlong *);
void          uwsgi_jvm_array_set_region_float(jfloatArray, jsize, jsize, jfloat *);
void          uwsgi_jvm_array_set_region_double(jdoubleArray, jsize, jsize, jdouble *);
jboolean *    uwsgi_jvm_array_elems_boolean(jbooleanArray);
jbyte *       uwsgi_jvm_array_elems_byte(jbyteArray);
jchar *       uwsgi_jvm_array_elems_char(jcharArray);
jshort *      uwsgi_jvm_array_elems_short(jshortArray);
jint *        uwsgi_jvm_array_elems_int(jintArray);
jlong *       uwsgi_jvm_array_elems_long(jlongArray);
jfloat *      uwsgi_jvm_array_elems_float(jfloatArray);
jdouble *     uwsgi_jvm_array_elems_double(jdoubleArray);
void          uwsgi_jvm_array_release_boolean(jbooleanArray, jboolean *, jint);
void          uwsgi_jvm_array_release_byte(jbyteArray, jbyte *, jint);
void          uwsgi_jvm_array_release_char(jcharArray, jchar *, jint);
void          uwsgi_jvm_array_release_short(jshortArray, jshort *, jint);
void          uwsgi_jvm_array_release_int(jintArray, jint *, jint);
void          uwsgi_jvm_array_release_long(jlongArray, jlong *, jint);
void          uwsgi_jvm_array_release_float(jfloatArray, jfloat *, jint);
void          uwsgi_jvm_array_release_double(jdoubleArray, jdouble *, jint);
jboolean      uwsgi_jvm_equal(jobject, jobject);
jstring       uwsgi_jvm_tostring(jobject);
jstring       uwsgi_jvm_string_from(char *, int length);
const jchar * uwsgi_jvm_tostrchars(jobject);
const char *  uwsgi_jvm_toutf8chars(jobject);
jobject       uwsgi_jvm_hashtable();
jsize         uwsgi_jvm_hashtable_size(jobject);
jobject       uwsgi_jvm_hashtable_get(jobject, jobject);
jobject       uwsgi_jvm_hashtable_put(jobject, jobject, jobject);
jobject       uwsgi_jvm_fd(int);
jobject       uwsgi_jvm_in();
jobject       uwsgi_jvm_out();
jobject       uwsgi_jvm_err();
void          uwsgi_jvm_print(jstring);
void          uwsgi_jvm_println(jstring);



