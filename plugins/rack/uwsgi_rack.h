#include "../../uwsgi.h"

#include <ruby.h>

#define LONG_ARGS_RACK_BASE     17000 + ((7 + 1) * 100)
#define LONG_ARGS_RAILS         LONG_ARGS_RACK_BASE + 1
#define LONG_ARGS_RUBY_GC_FREQ  LONG_ARGS_RACK_BASE + 2
#define LONG_ARGS_RACK          LONG_ARGS_RACK_BASE + 3

#ifndef RUBY19
        #define rb_errinfo() ruby_errinfo
        #define RUBY_GVL_LOCK
        #define RUBY_GVL_UNLOCK
#else
        void fiber_loop(void);
        #ifdef UWSGI_THREADING
                #define RUBY_GVL_LOCK if (uwsgi.threads > 1) {\
                        pthread_mutex_lock(&ur.gvl);\
                        }

                #define RUBY_GVL_UNLOCK if (uwsgi.threads > 1) {\
                        pthread_mutex_unlock(&ur.gvl);\
                        }
        #else
                #define RUBY_GVL_LOCK
                #define RUBY_GVL_UNLOCK
        #endif
#endif

#ifndef RARRAY_LEN
#define RARRAY_LEN(x) RARRAY(x)->len
#endif

#ifndef RARRAY_PTR
#define RARRAY_PTR(x) RARRAY(x)->ptr
#endif

#ifndef RSTRING_PTR
#define RSTRING_PTR(x) RSTRING(x)->ptr
#endif

#ifndef RSTRING_LEN
#define RSTRING_LEN(x) RSTRING(x)->len
#endif

struct uwsgi_rack {

        char *rails;
        char *rack;
        int gc_freq;
        uint64_t cycles;

        int call_gc;
        VALUE dispatcher;
        VALUE rb_uwsgi_io_class;
        ID call;
        VALUE fibers[200];
        int unprotected;

        pthread_mutex_t gvl;

};

void uwsgi_ruby_exception(void);
