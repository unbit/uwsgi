#include <uwsgi.h>
#include <v8.h>

// as we have isolates in multithread modes, we need to maintain
// special tables for the handlers (mules and spooler just run on the core 0)
struct uwsgi_v8_signal_table {
        v8::Persistent<v8::Function> *func;
        uint8_t registered;
};

struct uwsgi_v8_rpc_table {
        char *name;
        v8::Persistent<v8::Function> *func;
};

struct uwsgi_v8 {
        v8::Persistent<v8::Context> *contexts;
        v8::Isolate **isolates;
	char *jsgi;
	v8::Persistent<v8::Function> *jsgi_func;
	v8::Persistent<v8::Function> *jsgi_writer_func;
	int jsgi_announced;
        struct uwsgi_string_list *load;
        struct uwsgi_v8_signal_table *sigtable;
        struct uwsgi_v8_rpc_table *rpctable;
        pthread_key_t current_core;
        int preemptive;
        uint64_t gc_freq;
        struct uwsgi_string_list *module_paths;
};

v8::Persistent<v8::Function> uwsgi_v8_load_jsgi(int, char *);
