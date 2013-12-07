#include "v8_uwsgi.h"

struct uwsgi_v8 uv8;

extern struct uwsgi_server uwsgi;
extern struct uwsgi_plugin v8_plugin;

struct uwsgi_option uwsgi_v8_options[] = {
        {(char *)"v8-load", required_argument, 0, (char *)"load a javascript file", uwsgi_opt_add_string_list, &uv8.load, 0},
        {(char *)"v8-preemptive", required_argument, 0, (char *)"put v8 in preemptive move (single isolate) with the specified frequency", uwsgi_opt_set_int, &uv8.preemptive, 0},
        {(char *)"v8-gc-freq", required_argument, 0, (char *)"set the v8 garbage collection frequency", uwsgi_opt_set_64bit, &uv8.gc_freq, 0},
        {(char *)"v8-module-path", required_argument, 0, (char *)"set the v8 modules search path", uwsgi_opt_add_string_list, &uv8.module_paths, 0},
        {(char *)"v8-jsgi", required_argument, 0, (char *)"load the specified JSGI 3.0 application", uwsgi_opt_set_str, &uv8.jsgi, 0},
        {0, 0, 0, 0},
};

static v8::Handle<v8::Value> uwsgi_v8_api_register_signal(const v8::Arguments& args) {

        if (args.Length() > 2) {
		uint8_t uwsgi_signal = args[0]->Uint32Value();
		v8::String::Utf8Value signal_kind(args[1]->ToString());

		v8::Persistent<v8::Function> func = v8::Persistent<v8::Function>::New(v8::Handle<v8::Function>::Cast(args[2]));

		int core_id = (long) pthread_getspecific(uv8.current_core);
		struct uwsgi_v8_signal_table *uvst = &uv8.sigtable[uwsgi_signal];

		int need_register = 1;
		if (uvst->registered == 1) {
			need_register = 0;
		}

		uvst->func[core_id] = func;

		if (!need_register) {
			return v8::True();
		}

		if (uwsgi_register_signal(uwsgi_signal, *signal_kind, uvst, v8_plugin.modifier1)) {
			uwsgi_log("[uwsgi-v8] unable to register signal %d\n", uwsgi_signal);
			return v8::Undefined();
		}
		uvst->registered = 1 ;
		
		return v8::True();
        }

        return v8::Undefined();
}

static v8::Handle<v8::Value> uwsgi_v8_api_register_rpc(const v8::Arguments& args) {

        if (args.Length() > 1) {
		v8::String::Utf8Value name(args[0]->ToString());
		uint8_t j_argc = 0;
		if (args.Length() > 2) {
			j_argc = args[2]->Uint32Value();
		}

		v8::Persistent<v8::Function> func = v8::Persistent<v8::Function>::New(v8::Handle<v8::Function>::Cast(args[1]));

		int core_id = (long) pthread_getspecific(uv8.current_core);

		// get the rpc slot
		int i;
		int found = 0;
		struct uwsgi_v8_rpc_table *uvrt = NULL;
		for(i=0;i<(int)uwsgi.rpc_max;i++) {
			uvrt = &uv8.rpctable[i];
			if (uvrt->name == NULL) {
				found = 1;
				break;
			}
			// skip already registered funcs
			else if (!strcmp(uvrt->name, *name)) {
				uvrt->func[core_id] = func;
				return v8::True();
			}
		}
		if (!found || !uvrt) {
			uwsgi_log("[uwsgi-v8] unable to register RPC function \"%s\"\n", *name);
                        return v8::Undefined();
		}
		uvrt->name = uwsgi_str(*name);
		uvrt->func[core_id] = func;

		// we can safely call register_rpc here as it will check for already registered funcs
		if (uwsgi_register_rpc(*name, &v8_plugin, j_argc, uvrt)) {
			uwsgi_log("[uwsgi-v8] unable to register RPC function \"%s\"\n", *name);
			return v8::Undefined();
		}

		return v8::True();
        }

        return v8::Undefined();
}

static void uwsgi_v8_load_file(int core_id, char *filename) {

	uv8.isolates[core_id]->Enter();
	uv8.contexts[core_id]->Enter();
	v8::HandleScope handle_scope;
	
	size_t len = 0;
	char *code = uwsgi_open_and_read(filename, &len, 1, NULL);

        // we do not use TryCatch as we directly use stderr and simply exit with error code 1
        v8::Handle<v8::Script> script = v8::Script::Compile( v8::String::New(code), v8::String::New(filename) );
        free(code);
        if (script.IsEmpty()) {
		exit(1);
        }

        v8::Handle<v8::Value> result = script->Run();
        if (result.IsEmpty()) {
		exit(1);
        }

}

static v8::Handle<v8::Value> uwsgi_v8_api_log(const v8::Arguments& args) {

        if (args.Length() > 0) {
                v8::String::Utf8Value str(args[0]->ToString());
                size_t slen = strlen(*str);
                if ((*str)[slen-1] == '\n') {
                        uwsgi_log("%s", *str);
                }
                else {
                        uwsgi_log("%s\n", *str);
                }
        }
        return v8::Undefined();
}

v8::Persistent<v8::Context> uwsgi_v8_setup_context();

static v8::Persistent<v8::Context> uwsgi_v8_new_isolate(int core_id) {
        // create a new isolate
        v8::Isolate *isolate = v8::Isolate::New();
        // set as the current isolate
	isolate->Enter();

	uv8.isolates[core_id] = v8::Isolate::GetCurrent();

	v8::Persistent<v8::Context> context = uwsgi_v8_setup_context();
	context->Enter();

	v8::HandleScope handle_scope;

	// uWSGI api
        v8::Handle<v8::Object> uwsgi_api = v8::Object::New();
        uwsgi_api->Set(v8::String::New("log"), v8::FunctionTemplate::New(uwsgi_v8_api_log)->GetFunction());
        uwsgi_api->Set(v8::String::New("register_rpc"), v8::FunctionTemplate::New(uwsgi_v8_api_register_rpc)->GetFunction());
        uwsgi_api->Set(v8::String::New("register_signal"), v8::FunctionTemplate::New(uwsgi_v8_api_register_signal)->GetFunction());

        context->Global()->Set(v8::String::New("uwsgi"), uwsgi_api);

        return context;
}

extern "C" int uwsgi_v8_init(){
	int i;
        uwsgi_log("Initializing V8 %s environment... (%d Isolates)\n", v8::V8::GetVersion(), uwsgi.cores);
	uv8.isolates = (v8::Isolate **) uwsgi_malloc( sizeof(v8::Isolate *) * uwsgi.cores );
        uv8.contexts = (v8::Persistent<v8::Context> *) uwsgi_malloc( sizeof(v8::Persistent<v8::Context>) * uwsgi.cores );
	// allocates rpc and signal tables
	uv8.rpctable = (struct uwsgi_v8_rpc_table *) uwsgi_calloc(sizeof(struct uwsgi_v8_rpc_table) * uwsgi.rpc_max);
	for(i=0;i<(int)uwsgi.rpc_max;i++) {
		uv8.rpctable[i].func = (v8::Persistent<v8::Function>*) uwsgi_calloc(sizeof(v8::Persistent<v8::Function>) * uwsgi.cores);
	}
	uv8.sigtable = (struct uwsgi_v8_signal_table *) uwsgi_calloc(sizeof(struct uwsgi_v8_signal_table) * 256);
	for(i=0;i<256;i++) {
                uv8.sigtable[i].func = (v8::Persistent<v8::Function>*) uwsgi_calloc(sizeof(v8::Persistent<v8::Function>) * uwsgi.cores);
        }
	uv8.jsgi_func = (v8::Persistent<v8::Function> *) uwsgi_calloc( sizeof(v8::Persistent<v8::Function>) * uwsgi.cores );
	uv8.jsgi_writer_func = (v8::Persistent<v8::Function> *) uwsgi_calloc( sizeof(v8::Persistent<v8::Function>) * uwsgi.cores );

	pthread_key_create(&uv8.current_core, NULL);
	pthread_setspecific(uv8.current_core, (void *) 0);

        uv8.contexts[0] = uwsgi_v8_new_isolate(0);

        return 0;
}

static void uwsgi_v8_apps_do(int core_id) {
	struct uwsgi_string_list *usl = uv8.load;
        while(usl) {
                uwsgi_v8_load_file(core_id, usl->value);
                usl = usl->next;
        }

	if (uv8.jsgi) {
		uv8.jsgi_func[core_id] = uwsgi_v8_load_jsgi(core_id, uv8.jsgi);
	}
}

extern "C" void uwsgi_v8_apps() {
	uwsgi_v8_apps_do(0);
}

extern "C" void uwsgi_v8_configurator(char *filename, char *magic_table[]) {

	v8::HandleScope handle_scope;

	uwsgi_log_initial("[uWSGI] getting javascript (V8) configuration from %s\n", filename);

	size_t len = 0;
	char *code = uwsgi_open_and_read(filename, &len, 1, NULL);

	v8::Handle<v8::Context> context = v8::Context::New();

	v8::Context::Scope context_scope(context);

	// we do not use TryCatch as we directly use stderr and simply exit with error code 1
	
	v8::Handle<v8::Script> script = v8::Script::Compile( v8::String::New(code), v8::String::New(filename) );
	if (script.IsEmpty()) {
		exit(1);
	}
	free(code);

	v8::Handle<v8::Value> result = script->Run();
	if (result.IsEmpty()) {
		exit(1);
	}

	if (!result->IsArray() && !result->IsObject()) {
		uwsgi_log("javascript return value must be an object or an array !!!\n");
		exit(1);
	}

	uint32_t i;
	const v8::Local<v8::Array> props = result->ToObject()->GetPropertyNames();
	const uint32_t l = props->Length();

	for(i=0;i<l;i++) {
		const v8::Local<v8::Value> key = props->Get(i);	
		const v8::Local<v8::Value> value = result->ToObject()->Get(key);	
		v8::String::Utf8Value c_key(key->ToString());
		if (value->IsArray()) {
			uint32_t opt_l = value->ToObject()->Get(v8::String::New("length"))->ToObject()->Uint32Value();
			uint32_t j;
			for(j=0;j<opt_l;j++) {
				v8::String::Utf8Value c_value(value->ToObject()->Get(j)->ToString());
				add_exported_option(uwsgi_str(*c_key), uwsgi_str(*c_value), 0);
			}
		}
		else {
			v8::String::Utf8Value c_value(value->ToString());
			add_exported_option(uwsgi_str(*c_key), uwsgi_str(*c_value), 0);
		}
	}
	
}

extern "C" uint64_t uwsgi_v8_rpc(void * func, uint8_t argc, char **argv, uint16_t argvs[], char **buffer) {

	int core_id = (long) pthread_getspecific(uv8.current_core);

	uv8.isolates[core_id]->Enter();
	uv8.contexts[core_id]->Enter();
	v8::HandleScope handle_scope;
	v8::Handle<v8::Value> argj[256];

	struct uwsgi_v8_rpc_table *uvrt = (struct uwsgi_v8_rpc_table *) func;
	
	uint8_t i;
	for(i=0;i<argc;i++) {
		argj[i] = v8::String::New(argv[i], argvs[i]);
	}

	v8::Persistent<v8::Function> l_func = uvrt->func[core_id];

	v8::Handle<v8::Value> result = l_func->Call(uv8.contexts[core_id]->Global(), argc, argj);
	if (result.IsEmpty()) {
		return 0;
	}

	v8::Handle<v8::String> robj = result->ToString();
	
	v8::String::Utf8Value r_value(robj);
	if (!*robj) {
		return 0;
	}
	uint64_t rlen = (uint64_t) robj->Length();
	if (rlen > 0) {
		*buffer = (char *)uwsgi_malloc(rlen);
		memcpy(*buffer, *r_value, rlen);
	}
	// call GC every time, could be overkill, we should allow to tune that choice
	while(!v8::V8::IdleNotification()) {};
        return rlen;

}

extern "C" void uwsgi_v8_init_thread(int core_id) {
	pthread_setspecific(uv8.current_core, (void *) ((long)core_id));
	uv8.contexts[core_id] = uwsgi_v8_new_isolate(core_id);
	uwsgi_v8_apps_do(core_id);
}

extern "C" void uwsgi_v8_enable_threads() {
}

extern "C" int uwsgi_v8_signal_handler(uint8_t sig, void *handler) {
	int ret = 0;
	int core_id = (long) pthread_getspecific(uv8.current_core);

        uv8.isolates[core_id]->Enter();
        uv8.contexts[core_id]->Enter();
        v8::HandleScope handle_scope;
        v8::Handle<v8::Value> argj[1];
	argj[0] = v8::Number::New(sig);
	struct uwsgi_v8_signal_table *uvst = (struct uwsgi_v8_signal_table *) handler;
	v8::Persistent<v8::Function> l_func = uvst->func[core_id];
	v8::Handle<v8::Value> result = l_func->Call(uv8.contexts[core_id]->Global(), 1, argj);
	if (result.IsEmpty()) ret = -1;
	while(!v8::V8::IdleNotification()) {};
	return ret;
}

extern "C" int uwsgi_v8_mule(char *opt) {

        if (uwsgi_endswith(opt, (char *)".js")) {
		uwsgi_v8_load_file(0, opt);
                return 1;
        }

        return 0;

}
