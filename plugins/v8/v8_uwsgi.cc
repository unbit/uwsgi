#include <uwsgi.h>
#include <v8.h>

// as we have isolates in multithread modes, we need to maintain
// special tables for the handlers (mules and spooler just run on the core 0)
struct uwsgi_v8_signal_table {
	void *func;
};

struct uwsgi_v8_rpc_table {
	char *name;
	v8::Persistent<v8::Function> *func;
};

v8::Persistent<v8::Function> handler1;

struct uwsgi_v8 {
        v8::Persistent<v8::Context> *contexts;
	v8::Isolate **isolates;
        struct uwsgi_string_list *load;
	struct uwsgi_v8_signal_table **sigtable;
	struct uwsgi_v8_rpc_table *rpctable;
	int current_core;
	int preemptive;
} uv8;

extern struct uwsgi_server uwsgi;
extern struct uwsgi_plugin v8_plugin;

struct uwsgi_option uwsgi_v8_options[] = {
        {(char *)"v8-load", required_argument, 0, (char *)"load a javascript file", uwsgi_opt_add_string_list, &uv8.load, 0},
        {(char *)"v8-preemptive", required_argument, 0, (char *)"put v8 in preemptive move (single isolate) with the specified frequency", uwsgi_opt_set_int, &uv8.preemptive, 0},
        {0, 0, 0, 0},
};

static v8::Handle<v8::Value> uwsgi_v8_api_register_signal(const v8::Arguments& args) {

        if (args.Length() > 2) {
		uint8_t uwsgi_signal = args[0]->Uint32Value();
		v8::String::Utf8Value signal_kind(args[1]->ToString());

		v8::Persistent<v8::Function> func = v8::Persistent<v8::Function>::New(v8::Handle<v8::Function>::Cast(args[2]));

		if (uwsgi_register_signal(uwsgi_signal, *signal_kind, *func, v8_plugin.modifier1)) {
			uwsgi_log("[uwsgi-v8] unable to register signal %d\n", uwsgi_signal);
			return v8::Undefined();
		}
		
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

	
		//v8::Persistent<v8::Function> func = v8::Persistent<v8::Function>::New(v8::Handle<v8::Function>::Cast(args[1]));
		v8::Local<v8::Function> l_func = v8::Local<v8::Function>::Cast(args[1]);
		v8::Persistent<v8::Function> func = v8::Persistent<v8::Function>::New(l_func);

		int core_id = uv8.current_core;
		if (core_id < 0) {
			struct wsgi_request *wsgi_req = current_wsgi_req();
			core_id = wsgi_req->async_id;
		}

		if (core_id == 1) {
			uwsgi_log("OOOOps\n");
			handler1 = v8::Persistent<v8::Function>::New(l_func);
		}

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
		if (uwsgi_register_rpc(*name, v8_plugin.modifier1, j_argc, uvrt)) {
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


static v8::Persistent<v8::Context> uwsgi_v8_new_isolate(int core) {
        if (core > 0) {
                // create a new isolate
                v8::Isolate *isolate = v8::Isolate::New();
                // set as the current isolate
		isolate->Enter();
        }

	uv8.isolates[core] = v8::Isolate::GetCurrent();

	v8::HandleScope handle_scope;

	// uWSGI api
        v8::Handle<v8::ObjectTemplate> uwsgi_api = v8::ObjectTemplate::New();
        uwsgi_api->Set(v8::String::New("log"), v8::FunctionTemplate::New(uwsgi_v8_api_log));
        uwsgi_api->Set(v8::String::New("register_rpc"), v8::FunctionTemplate::New(uwsgi_v8_api_register_rpc));
        uwsgi_api->Set(v8::String::New("register_signal"), v8::FunctionTemplate::New(uwsgi_v8_api_register_signal));

	v8::Handle<v8::ObjectTemplate> global = v8::ObjectTemplate::New();
	global->Set(v8::String::New("uwsgi"), uwsgi_api);

        // create a new context
        v8::Persistent<v8::Context> context = v8::Context::New(NULL, global);
        return context;
}

extern "C" int uwsgi_v8_init(){
	int i;
        uwsgi_log("Initializing V8 %s environment... (%d Isolates)\n", v8::V8::GetVersion(), uwsgi.cores);
	uv8.isolates = (v8::Isolate **) uwsgi_malloc( sizeof(v8::Isolate *) * uwsgi.cores );
        uv8.contexts = (v8::Persistent<v8::Context> *) uwsgi_malloc( sizeof(v8::Persistent<v8::Context>) * uwsgi.cores );
	for(i=0;i<uwsgi.cores;i++) {
                uv8.contexts[i] = uwsgi_v8_new_isolate(i);
	}
	// allocates rpc and signal tables
	uv8.rpctable = (struct uwsgi_v8_rpc_table *) uwsgi_calloc(sizeof(struct uwsgi_v8_rpc_table) * uwsgi.rpc_max);
	for(i=0;i<(int)uwsgi.rpc_max;i++) {
		uv8.rpctable[i].func = (v8::Persistent<v8::Function>*) uwsgi_calloc(sizeof(v8::Persistent<v8::Function>) * uwsgi.cores);
	}
/*
	uv8.sigtable = (struct uwsgi_v8_signal_table **) uwsgi_calloc(sizeof(struct uwsgi_v8_signal_table *) * 256);
	for(i=0;i<256;i++) {
                uv8.sigtable[i] = (struct uwsgi_v8_signal_table *) uwsgi_calloc(sizeof(struct uwsgi_v8_signal_table) * uwsgi.cores);
        }
*/

        return 0;
}

extern "C" void uwsgi_v8_apps() {

        if (!uv8.load) return;

        int i;
        for(i=0;i<uwsgi.cores;i++) {
		uv8.current_core = i;
                struct uwsgi_string_list *usl = uv8.load;
                while(usl) {
                        uwsgi_v8_load_file(i, usl->value);
                        usl = usl->next;
                }
        }
	// inform the system to use current_wsgi_req
	uv8.current_core = -1;
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

extern "C" uint16_t uwsgi_v8_rpc(void * func, uint8_t argc, char **argv, uint16_t argvs[], char *buffer) {

	int core_id = 0;
	if (uwsgi.mywid > 0) {
        	struct wsgi_request *wsgi_req = current_wsgi_req();
		core_id = wsgi_req->async_id;
	}

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

	if (core_id == 1) {
		uwsgi_log("111111\n");
		l_func = handler1;
	}

	v8::Handle<v8::Value> result = l_func->Call(uv8.contexts[core_id]->Global(), argc, argj);
	if (result.IsEmpty()) {
		return 0;
	}

	v8::Handle<v8::String> robj = result->ToString();
	
	v8::String::Utf8Value r_value(robj);
	if (!*robj) {
		return 0;
	}
	uint16_t rlen = robj->Length();
	memcpy(buffer, *r_value, rlen);
	// call GC every time, could be overkill, we should allow to tune that choice
	while(!v8::V8::IdleNotification()) {};
        return rlen;

}

extern "C" int uwsgi_v8_signal_handler(uint8_t sig, void *handler) {
	int ret = 0;
	v8::HandleScope handle_scope;
	struct wsgi_request *wsgi_req = current_wsgi_req();
	v8::Context::Scope context_scope(uv8.contexts[wsgi_req->async_id]);
	v8::Persistent<v8::Function> l_func = static_cast<v8::Function*> (handler);
	v8::Handle<v8::Value> argj[1];
	argj[0] = v8::Number::New(sig);
	v8::Handle<v8::Value> result = l_func->Call(l_func, 1, argj);
	if (result.IsEmpty()) ret = -1;
	while(!v8::V8::IdleNotification()) {};
	return ret;
}
