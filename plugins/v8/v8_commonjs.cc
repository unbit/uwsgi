#include "v8_uwsgi.h"

extern struct uwsgi_v8 uv8;
extern struct uwsgi_server uwsgi;

/*

	support .js
	support .so files (TeaJS)

*/
static void uwsgi_v8_commonjs_require_do(char *filename, v8::Local<v8::Object> exports, v8::Local<v8::Object> module) {

	size_t len = 0;
        char *code = uwsgi_open_and_read(filename, &len, 1, NULL);

        // we do not use TryCatch as we directly use stderr and simply exit with error code 1
        v8::Handle<v8::Script> script = v8::Script::Compile( v8::String::New(code), v8::String::New(filename) );
        free(code);
        if (script.IsEmpty()) {
		return;
        }
        script->Run();
}

static void uwsgi_v8_commonjs_require_teajs_do(char *filename, v8::Local<v8::Object> exports, v8::Local<v8::Object> module) {

	void *handle = dlopen(filename, RTLD_LAZY);
	if (!handle) {
		uwsgi_log("error opening teajs module %s: %s\n", filename, dlerror());
		return;
	}
	typedef void (*init_t)(v8::Handle<v8::Function>, v8::Handle<v8::Object>, v8::Handle<v8::Object>);
	init_t func = (init_t) dlsym(handle, "init");
	if (!func) {
		uwsgi_log("unable to find teajs module init function\n");
		return;
	}
	func(v8::Handle<v8::Function>::Cast(v8::Context::GetCurrent()->Global()->Get(v8::String::New("require"))), exports, module);
}


static v8::Handle<v8::Value> uwsgi_v8_commonjs_require(const v8::Arguments& args) {
	if (args.Length() > 0) {
		v8::String::Utf8Value module_name(args[0]->ToString());
		char *id = (char *)"pippo";
		// we re-create every time an "exports" object to emulate a local object
		v8::Local<v8::Object> exports = v8::Object::New();
        	v8::Context::GetCurrent()->Global()->Set(v8::String::New("exports"), exports);
        	v8::Local<v8::Object> module = v8::Object::New();
        	v8::Context::GetCurrent()->Global()->Set(v8::String::New("module"), module);
        	module->Set(v8::String::New("id"), v8::String::New(id));
		// ok lets start searching the module
		if (uwsgi_is_file(*module_name)) {
			if (!uwsgi_endswith(*module_name, (char *)".js")) {
				uwsgi_v8_commonjs_require_do(*module_name, exports, module);
				return exports;
			}
			else if (!uwsgi_endswith(*module_name, (char *)".so")) {
				uwsgi_v8_commonjs_require_teajs_do(*module_name, exports, module);
				return exports;
			}
			return v8::Undefined();
		}

		// try appending .js/.so extension
		if (!uwsgi_endswith(*module_name, (char *)".js") && !uwsgi_endswith(*module_name, (char *)".so")) {
                        char *tmp_filename = uwsgi_concat2(*module_name, (char *)".so");
                        if (uwsgi_is_file(tmp_filename)) {
                                uwsgi_v8_commonjs_require_teajs_do(tmp_filename, exports, module);
                                free(tmp_filename);
				return exports;
                        }
                        free(tmp_filename);
			tmp_filename = uwsgi_concat2(*module_name, (char *)".js");
			if (uwsgi_is_file(tmp_filename)) {
				uwsgi_v8_commonjs_require_do(tmp_filename, exports, module);
				free(tmp_filename);
				return exports;	
			}
			free(tmp_filename);
                }

		// let's start searching in the modules search path
		struct uwsgi_string_list *usl = uv8.module_paths;
		while(usl) {
			char *tmp_filename = uwsgi_concat3(usl->value, (char *)"/", *module_name);
			if (uwsgi_is_file(tmp_filename)) {
				if (!uwsgi_endswith(tmp_filename, (char *)".js")) {
                        		uwsgi_v8_commonjs_require_do(tmp_filename, exports, module);
				}
				else if (!uwsgi_endswith(tmp_filename, (char *)".so")) {
                        		uwsgi_v8_commonjs_require_teajs_do(tmp_filename, exports, module);
				}
				else {
					free(tmp_filename);
					return v8::Undefined();
				}
				free(tmp_filename);
				return exports;
                	}
			free(tmp_filename);
			if (!uwsgi_endswith(*module_name, (char *)".js") && !uwsgi_endswith(*module_name, (char *)".so")) {
				tmp_filename = uwsgi_concat4(usl->value, (char *)"/", *module_name, (char *)".so");
                                if (uwsgi_is_file(tmp_filename)) {
                                        uwsgi_v8_commonjs_require_teajs_do(tmp_filename, exports, module);
                                        free(tmp_filename);
					return exports;
                                }
				tmp_filename = uwsgi_concat4(usl->value, (char *)"/", *module_name, (char *)".js");
				if (uwsgi_is_file(tmp_filename)) {
                                	uwsgi_v8_commonjs_require_do(tmp_filename, exports, module);
                                	free(tmp_filename);
                                	return exports;
                        	}
				free(tmp_filename);
			}
			free(tmp_filename);
			usl = usl->next;
		}
	}
	return v8::Undefined();
}

void uwsgi_v8_fill_commonjs(v8::Persistent<v8::Context> context) {
	context->Enter();
	v8::Handle<v8::Object> system = context->Global()->Get(v8::String::New("system"))->ToObject();
	v8::Handle<v8::Array> args = v8::Array::New();
	int i;
	for(i=0;i<uwsgi.argc;i++) {
		args->Set(v8::Integer::New(i), v8::String::New(uwsgi.argv[i]));
	}
	system->Set(v8::String::New("args"), args);
	v8::Handle<v8::Object> env = v8::Object::New();
	system->Set(v8::String::New("env"), env);	
}

void uwsgi_v8_add_commonjs(v8::Handle<v8::ObjectTemplate> global) {
	// the require function (Modules/1.1)
	global->Set(v8::String::New("require"), v8::FunctionTemplate::New(uwsgi_v8_commonjs_require));
	// the system namespace (System/1.0)
	v8::Handle<v8::ObjectTemplate> system = v8::ObjectTemplate::New();	
	global->Set(v8::String::New("system"), system);
}
