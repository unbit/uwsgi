#include "v8_uwsgi.h"

extern struct uwsgi_v8 uv8;

static v8::Handle<v8::Value> uwsgi_v8_commonjs_require_do(char *filename) {

	size_t len = 0;
        char *code = uwsgi_open_and_read(filename, &len, 1, NULL);

	// we re-create every time an "exports" object to emulate a local object
	v8::Local<v8::Object> exports = v8::Object::New();
	v8::Context::GetCurrent()->Global()->Set(v8::String::New("exports"), exports);

        // we do not use TryCatch as we directly use stderr and simply exit with error code 1
        v8::Handle<v8::Script> script = v8::Script::Compile( v8::String::New(code), v8::String::New(filename) );
        free(code);
        if (script.IsEmpty()) {
                exit(1);
        }

        v8::Handle<v8::Value> result = script->Run();
        if (result.IsEmpty()) {
		return v8::Undefined();
        }

	return exports;
}

static v8::Handle<v8::Value> uwsgi_v8_commonjs_require(const v8::Arguments& args) {
	if (args.Length() > 0) {
		v8::String::Utf8Value module_name(args[0]->ToString());
		// ok lets start searching the module
		if (uwsgi_is_file(*module_name)) {
			return uwsgi_v8_commonjs_require_do(*module_name);
		}

		// try appending .js extension
		if (!uwsgi_endswith(*module_name, (char *)".js")) {
			char *tmp_filename = uwsgi_concat2(*module_name, (char *)".js");
			if (uwsgi_is_file(tmp_filename)) {
				v8::Handle<v8::Value> ret = uwsgi_v8_commonjs_require_do(tmp_filename);
				free(tmp_filename);
				return ret;	
			}
			free(tmp_filename);
		}

		// let's start searching in the modules search path
		struct uwsgi_string_list *usl = uv8.module_paths;
		while(usl) {
			char *tmp_filename = uwsgi_concat3(usl->value, (char *)"/", *module_name);
			if (uwsgi_is_file(tmp_filename)) {
                        	v8::Handle<v8::Value> ret = uwsgi_v8_commonjs_require_do(tmp_filename);
				free(tmp_filename);
				return ret;
                	}
			free(tmp_filename);
			if (!uwsgi_endswith(*module_name, (char *)".js")) {
				tmp_filename = uwsgi_concat4(usl->value, (char *)"/", *module_name, (char *)".js");
				if (uwsgi_is_file(tmp_filename)) {
                                	v8::Handle<v8::Value> ret = uwsgi_v8_commonjs_require_do(tmp_filename);
                                	free(tmp_filename);
                                	return ret;
                        	}
			}
			free(tmp_filename);
			usl = usl->next;
		}
	}
	return v8::Undefined();
}

void uwsgi_v8_add_commonjs(v8::Handle<v8::ObjectTemplate> global) {
	global->Set(v8::String::New("require"), v8::FunctionTemplate::New(uwsgi_v8_commonjs_require));
}
