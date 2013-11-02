#include "v8_uwsgi.h"

extern struct uwsgi_server uwsgi;

#ifdef UWSGI_V8_TEAJS
#include "app.h"
#include "macros.h"
class TeaJS_uWSGI : public TeaJS_App {
public:
	void init() {
		TeaJS_App::init();	
		v8::HandleScope handle_scope;
		this->mainfile = "";
		this->create_context();
		this->mainModule = v8::Object::New();
		this->prepare(uwsgi.environ);
	}
        v8::Persistent<v8::Context> getContext() {
		return this->context;
	}
private:
        const char *instanceType() {
                return "uWSGI";
        }

        const char *executableName() {
                return uwsgi.binary_path;
        }

};

static v8::Handle < v8::Value > uwsgi_v8_commonjs_require(const v8::Arguments & args) {
        if (args.Length() > 0) {
		try {
			v8::String::Utf8Value module_name(args[0]->ToString());
			return APP_PTR->require(std::string(*module_name), "");
		}
		catch (std::string e) {
			uwsgi_log("%s\n", e.c_str());
		}
	}
	return v8::Undefined();
}
TeaJS_uWSGI app;
#else
static v8::Handle < v8::Value > uwsgi_v8_commonjs_require(const v8::Arguments &);
static v8::Handle < v8::Value > uwsgi_v8_commonjs_require_do(char *);
#endif

extern struct uwsgi_v8 uv8;
extern struct uwsgi_server uwsgi;


v8::Persistent<v8::Context> uwsgi_v8_setup_context() {
	v8::HandleScope handle_scope;
#ifdef UWSGI_V8_TEAJS
	try {
		app.init();
		app.getContext()->Global()->Set(v8::String::New("require"), v8::FunctionTemplate::New(uwsgi_v8_commonjs_require)->GetFunction());
		return app.getContext();
	}
	catch (std::string e) {
		uwsgi_log("%s\n", e.c_str());
		exit(1);
	}
}
#else
        // create a new context
        v8::Persistent<v8::Context> context = v8::Context::New();
        context->Enter();

        v8::Handle<v8::Object> global = context->Global();

        v8::Handle < v8::Object > system = v8::Object::New();
        v8::Handle < v8::Array > args = v8::Array::New();
        int i;
        for (i = 0; i < uwsgi.argc; i++) {
                args->Set(v8::Integer::New(i), v8::String::New(uwsgi.argv[i]));
        }
        system->Set(v8::String::New("args"), args);
        v8::Handle < v8::Object > env = v8::Object::New();
        system->Set(v8::String::New("env"), env);
        global->Set(v8::String::New("require"), v8::FunctionTemplate::New(uwsgi_v8_commonjs_require)->GetFunction());
        global->Set(v8::String::New("system"), system);
        return context;
}


/*

uWSGI native "require" support

*/

static v8::Handle < v8::Value > uwsgi_v8_commonjs_require_do(char *filename) {

	size_t len = 0;
	char *code = uwsgi_open_and_read(filename, &len, 1, NULL);

	// we re-create every time an "exports" object to emulate a local object
	v8::Local < v8::Object > exports = v8::Object::New();
	v8::Context::GetCurrent()->Global()->Set(v8::String::New("exports"), exports);

	// we do not use TryCatch as we directly use stderr and simply exit with error code 1
	v8::Handle < v8::Script > script = v8::Script::Compile(v8::String::New(code), v8::String::New(filename));
	free(code);
	if (script.IsEmpty()) {
		exit(1);
	}

	v8::Handle < v8::Value > result = script->Run();
	if (result.IsEmpty()) {
		return v8::Undefined();
	}

	return exports;
}

static v8::Handle < v8::Value > uwsgi_v8_commonjs_require(const v8::Arguments & args) {
	if (args.Length() > 0) {
		v8::String::Utf8Value module_name(args[0]->ToString());
		// ok lets start searching the module
		if (uwsgi_is_file(*module_name)) {
			return uwsgi_v8_commonjs_require_do(*module_name);
		}

		// try appending .js extension
		if (!uwsgi_endswith(*module_name, (char *) ".js")) {
			char *tmp_filename = uwsgi_concat2(*module_name, (char *) ".js");
			if (uwsgi_is_file(tmp_filename)) {
				v8::Handle < v8::Value > ret = uwsgi_v8_commonjs_require_do(tmp_filename);
				free(tmp_filename);
				return ret;
			}
			free(tmp_filename);
		}

		// let's start searching in the modules search path
		struct uwsgi_string_list *usl = uv8.module_paths;
		while (usl) {
			char *tmp_filename = uwsgi_concat3(usl->value, (char *) "/", *module_name);
			if (uwsgi_is_file(tmp_filename)) {
				v8::Handle < v8::Value > ret = uwsgi_v8_commonjs_require_do(tmp_filename);
				free(tmp_filename);
				return ret;
			}
			free(tmp_filename);
			if (!uwsgi_endswith(*module_name, (char *) ".js")) {
				tmp_filename = uwsgi_concat4(usl->value, (char *) "/", *module_name, (char *) ".js");
				if (uwsgi_is_file(tmp_filename)) {
					v8::Handle < v8::Value > ret = uwsgi_v8_commonjs_require_do(tmp_filename);
					free(tmp_filename);
					return ret;
				}
				free(tmp_filename);
			}
			usl = usl->next;
		}
	}
	return v8::Undefined();
}
#endif
