#include "v8_uwsgi.h"

extern struct uwsgi_v8 uv8;

extern "C" int uwsgi_v8_request(struct wsgi_request *wsgi_req) {
	char status_str[11];
	uint32_t i,l;
	v8::Handle<v8::Value> status, headers, body;
	v8::Local<v8::Array> props;
	v8::Local<v8::Value> key, value;

	/* Standard JSGI 3.0 request */
        if (!wsgi_req->uh->pktsize) {
                uwsgi_log( "Empty JSGI request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }
	
        int core_id = wsgi_req->async_id;

        uv8.isolates[core_id]->Enter();
        uv8.contexts[core_id]->Enter();
        v8::HandleScope handle_scope;
        v8::Handle<v8::Value> argj[1];
        argj[0] = v8::Object::New();
        v8::Handle<v8::Value> result = uv8.jsgi_func[core_id]->Call(uv8.contexts[core_id]->Global(), 1, argj);
        if (result.IsEmpty()) goto end;
	if (!result->IsObject()) goto end;

	status = result->ToObject()->Get(v8::String::New("status"));
	if (status.IsEmpty() || !status->IsNumber()) {
		uwsgi_log("invalid JSGI response status\n");
		exit(1);
	}
	headers = result->ToObject()->Get(v8::String::New("headers"));
	if (headers.IsEmpty() || !headers->IsObject()) {
                uwsgi_log("invalid JSGI response headers\n");
                exit(1);
        }
	body = result->ToObject()->Get(v8::String::New("body"));
	if (body.IsEmpty() || !body->IsObject()) {
                uwsgi_log("invalid JSGI response body\n");
                exit(1);
        }

	if (uwsgi_num2str2(status->Uint32Value(), status_str) != 3) {
                goto end;
        }

        if (uwsgi_response_prepare_headers(wsgi_req, status_str, 3)) goto end;

        props = headers->ToObject()->GetPropertyNames();
        l = props->Length();

        for(i=0;i<l;i++) {
        	key = props->Get(i);
                value = headers->ToObject()->Get(key);
                v8::String::Utf8Value c_key(key->ToString());
                if (value->IsArray()) {
                        uint32_t opt_l = value->ToObject()->Get(v8::String::New("length"))->ToObject()->Uint32Value();
                        uint32_t j;
                        for(j=0;j<opt_l;j++) {
                                v8::String::Utf8Value c_value(value->ToObject()->Get(j)->ToString());
                        	if (uwsgi_response_add_header(wsgi_req, *c_key, strlen(*c_key), *c_value, strlen(*c_value))) goto end;
                        }
                }
                else {
                        v8::String::Utf8Value c_value(value->ToString());
                        if (uwsgi_response_add_header(wsgi_req, *c_key, strlen(*c_key), *c_value, strlen(*c_value))) goto end;
                }
        }

end:
        while(!v8::V8::IdleNotification()) {};
	return UWSGI_OK;
}

v8::Persistent<v8::Function> uwsgi_v8_load_jsgi(int core_id, char *filename) {
	
	uv8.isolates[core_id]->Enter();
        uv8.contexts[core_id]->Enter();
        v8::HandleScope handle_scope;

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
		exit(1);
        }

	v8::Handle<v8::Value> app = exports->Get(v8::String::New("app"));
	if (!app.IsEmpty() && !app->IsNull() && !app->IsUndefined()) {
		if (app->ToObject()->IsFunction()) {
			if (!uv8.jsgi_announced) {
				uwsgi_log("JSGI 3.0 application loaded from \"exports.app\" in %s\n", filename);			
				uv8.jsgi_announced = -1;
			}
			return v8::Persistent<v8::Function>::New(v8::Handle<v8::Function>::Cast(app));
		}
	}

	if (!result->IsNull() && !result->IsUndefined() && result->ToObject()->IsFunction()) {
		if (!uv8.jsgi_announced) {
			uwsgi_log("JSGI 3.0 application loaded from return value of %s\n", filename);			
			uv8.jsgi_announced = -1;
		}
		return v8::Persistent<v8::Function>::New(v8::Handle<v8::Function>::Cast(result));
	}

	uwsgi_log("unable to find JSGI 3.0 entry point function\n");
	exit(1);
}
