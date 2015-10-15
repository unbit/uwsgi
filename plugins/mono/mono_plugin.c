#include <uwsgi.h>
#include <mono/jit/jit.h>
#include <mono/metadata/mono-config.h>
#include <mono/metadata/assembly.h>
#include <mono/metadata/threads.h>
#include <mono/metadata/debug-helpers.h>
#include <mono/metadata/mono-gc.h>
#include <mono/metadata/exception.h>

/*

	Mono ASP.NET plugin

	there are various mode of operation (based on security needs)

	(the --mono-key maps to DOCUMENT_ROOT by default)

	1) static application

		--mono-app <directory>

		will create an ApplicationHost on the specified <directory>

		the --mono-key will be searched for that directory

		the application runs on the main domain

	2) dynamic applications 

		the app is created on demand using the specified key as the physicalDirectory


	TODO:
		allows mounting apps under subpaths (currently all is mapped to "/")

	Thanks to:
		Robert Jordan for helping me understanding the ApplicationHost internals

*/

extern struct uwsgi_server uwsgi;
struct uwsgi_plugin mono_plugin;

struct uwsgi_mono {

	char *config;
	char *version;
	char *assembly_name ;

	struct uwsgi_string_list *key;
	struct uwsgi_string_list *index;

	// GC frequency
	uint64_t gc_freq;

	// a lock for dynamic apps
        pthread_mutex_t lock_loader;

	MonoDomain *main_domain;
	MonoMethod *create_application_host;

	MonoClass *application_class;
	MonoClass *api_class;

	MonoClass *byte_class;

	MonoClassField *filepath;

	// thunk
	void (*process_request)(MonoObject *, MonoException **);

	struct uwsgi_string_list *app;
	struct uwsgi_string_list *exec;
	
} umono;

struct uwsgi_option uwsgi_mono_options[] = {

        {"mono-app", required_argument, 0, "load a Mono asp.net app from the specified directory", uwsgi_opt_add_string_list, &umono.app, 0},
        {"mono-gc-freq", required_argument, 0, "run the Mono GC every <n> requests (default: run after every request)", uwsgi_opt_set_64bit, &umono.gc_freq, 0},
        {"mono-key", required_argument, 0, "select the ApplicationHost based on the specified CGI var", uwsgi_opt_add_string_list, &umono.key, 0},
        {"mono-version", required_argument, 0, "set the Mono jit version", uwsgi_opt_set_str, &umono.version, 0},
        {"mono-config", required_argument, 0, "set the Mono config file", uwsgi_opt_set_str, &umono.config, 0},
        {"mono-assembly", required_argument, 0, "load the specified main assembly (default: uwsgi.dll)", uwsgi_opt_set_str, &umono.assembly_name, 0},
        {"mono-exec", required_argument, 0, "exec the specified assembly just before app loading", uwsgi_opt_add_string_list, &umono.exec, 0},
        {"mono-index", required_argument, 0, "add an asp.net index file", uwsgi_opt_add_string_list, &umono.index, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

static MonoString *uwsgi_mono_method_GetFilePath(MonoObject *this) {
	MonoString *ret = NULL;
	// cache it !!!
	MonoObject *filepath = mono_field_get_value_object(mono_domain_get(), umono.filepath, this);
	if (filepath) {
		return (MonoString *) filepath;
	}
	struct wsgi_request *wsgi_req = current_wsgi_req();
	struct uwsgi_app *app = &uwsgi_apps[wsgi_req->app_id];
	char *path = uwsgi_concat3n(app->interpreter, strlen(app->interpreter), "/", 1, wsgi_req->path_info, wsgi_req->path_info_len);
	size_t path_len = strlen(app->interpreter) + 1 + wsgi_req->path_info_len;

	if (!uwsgi_file_exists(path)) {
		free(path);
		goto simple;
	}

	if (uwsgi_is_dir(path)) {
		struct uwsgi_string_list *usl = umono.index;
		while(usl) {
			char *index = uwsgi_concat3n(path, path_len, "/", 1 , usl->value, usl->len);
			if (uwsgi_file_exists(index)) {
				ret = mono_string_new(mono_domain_get(), index + strlen(app->interpreter));
				free(path);
				free(index);
				mono_field_set_value(this, umono.filepath, ret);
				return ret;	
			}
			free(index);
			usl = usl->next;
		}
	}
	free(path);
simple:
	ret = mono_string_new_len(mono_domain_get(), wsgi_req->path_info, wsgi_req->path_info_len);
	mono_field_set_value(this, umono.filepath, ret);
	return ret;
}

static MonoString *uwsgi_mono_method_GetUriPath(MonoObject *this) {
	return uwsgi_mono_method_GetFilePath(this);
}

static MonoString *uwsgi_mono_method_MapPath(MonoObject *this, MonoString *virtualPath) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	struct uwsgi_app *app = &uwsgi_apps[wsgi_req->app_id];
	char *path = uwsgi_concat3n(app->interpreter, strlen(app->interpreter), "/", 1, mono_string_to_utf8(virtualPath), mono_string_length(virtualPath));
	MonoString *ret = mono_string_new_len(mono_domain_get(), path, strlen(path));
	free(path);
	return ret;
}

static MonoString *uwsgi_mono_method_GetQueryString(MonoObject *this) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	return mono_string_new_len(mono_domain_get(), wsgi_req->query_string, wsgi_req->query_string_len);
}

static MonoString *uwsgi_mono_method_GetHttpVerbName(MonoObject *this) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	return mono_string_new_len(mono_domain_get(), wsgi_req->method, wsgi_req->method_len);
}

static MonoString *uwsgi_mono_method_GetRawUrl(MonoObject *this) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	return mono_string_new_len(mono_domain_get(), wsgi_req->uri, wsgi_req->uri_len);
}

static MonoString *uwsgi_mono_method_GetHttpVersion(MonoObject *this) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	return mono_string_new_len(mono_domain_get(), wsgi_req->protocol, wsgi_req->protocol_len);
}

static MonoString *uwsgi_mono_method_GetRemoteAddress(MonoObject *this) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	return mono_string_new_len(mono_domain_get(), wsgi_req->remote_addr, wsgi_req->remote_addr_len);
}

static void uwsgi_mono_method_SendStatus(MonoObject *this, int code, MonoString *msg) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	char status_code[4];
	uwsgi_num2str2n(code, status_code, 4);
	char *status_line = uwsgi_concat3n(status_code, 3, " ", 1, mono_string_to_utf8(msg), mono_string_length(msg));
	uwsgi_response_prepare_headers(wsgi_req, status_line, 4 + mono_string_length(msg));
	free(status_line);
}

static void uwsgi_mono_method_SendUnknownResponseHeader(MonoObject *this, MonoString *key, MonoString *value) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	uwsgi_response_add_header(wsgi_req, mono_string_to_utf8(key), mono_string_length(key), mono_string_to_utf8(value), mono_string_length(value));
}

static void uwsgi_mono_method_SendResponseFromMemory(MonoObject *this, MonoArray *byteArray, int len) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	uwsgi_response_write_body_do(wsgi_req, mono_array_addr(byteArray, char, 0), len);
}

static void uwsgi_mono_method_FlushResponse(MonoObject *this, int is_final) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	uwsgi_response_write_body_do(wsgi_req, "", 0);
}

static void uwsgi_mono_method_SendResponseFromFd(MonoObject *this, int fd, long offset, long len) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	wsgi_req->sendfile_fd = fd;
	if (fd >= 0) {
        	uwsgi_response_sendfile_do(wsgi_req, fd, offset, len);
	}
	wsgi_req->sendfile_fd = -1;
}

static void uwsgi_mono_method_SendResponseFromFile(MonoObject *this, MonoString *filename, long offset, long len) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	int fd = open(mono_string_to_utf8(filename), O_RDONLY);
	if (fd >= 0) {
        	uwsgi_response_sendfile_do(wsgi_req, fd, offset, len);
	}
}

static MonoString *uwsgi_mono_method_GetHeaderByName(MonoObject *this, MonoString *key) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	uint16_t rlen = 0;
	char *value = uwsgi_get_header(wsgi_req, mono_string_to_utf8(key), mono_string_length(key), &rlen);
	if (value) {
		return mono_string_new_len(mono_domain_get(), value, rlen);
	}
	return mono_string_new(mono_domain_get(), "");
}

static MonoString *uwsgi_mono_method_GetServerVariable(MonoObject *this, MonoString *key) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	uint16_t rlen = 0;
	char *value = uwsgi_get_var(wsgi_req, mono_string_to_utf8(key), mono_string_length(key), &rlen);
	if (value) {
		return mono_string_new_len(mono_domain_get(), value, rlen);
	}
	return mono_string_new(mono_domain_get(), "");
}

static int uwsgi_mono_method_ReadEntityBody(MonoObject *this, MonoArray *byteArray, int len) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	char *buf = mono_array_addr(byteArray, char, 0);	
	ssize_t rlen = 0;
	char *chunk = uwsgi_request_body_read(wsgi_req, len, &rlen);
	if (chunk == uwsgi.empty) {
		return 0;
	}
	if (chunk) {
		memcpy(buf, chunk, rlen);
		return rlen;
	}
	return -1;
}

static int uwsgi_mono_method_GetTotalEntityBodyLength(MonoObject *this) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
	return wsgi_req->post_cl;
}

static void uwsgi_mono_method_api_RegisterSignal(int signum, MonoString *target, MonoObject *func) {
	mono_gchandle_new(func, 1);
	if (uwsgi_register_signal(signum, mono_string_to_utf8(target), func, mono_plugin.modifier1)) {
		mono_raise_exception(mono_get_exception_invalid_operation("unable to register signal handler"));
	}
}

static void uwsgi_mono_method_api_Signal(int signum) {
	uwsgi_signal_send(uwsgi.signal_socket, signum);
}

static int uwsgi_mono_method_api_WorkerId() {
	return uwsgi.mywid;
}

static MonoArray *uwsgi_mono_method_api_CacheGet(MonoString *key, MonoString *cache) {
	char *c_key = mono_string_to_utf8(key);
	uint16_t c_keylen = mono_string_length(key);
	char *c_cache = NULL;
	if (cache) {
		c_cache = mono_string_to_utf8(cache);
	}
	uint64_t vallen = 0 ;
	char *value = uwsgi_cache_magic_get(c_key, c_keylen, &vallen, NULL, c_cache);
        if (value) {
		MonoArray *ret = mono_array_new(mono_domain_get(), umono.byte_class, vallen);
		char *buf = mono_array_addr(ret, char, 0);
		memcpy(buf, value, vallen);
		free(value);
                return ret;
        }

	return NULL;
}

static void uwsgi_mono_add_internal_calls() {
	// uWSGIRequest
	mono_add_internal_call("uwsgi.uWSGIRequest::SendResponseFromMemory", uwsgi_mono_method_SendResponseFromMemory);
	mono_add_internal_call("uwsgi.uWSGIRequest::SendStatus", uwsgi_mono_method_SendStatus);
	mono_add_internal_call("uwsgi.uWSGIRequest::SendUnknownResponseHeader", uwsgi_mono_method_SendUnknownResponseHeader);
	mono_add_internal_call("uwsgi.uWSGIRequest::FlushResponse", uwsgi_mono_method_FlushResponse);
	mono_add_internal_call("uwsgi.uWSGIRequest::GetQueryString", uwsgi_mono_method_GetQueryString);
	mono_add_internal_call("uwsgi.uWSGIRequest::MapPath", uwsgi_mono_method_MapPath);
	mono_add_internal_call("uwsgi.uWSGIRequest::GetHttpVerbName", uwsgi_mono_method_GetHttpVerbName);
	mono_add_internal_call("uwsgi.uWSGIRequest::GetRawUrl", uwsgi_mono_method_GetRawUrl);
	mono_add_internal_call("uwsgi.uWSGIRequest::GetFilePath", uwsgi_mono_method_GetFilePath);
	mono_add_internal_call("uwsgi.uWSGIRequest::GetUriPath", uwsgi_mono_method_GetUriPath);
	mono_add_internal_call("uwsgi.uWSGIRequest::SendResponseFromFile", uwsgi_mono_method_SendResponseFromFile);
	mono_add_internal_call("uwsgi.uWSGIRequest::SendResponseFromFd", uwsgi_mono_method_SendResponseFromFd);
	mono_add_internal_call("uwsgi.uWSGIRequest::GetHeaderByName", uwsgi_mono_method_GetHeaderByName);
	mono_add_internal_call("uwsgi.uWSGIRequest::ReadEntityBody", uwsgi_mono_method_ReadEntityBody);
	mono_add_internal_call("uwsgi.uWSGIRequest::GetTotalEntityBodyLength", uwsgi_mono_method_GetTotalEntityBodyLength);
	mono_add_internal_call("uwsgi.uWSGIRequest::GetHttpVersion", uwsgi_mono_method_GetHttpVersion);
	mono_add_internal_call("uwsgi.uWSGIRequest::GetServerVariable", uwsgi_mono_method_GetServerVariable);
	mono_add_internal_call("uwsgi.uWSGIRequest::GetRemoteAddress", uwsgi_mono_method_GetRemoteAddress);

	// api
	mono_add_internal_call("uwsgi.api::Signal", uwsgi_mono_method_api_Signal);
	mono_add_internal_call("uwsgi.api::WorkerId", uwsgi_mono_method_api_WorkerId);
	mono_add_internal_call("uwsgi.api::RegisterSignal", uwsgi_mono_method_api_RegisterSignal);
	mono_add_internal_call("uwsgi.api::CacheGet", uwsgi_mono_method_api_CacheGet);
}

static int uwsgi_mono_init() {

	if (!umono.version) {
		umono.version = "v4.0.30319";
	}

	if (!umono.assembly_name) {
		umono.assembly_name = "uwsgi.dll";
	}

	if (!umono.gc_freq) {
		umono.gc_freq = 1;
	}

	return 0;
}


static void uwsgi_mono_create_jit() {


	mono_config_parse(umono.config);

	umono.main_domain = mono_jit_init_version("uwsgi", umono.version);
	if (!umono.main_domain) {
		uwsgi_log("unable to initialize Mono JIT\n");
		exit(1);
	}

	uwsgi_log("Mono JIT initialized on worker %d with version %s\n", uwsgi.mywid, umono.version);

	MonoAssembly *assembly = mono_domain_assembly_open(umono.main_domain, umono.assembly_name);
	if (!assembly) {
		uwsgi_log("%s not found trying in global gac...\n", umono.assembly_name);
		assembly = mono_assembly_load_with_partial_name(umono.assembly_name, NULL);
		if (!assembly) {
			if (!strcmp("uwsgi.dll", umono.assembly_name)) {
				assembly = mono_assembly_load_with_partial_name("uwsgi", NULL);
			}	
		}
	}

	if (!assembly) {
		uwsgi_log("unable to load \"%s\" in the Mono domain\n", umono.assembly_name);
		exit(1);
	}

	uwsgi_mono_add_internal_calls();

	MonoImage *image = mono_assembly_get_image(assembly);
	if (!image) {
		uwsgi_log("unable to get assembly image\n");
		exit(1);
	}
	umono.application_class = mono_class_from_name(image, "uwsgi", "uWSGIApplication");
	if (!umono.application_class) {
		uwsgi_log("unable to get reference to class uwsgi.uWSGIApplication\n");
		exit(1);
	}

	umono.byte_class = mono_class_from_name(mono_get_corlib(), "System", "Byte");
        if (!umono.byte_class) {
                uwsgi_log("unable to get reference to class System.Byte\n");
                exit(1);
        }

	MonoClass *urequest = mono_class_from_name(image, "uwsgi", "uWSGIRequest");
	if (!urequest) {
		uwsgi_log("unable to get reference to class uwsgi.uWSGIRequest\n");
                exit(1);
	}

	umono.filepath = mono_class_get_field_from_name(urequest, "filepath");
	if (!umono.filepath) {
		uwsgi_log("unable to get reference to field uwsgi.uWSGIRequest.filepath\n");
	}

	umono.api_class = mono_class_from_name(image, "uwsgi", "api");
        if (!umono.api_class) {
                uwsgi_log("unable to get reference to class uwsgi.api\n");
                exit(1);
        }

	MonoMethodDesc *desc = mono_method_desc_new("uwsgi.uWSGIApplication:.ctor(string,string)", 1);
	if (!desc) {
		uwsgi_log("unable to create description for uwsgi.uWSGIApplication:.ctor(string,string)\n");
		exit(1);
	}
	umono.create_application_host = mono_method_desc_search_in_class(desc, umono.application_class);
	if (!umono.create_application_host) {
		uwsgi_log("unable to find constructor in uWSGIApplication class\n");
		exit(1);
	}
	mono_method_desc_free(desc);

	desc = mono_method_desc_new("uwsgi.uWSGIApplication:Request()", 1);
	if (!desc) {
		uwsgi_log("unable to create description for uwsgi.uWSGIApplication:Request()\n");
		exit(1);
	}
	MonoMethod *process_request = mono_method_desc_search_in_class(desc, umono.application_class);
	if (!process_request) {
		uwsgi_log("unable to find ProcessRequest method in uwsgi_host class\n");
		exit(1);
	}
	mono_method_desc_free(desc);

	umono.process_request = mono_method_get_unmanaged_thunk(process_request);

	struct uwsgi_string_list *usl = umono.exec;
	while(usl) {
		char *assembly_name = usl->value;
		char *argv = "";
		char *colon = strchr(usl->value, ':');
		if (colon) {
			argv = colon+1;
			assembly_name = uwsgi_concat2n(usl->value, colon-usl->value, "", 0);
		}
	
		MonoAssembly *assembly = mono_domain_assembly_open(umono.main_domain, assembly_name);
		if (!assembly) {
			uwsgi_log("unable to load assembly \"%s\"\n", assembly_name);
			exit(1);
		}
		mono_jit_exec(umono.main_domain, assembly, 1, &argv);
		if (assembly_name != usl->value) {
			free(assembly_name);
		}
		usl = usl->next;
	}

}

static int uwsgi_mono_create_app(char *key, uint16_t key_len, char *physicalDir, uint16_t physicalDir_len, int new_domain) {
	void *params[3];
        params[2] = NULL;

	params[0] = mono_string_new(mono_domain_get(), "/");
	params[1] = mono_string_new_len(mono_domain_get(), physicalDir, physicalDir_len);

	int id = uwsgi_apps_cnt;
	time_t now = uwsgi_now();

	MonoObject *appHost = mono_object_new(mono_domain_get(), umono.application_class);
        if (!appHost) {
        	uwsgi_log("unable to initialize asp.net ApplicationHost\n");
		return -1;
	}

	MonoObject *exc = NULL;
	mono_runtime_invoke(umono.create_application_host, appHost, params, &exc);
	if (exc) {
                mono_print_unhandled_exception(exc);
		return -1;
        }

	struct uwsgi_app *app = uwsgi_add_app(id, mono_plugin.modifier1, key, key_len, uwsgi_concat2n(physicalDir, physicalDir_len, "", 0), appHost);
        app->started_at = now;
        app->startup_time = uwsgi_now() - now;
	// get a handlet to appHost
	mono_gchandle_new(app->callable, 1);
	uwsgi_log("Mono asp.net app %d (%.*s) loaded in %d seconds at %p (worker %d)\n", id, key_len, key, (int) app->startup_time, appHost, uwsgi.mywid);

	// set it as default app if needed
	if (uwsgi.default_app == -1) {
		uwsgi.default_app = id;
	}

	return id;
}

static void uwsgi_mono_init_apps() {

	if (!umono.main_domain) {
		uwsgi_mono_create_jit();
	}

	struct uwsgi_string_list *usl = umono.app;

	while(usl) {

		char *mountpoint = usl->value;
		uint8_t mountpoint_len = usl->len;
		char *physicalDir = mountpoint;
		uint8_t physicalDir_len = mountpoint_len;

		char *equal = strchr(mountpoint, '=');
		if (equal) {
			physicalDir = equal+1;
			physicalDir_len = strlen(physicalDir);
			// ensure NULL char is at end (just for being backward compatible)
			mountpoint = uwsgi_concat2n(mountpoint, equal - mountpoint, "", 0);
			mountpoint_len = strlen(mountpoint);
		}

		int id = uwsgi_mono_create_app(mountpoint, mountpoint_len, physicalDir, physicalDir_len, 0);
		if (id == -1) {
			exit(1);
		}
		uwsgi_emulate_cow_for_apps(id);
	
		usl = usl->next;
	}
}

static int uwsgi_mono_request(struct wsgi_request *wsgi_req) {

	/* Standard ASP.NET request */
        if (!wsgi_req->uh->pktsize) {
                uwsgi_log("Empty Mono/ASP.NET request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }

	char *key = wsgi_req->document_root;
	uint16_t key_len = wsgi_req->document_root_len;

	struct uwsgi_string_list *usl = umono.key;
	while(usl) {
		key = uwsgi_get_var(wsgi_req, usl->value, usl->len, &key_len);
		if (key) break;
		usl = usl->next;
	}

	// avoid unexpected values
	if (key == NULL) {
		key = "";
		key_len = 0;
	}

        wsgi_req->app_id = uwsgi_get_app_id(NULL, key, key_len, mono_plugin.modifier1);
        // if it is -1, try to load a dynamic app
        if (wsgi_req->app_id == -1 && key_len > 0) {
        	if (uwsgi.threads > 1) {
                	pthread_mutex_lock(&umono.lock_loader);
                }

		// check if in the mean time, something changed		
		wsgi_req->app_id = uwsgi_get_app_id(NULL, key, key_len, mono_plugin.modifier1);

		if (wsgi_req->app_id == -1) {
                	wsgi_req->app_id = uwsgi_mono_create_app(key, key_len, key, key_len, 0);
		}

                if (uwsgi.threads > 1) {
                	pthread_mutex_unlock(&umono.lock_loader);
                }
        }


        if (wsgi_req->app_id == -1) {
		if (!uwsgi.no_default_app && uwsgi.default_app > -1 && uwsgi_apps[uwsgi.default_app].modifier1 == mono_plugin.modifier1) {
               		wsgi_req->app_id = uwsgi.default_app;
                }
		else {
        		uwsgi_500(wsgi_req);
                	uwsgi_log("--- unable to find Mono/ASP.NET application ---\n");
                	// nothing to clear/free
                	return UWSGI_OK;
		}
        }

        struct uwsgi_app *app = &uwsgi_apps[wsgi_req->app_id];
        app->requests++;

	// check for directory without slash
	char *path = uwsgi_concat3n(app->interpreter, strlen(app->interpreter), "/", 1, wsgi_req->path_info, wsgi_req->path_info_len);
        size_t path_len = strlen(app->interpreter) + 1 + wsgi_req->path_info_len;

        if (uwsgi_is_dir(path) && path[path_len-1] != '/') {
		free(path);
		uwsgi_redirect_to_slash(wsgi_req);
        	return UWSGI_OK;
	}
	free(path);

	MonoException *exc = NULL;

	umono.process_request(app->callable, &exc);

	if (exc) {
		mono_print_unhandled_exception((MonoObject *)exc);
	}

	if ( uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].requests % umono.gc_freq == 0) {
		mono_gc_collect (mono_gc_max_generation());
	}

	return UWSGI_OK;
}

static void uwsgi_mono_after_request(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

static void uwsgi_mono_init_thread(int core_id) {
	mono_thread_attach(umono.main_domain);
	// SIGPWR, SIGXCPU: these are used internally by the GC and pthreads.
	sigset_t smask;
        sigemptyset(&smask);
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__GNU_kFreeBSD__)
        sigaddset(&smask, SIGXFSZ);
#else
        sigaddset(&smask, SIGPWR);
#endif
        if (sigprocmask(SIG_UNBLOCK, &smask, NULL)) {
                uwsgi_error("uwsgi_mono_init_thread()/sigprocmask()");
        }
}

static void uwsgi_mono_pthread_prepare(void) {
        pthread_mutex_lock(&umono.lock_loader);
}

static void uwsgi_mono_pthread_parent(void) {
        pthread_mutex_unlock(&umono.lock_loader);
}

static void uwsgi_mono_pthread_child(void) {
        pthread_mutex_init(&umono.lock_loader, NULL);
}


static void uwsgi_mono_enable_threads(void) {
        pthread_mutex_init(&umono.lock_loader, NULL);
        pthread_atfork(uwsgi_mono_pthread_prepare, uwsgi_mono_pthread_parent, uwsgi_mono_pthread_child);
}

static void uwsgi_mono_post_fork() {

	// yes, Mono is not fork-friendly, so we initialize it in the post_fork hook
	uwsgi_mono_init_apps();

	MonoMethodDesc *desc = mono_method_desc_new("uwsgi.api:RunPostForkHook()", 1);
        if (!desc) {
		return;
        }
        MonoMethod *method = mono_method_desc_search_in_class(desc, umono.api_class);
        mono_method_desc_free(desc);
        if (!method) {
		return;
        }

	MonoObject *exc = NULL;
	mono_runtime_invoke(method, NULL, NULL, &exc);
	if (exc) {
		mono_print_unhandled_exception(exc);
	}
}

static int uwsgi_mono_signal_handler(uint8_t sig, void *handler) {
	void *params[2];
	int signum = sig;
	params[0] = &signum;
	params[1] = NULL;
	MonoObject *exc = NULL;
	mono_runtime_delegate_invoke((MonoObject *) handler, params, &exc);
	if (exc) {
		mono_print_unhandled_exception(exc);
		return -1;
	}
	return 0;
}

struct uwsgi_plugin mono_plugin = {

	.name = "mono",
	.modifier1 = 15,

	.options = uwsgi_mono_options,

	.init = uwsgi_mono_init,

	.request = uwsgi_mono_request,
	.after_request = uwsgi_mono_after_request,

	.init_thread = uwsgi_mono_init_thread,
	.enable_threads = uwsgi_mono_enable_threads,

	.post_fork = uwsgi_mono_post_fork,

	.signal_handler = uwsgi_mono_signal_handler,
};
