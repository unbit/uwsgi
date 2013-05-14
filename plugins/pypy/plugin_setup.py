
import uwsgi

import os, sys
sys.path.insert(0, '.')
import cffi
ffi = cffi.FFI()

ffi.cdef('''
void *memset(void *s, int c, size_t n);
''')

ffi.cdef('''
typedef struct sockaddr_un {
   ...;
};

typedef struct uwsgi_header {
   ...;
};

typedef struct uwsgi_buffer {
   ...;
};

typedef struct wsgi_request {
   int fd;
   struct uwsgi_header *uh;

   int app_id;
   int dynamic;
   int parsed;

   char *appid;
   uint16_t appid_len;

   //this is big enough to contain sockaddr_in
   struct sockaddr_un c_addr;
   int c_len;

   uint64_t start_of_request;
   uint64_t start_of_request_in_sec;
   uint64_t end_of_request;

   char *uri;
   uint16_t uri_len;
   char *remote_addr;
   uint16_t remote_addr_len;
   char *remote_user;
   uint16_t remote_user_len;
   char *query_string;
   uint16_t query_string_len;
   char *protocol;
   uint16_t protocol_len;
   char *method;
   uint16_t method_len;
   char *scheme;
   uint16_t scheme_len;
   char *https;
   uint16_t https_len;
   char *script_name;
   uint16_t script_name_len;
   int script_name_pos;

   char *host;
   uint16_t host_len;

   char *content_type;
   uint16_t content_type_len;

   char *document_root;
   uint16_t document_root_len;

   char *user_agent;
   uint16_t user_agent_len;

   char *encoding;
   uint16_t encoding_len;

   char *referer;
   uint16_t referer_len;

   char *cookie;
   uint16_t cookie_len;

   char *path_info;
   uint16_t path_info_len;
   int path_info_pos;

   char *authorization;
   uint16_t authorization_len;

   uint16_t via;

   char *script;
   uint16_t script_len;
   char *module;
   uint16_t module_len;
   char *callable;
   uint16_t callable_len;
   char *home;
   uint16_t home_len;

   char *file;
   uint16_t file_len;

   char *paste;
   uint16_t paste_len;

   char *chdir;
   uint16_t chdir_len;

   char *touch_reload;
   uint16_t touch_reload_len;

   char *cache_get;
   uint16_t cache_get_len;

   char *if_modified_since;
   uint16_t if_modified_since_len;

   int fd_closed;

   int sendfile_fd;
   size_t sendfile_fd_chunk;
   size_t sendfile_fd_size;
   size_t sendfile_fd_pos;
   void *sendfile_obj;

   uint16_t var_cnt;
   uint16_t header_cnt;

   int do_not_log;

   int do_not_add_to_async_queue;

   int do_not_account;

   int status;
   struct uwsgi_buffer *headers;

   size_t response_size;
   size_t headers_size;

   int async_id;
   int async_status;

   int switches;
   size_t write_pos;

   int async_timed_out;
   int async_ready_fd;
   int async_last_ready_fd;

   ...;
};

typedef struct uwsgi_plugin {
   const char *name;
   int (*request)(struct wsgi_request *);
   void (*init_apps)();
   ...;
};

int uwsgi_response_prepare_headers(struct wsgi_request*, char*, int);
int uwsgi_response_add_header(struct wsgi_request*, char*, int, char*, int);
int uwsgi_response_write_body_do(struct wsgi_request*, char*, int);
int uwsgi_parse_vars(struct wsgi_request*);
void uwsgi_500(struct wsgi_request*);
void uwsgi_log(char*);

typedef struct uwsgi_app {
   char mountpoint[0xff];
   uint8_t mountpoint_len;
   void *callable;
   ...;
};

typedef struct uwsgi_worker {
	int apps_cnt;
	struct uwsgi_app *apps;
   ...;
};

typedef struct uwsgi_server {
   int mywid;
   struct uwsgi_worker *workers;
   struct wsgi_request *wsgi_req;

   int default_app;
   ...;
};

int uwsgi_get_app_id(struct wsgi_request*, char *, uint16_t, int);

struct uwsgi_plugin pypy_plugin;
struct uwsgi_server uwsgi;

struct uwsgi_pypy {
  char *homedir;
  char *wsgi_app;
};

struct uwsgi_pypy uwsgi_pypy_settings;

#define UWSGI_OK ...
''')

with open("uwsgibuild.lastcflags") as f:
    flags = f.read().decode('hex')
    defflags = [flag[2:] for flag in flags.split(" ") if flag.startswith('-D')]
    defines = []
    for define in defflags:
        if define.find("=") not in (-1, len(define)):
            defines.append("#define %s %s" % tuple(define.split("=")))
        else:
            defines.append("#define %s 1" % define)

lib = ffi.verify('''
   %(defines)s

   #include <sys/types.h>
   #include <sys/socket.h>
   #include <string.h>
   #include "uwsgi.h"
   #include "uwsgi_pypy.h"

   extern struct uwsgi_server uwsgi;
   ''' % {'defines': '\n'.join(defines)},
   include_dirs=[os.getcwd(), os.path.join(os.path.join(os.getcwd(), 'plugins',
                                                        'pypy'))],
   libraries=[':pypy_plugin.so'])

@ffi.callback("int(struct wsgi_request*)")
def request(wsgi_req):
    if lib.uwsgi_parse_vars(wsgi_req):
        return -1
    appid = lib.uwsgi_get_app_id(wsgi_req, wsgi_req.appid,
                                    wsgi_req.appid_len, 0)
    if appid == -1:
        lib.uwsgi_500(wsgi_req)
        lib.uwsgi_log("--- no python application found, check your startup logs for errors ---\n")
        return lib.UWSGI_OK

    def start_response(status, response_headers):
        """ Start response

        status - string
        response_headers - list of 2-tuples with header: value
        """
        # this is done as a closure to refer to wsgi_req
        lib.uwsgi_response_prepare_headers(wsgi_req, status, len(status))
        for key, v in response_headers:
            lib.uwsgi_response_add_header(wsgi_req, key, len(key),
                                          v, len(v))
        return lib.UWSGI_OK

    callable = uwsgi.uwsgi_global_state.callables[appid]
    environ = {} # XXX for now
    output = callable(environ, start_response)
    # output is a list of strings
    for s in output:
        lib.uwsgi_response_write_body_do(wsgi_req, s, len(s))
    return lib.UWSGI_OK

@ffi.callback("void()")
def init_apps():
    """ Set up apps provided by --wsgi command line option
    """
    wsgi_app = ffi.string(lib.uwsgi_pypy_settings.wsgi_app)
    mod = __import__(wsgi_app)
    appid = lib.uwsgi.workers[lib.uwsgi.mywid].apps_cnt
    if lib.uwsgi_get_app_id(ffi.NULL, lib.uwsgi.wsgi_req.appid,
                            lib.uwsgi.wsgi_req.appid_len, -1) != -1:
        lib.uwsgi_log("app alread registered skipping")
        return -1
    app = lib.uwsgi.workers[lib.uwsgi.mywid].apps[appid]
    lib.memset(ffi.addressof(app), 0, ffi.sizeof("struct uwsgi_app"))
    # XXX set it up
    app.mountpoint = "default"
    app.callable = ffi.cast("void*", 1)
    # non-null, we keep a separate mapping anyway
    uwsgi.uwsgi_global_state.callables[appid] = mod.application
    lib.uwsgi.workers[lib.uwsgi.mywid].apps_cnt = appid + 1
    lib.uwsgi.default_app = appid # for now, make it always the default

lib.pypy_plugin.request = request
lib.pypy_plugin.init_apps = init_apps
