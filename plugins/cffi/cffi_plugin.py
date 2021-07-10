# based on the example and pypy plugins

import cffi
import build_bundle
import io

ffibuilder = cffi.FFI()

# cdef() exposes uwsgi functions to Python
ffibuilder.cdef(open("types.h").read())
ffibuilder.cdef(open("_constants.h").read())
ffibuilder.cdef(open("_uwsgi.h").read())

plugin_data = """
static struct uwsgi_cffi {
    char *wsgi;
    char *init;
    char *home;

    struct uwsgi_string_list *eval;
    struct uwsgi_string_list *eval_post_fork;
    struct uwsgi_string_list *exec;
    struct uwsgi_string_list *exec_post_fork;
} ucffi;
"""

# defined by our plugin
ffibuilder.cdef(
    plugin_data
    + """
void uwsgi_cffi_more_apps();

// libc functions
ssize_t read (int, void *, size_t);
ssize_t write (int, const void *, size_t);
void free(void *);
"""
    # For cffi_asyncio.
    # Bound to Python code with @ffi.def_extern().
    # Also OK to leave unbound & uncalled.
    + """
extern "Python" static void uwsgi_pypy_continulet_schedule(void);
extern "Python" static void uwsgi_pypy_continulet_switch(struct wsgi_request *);
extern "Python" static void uwsgi_pypy_greenlet_schedule_to_req(void);
extern "Python" static void uwsgi_pypy_greenlet_schedule_to_main(struct wsgi_request *);
extern "Python" static struct wsgi_request * uwsgi_pypy_greenlet_current_wsgi_req();
extern "Python" static int uwsgi_asyncio_wait_read_hook(int fd, int timeout);
extern "Python" static int uwsgi_asyncio_wait_write_hook(int fd, int timeout);
extern "Python" static void uwsgi_asyncio_schedule_fix(struct wsgi_request *);
extern "Python" static void asyncio_loop(void);
"""
)

# embedding_api() exposes Python functions to uwsgi.
# Similar to extern "Python", but referenced by our own C set_source()
# as well as our Python code:
exposed_to_uwsgi = """
extern struct uwsgi_server uwsgi;
extern struct uwsgi_plugin cffi_plugin;

static int uwsgi_cffi_init();
static void uwsgi_cffi_preinit_apps();
static void uwsgi_cffi_init_apps();
static int uwsgi_cffi_request(struct wsgi_request *wsgi_req);
static void uwsgi_cffi_after_request(struct wsgi_request *wsgi_req);
static void uwsgi_cffi_onload();

static uint64_t uwsgi_cffi_rpc(void *, uint8_t,  char **, uint16_t *, char **);
static void uwsgi_cffi_post_fork();
static void uwsgi_cffi_enable_threads();
static void uwsgi_cffi_init_thread();
static int uwsgi_cffi_mule(char *opt);
static int uwsgi_cffi_mule_msg(char *message, size_t len);
static int uwsgi_cffi_signal_handler(uint8_t sig, void *handler);

static int uwsgi_cffi_mount_app(char *, char *);
"""
ffibuilder.embedding_api(exposed_to_uwsgi)

init_code = io.StringIO()
build_bundle.bundler(init_code)
ffibuilder.embedding_init_code(init_code.getvalue())

ffibuilder.set_source(
    "cffi_plugin",
    """
#include <uwsgi.h>
"""
    + plugin_data
    + exposed_to_uwsgi
    + """

extern void uwsgi_cffi_more_apps() {
    uwsgi_apps_cnt++;
}

static struct uwsgi_option uwsgi_cffi_options[] = {
    {"cffi-home", required_argument, 0, "set PYTHONHOME/virtualenv", uwsgi_opt_set_str, &ucffi.home, 0},
    {"cffi-wsgi", required_argument, 0, "load a WSGI module (or use --mount instead)", uwsgi_opt_set_str, &ucffi.wsgi, 0},
    {"cffi-init", required_argument, 0, "load a module during init", uwsgi_opt_set_str, &ucffi.init, 0},
    {"cffi-eval", required_argument, 0, "evaluate Python code before fork()", uwsgi_opt_add_string_list, &ucffi.eval, 0},
    {"cffi-eval-post-fork", required_argument, 0, "evaluate Python code soon after fork()", uwsgi_opt_add_string_list, &ucffi.eval_post_fork, 0},
    {"cffi-exec", required_argument, 0, "execute Python code from file before fork()", uwsgi_opt_add_string_list, &ucffi.exec, 0},
    {"cffi-exec-post-fork", required_argument, 0, "execute Python code from file soon after fork()", uwsgi_opt_add_string_list, &ucffi.exec_post_fork, 0},
    {0, 0, 0, 0, 0, 0, 0},
};

CFFI_DLLEXPORT struct uwsgi_plugin cffi_plugin = {
    .name = "cffi",
    .modifier1 = 0,
    .init = uwsgi_cffi_init,
    .request = uwsgi_cffi_request,
    .after_request = uwsgi_cffi_after_request,
    .options = uwsgi_cffi_options,
    .preinit_apps = uwsgi_cffi_preinit_apps,
    .init_apps = uwsgi_cffi_init_apps,
    .init_thread = uwsgi_cffi_init_thread,
    .signal_handler = uwsgi_cffi_signal_handler,
    .mount_app = uwsgi_cffi_mount_app,
    .enable_threads = uwsgi_cffi_enable_threads,
    .rpc = uwsgi_cffi_rpc,
    .post_fork = uwsgi_cffi_post_fork,
    .mule = uwsgi_cffi_mule,
    .mule_msg = uwsgi_cffi_mule_msg,
};
""",
)

if __name__ == "__main__":
    ffibuilder.emit_c_code("cffi_plugin.c")
