# based on the example and pypy plugins

import cffi

ffibuilder = cffi.FFI()

# uwsgi functions exposed to Python
# TODO split out parts that have to be duplicated between
# cdef, embedding_api, and set_source

ffibuilder.cdef(open("defines.h", "r").read())

ffibuilder.cdef(
    """
struct iovec {
        void *iov_base;
        size_t iov_len;
        ...;
};

struct uwsgi_header {
        uint8_t modifier1;
        ...;
};

struct wsgi_request {
        int fd;
        int async_id;
        uint16_t var_cnt;
        struct iovec *hvec;

        int async_ready_fd;
        int async_last_ready_fd;

        int suspended;

        struct uwsgi_header *uh;
        ...;
};

struct uwsgi_opt {
        char *key;
        char *value;
        ...;
};

struct uwsgi_worker {
        int id;
        int pid;
        uint64_t requests;
        uint64_t delta_requests;
        uint64_t signals;

        int cheaped;
        int suspended;
        int sig;
        uint8_t signum;

        uint64_t running_time;
        uint64_t avg_response_time;
        uint64_t tx;
        ...;
};

struct uwsgi_plugin {
        uint8_t modifier1;

        void (*suspend) (struct wsgi_request *);
        void (*resume) (struct wsgi_request *);
        ...;
};

struct uwsgi_buffer {
        char *buf;
        size_t pos;
        ...;
};

struct uwsgi_lock_item {
        ...;
};

struct uwsgi_cache {
        struct uwsgi_lock_item *lock;
        ...;
};

struct uwsgi_cache_item {
        uint64_t keysize;
        ...;
};

struct uwsgi_server {
        char hostname[];
        int mywid;
        int muleid;
        int master_process;

        struct uwsgi_opt **exported_opts;
        int exported_opts_cnt;

        struct uwsgi_worker *workers;

        int signal_socket;
        int numproc;
        int async;

        void (*schedule_to_main) (struct wsgi_request *);
        void (*schedule_to_req) (void);

        struct wsgi_request *(*current_wsgi_req) (void);

        struct wsgi_request *wsgi_req;

        struct uwsgi_plugin *p[];
        ...;
};
struct uwsgi_server uwsgi;

// OURS v
struct uwsgi_cffi {
	char *wsgi;
} ucffi;

void uwsgi_cffi_more_apps();
// OURS ^

char *uwsgi_binary_path();

void *uwsgi_malloc(size_t);

struct uwsgi_logvar {
	char key[256];
	uint8_t keylen;
	char val[256];
	uint8_t vallen;
	struct uwsgi_logvar *next;
};

struct uwsgi_logvar *uwsgi_logvar_get(struct wsgi_request *, char *, uint8_t);
void uwsgi_logvar_add(struct wsgi_request *, char *, uint8_t, char *, uint8_t);

int uwsgi_response_prepare_headers(struct wsgi_request *, char *, size_t);
int uwsgi_response_add_header(struct wsgi_request *, char *, uint16_t, char *, uint16_t);
int uwsgi_response_write_body_do(struct wsgi_request *, char *, size_t);
int uwsgi_response_sendfile_do_can_close(struct wsgi_request *, int, size_t, size_t, int);

char *uwsgi_request_body_read(struct wsgi_request *, ssize_t , ssize_t *);
char *uwsgi_request_body_readline(struct wsgi_request *, ssize_t, ssize_t *);

void uwsgi_buffer_destroy(struct uwsgi_buffer *);
int uwsgi_is_again();

int uwsgi_register_rpc(char *, struct uwsgi_plugin *, uint8_t, void *);
int uwsgi_register_signal(uint8_t, char *, void *, uint8_t);

char *uwsgi_do_rpc(char *, char *, uint8_t, char **, uint16_t *, uint64_t *);

void uwsgi_set_processname(char *);
int uwsgi_signal_send(int, uint8_t);
uint64_t uwsgi_worker_exceptions(int);
int uwsgi_worker_is_busy(int);

char *uwsgi_cache_magic_get(char *, uint16_t, uint64_t *, uint64_t *, char *);
int uwsgi_cache_magic_set(char *, uint16_t, char *, uint64_t, uint64_t, uint64_t, char *);
int uwsgi_cache_magic_del(char *, uint16_t, char *);
int uwsgi_cache_magic_exists(char *, uint16_t, char *);
int uwsgi_cache_magic_clear(char *);
struct uwsgi_cache *uwsgi_cache_by_name(char *);
void uwsgi_cache_rlock(struct uwsgi_cache *);
void uwsgi_cache_rwunlock(struct uwsgi_cache *);
char *uwsgi_cache_item_key(struct uwsgi_cache_item *);
struct uwsgi_cache_item *uwsgi_cache_keys(struct uwsgi_cache *, uint64_t *, struct uwsgi_cache_item **);

int uwsgi_add_file_monitor(uint8_t, char *);
int uwsgi_add_timer(uint8_t, int);
int uwsgi_signal_add_rb_timer(uint8_t, int, int);

int uwsgi_user_lock(int);
int uwsgi_user_unlock(int);

int uwsgi_signal_registered(uint8_t);

int uwsgi_signal_add_cron(uint8_t, int, int, int, int, int);
void uwsgi_alarm_trigger(char *, char *, size_t);

void async_schedule_to_req_green(void);
void async_add_timeout(struct wsgi_request *, int);
int async_add_fd_write(struct wsgi_request *, int, int);
int async_add_fd_read(struct wsgi_request *, int, int);
int uwsgi_connect(char *, int, int);

void log_request(struct wsgi_request *);

int uwsgi_websocket_handshake(struct wsgi_request *, char *, uint16_t, char *, uint16_t, char *, uint16_t);
int uwsgi_websocket_send(struct wsgi_request *, char *, size_t);
struct uwsgi_buffer *uwsgi_websocket_recv(struct wsgi_request *);
struct uwsgi_buffer *uwsgi_websocket_recv_nb(struct wsgi_request *);

char *uwsgi_chunked_read(struct wsgi_request *, size_t *, int, int);

void uwsgi_disconnect(struct wsgi_request *);

int uwsgi_ready_fd(struct wsgi_request *);

void set_user_harakiri(struct wsgi_request *, int);

int uwsgi_metric_set(char *, char *, int64_t);
int uwsgi_metric_inc(char *, char *, int64_t);
int uwsgi_metric_dec(char *, char *, int64_t);
int uwsgi_metric_mul(char *, char *, int64_t);
int uwsgi_metric_div(char *, char *, int64_t);
int64_t uwsgi_metric_get(char *, char *);
"""
)

# Python functions exposed to uwsgi
ffibuilder.embedding_api(
    """
extern struct uwsgi_server uwsgi;

static int uwsgi_cffi_init();
static void uwsgi_cffi_init_apps();
static int uwsgi_cffi_request(struct wsgi_request *wsgi_req);
static void uwsgi_cffi_after_request(struct wsgi_request *wsgi_req);
"""
)

ffibuilder.embedding_init_code(open("cffi_init.py", "r").read())


ffibuilder.set_source(
    "cffi_plugin",
    """
#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_cffi {
	char *wsgi;
} ucffi;

static int uwsgi_cffi_init();
static void uwsgi_cffi_init_apps();
static int uwsgi_cffi_request(struct wsgi_request *wsgi_req);
static void uwsgi_cffi_after_request(struct wsgi_request *wsgi_req);

extern void uwsgi_cffi_more_apps() {
    uwsgi_apps_cnt++;
}

static struct uwsgi_option uwsgi_cffi_options[] = {
	{"cffi-wsgi", required_argument, 0, "load a WSGI module", uwsgi_opt_set_str, &ucffi.wsgi, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

CFFI_DLLEXPORT struct uwsgi_plugin cffi_plugin = {
    .name = "cffi",
    .modifier1 = 0,
    .init = uwsgi_cffi_init,
    .init_apps = uwsgi_cffi_init_apps,
    .options = uwsgi_cffi_options,
    .request = uwsgi_cffi_request,
    .after_request = uwsgi_cffi_after_request,
};
""",
)


ffibuilder.emit_c_code("cffi_plugin.c")
