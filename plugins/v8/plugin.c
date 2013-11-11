#include <uwsgi.h>

int uwsgi_v8_init(void);
void uwsgi_v8_apps(void);
void uwsgi_v8_configurator(char *, char **);
uint64_t uwsgi_v8_rpc(void *, uint8_t, char **, uint16_t *, char **);
int uwsgi_v8_signal_handler(uint8_t, void *);
void uwsgi_v8_init_thread(int);
void uwsgi_v8_enable_threads();
int uwsgi_v8_mule(char *);

static void uwsgi_v8_register(void) {
        uwsgi_register_configurator(".js", uwsgi_v8_configurator);
}

extern struct uwsgi_option uwsgi_v8_options[];

int uwsgi_v8_request(struct wsgi_request *);

static void uwsgi_v8_after_request(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

struct uwsgi_plugin v8_plugin = {
	.name = "v8",
	.modifier1 = 24,
	.init = uwsgi_v8_init,
	.init_apps = uwsgi_v8_apps,
	.options = uwsgi_v8_options,
	.on_load = uwsgi_v8_register,
	.rpc = uwsgi_v8_rpc,
	.request = uwsgi_v8_request,
	.after_request = uwsgi_v8_after_request,
	.signal_handler = uwsgi_v8_signal_handler,
	.enable_threads = uwsgi_v8_enable_threads,
	.init_thread = uwsgi_v8_init_thread,
	.mule = uwsgi_v8_mule,
};
