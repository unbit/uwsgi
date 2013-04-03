#include <uwsgi.h>

int uwsgi_gridfs_request(struct wsgi_request *);
void uwsgi_gridfs_mount();
extern struct uwsgi_option uwsgi_gridfs_options[];

static void uwsgi_gridfs_log(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

#ifdef UWSGI_ROUTING
int uwsgi_router_gridfs(struct uwsgi_route *, char *);
static void uwsgi_gridfs_register_router() {
        uwsgi_register_router("gridfs", uwsgi_router_gridfs);
}
#endif


struct uwsgi_plugin gridfs_plugin = {

	.name = "gridfs",
	.modifier1 = 25,

	.init_apps = uwsgi_gridfs_mount,
	.options = uwsgi_gridfs_options,
	.request = uwsgi_gridfs_request,
	.after_request = uwsgi_gridfs_log,
#ifdef UWSGI_ROUTING
	.on_load = uwsgi_gridfs_register_router,
#endif
};
