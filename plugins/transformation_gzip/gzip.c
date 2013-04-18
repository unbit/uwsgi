#include <uwsgi.h>

static int transform_gzip(struct wsgi_request *wsgi_req, struct uwsgi_buffer *ub, struct uwsgi_buffer **new) {
	struct uwsgi_buffer *gzipped = uwsgi_gzip(ub->buf, ub->pos);
	if (!gzipped) {
		return -1;
	}
	// use this new buffer
	*new = gzipped;	
	return 0;
}

static int uwsgi_routing_func_gzip(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {
	uwsgi_add_transformation(wsgi_req, transform_gzip);
	return UWSGI_ROUTE_NEXT;
}

static int uwsgi_router_gzip(struct uwsgi_route *ur, char *args) {
	ur->func = uwsgi_routing_func_gzip;
	return 0;
}

static void router_gzip_register(void) {
	uwsgi_register_router("gzip", uwsgi_router_gzip);
}

struct uwsgi_plugin transformation_gzip_plugin = {
	.name = "transformation_gzip",
	.on_load = router_gzip_register,
};
