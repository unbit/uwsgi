#include <uwsgi.h>

#if defined(UWSGI_ROUTING) && defined(UWSGI_ZLIB)

/*

	gzip transformations add content-encoding to your headers and changes the final size !!!

	remember to fix the content_length !!!

*/

static int transform_gzip(struct wsgi_request *wsgi_req, struct uwsgi_transformation *ut) {
	struct uwsgi_buffer *ub = ut->chunk;
	struct uwsgi_buffer *gzipped = uwsgi_gzip(ub->buf, ub->pos);
	if (!gzipped) {
		return -1;
	}
	// swap the old buf with the new one
	uwsgi_buffer_destroy(ut->chunk);
	ut->chunk = gzipped;
	if (!wsgi_req->headers_sent) {
        	if (uwsgi_response_add_header(wsgi_req, "Content-Encoding", 16, "gzip", 4)) return -1;
	}
	return 0;
}

static int uwsgi_routing_func_gzip(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {
	uwsgi_add_transformation(wsgi_req, transform_gzip, NULL);
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
#else
struct uwsgi_plugin transformation_gzip_plugin = {
	.name = "transformation_gzip",
};
#endif
