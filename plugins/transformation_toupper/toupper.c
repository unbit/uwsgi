#include <uwsgi.h>

static int transform_toupper(struct wsgi_request *wsgi_req, struct uwsgi_transformation *ut) {
	size_t i;
	for(i=0;i<ut->chunk->pos;i++) {
		ut->chunk->buf[i] = toupper((int) ut->chunk->buf[i]);
	}
	return 0;
}

static int uwsgi_routing_func_toupper(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {
	struct uwsgi_transformation *ut = uwsgi_add_transformation(wsgi_req, transform_toupper, NULL);
	ut->can_stream = 1;
	return UWSGI_ROUTE_NEXT;
}

static int uwsgi_router_toupper(struct uwsgi_route *ur, char *args) {
	ur->func = uwsgi_routing_func_toupper;
	return 0;
}

static void router_toupper_register(void) {
	uwsgi_register_router("toupper", uwsgi_router_toupper);
}

struct uwsgi_plugin transformation_toupper_plugin = {
	.name = "transformation_toupper",
	.on_load = router_toupper_register,
};
