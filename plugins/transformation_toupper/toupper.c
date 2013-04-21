#include <uwsgi.h>

static int transform_toupper(struct wsgi_request *wsgi_req, struct uwsgi_buffer *ub, struct uwsgi_buffer **foobar, void *data) {
	size_t i;
	for(i=0;i<ub->pos;i++) {
		ub->buf[i] = toupper((int) ub->buf[i]);
	}
	return 0;
}

static int uwsgi_routing_func_toupper(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {
	uwsgi_add_transformation(wsgi_req, transform_toupper, NULL);
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
