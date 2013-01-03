#include "../../uwsgi.h"

#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

int uwsgi_routing_func_static(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

	char *filename = uwsgi_regexp_apply_ovec(*subject, *subject_len, ur->data, ur->data_len, ur->ovector, ur->ovn);
	uint16_t filename_len = strlen(filename);
	
	uwsgi_file_serve(wsgi_req, filename, filename_len, NULL, 0, 1);
	return UWSGI_ROUTE_BREAK;
}


int uwsgi_router_static(struct uwsgi_route *ur, char *args) {

	ur->func = uwsgi_routing_func_static;
	ur->data = args;
	ur->data_len = strlen(args);
	return 0;
}


static void router_static_register(void) {

	uwsgi_register_router("static", uwsgi_router_static);
}

struct uwsgi_plugin router_static_plugin = {

	.name = "router_static",
	.on_load = router_static_register,
};
#else
struct uwsgi_plugin router_static_plugin = {
	.name = "router_static",
};
#endif
