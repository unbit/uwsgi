#include "../../uwsgi.h"

#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

int uwsgi_routing_func_redirect(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	char *url = NULL;

	if (uwsgi_response_headers_prepare(wsgi_req, "302 Found", 9)) goto end
	
	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

	url = uwsgi_regexp_apply_ovec(*subject, *subject_len, ur->data, ur->data_len, ur->ovector, ur->ovn);

	if (uwsgi_response_add_header(wsgi_req, "Location", 8, url, strlen(url))) goto end;
	// no need to check the ret value
	uwsgi_response_body_write_do(wsgi_req, "Moved", 5);
end:
	if (url)
		free(url);
	return UWSGI_ROUTE_BREAK;
}


int uwsgi_router_redirect(struct uwsgi_route *ur, char *args) {

	ur->func = uwsgi_routing_func_redirect;
	ur->data = args;
	ur->data_len = strlen(args);
	return 0;
}


void router_redirect_register(void) {

	uwsgi_register_router("redirect", uwsgi_router_redirect);
}

struct uwsgi_plugin router_redirect_plugin = {

	.name = "router_redirect",
	.on_load = router_redirect_register,
};
#else
struct uwsgi_plugin router_redirect_plugin = {
	.name = "router_redirect",
};
#endif
