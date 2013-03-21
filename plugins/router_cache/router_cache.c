#include "../../uwsgi.h"

#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

/*

	by Unbit

	syntax:

	route = /^foobar1(.*)/ cache:key=foo$1poo,type=body,content_type=text/html,name=foobar

*/

struct uwsgi_router_cache_conf {

	// the name of the cache
	char *name;

	char *key;
	size_t key_len;

	char *type;

	char *content_type;
	size_t content_type_len;

	// 0 -> full, 1 -> body
	int type_num;
	struct uwsgi_cache *cache;
	
};

static int uwsgi_routing_func_cache(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){

	struct uwsgi_router_cache_conf *urcc = (struct uwsgi_router_cache_conf *) ur->data2;

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);
	struct uwsgi_buffer *ub = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urcc->key, urcc->key_len);
        if (!ub) return UWSGI_ROUTE_BREAK;

	uint64_t valsize = 0;
	char *value = uwsgi_cache_magic_get(ub->buf, ub->pos, &valsize, urcc->name);
	uwsgi_buffer_destroy(ub);
	if (value) {
		if (urcc->type_num == 1) {
			if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) goto error;
			if (uwsgi_response_add_content_type(wsgi_req, urcc->content_type, urcc->content_type_len)) goto error;
			if (uwsgi_response_add_content_length(wsgi_req, valsize)) goto error;
		}
		// body only
		uwsgi_response_write_body_do(wsgi_req, value, valsize);
		free(value);
		if (ur->custom)
			return UWSGI_ROUTE_NEXT;
		return UWSGI_ROUTE_BREAK;
	}
	
	return UWSGI_ROUTE_NEXT;
error:
	free(value);
	return UWSGI_ROUTE_BREAK;
}

static int uwsgi_router_cache(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_cache;
        ur->data = args;
        ur->data_len = strlen(args);
	struct uwsgi_router_cache_conf *urcc = uwsgi_calloc(sizeof(struct uwsgi_router_cache_conf));
                if (uwsgi_kvlist_parse(ur->data, ur->data_len, ',', '=',
                        "key", &urcc->key,
                        "content_type", &urcc->content_type,
                        "name", &urcc->name,
                        "type", &urcc->type, NULL)) {
			uwsgi_log("invalid route syntax: %s\n", args);
			exit(1);
                }

		if (urcc->key) {
			urcc->key_len = strlen(urcc->key);
		}

		if (!urcc->key) {
			uwsgi_log("invalid route syntax: you need to specify a cache key\n");
			exit(1);
		}

                if (!urcc->type) urcc->type = "full";
                if (!urcc->content_type) urcc->content_type = "text/html";

                urcc->content_type_len = strlen(urcc->content_type);

                if (!strcmp(urcc->type, "body")) {
                        urcc->type_num = 1;
                }

                ur->data2 = urcc;
	return 0;
}

static int uwsgi_router_cache_continue(struct uwsgi_route *ur, char *args) {
	uwsgi_router_cache(ur, args);
	ur->custom = 1;
	return 0;
}

static void router_cache_register() {
	uwsgi_register_router("cache", uwsgi_router_cache);
	uwsgi_register_router("cache-continue", uwsgi_router_cache_continue);
}

struct uwsgi_plugin router_cache_plugin = {
	.name = "router_cache",
	.on_load = router_cache_register,
};

#else
struct uwsgi_plugin router_cache_plugin = {
	.name = "router_cache",
};
#endif
