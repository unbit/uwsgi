#include "../../uwsgi.h"

#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

/*

	by Unbit

	syntax:

	route = /^foobar1 cache:key=PATH_INFO,type=body
	route = /^foobar2 cache:key=REQUEST_URI,type=full
	route = /^foobar3 cache:key=REQUEST_URI,type=body,content_type=text/html

*/

struct uwsgi_router_cache_conf {
	char *key;
	char *type;

	long key_offset;
	long key_offset_len;

	char *content_type;
	size_t content_type_len;

	// 0 -> full, 1 -> body
	int type_num;
	
};

static int uwsgi_routing_func_cache(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){

	struct uwsgi_router_cache_conf *urcc = (struct uwsgi_router_cache_conf *) ur->data2;

	if (!uwsgi.cache_max_items) return UWSGI_ROUTE_NEXT;

	if (!urcc) {
		urcc = uwsgi_calloc(sizeof(struct uwsgi_router_cache_conf));
		if (uwsgi_kvlist_parse(ur->data, ur->data_len, ',', '=',
			"key", &urcc->key,
			"content_type", &urcc->content_type,
			"type", &urcc->type, NULL)) {
			free(urcc);
			return UWSGI_ROUTE_NEXT;
		}
		if (!urcc->key) urcc->key = "REQUEST_URI";
		if (!urcc->type) urcc->type = "full";
		if (!urcc->content_type) urcc->content_type = "text/html";

		urcc->content_type_len = strlen(urcc->content_type);

		if (!strcmp(urcc->key, "REQUEST_URI")) {
			urcc->key_offset = offsetof(struct wsgi_request, uri);
                        urcc->key_offset_len = offsetof(struct wsgi_request, uri_len);
		}
		else if (!strcmp(urcc->key, "PATH_INFO")) {
			urcc->key_offset = offsetof(struct wsgi_request, path_info);
                        urcc->key_offset_len = offsetof(struct wsgi_request, path_info_len);
		}
		else {
			urcc->key_offset = offsetof(struct wsgi_request, uri);
                        urcc->key_offset_len = offsetof(struct wsgi_request, uri_len);
		}

		if (!strcmp(urcc->type, "body")) {
			urcc->type_num = 1;
		}

		ur->data2 = urcc;
	}

	char **key = (char **) (((char *) wsgi_req) + urcc->key_offset);
        uint16_t *keylen = (uint16_t *) (((char *) wsgi_req) + urcc->key_offset_len);

	uint64_t valsize = 0;
	char *value = uwsgi_cache_get(*key, *keylen, &valsize);
	if (value) {
		// body only
		if (urcc->type_num == 1) {
			wsgi_req->status = 200;
			wsgi_req->headers_size += wsgi_req->socket->proto_write_header(wsgi_req, "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: ", 50);
			wsgi_req->headers_size += wsgi_req->socket->proto_write_header(wsgi_req, urcc->content_type, urcc->content_type_len);
			wsgi_req->headers_size += wsgi_req->socket->proto_write_header(wsgi_req, "\r\n\r\n", 4);
			wsgi_req->header_cnt = 2;		
		}
		wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, value, valsize);
		return UWSGI_ROUTE_BREAK;
	}
	
	return UWSGI_ROUTE_NEXT;
}

static int uwsgi_router_cache(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_cache;
        ur->data = args;
        ur->data_len = strlen(args);
	return 0;
}

static void router_cache_register() {
	uwsgi_register_router("cache", uwsgi_router_cache);
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
