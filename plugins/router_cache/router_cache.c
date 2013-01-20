#include "../../uwsgi.h"

#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

/*

	by Unbit

	syntax:

	route = /^foobar1(.*)/ cache:key=foo$1poo,type=body
	route = /^foobar1 cache:var=PATH_INFO,type=body
	route = /^foobar2 cache:var=REQUEST_URI,type=full
	route = /^foobar3 cache:var=REQUEST_URI,type=body,content_type=text/html

*/

struct uwsgi_router_cache_conf {

	char *key;
	size_t key_len;
	char *var;
	char *type;

	long var_offset;
	long var_offset_len;

	char *content_type;
	size_t content_type_len;

	// 0 -> full, 1 -> body
	int type_num;
	
};

static int uwsgi_routing_func_cache(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){

	struct uwsgi_router_cache_conf *urcc = (struct uwsgi_router_cache_conf *) ur->data2;

	if (!uwsgi.cache_max_items) return UWSGI_ROUTE_NEXT;

	char *c_k = NULL;
	uint16_t c_k_len = 0;
	struct uwsgi_buffer *ub = NULL;
	int k_need_free = 0;

	if (urcc->key) {
		char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        	uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

        	c_k = uwsgi_regexp_apply_ovec(*subject, *subject_len, urcc->key, urcc->key_len, ur->ovector, ur->ovn);
		c_k_len = strlen(c_k);
		k_need_free = 1;
	}
	else {
		char **key = (char **) (((char *) wsgi_req) + urcc->var_offset);
        	uint16_t *keylen = (uint16_t *) (((char *) wsgi_req) + urcc->var_offset_len);
		c_k = *key;
		c_k_len = *keylen;
	}

	uint64_t valsize = 0;
	char *value = uwsgi_cache_get(c_k, c_k_len, &valsize);
	if (value) {
		ub = uwsgi_buffer_new(uwsgi.page_size);
		if (urcc->type_num == 1) {
			wsgi_req->status = 200;
			if (uwsgi_buffer_append(ub, "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: ", 50)) goto error;
			if (uwsgi_buffer_append(ub, urcc->content_type, urcc->content_type_len)) goto error;
			if (uwsgi_buffer_append(ub, "\r\nContent-Length: ", 18 )) goto error;
			if (uwsgi_buffer_num64(ub, valsize)) goto error;
			if (uwsgi_buffer_append(ub, "\r\n\r\n", 4 )) goto error;
			//wsgi_req->headers_size += wsgi_req->socket->proto_write_header(wsgi_req, ub->buf, ub->pos);
			uwsgi_buffer_destroy(ub);
			wsgi_req->header_cnt = 3;		
		}
		// body only
		wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, value, valsize);
		if (k_need_free) free(c_k);
		if (ur->custom)
			return UWSGI_ROUTE_NEXT;
		return UWSGI_ROUTE_BREAK;
	}
	if (k_need_free) free(c_k);
	
	return UWSGI_ROUTE_NEXT;
error:
	uwsgi_buffer_destroy(ub);
	if (k_need_free) free(c_k);
	return UWSGI_ROUTE_BREAK;
}

static int uwsgi_router_cache(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_cache;
        ur->data = args;
        ur->data_len = strlen(args);
	struct uwsgi_router_cache_conf *urcc = uwsgi_calloc(sizeof(struct uwsgi_router_cache_conf));
                if (uwsgi_kvlist_parse(ur->data, ur->data_len, ',', '=',
                        "key", &urcc->key,
                        "var", &urcc->var,
                        "content_type", &urcc->content_type,
                        "type", &urcc->type, NULL)) {
			uwsgi_log("invalid route syntax: %s\n", args);
			exit(1);
                }

		if (urcc->key) {
			urcc->key_len = strlen(urcc->key);
		}

		if (!urcc->key && !urcc->var) {
			uwsgi_log("invalid route syntax: you need to specify a cache key or var\n");
			exit(1);
		}

                if (!urcc->type) urcc->type = "full";
                if (!urcc->content_type) urcc->content_type = "text/html";

                urcc->content_type_len = strlen(urcc->content_type);

		if (urcc->var) {
                if (!strcmp(urcc->var, "REQUEST_URI")) {
                        urcc->var_offset = offsetof(struct wsgi_request, uri);
                        urcc->var_offset_len = offsetof(struct wsgi_request, uri_len);
                }
                else if (!strcmp(urcc->var, "PATH_INFO")) {
                        urcc->var_offset = offsetof(struct wsgi_request, path_info);
                        urcc->var_offset_len = offsetof(struct wsgi_request, path_info_len);
                }
                else {
                        urcc->var_offset = offsetof(struct wsgi_request, uri);
                        urcc->var_offset_len = offsetof(struct wsgi_request, uri_len);
                }
		}

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
