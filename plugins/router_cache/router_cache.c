#include <uwsgi.h>

#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

/*

	by Unbit

	syntax:

	route = /^foobar1(.*)/ cache:key=foo$1poo,content_type=text/html,name=foobar

*/

struct uwsgi_router_cache_conf {

	// the name of the cache
	char *name;
	size_t name_len;

	char *key;
	size_t key_len;

	// use mime types ?
	char *mime;

#ifdef UWSGI_ZLIB
	char *gzip;
	size_t gzip_len;
#endif

	char *content_type;
	size_t content_type_len;

	char *content_encoding;
	size_t content_encoding_len;

	struct uwsgi_cache *cache;

	char *expires_str;
	uint64_t expires;
};

// this is allocated for each transformation
struct uwsgi_transformation_cache_conf {
	struct uwsgi_buffer *cache_it;
#ifdef UWSGI_ZLIB
        struct uwsgi_buffer *cache_it_gzip;
#endif

        struct uwsgi_buffer *cache_it_to;
        uint64_t cache_it_expires;
};

static int transform_cache(struct wsgi_request *wsgi_req, struct uwsgi_buffer *ub, struct uwsgi_buffer **new, void *data) {
	struct uwsgi_transformation_cache_conf *utcc = (struct uwsgi_transformation_cache_conf *) data;

	// store only successfull response
	if (wsgi_req->write_errors == 0 && wsgi_req->status == 200 && ub->pos > 0) {
		if (utcc->cache_it) {
			uwsgi_cache_magic_set(utcc->cache_it->buf, utcc->cache_it->pos, ub->buf, ub->pos, utcc->cache_it_expires,
				UWSGI_CACHE_FLAG_UPDATE, utcc->cache_it_to ? utcc->cache_it_to->buf : NULL);
#ifdef UWSGI_ZLIB
			if (utcc->cache_it_gzip) {
				struct uwsgi_buffer *gzipped = uwsgi_gzip(ub->buf, ub->pos);
				if (gzipped) {
					uwsgi_cache_magic_set(utcc->cache_it_gzip->buf, utcc->cache_it_gzip->pos, gzipped->buf, gzipped->pos, utcc->cache_it_expires,
                                		UWSGI_CACHE_FLAG_UPDATE, utcc->cache_it_to ? utcc->cache_it_to->buf : NULL);
					uwsgi_buffer_destroy(gzipped);
				}
			}
#endif
		}
	}

	// free resources
	if (utcc->cache_it) uwsgi_buffer_destroy(utcc->cache_it);
#ifdef UWSGI_ZLIB
	if (utcc->cache_it_gzip) uwsgi_buffer_destroy(utcc->cache_it_gzip);
#endif
	if (utcc->cache_it_to) uwsgi_buffer_destroy(utcc->cache_it_to);
	free(utcc);
        return 0;
}


// be tolerant on errors
static int uwsgi_routing_func_cache_store(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){
	struct uwsgi_router_cache_conf *urcc = (struct uwsgi_router_cache_conf *) ur->data2;

	struct uwsgi_transformation_cache_conf *utcc = uwsgi_calloc(sizeof(struct uwsgi_transformation_cache_conf));

	// build key and name
        char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

        utcc->cache_it = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urcc->key, urcc->key_len);
        if (!utcc->cache_it) goto error;
	
	if (urcc->name) {
		utcc->cache_it_to = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urcc->name, urcc->name_len);
		if (!utcc->cache_it_to) goto error;
	}

#ifdef UWSGI_ZLIB
	if (urcc->gzip) {
		utcc->cache_it_gzip = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urcc->gzip, urcc->gzip_len);
        	if (!utcc->cache_it_gzip) goto error;
	}
#endif
	utcc->cache_it_expires = urcc->expires;

	uwsgi_add_transformation(wsgi_req, transform_cache, utcc);

	return UWSGI_ROUTE_NEXT;

error:
	if (utcc->cache_it) uwsgi_buffer_destroy(utcc->cache_it);
#ifdef UWSGI_ZLIB
	if (utcc->cache_it_gzip) uwsgi_buffer_destroy(utcc->cache_it_gzip);
#endif
	if (utcc->cache_it_to) uwsgi_buffer_destroy(utcc->cache_it_to);
	free(utcc);
	return UWSGI_ROUTE_NEXT;
}

static int uwsgi_routing_func_cache(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){

	char *mime_type = NULL;
	size_t mime_type_len = 0;
	struct uwsgi_router_cache_conf *urcc = (struct uwsgi_router_cache_conf *) ur->data2;

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);
	struct uwsgi_buffer *ub = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urcc->key, urcc->key_len);
        if (!ub) return UWSGI_ROUTE_BREAK;

	uint64_t valsize = 0;
	uint64_t expires = 0;
	char *value = uwsgi_cache_magic_get(ub->buf, ub->pos, &valsize, &expires, urcc->name);
	if (urcc->mime && value) {
		mime_type = uwsgi_get_mime_type(ub->buf, ub->pos, &mime_type_len);	
	}
	uwsgi_buffer_destroy(ub);
	if (value) {
		if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) goto error;
		if (mime_type) {
                        uwsgi_response_add_content_type(wsgi_req, mime_type, mime_type_len);
		}
		else {
			if (uwsgi_response_add_content_type(wsgi_req, urcc->content_type, urcc->content_type_len)) goto error;
		}
		if (urcc->content_encoding_len) {
			if (uwsgi_response_add_header(wsgi_req, "Content-Encoding", 16, urcc->content_encoding, urcc->content_encoding_len)) goto error;	
		}
		if (expires) {
			if (uwsgi_response_add_expires(wsgi_req, expires)) goto error;	
		}
		if (uwsgi_response_add_content_length(wsgi_req, valsize)) goto error;
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

static int uwsgi_router_cache_store(struct uwsgi_route *ur, char *args) {
	ur->func = uwsgi_routing_func_cache_store;
	ur->data = args;
	ur->data_len = strlen(args);
	struct uwsgi_router_cache_conf *urcc = uwsgi_calloc(sizeof(struct uwsgi_router_cache_conf));
	if (uwsgi_kvlist_parse(ur->data, ur->data_len, ',', '=',
                        "key", &urcc->key,
#ifdef UWSGI_ZLIB
                        "gzip", &urcc->gzip,
#endif
                        "name", &urcc->name,
                        "expires", &urcc->expires_str, NULL)) {
                        uwsgi_log("invalid cachestore route syntax: %s\n", args);
			goto error;
                }

                if (urcc->key) {
                        urcc->key_len = strlen(urcc->key);
                }

#ifdef UWSGI_ZLIB
		if (urcc->gzip) {
			urcc->gzip_len = strlen(urcc->gzip);
		}
#endif

		if (urcc->name) {
                        urcc->name_len = strlen(urcc->name);
		}

                if (!urcc->key) {
                        uwsgi_log("invalid cachestore route syntax: you need to specify a cache key\n");
			goto error;
                }

		if (urcc->expires_str) {
			urcc->expires = strtoul(urcc->expires_str, NULL, 10);
		}

	ur->data2 = urcc;
        return 0;
error:
	if (urcc->key) free(urcc->key);
	if (urcc->name) free(urcc->name);
	if (urcc->expires_str) free(urcc->expires_str);
	free(urcc);
	return -1;
}

static int uwsgi_router_cache(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_cache;
        ur->data = args;
        ur->data_len = strlen(args);
	struct uwsgi_router_cache_conf *urcc = uwsgi_calloc(sizeof(struct uwsgi_router_cache_conf));
                if (uwsgi_kvlist_parse(ur->data, ur->data_len, ',', '=',
                        "key", &urcc->key,
                        "content_type", &urcc->content_type,
                        "content_encoding", &urcc->content_encoding,
                        "mime", &urcc->mime,
                        "name", &urcc->name,
                        NULL)) {
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

                if (!urcc->content_type) urcc->content_type = "text/html";

                urcc->content_type_len = strlen(urcc->content_type);

		if (urcc->content_encoding) {
			urcc->content_encoding_len = strlen(urcc->content_encoding);
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
	uwsgi_register_router("cachestore", uwsgi_router_cache_store);
	uwsgi_register_router("cache-store", uwsgi_router_cache_store);
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
