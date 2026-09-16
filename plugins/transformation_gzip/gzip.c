#include <uwsgi.h>

#if defined(UWSGI_ROUTING) && defined(UWSGI_ZLIB)

/*

	gzip transformations add content-encoding to your headers and changes the final size !!!

	remember to fix the content_length (or use chunked encoding) !!!

*/

struct uwsgi_transformation_gzip {
	z_stream z;
	uint32_t crc32;
	size_t len;
	uint8_t header;
	uint8_t prepared;
};

extern char gzheader[];

// the headers are already out: gzip can be applied only if they announce it (e.g. --add-header)
static int uwsgi_gzip_announced(struct wsgi_request *wsgi_req) {
	struct uwsgi_buffer *ub = wsgi_req->headers;
	if (!ub) return 0;
	char *line = ub->buf;
	char *end = ub->buf + ub->pos;
	while (line < end) {
		char *eol = memchr(line, '\n', end - line);
		char *line_end = eol ? eol : end;
		if (line_end > line && line_end[-1] == '\r') line_end--;
		if (line_end - line > 17 && !uwsgi_strnicmp(line, 17, "Content-Encoding:", 17)) {
			// a comma-separated list of codings
			char *token = line + 17;
			while (token < line_end) {
				char *comma = memchr(token, ',', line_end - token);
				char *token_end = comma ? comma : line_end;
				while (token < token_end && (*token == ' ' || *token == '\t')) token++;
				while (token_end > token && (token_end[-1] == ' ' || token_end[-1] == '\t')) token_end--;
				int tl = (int) (token_end - token);
				if (!uwsgi_strnicmp(token, tl, "gzip", 4) || !uwsgi_strnicmp(token, tl, "x-gzip", 6)) return 1;
				token = comma ? comma + 1 : line_end;
			}
		}
		line = eol ? eol + 1 : end;
	}
	return 0;
}

static void transform_gzip_free(struct uwsgi_transformation *ut) {
	struct uwsgi_transformation_gzip *utgz = (struct uwsgi_transformation_gzip *) ut->data;
	if (utgz->prepared) {
		deflateEnd(&utgz->z);
	}
	free(utgz);
}

static int transform_gzip(struct wsgi_request *wsgi_req, struct uwsgi_transformation *ut) {
	struct uwsgi_transformation_gzip *utgz = (struct uwsgi_transformation_gzip *) ut->data;
	struct uwsgi_buffer *ub = ut->chunk;

	if (ut->is_final) {
		if (utgz->len == 0) return 0;
		// uwsgi_gzip_fix() ends the stream on both of its paths
		utgz->prepared = 0;
		return uwsgi_gzip_fix(&utgz->z, utgz->crc32, ub, utgz->len) ? -1 : 0;
	}

	if (ub->pos == 0) return 0;

	if (!utgz->prepared) {
		// Content-Encoding can no longer be added once the headers are out
		if (wsgi_req->headers_sent && !uwsgi_gzip_announced(wsgi_req)) return 0;
		// the ~400 KB deflate state is allocated here, so a response without a body never gets one
		if (uwsgi_gzip_prepare(&utgz->z, NULL, 0, &utgz->crc32)) return -1;
		utgz->prepared = 1;
	}

	size_t dlen = 0;
	char *gzipped = uwsgi_gzip_chunk(&utgz->z, &utgz->crc32, ub->buf, ub->pos, &dlen);
	if (!gzipped) return -1;
	utgz->len += ub->pos;
	uwsgi_buffer_map(ub, gzipped, dlen);
	if (!utgz->header) {
		// do not check for errors !!!
		uwsgi_response_add_header(wsgi_req, "Content-Encoding", 16, "gzip", 4);
		utgz->header = 1;
		if (uwsgi_buffer_insert(ub, 0, gzheader, 10)) {
			return -1;
		}
	}

	return 0;
}

static int uwsgi_routing_func_gzip(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {
	struct uwsgi_transformation_gzip *utgz = uwsgi_calloc(sizeof(struct uwsgi_transformation_gzip));
	struct uwsgi_transformation *ut = uwsgi_add_transformation(wsgi_req, transform_gzip, utgz);
	ut->free_data = transform_gzip_free;
	ut->can_stream = 1;
	ut = uwsgi_add_transformation(wsgi_req, transform_gzip, utgz);
	ut->is_final = 1;
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
