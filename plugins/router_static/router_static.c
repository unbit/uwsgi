#include <uwsgi.h>

#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

struct uwsgi_router_file_conf {

	char *filename;
	size_t filename_len;

	char *status;
	size_t status_len;

	char *content_type;
	size_t content_type_len;
	
	char *mime;
};

int uwsgi_routing_func_static(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

	struct uwsgi_buffer *ub = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, ur->data, ur->data_len);
        if (!ub) return UWSGI_ROUTE_BREAK;

	uwsgi_file_serve(wsgi_req, ub->buf, ub->pos, NULL, 0, 1);
	uwsgi_buffer_destroy(ub);
	return UWSGI_ROUTE_BREAK;
}

int uwsgi_routing_func_file(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	char buf[32768];
	struct stat st;
	int ret = UWSGI_ROUTE_BREAK;

	struct uwsgi_router_file_conf *urfc = (struct uwsgi_router_file_conf *) ur->data2;

        char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

        struct uwsgi_buffer *ub = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urfc->filename, urfc->filename_len);
        if (!ub) return UWSGI_ROUTE_BREAK;

	int fd = open(ub->buf, O_RDONLY);
	if (fd < 0) {
		if (ur->custom)
			ret = UWSGI_ROUTE_NEXT;
		goto end; 
	}

	if (fstat(fd, &st)) {
		goto end2;
	}

	struct uwsgi_buffer *ub_s = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urfc->status, urfc->status_len);
        if (!ub_s) goto end2;

	if (uwsgi_response_prepare_headers(wsgi_req, ub_s->buf, ub_s->pos)) {
		uwsgi_buffer_destroy(ub_s);
		goto end2;
	}
	uwsgi_buffer_destroy(ub_s);
	if (uwsgi_response_add_content_length(wsgi_req, st.st_size)) goto end2;
	if (urfc->mime) {
		size_t mime_type_len = 0;
		char *mime_type = uwsgi_get_mime_type(ub->buf, ub->pos, &mime_type_len);
		if (mime_type) {
			if (uwsgi_response_add_content_type(wsgi_req, mime_type, mime_type_len)) goto end2;
		}
		else {
			if (uwsgi_response_add_content_type(wsgi_req, urfc->content_type, urfc->content_type_len)) goto end2;
		}
	}
	else {
		if (uwsgi_response_add_content_type(wsgi_req, urfc->content_type, urfc->content_type_len)) goto end2;
	}
	
	size_t remains = st.st_size;
	while(remains) {
		ssize_t rlen = read(fd, buf, UMIN(32768, remains));
		if (rlen <= 0) goto end2;
		if (uwsgi_response_write_body_do(wsgi_req, buf, rlen)) goto end2;
		remains -= rlen;
	}
	
end2:
	close(fd);
end:
        uwsgi_buffer_destroy(ub);
        return ret;
}


static int uwsgi_router_static(struct uwsgi_route *ur, char *args) {

	ur->func = uwsgi_routing_func_static;
	ur->data = args;
	ur->data_len = strlen(args);
	return 0;
}

static int uwsgi_router_file(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_file;
        ur->data = args;
        ur->data_len = strlen(args);
        struct uwsgi_router_file_conf *urfc = uwsgi_calloc(sizeof(struct uwsgi_router_file_conf));
        if (uwsgi_kvlist_parse(ur->data, ur->data_len, ',', '=',
                        "filename", &urfc->filename,
                        "status", &urfc->status,
                        "content_type", &urfc->content_type,
                        "mime", &urfc->mime,
                        NULL)) {
                        uwsgi_log("invalid file route syntax: %s\n", args);
			return -1;
	}

	if (!urfc->filename) {
		uwsgi_log("you have to specifify a filename for the \"file\" router\n");
		return -1;
	}

	urfc->filename_len = strlen(urfc->filename);
	if (!urfc->content_type) {
		urfc->content_type = "text/html";
	}
	urfc->content_type_len = strlen(urfc->content_type);

	if (!urfc->status) {
		urfc->status = "200 OK";
	}
	urfc->status_len = strlen(urfc->status);

	ur->data2 = urfc;
	return 0;
}

static int uwsgi_router_file_next(struct uwsgi_route *ur, char *args) {
	ur->custom = 1;
	return uwsgi_router_file(ur, args);
}


static void router_static_register(void) {

	uwsgi_register_router("static", uwsgi_router_static);
	uwsgi_register_router("file", uwsgi_router_file);
	uwsgi_register_router("file-next", uwsgi_router_file_next);
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
