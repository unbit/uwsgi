#include "../../uwsgi.h"
#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

int uwsgi_routing_func_rewrite(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	char *tmp_qs = NULL;

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

        char *path_info = uwsgi_regexp_apply_ovec(*subject, *subject_len, ur->data, ur->data_len, ur->ovector, ur->ovn);
	uint16_t path_info_len = strlen(path_info);

	uint16_t query_string_len = 0;
	
	char *query_string = strchr(path_info, '?');
	if (query_string) {
		path_info_len = query_string - path_info;
		query_string++;
		query_string_len = strlen(query_string);
		if (wsgi_req->query_string_len > 0) {
			tmp_qs = uwsgi_concat4n(query_string, query_string_len, "&", 1, wsgi_req->query_string, wsgi_req->query_string_len, "", 0);
			query_string = tmp_qs;
			query_string_len = strlen(query_string);
		}	
	}
	// over engineering, could be requiredin the future...
	else {
		if (wsgi_req->query_string_len > 0) {
			query_string = wsgi_req->query_string;
			query_string_len = wsgi_req->query_string_len;
		}
		else {
			query_string = "";
		}
	}

	char *ptr = uwsgi_req_append(wsgi_req, "PATH_INFO", 9, path_info, path_info_len);
        if (!ptr) goto clear;

	// set new path_info
	wsgi_req->path_info = ptr;
	wsgi_req->path_info_len = path_info_len;

	ptr = uwsgi_req_append(wsgi_req, "QUERY_STRING", 12, query_string, query_string_len);
	if (!ptr) goto clear;

	// set new query_string
	wsgi_req->query_string = ptr;
	wsgi_req->query_string_len = query_string_len;

	free(path_info);
	if (tmp_qs) free(tmp_qs);
	if (ur->custom)
		return UWSGI_ROUTE_CONTINUE;
	return UWSGI_ROUTE_NEXT;

clear:
	free(path_info);
	if (tmp_qs) free(tmp_qs);
	return UWSGI_ROUTE_BREAK;
}

int uwsgi_router_rewrite(struct uwsgi_route *ur, char *args) {

        ur->func = uwsgi_routing_func_rewrite;
        ur->data = args;
        ur->data_len = strlen(args);
        return 0;
}


int uwsgi_router_rewrite_last(struct uwsgi_route *ur, char *args) {

        ur->func = uwsgi_routing_func_rewrite;
        ur->data = args;
        ur->data_len = strlen(args);
	ur->custom = 1;
        return 0;
}


void router_rewrite_register(void) {

	uwsgi_register_router("rewrite", uwsgi_router_rewrite);
	uwsgi_register_router("rewrite-last", uwsgi_router_rewrite_last);
}

struct uwsgi_plugin router_rewrite_plugin = {
	.name = "router_rewrite",
	.on_load = router_rewrite_register,
};
#else
struct uwsgi_plugin router_rewrite_plugin = {
	.name = "router_rewrite",
};
#endif
