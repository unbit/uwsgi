#ifdef UWSGI_ROUTING
#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_apply_routes(struct wsgi_request *wsgi_req) {

	struct uwsgi_route *routes = uwsgi.routes;

	if (!routes)
		return UWSGI_ROUTE_CONTINUE;

	if (uwsgi_parse_vars(wsgi_req)) {
		return UWSGI_ROUTE_BREAK;
	}

	while (routes) {
		char **subject = (char **) (((char *) (wsgi_req)) + routes->subject);
		uint16_t *subject_len = (uint16_t *) (((char *) (wsgi_req)) + routes->subject_len);
#ifdef UWSGI_DEBUG
		uwsgi_log("route subject = %.*s\n", *subject_len, *subject);
#endif
		int n = uwsgi_regexp_match_ovec(routes->pattern, routes->pattern_extra, *subject, *subject_len, routes->ovector, routes->ovn);
		if (n >= 0) {
			int ret = routes->func(wsgi_req, routes);
			if (ret == UWSGI_ROUTE_BREAK) uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].routed_requests++;
			if (ret != UWSGI_ROUTE_NEXT) {
				return ret;
			}
		}
		routes = routes->next;
	}

	return UWSGI_ROUTE_CONTINUE;
}

int uwsgi_apply_routes_fast(struct wsgi_request *wsgi_req, char *uri, int len) {

	struct uwsgi_route *routes = uwsgi.routes;

	if (!routes)
		return UWSGI_ROUTE_CONTINUE;

	while (routes) {
		int n = uwsgi_regexp_match_ovec(routes->pattern, routes->pattern_extra, uri, len, routes->ovector, routes->ovn);
		if (n >= 0) {
			int ret = routes->func(wsgi_req, routes);
			if (ret == UWSGI_ROUTE_BREAK) uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].routed_requests++;
			if (ret != UWSGI_ROUTE_NEXT) {
				return ret;
			}
		}

		routes = routes->next;
	}

	return UWSGI_ROUTE_CONTINUE;
}


void uwsgi_opt_add_route(char *opt, char *value, void *foobar) {

	char *route = uwsgi_str(value);

	char *space = strchr(route, ' ');
	if (!space) {
		uwsgi_log("invalid route syntax\n");
		exit(1);
	}

	*space = 0;

	struct uwsgi_route *ur = uwsgi.routes;
	if (!ur) {
		uwsgi.routes = uwsgi_calloc(sizeof(struct uwsgi_route));
		ur = uwsgi.routes;
	}
	else {
		while (ur) {
			if (!ur->next) {
				ur->next = uwsgi_calloc(sizeof(struct uwsgi_route));
				ur = ur->next;
				break;
			}
			ur = ur->next;
		}
	}

	if (!strcmp(foobar, "http_host")) {
		ur->subject = offsetof(struct wsgi_request, host);
		ur->subject_len = offsetof(struct wsgi_request, host_len);
	}
	else if (!strcmp(foobar, "request_uri")) {
		ur->subject = offsetof(struct wsgi_request, uri);
		ur->subject_len = offsetof(struct wsgi_request, uri_len);
	}
	else if (!strcmp(foobar, "query_string")) {
		ur->subject = offsetof(struct wsgi_request, query_string);
		ur->subject_len = offsetof(struct wsgi_request, query_string_len);
	}
	else {
		ur->subject = offsetof(struct wsgi_request, path_info);
		ur->subject_len = offsetof(struct wsgi_request, path_info_len);
	}

	if (uwsgi_regexp_build(route, &ur->pattern, &ur->pattern_extra)) {
		exit(1);
	}

	ur->ovn = uwsgi_regexp_ovector(ur->pattern, ur->pattern_extra);
	if (ur->ovn > 0) {
		ur->ovector = uwsgi_calloc(sizeof(int) * (3 * (ur->ovn + 1)));
	}

	char *command = space + 1;

	char *colon = strchr(command, ':');
	if (!colon) {
		uwsgi_log("invalid route syntax\n");
		exit(1);
	}

	*colon = 0;

	struct uwsgi_router *r = uwsgi.routers;
	while (r) {
		if (!strcmp(r->name, command)) {
			if (r->func(ur, colon + 1) == 0) {
				// apply is_last
				struct uwsgi_route *last_ur = ur;
				ur = uwsgi.routes;
				while (ur) {
					if (ur->func == last_ur->func) {
						ur->is_last = 0;
					}
					ur = ur->next;
				}
				last_ur->is_last = 1;
				return;
			}
		}
		r = r->next;
	}

	uwsgi_log("unable to register route \"%s\"\n", value);
	exit(1);
}

struct uwsgi_router *uwsgi_register_router(char *name, int (*func) (struct uwsgi_route *, char *)) {

	struct uwsgi_router *ur = uwsgi.routers;
	if (!ur) {
		uwsgi.routers = uwsgi_calloc(sizeof(struct uwsgi_router));
		uwsgi.routers->name = name;
		uwsgi.routers->func = func;
		return uwsgi.routers;
	}

	while (ur) {
		if (!ur->next) {
			ur->next = uwsgi_calloc(sizeof(struct uwsgi_router));
			ur->next->name = name;
			ur->next->func = func;
			return ur->next;
		}
		ur = ur->next;
	}

	return NULL;

}
#endif
