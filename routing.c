#ifdef UWSGI_ROUTING
#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_apply_routes(struct wsgi_request *wsgi_req) {

	struct uwsgi_route *routes = uwsgi.routes;

	if (!routes) return 0;

	if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }

	while(routes) {
		int n = uwsgi_regexp_match_ovec(routes->pattern, routes->pattern_extra, wsgi_req->path_info, wsgi_req->path_info_len, routes->ovector, routes->ovn);
		if (n>= 0) {
			return routes->func(wsgi_req, routes);
		}
		
		routes = routes->next;
	}

	return 0;
}

int uwsgi_apply_routes_fast(struct wsgi_request *wsgi_req, char *uri, int len) {

        struct uwsgi_route *routes = uwsgi.routes;

        if (!routes) return 0;

        while(routes) {
                int n = uwsgi_regexp_match_ovec(routes->pattern, routes->pattern_extra, uri, len, routes->ovector, routes->ovn);
                if (n>= 0) {
                        return routes->func(wsgi_req, routes);
                }

                routes = routes->next;
        }

        return 0;
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
		while(ur) {
			if (!ur->next) {
				ur->next = uwsgi_calloc(sizeof(struct uwsgi_route));	
				ur = ur->next;
				break;
			}
			ur = ur->next;
		}
	}

	if (uwsgi_regexp_build(route, &ur->pattern, &ur->pattern_extra)) {
		exit(1);
	}

	ur->ovn = uwsgi_regexp_ovector(ur->pattern, ur->pattern_extra);
	if (ur->ovn > 0) {
		ur->ovector = uwsgi_calloc(sizeof(int) * (3 * (ur->ovn + 1)) );
	}

	char *command = space+1;

	char *colon = strchr(command, ':');
	if (!colon) {
		uwsgi_log("invalid route syntax\n");
		exit(1);
	}

	*colon = 0;

	struct uwsgi_router *r = uwsgi.routers;
	while(r) {
		if (!strcmp(r->name, command)) {
			if (r->func(ur, colon+1) == 0) {
				return;
			}
		}
		r = r->next;
	}

	uwsgi_log("unable to register route \"%s\"\n", value);
	exit(1);
}

struct uwsgi_router *uwsgi_register_router(char *name, int (*func)(struct uwsgi_route *, char *)) {

	struct uwsgi_router *ur = uwsgi.routers;
	if (!ur) {
		uwsgi.routers = uwsgi_calloc(sizeof(struct uwsgi_router));
		uwsgi.routers->name = name;
		uwsgi.routers->func = func;
		return uwsgi.routers;
	}

	while(ur) {
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
