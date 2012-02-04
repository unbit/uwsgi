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

		if (uwsgi_regexp_match(routes->pattern, routes->pattern_extra, wsgi_req->path_info, wsgi_req->path_info_len) >= 0) {

			uwsgi_log("regexp match for %.*s\n", wsgi_req->path_info_len, wsgi_req->path_info);
			return routes->func(wsgi_req, routes->data);
		}
		
		routes = routes->next;
	}

	return 0;
}

int uwsgi_routing_func_uwsgi_simple(struct wsgi_request *wsgi_req, void *data) {

	struct uwsgi_header *uh = (struct uwsgi_header *) data;

	wsgi_req->uh.modifier1 = uh->modifier1;
	wsgi_req->uh.modifier2 = uh->modifier2;

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

	char *command = space+1;

	char *colon = strchr(command, ':');
	if (!colon) {
		uwsgi_log("invalid route syntax\n");
		exit(1);
	}

	*colon = 0;

	if (!strcmp(command, "uwsgi")) {
		char *args = colon+1;
		// check for commas
		char *comma1 = strchr(args, ',');
		if (!comma1) {
			uwsgi_log("invalid route syntax\n");
			exit(1);
		}

		char *comma2 = strchr(comma1+1, ',');
		if (!comma2) {
			uwsgi_log("invalid route syntax\n");
			exit(1);
		}

		*comma1 = 0;
		*comma2 = 0;
		// simple modifier remapper
		if (*args == 0) {
			struct uwsgi_header *uh = uwsgi_calloc(sizeof(struct uwsgi_header));
			ur->func = uwsgi_routing_func_uwsgi_simple;
			ur->data = (void *) uh;

			uh->modifier1 = atoi(comma1+1);
			uh->modifier2 = atoi(comma2+1);
		}
	}
}
#endif
