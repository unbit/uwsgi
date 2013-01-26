#ifdef UWSGI_ROUTING
#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

static int uwsgi_apply_routes_do(struct wsgi_request *wsgi_req) {

	struct uwsgi_route *routes = uwsgi.routes;
        void *goon_func = NULL;

	while (routes) {

		if (wsgi_req->route_goto > 0 && wsgi_req->route_pc < wsgi_req->route_goto) {
			goto next;
		}
		if (goon_func && goon_func == routes->func) {
			goto next;
		}
		goon_func = NULL;
		wsgi_req->route_goto = 0;

		char **subject = (char **) (((char *) (wsgi_req)) + routes->subject);
		uint16_t *subject_len = (uint16_t *) (((char *) (wsgi_req)) + routes->subject_len);
#ifdef UWSGI_DEBUG
		uwsgi_log("route subject = %.*s\n", *subject_len, *subject);
#endif
		int n = uwsgi_regexp_match_ovec(routes->pattern, routes->pattern_extra, *subject, *subject_len, routes->ovector, routes->ovn);
		if (n >= 0) {
			wsgi_req->is_routing = 1;
			int ret = routes->func(wsgi_req, routes);
			wsgi_req->is_routing = 0;
			if (ret == UWSGI_ROUTE_BREAK) {
				uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].routed_requests++;
				return ret;
			}
			if (ret == UWSGI_ROUTE_CONTINUE) {
				return ret;
			}
			
			if (ret == UWSGI_ROUTE_GOON) {
				goon_func = routes->func;
			}
		}
next:
		routes = routes->next;
		if (routes) wsgi_req->route_pc++;
	}

	return UWSGI_ROUTE_CONTINUE;
}

int uwsgi_apply_routes(struct wsgi_request *wsgi_req) {

	if (!uwsgi.routes)
		return UWSGI_ROUTE_CONTINUE;

	// avoid loops
	if (wsgi_req->is_routing)
		return UWSGI_ROUTE_CONTINUE;

	if (uwsgi_parse_vars(wsgi_req)) {
		return UWSGI_ROUTE_BREAK;
	}

	return uwsgi_apply_routes_do(wsgi_req);
}


int uwsgi_apply_routes_fast(struct wsgi_request *wsgi_req) {

	if (!uwsgi.routes)
		return UWSGI_ROUTE_CONTINUE;

	// avoid loops
	if (wsgi_req->is_routing)
		return UWSGI_ROUTE_CONTINUE;

	return uwsgi_apply_routes_do(wsgi_req);
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
	else if (!strcmp(foobar, "remote_addr")) {
		ur->subject = offsetof(struct wsgi_request, remote_addr);
		ur->subject_len = offsetof(struct wsgi_request, remote_addr_len);
	}
	else if (!strcmp(foobar, "user_agent")) {
		ur->subject = offsetof(struct wsgi_request, user_agent);
		ur->subject_len = offsetof(struct wsgi_request, user_agent_len);
	}
	else if (!strcmp(foobar, "remote_user")) {
		ur->subject = offsetof(struct wsgi_request, remote_user);
		ur->subject_len = offsetof(struct wsgi_request, remote_user_len);
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

// continue/last route

static int uwsgi_router_continue_func(struct wsgi_request *wsgi_req, struct uwsgi_route *route) {
	return UWSGI_ROUTE_CONTINUE;	
}

static int uwsgi_router_continue(struct uwsgi_route *ur, char *arg) {
	ur->func = uwsgi_router_continue_func;
	return 0;
}

// break route

static int uwsgi_router_break_func(struct wsgi_request *wsgi_req, struct uwsgi_route *route) {
	if (route->data_len >= 3) {
		if (uwsgi_response_prepare_headers(wsgi_req, route->data, route->data_len)) goto end;
		if (uwsgi_response_add_connection_close(wsgi_req)) goto end;
		if (uwsgi_response_add_content_type(wsgi_req, "text/plain", 10)) goto end;
		// no need to check for return value
		uwsgi_response_write_headers_do(wsgi_req);
	}
end:
	return UWSGI_ROUTE_BREAK;	
}

static int uwsgi_router_break(struct uwsgi_route *ur, char *arg) {
	ur->func = uwsgi_router_break_func;
	ur->data = arg;
        ur->data_len = strlen(arg);
	return 0;
}

// goon route
static int uwsgi_router_goon_func(struct wsgi_request *wsgi_req, struct uwsgi_route *route) {
	return UWSGI_ROUTE_GOON;	
}
static int uwsgi_router_goon(struct uwsgi_route *ur, char *arg) {
	ur->func = uwsgi_router_goon_func;
	return 0;
}

// log route
static int uwsgi_router_log_func(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

        char *logline = uwsgi_regexp_apply_ovec(*subject, *subject_len, ur->data, ur->data_len, ur->ovector, ur->ovn);
	uwsgi_log("%s\n", logline);
	free(logline);

	return UWSGI_ROUTE_NEXT;	
}

static int uwsgi_router_log(struct uwsgi_route *ur, char *arg) {
	ur->func = uwsgi_router_log_func;
	ur->data = arg;
	ur->data_len = strlen(arg);
	return 0;
}

// logvar route
static int uwsgi_router_logvar_func(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

        char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

        char *logline = uwsgi_regexp_apply_ovec(*subject, *subject_len, ur->data2, ur->data2_len, ur->ovector, ur->ovn);
	uwsgi_logvar_add(wsgi_req, ur->data, ur->data_len, logline, strlen(logline));
        free(logline);

        return UWSGI_ROUTE_NEXT;
}

static int uwsgi_router_logvar(struct uwsgi_route *ur, char *arg) {
        ur->func = uwsgi_router_logvar_func;
	char *equal = strchr(arg, '=');
	if (!equal) {
		uwsgi_log("invalid logvar syntax, must be key=value\n");
		exit(1);
	}
        ur->data = arg;
        ur->data_len = equal-arg;
	ur->data2 = equal+1;
	ur->data2_len = strlen(ur->data2);
        return 0;
}


// goto route 

static int uwsgi_router_goto_func(struct wsgi_request *wsgi_req, struct uwsgi_route *route) {
	if (route->custom <= wsgi_req->route_pc) {
		uwsgi_log("[uwsgi-route] ERROR \"goto\" instruction can only jump forward\n");
		return UWSGI_ROUTE_BREAK;
	}
	wsgi_req->route_goto = route->custom;
	return UWSGI_ROUTE_NEXT;	
}

static int uwsgi_router_goto(struct uwsgi_route *ur, char *arg) {
	ur->func = uwsgi_router_goto_func;
	ur->custom = atoi(arg);
        return 0;
}

// addvar route
static int uwsgi_router_addvar_func(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

        char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

        char *value = uwsgi_regexp_apply_ovec(*subject, *subject_len, ur->data2, ur->data2_len, ur->ovector, ur->ovn);
        uint16_t value_len = strlen(value);

	if (!uwsgi_req_append(wsgi_req, ur->data, ur->data_len, value, value_len)) {
		free(value);
        	return UWSGI_ROUTE_BREAK;
	}
	free(value);
        return UWSGI_ROUTE_NEXT;
}


static int uwsgi_router_addvar(struct uwsgi_route *ur, char *arg) {
        ur->func = uwsgi_router_addvar_func;
	char *equal = strchr(arg, '=');
	if (!equal) {
		uwsgi_log("[uwsgi-route] invalid addvar syntax, must be KEY=VAL\n");
		exit(1);
	}
	ur->data = arg;
	ur->data_len = equal-arg;
	ur->data2 = equal+1;
	ur->data2_len = strlen(ur->data2);
        return 0;
}


// addheader route
static int uwsgi_router_addheader_func(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

        char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

        char *value = uwsgi_regexp_apply_ovec(*subject, *subject_len, ur->data, ur->data_len, ur->ovector, ur->ovn);
        uint16_t value_len = strlen(value);
	uwsgi_additional_header_add(wsgi_req, value, value_len);
        free(value);
        return UWSGI_ROUTE_NEXT;
}


static int uwsgi_router_addheader(struct uwsgi_route *ur, char *arg) {
        ur->func = uwsgi_router_addheader_func;
        ur->data = arg;
        ur->data_len = strlen(arg);
        return 0;
}

// remheader route
static int uwsgi_router_remheader_func(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

        char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

        char *value = uwsgi_regexp_apply_ovec(*subject, *subject_len, ur->data, ur->data_len, ur->ovector, ur->ovn);
        uint16_t value_len = strlen(value);
        uwsgi_remove_header(wsgi_req, value, value_len);
        free(value);
        return UWSGI_ROUTE_NEXT;
}


static int uwsgi_router_remheader(struct uwsgi_route *ur, char *arg) {
        ur->func = uwsgi_router_remheader_func;
        ur->data = arg;
        ur->data_len = strlen(arg);
        return 0;
}



// signal route
static int uwsgi_router_signal_func(struct wsgi_request *wsgi_req, struct uwsgi_route *route) {
	uwsgi_signal_send(uwsgi.signal_socket, route->custom);	
        return UWSGI_ROUTE_NEXT;
}
static int uwsgi_router_signal(struct uwsgi_route *ur, char *arg) {
        ur->func = uwsgi_router_signal_func;
	ur->custom = atoi(arg);
        return 0;
}


// send route
static int uwsgi_router_send_func(struct wsgi_request *wsgi_req, struct uwsgi_route *route) {
	uwsgi_response_write_body_do(wsgi_req, route->data, route->data_len);
	if (route->custom) {
		uwsgi_response_write_body_do(wsgi_req, "\r\n", 2);
	}
        return UWSGI_ROUTE_NEXT;
}
static int uwsgi_router_send(struct uwsgi_route *ur, char *arg) {
        ur->func = uwsgi_router_send_func;
	ur->data = arg;
	ur->data_len = strlen(arg);
        return 0;
}
static int uwsgi_router_send_crnl(struct uwsgi_route *ur, char *arg) {
	uwsgi_router_send(ur, arg);
        ur->custom = 1;
        return 0;
}


// register embedded routers
void uwsgi_register_embedded_routers() {
	uwsgi_register_router("continue", uwsgi_router_continue);
        uwsgi_register_router("last", uwsgi_router_continue);
        uwsgi_register_router("break", uwsgi_router_break);
        uwsgi_register_router("goon", uwsgi_router_goon);
        uwsgi_register_router("log", uwsgi_router_log);
        uwsgi_register_router("logvar", uwsgi_router_logvar);
        uwsgi_register_router("goto", uwsgi_router_goto);
        uwsgi_register_router("addvar", uwsgi_router_addvar);
        uwsgi_register_router("addheader", uwsgi_router_addheader);
        uwsgi_register_router("delheader", uwsgi_router_remheader);
        uwsgi_register_router("remheader", uwsgi_router_remheader);
        uwsgi_register_router("signal", uwsgi_router_signal);
        uwsgi_register_router("send", uwsgi_router_send);
        uwsgi_register_router("send-crnl", uwsgi_router_send_crnl);
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
