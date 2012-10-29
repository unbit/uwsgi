#include "../../uwsgi.h"
#include <tcpd.h>

/*

	by Colin Ligertwood

	syntax:

	route = /^foobar access:action=hosts,daemon=uwsgi
	route = /^foobar access:action=allow,daemon=uwsgi,addr=127.0.0.1
	route = /^foobar access:action=deny,daemon=uwsgi2,addr=192.168.*
	route = /^foobar access:action=deny,daemon=uwsgi3,addr=192.168.0.0/24

	TODO only the 'hosts' action is supported

*/

struct uwsgi_router_access_conf {
	char *action;
	char *daemon;
	char *addr;
};

static int uwsgi_routing_func_access(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){

	int pass = 0;
	struct uwsgi_router_access_conf *urac = (struct uwsgi_router_access_conf *) ur->data2;

	if (!urac) {
		urac = uwsgi_calloc(sizeof(struct uwsgi_router_access_conf));
		if (uwsgi_kvlist_parse(ur->data, ur->data_len, ',', '=',
			"action", &urac->action,
			"daemon", &urac->daemon,
			"addr", &urac->addr, NULL)) {
			free(urac);
			goto forbidden;		
		}
		if (!urac->action) urac->action = "hosts";
		if (!urac->daemon) urac->action = "uwsgi";
		ur->data2 = urac;
	}

	char *addr = uwsgi_concat2n(wsgi_req->remote_addr, wsgi_req->remote_addr_len, "", 0);

	if (!strcmp(urac->action, "hosts")){
		pass = hosts_ctl(urac->daemon, STRING_UNKNOWN, addr, STRING_UNKNOWN);
	}
	else if (!strcmp(urac->action, "allow") && urac->addr){
		// unimplemented
	}
	else if (!strcmp(urac->action, "deny") && urac->addr){
		// unimplemented
	}

	free(addr);
	
	if (pass) return UWSGI_ROUTE_NEXT;

forbidden:

	wsgi_req->status = 403;
	wsgi_req->headers_size += wsgi_req->socket->proto_write_header(wsgi_req, "HTTP/1.0 403 Forbidden\r\nContent-Type: text/html\r\n\r\n", 51);
	wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req,"<h1>403 Forbidden</h1>", 23);
	return UWSGI_ROUTE_BREAK;
}

static int uwsgi_router_access(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_access;
        ur->data = args;
        ur->data_len = strlen(args);
	return 0;
}

static void router_access_register() {
	uwsgi_register_router("access", uwsgi_router_access);
}

struct uwsgi_plugin router_access_plugin = {
	.name = "router_access",
	.on_load = router_access_register,
};
