#include <sys/types.h>
#include <tcpd.h>
#include <syslog.h>
#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;

int uwsgi_routing_func_access(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){
	int pass = 0;
	char *action;
	char *host;

	if (strchr((char *)ur->data, ',')){
		action = strtok((char *)ur->data, ",");
		host = strtok(NULL, "");
	}

	else {
		action = "access:hosts";
	}

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}

	if (!strcmp(action, "access:hosts")){
		// syntax access:hosts to use hosts.allow, hosts.deny
		char *host = uwsgi_concat2n(wsgi_req->host, wsgi_req->host_len, "", 0);
		char *remote_addr = uwsgi_concat2n(wsgi_req->remote_addr, wsgi_req->remote_addr_len, "", 0);

		pass = hosts_ctl("uwsgi", wsgi_req->host, wsgi_req->remote_addr, STRING_UNKNOWN);

		free(host);
		free(remote_addr);
	}
	
	else if (!strcmp(action, "access:allow")){
		// implement hosts allow check on syntax access:allow,addr
	}

	else if (!strcmp(host, "access:deny")){
		// implement hosts deny check on syntax access:deny,addr
	}

	if (pass){
#ifdef UWSGI_DEBUG
		uwsgi_log("Access: allowing access from %s\n", wsgi_req->remote_addr);
#endif
		return UWSGI_ROUTE_NEXT;
	}
	else {
#ifdef UWSGI_DEBUG
		uwsgi_log("Access: denying access from %s\n", wsgi_req->remote_addr);
#endif
		wsgi_req->status = 403;
		wsgi_req->headers_size += wsgi_req->socket->proto_write_header(wsgi_req, "HTTP/1.0 403 Forbidden\r\nContent-Type: text/html\r\n\r\n", 51);
		wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req,"<h1>403 Forbidden</h1>", 23);
		return UWSGI_ROUTE_BREAK;
	}
	return UWSGI_ROUTE_BREAK;
}

int uwsgi_router_access(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_access;
        ur->data = args;
        ur->data_len = strlen(args);
	return 0;
}

void router_access_register() {
	uwsgi_register_router("access", uwsgi_router_access);
}

struct uwsgi_plugin router_access_plugin = {
	.name = "router_access",
	.on_load = router_access_register,
};

