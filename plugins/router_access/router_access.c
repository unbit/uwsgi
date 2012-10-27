#include <sys/types.h>
#include <tcpd.h>
#include <syslog.h>
#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;

int uwsgi_routing_func_access(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){
	int pass = 0;
	char *access_data = malloc(0xff);
	char *access_action = malloc(0xff);
	char *access_param = malloc(0xff);
	char *access_addr = malloc(0xff);

	bzero(access_data, 0xff);
	bzero(access_action, 0xff);
	bzero(access_param, 0xff);
	bzero(access_addr, 0xff);

	if (uwsgi_parse_vars(wsgi_req)) {
		return UWSGI_ROUTE_BREAK;
	}

#ifdef UWSGI_DEBUG
    uwsgi_log("Access: Parsing router: %s\n", ur->data);
#endif

    strncpy(access_data, ur->data, 0xff);

	if (strchr(access_data, '=')){
	    // parse router config: action=param
		access_action = strtok(access_data, "=");
		access_param = strtok(NULL, "");

		if (!access_param){
    	    // config syntax error if no access_param
    	    uwsgi_log("Access: syntax error - no paramater specified after action\n");
    	    return UWSGI_ROUTE_BREAK;
        }

	} else {
	    // set default access_action, access_param if no colon found
		access_action = "hosts";
		access_param = "uwsgi";
	}

#ifdef UWSGI_DEBUG
        uwsgi_log("Access: access_action = %s, access_param = %s\n", access_action, access_param);
#endif
	
	if (!strncmp(access_action, "hosts", 4)){
		// syntax access:hosts=svcname to use hosts.allow, hosts.deny with svcname as daemon name
		access_addr = uwsgi_concat2n(wsgi_req->remote_addr, wsgi_req->remote_addr_len, "", 0);
		pass = hosts_ctl(access_param, STRING_UNKNOWN, access_addr, STRING_UNKNOWN);
	} else if (!strncmp(access_action, "allow", 4)){
		// implement hosts allow check on syntax access:allow=addr
	} else if (!strncmp(access_action, "deny", 3)){
		// implement hosts deny check on syntax access:deny=addr
	}
	
	free(access_data);

	if (pass == 1){

#ifdef UWSGI_DEBUG
		uwsgi_log("Access: allowing access from %s\n", access_addr);
#endif
        free(access_addr);
		return UWSGI_ROUTE_NEXT;
	} else if (pass == 0){
#ifdef UWSGI_DEBUG
		uwsgi_log("Access: denying access from %s\n", access_addr);
#endif
		wsgi_req->status = 403;
		wsgi_req->headers_size += wsgi_req->socket->proto_write_header(wsgi_req, "HTTP/1.0 403 Forbidden\r\nContent-Type: text/html\r\n\r\n", 51);
		wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req,"<h1>403 Forbidden</h1>", 23);

		free(access_addr);
		return UWSGI_ROUTE_BREAK;
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("Access: Something went wrong: %d\n", pass);
#endif

    free(access_addr);
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
