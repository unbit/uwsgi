#include "../../uwsgi.h"

#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

int uwsgi_routing_func_http(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	// mark a route request
        wsgi_req->status = -17;

	// get the http address from the route
	char *addr = ur->data;

	char *uri = NULL;
	uint16_t uri_len = 0;
	if (ur->data3_len) {
		uri = uwsgi_regexp_apply_ovec(wsgi_req->uri, wsgi_req->uri_len, ur->data3, ur->data3_len, ur->ovector, ur->ovn);
		uri_len = strlen(uri);
	}


	// convert the wsgi_request to an http proxy request
	struct uwsgi_buffer *ub = uwsgi_to_http(wsgi_req, ur->data2, ur->data2_len, uri, uri_len);	
	if (!ub) {
		if (uri) free(uri);
		uwsgi_log("unable to generate http request for %s\n", addr);
                return UWSGI_ROUTE_NEXT;
	}

	if (uri) free(uri);

	// ok now if have offload threads, directly use them
	if (wsgi_req->socket->can_offload) {
        	if (!uwsgi_offload_request_net_do(wsgi_req, addr, ub)) {
                	wsgi_req->status = -30;
			return UWSGI_ROUTE_BREAK;
                }
	}

	// connect to the http server
	int http_fd = uwsgi_connect(addr, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], 0);
	if (http_fd < 0) {
		uwsgi_log("unable to connect to host %s\n", addr);
		return UWSGI_ROUTE_NEXT;
	}

	// send the request
	if (uwsgi_buffer_send(ub, http_fd)) {
		uwsgi_log("error routing request to http server %s\n", addr);
		close(http_fd);
		uwsgi_buffer_destroy(ub);
                return UWSGI_ROUTE_NEXT;
	}

	ssize_t ret;

	// pipe the body
	if (wsgi_req->post_cl > 0) {
		int post_fd = wsgi_req->poll.fd;
		if (wsgi_req->async_post) {
			post_fd = fileno((FILE *)wsgi_req->async_post);
		}
		ret = uwsgi_pipe_sized(post_fd, http_fd, wsgi_req->post_cl, 0);
		if (ret < 0) {
			uwsgi_log("error routing request body (%llu bytes) to http server %s\n", (unsigned long long) wsgi_req->post_cl, addr);
			close(http_fd);
                	uwsgi_buffer_destroy(ub);
			return UWSGI_ROUTE_BREAK;
		}
	}

	// pipe the response
	ret = uwsgi_pipe(http_fd, wsgi_req->poll.fd, 0);
	if (ret > 0) {
		wsgi_req->response_size += ret;
	}
	else {
		uwsgi_log("error routing request to http server %s\n", addr);
	}

	close(http_fd);
	uwsgi_buffer_destroy(ub);

	return UWSGI_ROUTE_BREAK;

}

int uwsgi_router_http(struct uwsgi_route *ur, char *args) {

	ur->func = uwsgi_routing_func_http;
	ur->data = (void *) args;
	ur->data_len = strlen(args);
	
	char *comma = strchr(ur->data, ',');
	if (comma) {
		*comma = 0;
		ur->data_len = strlen(ur->data);
		ur->data2 = comma+1;
		comma = strchr(ur->data2, ',');
		if (comma) {
			*comma = 0;
			ur->data3 = comma+1;
			ur->data3_len = strlen(ur->data3);
		}
		ur->data2_len = strlen(ur->data2);
	}
	return 0;
}


void router_http_register(void) {

	uwsgi_register_router("http", uwsgi_router_http);
}

struct uwsgi_plugin router_http_plugin = {
	.name = "router_http",
	.on_load = router_http_register,
};
#else
struct uwsgi_plugin router_http_plugin = {
	.name = "router_http",
};
#endif
