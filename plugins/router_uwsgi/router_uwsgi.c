#include "../../uwsgi.h"
#ifdef UWSGI_ROUTING

extern struct uwsgi_server uwsgi;

int uwsgi_routing_func_uwsgi_simple(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	struct uwsgi_header *uh = (struct uwsgi_header *) ur->data;

	wsgi_req->uh.modifier1 = uh->modifier1;
	wsgi_req->uh.modifier2 = uh->modifier2;

	// set appid
	if (ur->data2_len > 0) {
		wsgi_req->appid = ur->data2;
		wsgi_req->appid_len = ur->data2_len;
		char *ptr = uwsgi_req_append(wsgi_req, "UWSGI_APPID", 11, ur->data2, ur->data2_len);
		if (ptr) {
			// fill iovec
			if (wsgi_req->var_cnt + 2 < uwsgi.vec_size - (4 + 1)) {
				wsgi_req->hvec[wsgi_req->var_cnt].iov_base = ptr - (2 + 11);
                        	wsgi_req->hvec[wsgi_req->var_cnt].iov_len = 11;	
                		wsgi_req->var_cnt++;
				wsgi_req->hvec[wsgi_req->var_cnt].iov_base = ptr;
                        	wsgi_req->hvec[wsgi_req->var_cnt].iov_len = ur->data2_len;	
                		wsgi_req->var_cnt++;
                	}
		}
	}

	return UWSGI_ROUTE_CONTINUE;
}

int uwsgi_routing_func_uwsgi_remote(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	struct uwsgi_header *uh = (struct uwsgi_header *) ur->data;
	char *addr = ur->data + sizeof(struct uwsgi_header);
	
	// mark a route request
        wsgi_req->status = -17;

	// append appid
	if (ur->data2_len > 0) {
		uwsgi_req_append(wsgi_req, "UWSGI_APPID", 11, ur->data2, ur->data2_len);
	}

	// ok now if have offload threads, directly use them
        if (wsgi_req->socket->can_offload) {
		struct uwsgi_buffer *ub = uwsgi_buffer_new(4 + wsgi_req->uh.pktsize);
		if (ub) {
			uh->pktsize = wsgi_req->uh.pktsize;
			if (uwsgi_buffer_append(ub, (char *) uh, 4)) goto bad;
			if (uwsgi_buffer_append(ub, wsgi_req->buffer, uh->pktsize)) goto bad;
                	if (!uwsgi_offload_request_net_do(wsgi_req, addr, ub)) {
                        	wsgi_req->status = -30;
                        	return UWSGI_ROUTE_BREAK;
                	}
bad:
			uwsgi_buffer_destroy(ub);
		}
        }


	int uwsgi_fd = uwsgi_connect(addr, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], 0);
	if (uwsgi_fd < 0) {
		uwsgi_log("unable to connect to host %s\n", addr);
		return UWSGI_ROUTE_NEXT;
	}

	int post_fd = wsgi_req->poll.fd;
	if (wsgi_req->async_post) {
		post_fd = fileno((FILE*)wsgi_req->async_post);
	}

	if (uwsgi_send_message(uwsgi_fd, uh->modifier1, uh->modifier2, wsgi_req->buffer, wsgi_req->uh.pktsize, post_fd, wsgi_req->post_cl, 0) < 0) {
		uwsgi_log("unable to send uwsgi request to host %s", addr);
		return UWSGI_ROUTE_NEXT;
	}

	ssize_t ret = uwsgi_pipe(uwsgi_fd, wsgi_req->poll.fd, 0);
	if (ret > 0) {
		wsgi_req->response_size += ret;
	}
	else {
		uwsgi_log("unable to manage uwsgi route response for %s\n", addr);
	}

	close(uwsgi_fd);
	return UWSGI_ROUTE_BREAK;

}

int uwsgi_router_uwsgi(struct uwsgi_route *ur, char *args) {

	// check for commas
	char *comma1 = strchr(args, ',');
	if (!comma1) {
		uwsgi_log("invalid route syntax: %s\n", args);
		exit(1);
	}

	char *comma2 = strchr(comma1+1, ',');
	if (!comma2) {
		uwsgi_log("invalid route syntax: %s\n", args);
		exit(1);
	}

	char *comma3 = strchr(comma2+1, ',');
	if (comma3) {
		*comma3 = 0;
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

		if (comma3) {
			ur->data2 = comma3+1;
			ur->data2_len = strlen(ur->data2);
		}
		return 0;
	}
	else {
		struct uwsgi_header *uh = uwsgi_calloc(sizeof(struct uwsgi_header) + strlen(args) + 1);
		ur->func = uwsgi_routing_func_uwsgi_remote;
		ur->data = (void *) uh;

		uh->modifier1 = atoi(comma1+1);
		uh->modifier2 = atoi(comma2+1);

		if (comma3) {
			ur->data2 = comma3+1;
			ur->data2_len = strlen(ur->data2);
		}

		void *ptr = (void *) uh;
		strcpy(ptr+sizeof(struct uwsgi_header), args);
		return 0;

	}

	return -1;
}


void router_uwsgi_register(void) {

	uwsgi_register_router("uwsgi", uwsgi_router_uwsgi);
}

struct uwsgi_plugin router_uwsgi_plugin = {
	.name = "router_uwsgi",
	.on_load = router_uwsgi_register,
};
#else
struct uwsgi_plugin router_uwsgi_plugin = {
	.name = "router_uwsgi",
};
#endif
