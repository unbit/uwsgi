#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;


int uwsgi_rpc_request(struct wsgi_request *wsgi_req) {

	char *argv[0xff];
	uint8_t argc;
	int i;

	/* Standard RPC request */
        if (!wsgi_req->uh.pktsize) {
                uwsgi_log("Invalid RPC request. skip.\n");
                return -1;
        }

	uwsgi_log("parsing array\n");
	if (uwsgi_parse_array(wsgi_req->buffer, wsgi_req->uh.pktsize, argv, &argc)) {
                uwsgi_log("Invalid RPC request. skip.\n");
                return -1;
	}
	uwsgi_log("done\n");
	
	for(i=0;i<argc;i++) {
		uwsgi_log("arg %d %s\n", i, argv[i]);
	}

	wsgi_req->uh.pktsize = uwsgi_rpc(argv[0], argc-1, argv+1, wsgi_req->buffer);

	if (wsgi_req->uh.modifier2 == 0) {
		wsgi_req->headers_size = wsgi_req->socket->proto_write_header(wsgi_req, (char *)&wsgi_req->uh, 4);
	}

	wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, wsgi_req->buffer, wsgi_req->uh.pktsize);
	wsgi_req->status = 0;
	
	return 0;
}

struct uwsgi_plugin rpc_plugin = {

	.name = "rpc",
	.modifier1 = 173,
	
	.request = uwsgi_rpc_request,
};
