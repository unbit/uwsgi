#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;


int uwsgi_rpc_request(struct wsgi_request *wsgi_req) {

	// this is the list of args
	char *argv[256];
	// this is the size of each argument
	uint16_t argvs[256];
	// maximum number of supported arguments
	uint8_t argc = 0xff;

	/* Standard RPC request */
        if (!wsgi_req->uh->pktsize) {
                uwsgi_log("Empty RPC request. skip.\n");
                return -1;
        }

	/*
	for(argc=0;argc<wsgi_req->uh.pktsize;argc++) {
		uwsgi_log("rpc: %c\n", wsgi_req->buffer[argc]);
	}
	*/

#ifdef UWSGI_DEBUG
	uwsgi_log("RPC pktsize %d\n", wsgi_req->uh->pktsize);
#endif

	if (uwsgi_parse_array(wsgi_req->buffer, wsgi_req->uh->pktsize, argv, argvs, &argc)) {
                uwsgi_log("Invalid RPC request. skip.\n");
                return -1;
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("RPC args %d\n", argc-1);
#endif
	
	// call the function (output will be in wsgi_req->buffer)
	wsgi_req->uh->pktsize = uwsgi_rpc(argv[0], argc-1, argv+1, argvs+1, wsgi_req->buffer);

	// using modifier1 we may want a raw output
	if (wsgi_req->uh->modifier2 == 0) {
		if (uwsgi_response_write_body_do(wsgi_req, (char *) wsgi_req->uh, 4)) {
			return -1;
		}
	}
	// write the response
	uwsgi_response_write_body_do(wsgi_req, wsgi_req->buffer, wsgi_req->uh->pktsize);
	
	return 0;
}

struct uwsgi_plugin rpc_plugin = {

	.name = "rpc",
	.modifier1 = 173,
	
	.request = uwsgi_rpc_request,
};
