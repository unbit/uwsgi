#include <uwsgi.h>

extern struct uwsgi_server uwsgi;


static int uwsgi_rpc_request(struct wsgi_request *wsgi_req) {

	// this is the list of args
	char *argv[UMAX8];
	// this is the size of each argument
	uint16_t argvs[UMAX8];
	// maximum number of supported arguments
	uint8_t argc = 0xff;
	// response output
	char response_buf[UMAX16];

	/* Standard RPC request */
        if (!wsgi_req->uh->pktsize) {
                uwsgi_log("Empty RPC request. skip.\n");
                return -1;
        }

	if (uwsgi_parse_array(wsgi_req->buffer, wsgi_req->uh->pktsize, argv, argvs, &argc)) {
                uwsgi_log("Invalid RPC request. skip.\n");
                return -1;
	}

	// call the function (output will be in wsgi_req->buffer)
	wsgi_req->uh->pktsize = uwsgi_rpc(argv[0], argc-1, argv+1, argvs+1, response_buf);

	// using modifier2 we may want a raw output
	if (wsgi_req->uh->modifier2 == 0) {
		if (uwsgi_response_write_body_do(wsgi_req, (char *) wsgi_req->uh, 4)) {
			return -1;
		}
	}
	// write the response
	uwsgi_response_write_body_do(wsgi_req, response_buf, wsgi_req->uh->pktsize);
	
	return UWSGI_OK;
}

struct uwsgi_plugin rpc_plugin = {

	.name = "rpc",
	.modifier1 = 173,
	
	.request = uwsgi_rpc_request,
};
