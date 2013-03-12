#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

/* uwsgi ADMIN|10 */
int uwsgi_request_admin(struct wsgi_request *wsgi_req) {

        uint32_t opt_value = 0;

	if (wsgi_req->uh->pktsize != 0 && wsgi_req->uh->pktsize != 4)
		return UWSGI_OK;

	// write request
	if (wsgi_req->uh->pktsize == 4) {
                memcpy(&opt_value, wsgi_req->buffer, 4);
        	uwsgi_log( "setting internal option %d to %d\n", wsgi_req->uh->modifier2, opt_value);
        	uwsgi.shared->options[wsgi_req->uh->modifier2] = opt_value;

        	// ACK
        	wsgi_req->uh->modifier1 = 255;
        	wsgi_req->uh->pktsize = 0;
        	wsgi_req->uh->modifier2 = 1;
		uwsgi_response_write_body_do(wsgi_req, (char *)wsgi_req->uh , 4);
	}
	// get request
	else {
		uwsgi_log( "internal option %d = %d\n", wsgi_req->uh->modifier2, uwsgi.shared->options[wsgi_req->uh->modifier2]);

		wsgi_req->uh->modifier1 = 10;
		wsgi_req->uh->pktsize = 4;
		uwsgi_response_write_body_do(wsgi_req, (char *)wsgi_req->uh , 4);
		uwsgi_response_write_body_do(wsgi_req, (char *) &uwsgi.shared->options[wsgi_req->uh->modifier2], 4);
	}

        return UWSGI_OK;
}


struct uwsgi_plugin admin_plugin = {

        .name = "admin",
        .modifier1 = 10,
        .request = uwsgi_request_admin,

};

