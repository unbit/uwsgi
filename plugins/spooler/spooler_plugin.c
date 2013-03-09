#include "../../uwsgi.h"

/*

this plugin, allows remote spooling of jobs

*/

extern struct uwsgi_server uwsgi;

int uwsgi_request_spooler(struct wsgi_request *wsgi_req) {

        int i;
        char spool_filename[1024];
	struct uwsgi_header uh;

        // get the spooler from the modifier2

        struct uwsgi_spooler *uspool = uwsgi.spoolers;

        if (uspool == NULL) {
                uwsgi_log("the spooler is inactive !!!...skip\n");
		uh.modifier1 = 255;
		uh.pktsize = 0;
		uh.modifier2 = 0;
		uwsgi_response_write_body_do(wsgi_req, (char *) &uh, 4);
                return -1;
        }

        i = spool_request(uspool, spool_filename, uwsgi.workers[0].requests + 1, wsgi_req->async_id, wsgi_req->buffer, wsgi_req->uh->pktsize, NULL, 0, NULL, 0);
        uh.modifier1 = 255;
        uh.pktsize = 0;
        if (i > 0) {
                uh.modifier2 = 1;
		if (uwsgi_response_write_body_do(wsgi_req, (char *) &uh, 4)) {
                        uwsgi_log("disconnected client, remove spool file.\n");
                        /* client disconnect, remove spool file */
                        if (unlink(spool_filename)) {
                                uwsgi_error("unlink()");
                                uwsgi_log("something horrible happened !!! check your spooler ASAP !!!\n");
                                exit(1);
                        }
                }
                return 0;
        }
        else {
                /* announce a failed spool request */
                uh.modifier2 = 0;
		uwsgi_response_write_body_do(wsgi_req, (char *) &uh, 4);
        }

        return -1;
}


struct uwsgi_plugin spooler_plugin = {

	.name = "spooler",
	.modifier1 = 17,
	
	.request = uwsgi_request_spooler,
};
