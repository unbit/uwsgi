#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_request_spooler(struct wsgi_request *wsgi_req) {

        int i;
        char spool_filename[1024];

        // get the spooler from the modifier2

        struct uwsgi_spooler *uspool = uwsgi.spoolers;

        if (uspool == NULL) {
                uwsgi_log("the spooler is inactive !!!...skip\n");
                uwsgi_send_empty_pkt(wsgi_req->poll.fd, NULL, 255, 0);
                return -1;
        }

        i = spool_request(uspool, spool_filename, uwsgi.workers[0].requests + 1, wsgi_req->async_id, wsgi_req->buffer, wsgi_req->uh.pktsize, NULL, 0, NULL, 0);
        wsgi_req->uh.modifier1 = 255;
        wsgi_req->uh.pktsize = 0;
        if (i > 0) {
                wsgi_req->uh.modifier2 = 1;
                if (write(wsgi_req->poll.fd, wsgi_req, 4) != 4) {
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
                wsgi_req->uh.modifier2 = 0;
                i = write(wsgi_req->poll.fd, wsgi_req, 4);
                if (i != 4) {
                        uwsgi_error("write()");
                }
        }

        return -1;
}


struct uwsgi_plugin spooler_plugin = {

	.name = "spooler",
	.modifier1 = 17,
	
	.request = uwsgi_request_spooler,
};
