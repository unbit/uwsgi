/* uwsgi ADMIN|10 */
int uwsgi_request_admin(struct wsgi_request *wsgi_req) {
        uint32_t opt_value = 0;
        int i;

        if (wsgi_req->uh.pktsize >= 4) {
                memcpy(&opt_value, wsgi_req->buffer, 4);
                // TODO: check endianess ?
        }

        uwsgi_log( "setting internal option %d to %d\n", wsgi_req->uh.modifier2, opt_value);
        uwsgi.shared->options[wsgi_req->uh.modifier2] = opt_value;

        // ACK
        wsgi_req->uh.modifier1 = 255;
        wsgi_req->uh.pktsize = 0;
        wsgi_req->uh.modifier2 = 1;

        i = write(wsgi_req->poll.fd, wsgi_req, 4);
        if (i != 4) {
                uwsgi_error("write()");
        }



        return UWSGI_OK;
}

