
{"ping", required_argument, 0, LONG_ARGS_PING},
{"ping-timeout", required_argument, 0, LONG_ARGS_PING_TIMEOUT},


void ping() {

        struct uwsgi_header uh;
        struct pollfd uwsgi_poll;

        // use a 3 secs timeout by default
        if (!uwsgi.ping_timeout) uwsgi.ping_timeout = 3 ;

        uwsgi_poll.fd = uwsgi_connect(uwsgi.ping, uwsgi.ping_timeout);
        if (uwsgi_poll.fd < 0) {
                exit(1);
        }

        uh.modifier1 = UWSGI_MODIFIER_PING;
        uh.pktsize = 0;
        uh.modifier2 = 0;
        if (write(uwsgi_poll.fd, &uh, 4) != 4) {
                uwsgi_error("write()");
                exit(2);
        }
        uwsgi_poll.events = POLLIN;
        if (!uwsgi_parse_response(&uwsgi_poll, uwsgi.ping_timeout, &uh, NULL)) {
                exit(1);
        }
        else {
                if (uh.pktsize > 0) {
                        exit(2);
                }
                else {
                        exit(0);
                }
        }

}


/* uwsgi PING|100 */
int uwsgi_request_ping(struct wsgi_request *wsgi_req) {
        char len;

        uwsgi_log( "PING\n");
        wsgi_req->uh.modifier2 = 1;
        wsgi_req->uh.pktsize = 0;

        len = strlen(uwsgi.shared->warning_message);
        if (len > 0) {
                // TODO: check endianess ?
                wsgi_req->uh.pktsize = len;
        }
        if (write(wsgi_req->poll.fd, wsgi_req, 4) != 4) {
                uwsgi_error("write()");
        }

        if (len > 0) {
                if (write(wsgi_req->poll.fd, uwsgi.shared->warning_message, len)
                    != len) {
                        uwsgi_error("write()");
                }
        }

        return UWSGI_OK;
}

