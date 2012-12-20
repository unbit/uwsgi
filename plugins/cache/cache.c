#include "../../uwsgi.h"

void cache_command(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

        struct wsgi_request *wsgi_req = (struct wsgi_request *) data;
        uint64_t tmp_vallen = 0;

        if (vallen > 0) {
                if (!uwsgi_strncmp(key, keylen, "key", 3)) {
                        val = uwsgi_cache_get(val, vallen, &tmp_vallen);
                        if (val && tmp_vallen > 0) {
#ifdef UWSGI_DEBUG
				uwsgi_log("cache value size: %llu\n", tmp_vallen);
#endif
                                wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, val, tmp_vallen);
                        }

                }
                else if (!uwsgi_strncmp(key, keylen, "get", 3)) {
                        val = uwsgi_cache_get(val, vallen, &tmp_vallen);
                        if (val && vallen > 0) {
                                wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, val, tmp_vallen);
                        }
                        else {
                                wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, "HTTP/1.0 404 Not Found\r\n\r\n<h1>Not Found</h1>", 44);
                        }
                }
        }
}


int uwsgi_cache_request(struct wsgi_request *wsgi_req) {

        uint64_t vallen = 0;
        char *value;
        char *argv[3];
        uint16_t argvs[3];
        uint8_t argc = 0;

        switch(wsgi_req->uh.modifier2) {
                case 0:
                        // get
                        if (wsgi_req->uh.pktsize > 0) {
                                value = uwsgi_cache_get(wsgi_req->buffer, wsgi_req->uh.pktsize, &vallen);
                                if (value && vallen > 0) {
                                        wsgi_req->uh.pktsize = vallen;
                                        wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, (char *)&wsgi_req->uh, 4);
                                        wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, value, vallen);
                                }
                        }
                        break;
                case 1:
                        // set
                        if (wsgi_req->uh.pktsize > 0) {
                                argc = 3;
                                if (!uwsgi_parse_array(wsgi_req->buffer, wsgi_req->uh.pktsize, argv, argvs, &argc)) {
                                        if (argc > 1) {
                                                uwsgi_cache_set(argv[0], argvs[0], argv[1], argvs[1], 0, 0);
                                        }
                                }
                        }
                        break;
                case 2:
                        // del
                        if (wsgi_req->uh.pktsize > 0) {
                                uwsgi_cache_del(wsgi_req->buffer, wsgi_req->uh.pktsize, 0, 0);
                        }
                        break;
                case 3:
                case 4:
                        // dict
                        if (wsgi_req->uh.pktsize > 0) {
                                uwsgi_hooked_parse(wsgi_req->buffer, wsgi_req->uh.pktsize, cache_command, (void *) wsgi_req);
                        }
                        break;
                case 5:
                        // get (uwsgi + stream)
                        if (wsgi_req->uh.pktsize > 0) {
                                value = uwsgi_cache_get(wsgi_req->buffer, wsgi_req->uh.pktsize, &vallen);
                                if (value && vallen > 0) {
                                        wsgi_req->uh.pktsize = 0;
                                        wsgi_req->uh.modifier2 = 1;
                                        wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, (char *)&wsgi_req->uh, 4);
                                        wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, value, vallen);
                                }
                                else {
                                        wsgi_req->uh.pktsize = 0;
                                        wsgi_req->uh.modifier2 = 0;
                                        wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req, (char *)&wsgi_req->uh, 4);
                                }
                        }
                        break;
        }

        return 0;
}

struct uwsgi_plugin cache_plugin = {

        .name = "cache",
        .modifier1 = 111,
        .request = uwsgi_cache_request,

};

