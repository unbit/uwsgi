/* async SCGI protocol parser */

#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

int uwsgi_proto_scgi_parser(struct wsgi_request *wsgi_req) {
	char *ptr = (char *) wsgi_req->uh;
	ssize_t len = read(wsgi_req->fd, ptr + wsgi_req->proto_parser_pos, (uwsgi.buffer_size+4) - wsgi_req->proto_parser_pos);
	if (len > 0) {
		wsgi_req->proto_parser_pos += len;
		if (wsgi_req->proto_parser_pos >= 4) {
			if ((wsgi_req->proto_parser_pos-4) == wsgi_req->uh->pktsize) {
				return UWSGI_OK;	
			}
			if ((wsgi_req->proto_parser_pos-4) > wsgi_req->uh->pktsize) {
				wsgi_req->proto_parser_remains = wsgi_req->proto_parser_pos-(4+wsgi_req->uh->pktsize);
				wsgi_req->proto_parser_remains_buf = wsgi_req->buffer + wsgi_req->uh->pktsize;
				return UWSGI_OK;	
			}
			if (wsgi_req->uh->pktsize > uwsgi.buffer_size) {
				uwsgi_log("invalid request block size: %u (max %u)...skip\n", wsgi_req->uh->pktsize, uwsgi.buffer_size);
				return -1;
			}
		}
		return UWSGI_AGAIN;
	}
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
			return UWSGI_AGAIN;
		}
		uwsgi_error("uwsgi_proto_uwsgi_parser()");	
		return -1;
	}
	// 0 len
	if (wsgi_req->proto_parser_pos > 0) {
		uwsgi_error("uwsgi_proto_uwsgi_parser()");	
	}
	return -1;
}
