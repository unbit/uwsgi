
#include "../uwsgi.h"

int uwsgi_proto_base_accept(struct wsgi_request *wsgi_req, int fd) {

	int client_fd = accept(fd, (struct sockaddr *) &wsgi_req->c_addr, (socklen_t *) &wsgi_req->c_len);
	if (client_fd < 0) {
		uwsgi_error("accept()");
	}

	return client_fd;
}
