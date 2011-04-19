
#include "../uwsgi.h"

int uwsgi_proto_base_accept(struct wsgi_request *wsgi_req, int fd) {

	int client_fd = accept(fd, (struct sockaddr *) &wsgi_req->c_addr, (socklen_t *) &wsgi_req->c_len);
	if (client_fd < 0) {
		uwsgi_error("accept()");
	}

	return client_fd;
}

void uwsgi_proto_base_close(struct wsgi_request *wsgi_req) {

        if (wsgi_req->async_post) {
                fclose(wsgi_req->async_post);
                if (wsgi_req->body_as_file) {
                        close(wsgi_req->poll.fd);
                }
        }
        else {
                close(wsgi_req->poll.fd);
        }
}

