#include <uwsgi.h>

/*

	uWSGI transformations

	responses can be buffered in the wsgi_request structure (instead of being sent to the client)
	Before closing the request, the transformations are applied in chain to the response buffer

	Finally the resulting buffer is sent to the client

*/

extern struct uwsgi_server uwsgi;

int uwsgi_apply_transformations(struct wsgi_request *wsgi_req) {
	struct uwsgi_transformation *ut = wsgi_req->transformations;
	while(ut) {
		struct uwsgi_buffer *new_ub = NULL;
		if (ut->func(wsgi_req, wsgi_req->response_buffer, &new_ub)) {
			return -1;
		}
		if (new_ub) {
			uwsgi_buffer_destroy(wsgi_req->response_buffer);
			wsgi_req->response_buffer = new_ub;
		}
		ut = ut->next;
	}
	return 0;
}

struct uwsgi_transformation *uwsgi_add_transformation(struct wsgi_request *wsgi_req, int (*func)(struct wsgi_request *, struct uwsgi_buffer *, struct uwsgi_buffer **)) {
	struct uwsgi_transformation *old_ut = NULL, *ut = wsgi_req->transformations;
	while(ut) {
		old_ut = ut;
		ut = ut->next;
	}

	ut = uwsgi_malloc(sizeof(struct uwsgi_transformation));
	ut->func = func;
	ut->next = NULL;

	if (old_ut) {
		old_ut->next = ut;
	}
	else {
		wsgi_req->transformations = ut;
	}

	// start buffering
        if (!wsgi_req->response_buffer) {
                wsgi_req->response_buffer = uwsgi_buffer_new(uwsgi.page_size);
        }

	return ut;
}
