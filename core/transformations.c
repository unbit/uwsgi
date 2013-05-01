#include <uwsgi.h>

/*

	uWSGI transformations

	responses can be buffered in the wsgi_request structure (instead of being sent to the client)
	Before closing the request, the transformations are applied in chain to the response buffer

	Finally the resulting buffer is sent to the client

	Transformations (if required) could completely swallow already set headers

*/

extern struct uwsgi_server uwsgi;

// -1 error, 0 = no buffer, send the body, 1 = buffer
int uwsgi_apply_transformations(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	wsgi_req->transformed_chunk = NULL;
	wsgi_req->transformed_chunk_len = 0;
	struct uwsgi_transformation *ut = wsgi_req->transformations;
	char *t_buf = buf;
	size_t t_len = len;
	while(ut) {
		// allocate the buffer (if needed)
		if (!ut->chunk) {
			ut->chunk = uwsgi_buffer_new(t_len);
		}
		// skip final transformations before appending data
		if (ut->is_final) goto next;
		if (uwsgi_buffer_append(ut->chunk, t_buf, t_len)) {
			return -1;
		}

		// if the transformation cannot stream, continue buffering (the func will be called at the end)
		if (!ut->can_stream) return 1;
		
		if (ut->func(wsgi_req, ut)) {
			return -1;
		}

		t_buf = ut->chunk->buf;
		t_len = ut->chunk->pos;
		// we reset the buffer, so we do not waste memory
		ut->chunk->pos = 0;
next:
		ut = ut->next;
	}

	// if we are here we can tell the writer to send the body to the client
	// no buffering please
	wsgi_req->transformed_chunk = t_buf;
	wsgi_req->transformed_chunk_len = t_len;
	return 0;

}

int uwsgi_apply_final_transformations(struct wsgi_request *wsgi_req) {
	struct uwsgi_transformation *ut = wsgi_req->transformations;
	wsgi_req->transformed_chunk = NULL;
        wsgi_req->transformed_chunk_len = 0;
	char *t_buf = NULL;
	size_t t_len = 0;
	while(ut) {
		if (ut->chunk) {
			t_buf = ut->chunk->buf;
			t_len = ut->chunk->pos;
			// if the transformation can stream and has a chunk, we already applied it
			if (ut->can_stream) goto next;
		}
		else if (t_len > 0) {
			ut->chunk = uwsgi_buffer_new(t_len);
			if (uwsgi_buffer_append(ut->chunk, t_buf, t_len)) {
				return -1;
			}
		}
		// if we have no buffer, just stop the chain
		else {
			return -1;
		}

		
		// run the transformation
		if (ut->func(wsgi_req, ut)) {
			return -1;
                }

		t_buf = ut->chunk->buf;
		t_len = ut->chunk->pos;
		
next:
		ut = ut->next;
	}

	// if we are here, all of the transformations are applied
	wsgi_req->transformed_chunk = t_buf;
        wsgi_req->transformed_chunk_len = t_len;
        return 0;
}

void uwsgi_free_transformations(struct wsgi_request *wsgi_req) {
	struct uwsgi_transformation *ut = wsgi_req->transformations;
	while(ut) {
		struct uwsgi_transformation *current_ut = ut;
		if (current_ut->chunk) {
			uwsgi_buffer_destroy(current_ut->chunk);
		}
		ut = ut->next;
		free(current_ut);
	}
}

struct uwsgi_transformation *uwsgi_add_transformation(struct wsgi_request *wsgi_req, int (*func)(struct wsgi_request *, struct uwsgi_transformation *), void *data) {
	struct uwsgi_transformation *old_ut = NULL, *ut = wsgi_req->transformations;
	while(ut) {
		old_ut = ut;
		ut = ut->next;
	}

	ut = uwsgi_malloc(sizeof(struct uwsgi_transformation));
	ut->func = func;
	ut->is_final = 0;
	ut->next = NULL;
	ut->chunk = NULL;
	ut->can_stream = 0;
	ut->data = data;

	if (old_ut) {
		old_ut->next = ut;
	}
	else {
		wsgi_req->transformations = ut;
	}

	return ut;
}
