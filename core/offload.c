#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

/*

enqueue a file transfer to the offload thread

*/

int uwsgi_offload_request_do(struct wsgi_request *wsgi_req, char *filename, size_t len) {

	struct stat st;

	// avoid closing the connection
	wsgi_req->fd_closed = 1;

	// fill offload request
	struct uwsgi_offload_request uor;
	uor.fd = open(filename, O_RDONLY | O_NONBLOCK);
	if (uor.fd < 0) {
		uwsgi_error_open(filename);
		goto error;
	}
	uor.s = wsgi_req->poll.fd;
	// make a fstat to get the file size
	if (!len) {
		if (fstat(uor.fd, &st)) {
			uwsgi_error("fstat()");
			goto error2;
		}
		len = st.st_size;
	}
	uor.pos = 0;
	uor.len = len;
	uor.written = 0;
	uor.buf = NULL;
	uor.prev = NULL;
	uor.next = NULL;

	// put socket in non-blocking mode
	uwsgi_socket_nb(uor.s);

	if (write(uwsgi.offload_thread->pipe[0], &uor, sizeof(struct uwsgi_offload_request)) != sizeof(struct uwsgi_offload_request)) {
		goto error2;
	}

	return 0;

error2:
	close(uor.fd);
error:
	wsgi_req->fd_closed = 0;
	return -1;
}

static void uwsgi_offload_close(struct uwsgi_offload_request *uor) {
	// close the socket and the file descriptor
	close(uor->s);
	close(uor->fd);
	// remove the structure from the linked list;
	struct uwsgi_offload_request *prev = uor->prev;
	struct uwsgi_offload_request *next = uor->next;

	if (uor == uwsgi.offload_requests_head) {
		uwsgi.offload_requests_head = next;
	}

	if (uor == uwsgi.offload_requests_tail) {
		uwsgi.offload_requests_tail = prev;
	}

	if (prev) {
		prev->next = next;
	}

	if (next) {
		next->prev = prev;
	}

	if (uor->buf) {
		free(uor->buf);
	}

	free(uor);
}

static void uwsgi_offload_append(struct uwsgi_offload_request *uor) {

	if (!uwsgi.offload_requests_head) {
		uwsgi.offload_requests_head = uor;
	}

	if (uwsgi.offload_requests_tail) {
		uwsgi.offload_requests_tail->next = uor;
		uor->prev = uwsgi.offload_requests_tail;
	}

	uwsgi.offload_requests_tail = uor;
}

static struct uwsgi_offload_request *uwsgi_offload_get_by_socket(int s) {
	struct uwsgi_offload_request *uor = uwsgi.offload_requests_head;
	while (uor) {
		if (uor->s == s) {
			return uor;
		}
		uor = uor->next;
	}

	return NULL;
}

static void uwsgi_offload_loop(struct uwsgi_thread *ut) {

	int i;
	void *events = event_queue_alloc(uwsgi.static_offload_to_thread);

	for (;;) {
		int nevents = event_queue_wait_multi(ut->queue, -1, events, uwsgi.static_offload_to_thread);
		for (i = 0; i < nevents; i++) {
			int interesting_fd = event_queue_interesting_fd(events, i);
			if (interesting_fd == uwsgi.offload_thread->pipe[1]) {
				struct uwsgi_offload_request *uor = uwsgi_malloc(sizeof(struct uwsgi_offload_request));
				ssize_t len = read(uwsgi.offload_thread->pipe[1], uor, sizeof(struct uwsgi_offload_request));
				if (len != sizeof(struct uwsgi_offload_request)) {
					uwsgi_error("read()");
					free(uor);
					continue;
				}
				// start monitoring socket for write
				if (event_queue_add_fd_write(ut->queue, uor->s)) {
					free(uor);
					continue;
				}
				uwsgi_offload_append(uor);
				continue;
			}
			// ok check for socket writability
			struct uwsgi_offload_request *uor = uwsgi_offload_get_by_socket(interesting_fd);
			if (!uor)
				continue;
			// sendfile() in chunks (128k is a good size...)
#if defined(__linux__)
			ssize_t len = sendfile(uor->s, uor->fd, &uor->pos, 128 * 1024);
			if (len > 0) {
				uor->written += len;
				if (uor->written >= uor->len) {
					uwsgi_offload_close(uor);
				}
				continue;
			}
			else if (len < 0) {
				if (errno == EAGAIN)
					continue;
				uwsgi_error("sendfile()");
			}
#else
			if (!uor->buf) {
				uor->buf = uwsgi_malloc(32768);
				uor->to_write = 0;
			}
			if (uor->to_write == 0) {
				ssize_t len = read(uor->fd, uor->buf, 32768);
				if (len > 0) {
					uor->to_write = len;
					uor->buf_pos = 0;
					continue;
				}
				else if (len < 0) {
					uwsgi_error("read()");
				}
				uwsgi_offload_close(uor);
				continue;
			}
			ssize_t len = write(uor->s, uor->buf + uor->buf_pos, uor->to_write);
			if (len > 0) {
				uor->written += len;
				uor->to_write -= len;
				uor->buf_pos += len;
				if (uor->written >= uor->len) {
					uwsgi_offload_close(uor);
				}
				continue;
			}
			else if (len < 0) {
				if (errno == EAGAIN)
					continue;
				uwsgi_error("write()");
			}

#endif
			uwsgi_offload_close(uor);
		}
	}
}

struct uwsgi_thread *uwsgi_offload_thread_start() {
	return uwsgi_thread_new(uwsgi_offload_loop);
}
