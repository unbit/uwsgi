#include "uwsgi.h"

/*

	uWSGI offloading subsystem

*/


extern struct uwsgi_server uwsgi;

#define uwsgi_offload_retry if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) return 0;
#define uwsgi_offload_0r_1w(x, y) if (event_queue_del_fd(ut->queue, x, event_queue_read())) return -1;\
					if (event_queue_fd_read_to_write(ut->queue, y)) return -1;

static int uwsgi_offload_net_transfer(struct uwsgi_thread *, struct uwsgi_offload_request *, int);
static int uwsgi_offload_sendfile_transfer(struct uwsgi_thread *, struct uwsgi_offload_request *, int);

static void uwsgi_offload_setup(struct uwsgi_offload_request *uor, struct wsgi_request *wsgi_req,
	int (*func)(struct uwsgi_thread *, struct uwsgi_offload_request *, int)) {

	wsgi_req->fd_closed = 1;
	memset(uor, 0, sizeof(struct uwsgi_offload_request));
	uor->s = wsgi_req->poll.fd;
	uor->func = func;
	// put socket in non-blocking mode
	uwsgi_socket_nb(uor->s);
	
}

static int uwsgi_offload_enqueue(struct wsgi_request *wsgi_req, struct uwsgi_offload_request *uor) {
	struct uwsgi_core *uc = &uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id];
	uc->offloaded_requests++;
	// round robin
	if (uc->offload_rr >= uwsgi.offload_threads) {
		uc->offload_rr = 0;
	}
	struct uwsgi_thread *ut = uwsgi.offload_thread[uc->offload_rr];
	uc->offload_rr++;
	if (write(ut->pipe[0], uor, sizeof(struct uwsgi_offload_request)) != sizeof(struct uwsgi_offload_request)) {
		return -1;
	}
	return 0;
}

int uwsgi_offload_request_net_do(struct wsgi_request *wsgi_req, char *socket, struct uwsgi_buffer *ubuf) {

	// fill offload request
	struct uwsgi_offload_request uor;
	uwsgi_offload_setup(&uor, wsgi_req, uwsgi_offload_net_transfer);

	uor.fd = uwsgi_connect(socket, 0, 1);
	if (uor.fd < 0) {
		uwsgi_error("uwsgi_offload_request_net_do() -> connect()");
		goto error;
	}

	uor.ubuf = ubuf;

	if (uwsgi_offload_enqueue(wsgi_req, &uor)) {
		goto error2;
	}

	return 0;

error2:
	close(uor.fd);
error:
	wsgi_req->fd_closed = 0;
	return -1;
}

int uwsgi_offload_request_sendfile_do(struct wsgi_request *wsgi_req, char *filename, size_t len) {

	// fill offload request
	struct uwsgi_offload_request uor;
	uwsgi_offload_setup(&uor, wsgi_req, uwsgi_offload_sendfile_transfer);

	uor.fd = open(filename, O_RDONLY | O_NONBLOCK);
	if (uor.fd < 0) {
		uwsgi_error_open(filename);
		goto error;
	}

	// make a fstat to get the file size
	if (!len) {
		struct stat st;
		if (fstat(uor.fd, &st)) {
			uwsgi_error("fstat()");
			goto error2;
		}
		len = st.st_size;
	}

	uor.len = len;

	if (uwsgi_offload_enqueue(wsgi_req, &uor)) {
		goto error2;
	}

	return 0;

error2:
	close(uor.fd);
error:
	wsgi_req->fd_closed = 0;
	return -1;
}

static void uwsgi_offload_close(struct uwsgi_thread *ut, struct uwsgi_offload_request *uor) {
	// close the socket and the file descriptor
	close(uor->s);
	close(uor->fd);
	// remove the structure from the linked list;
	struct uwsgi_offload_request *prev = uor->prev;
	struct uwsgi_offload_request *next = uor->next;

	if (uor == ut->offload_requests_head) {
		ut->offload_requests_head = next;
	}

	if (uor == ut->offload_requests_tail) {
		ut->offload_requests_tail = prev;
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

	if (uor->ubuf) {
		uwsgi_buffer_destroy(uor->ubuf);
	}

	free(uor);
}

static void uwsgi_offload_append(struct uwsgi_thread *ut, struct uwsgi_offload_request *uor) {

	if (!ut->offload_requests_head) {
		ut->offload_requests_head = uor;
	}

	if (ut->offload_requests_tail) {
		ut->offload_requests_tail->next = uor;
		uor->prev = ut->offload_requests_tail;
	}

	ut->offload_requests_tail = uor;
}

static struct uwsgi_offload_request *uwsgi_offload_get_by_fd(struct uwsgi_thread *ut, int s) {
	struct uwsgi_offload_request *uor = ut->offload_requests_head;
	while (uor) {
		if (uor->s == s || uor->fd == s) {
			return uor;
		}
		uor = uor->next;
	}

	return NULL;
}

static void uwsgi_offload_loop(struct uwsgi_thread *ut) {

	int i;
	void *events = event_queue_alloc(uwsgi.offload_threads_events);

	for (;;) {
		int nevents = event_queue_wait_multi(ut->queue, -1, events, uwsgi.offload_threads_events);
		for (i = 0; i < nevents; i++) {
			int interesting_fd = event_queue_interesting_fd(events, i);
			if (interesting_fd == ut->pipe[1]) {
				struct uwsgi_offload_request *uor = uwsgi_malloc(sizeof(struct uwsgi_offload_request));
				ssize_t len = read(ut->pipe[1], uor, sizeof(struct uwsgi_offload_request));
				if (len != sizeof(struct uwsgi_offload_request)) {
					uwsgi_error("read()");
					free(uor);
					continue;
				}
				// start monitoring socket for write
				if (uor->func(ut, uor, -1)) {
					uwsgi_offload_close(ut, uor);
					continue;
				}
				uwsgi_offload_append(ut, uor);
				continue;
			}

			// get the task from the interesting fd
			struct uwsgi_offload_request *uor = uwsgi_offload_get_by_fd(ut, interesting_fd);
			if (!uor)
				continue;
			// run the hook
			if (uor->func(ut, uor, interesting_fd)) {
				uwsgi_offload_close(ut, uor);
			}
		}
	}
}

struct uwsgi_thread *uwsgi_offload_thread_start() {
	return uwsgi_thread_new(uwsgi_offload_loop);
}

/*

the offload task starts after having acquired the file fd

	uor->len -> the size of the file
	uor->pos -> start writing from pos (default 0)

	status: none

*/

static int uwsgi_offload_sendfile_transfer(struct uwsgi_thread *ut, struct uwsgi_offload_request *uor, int fd) {

	if (fd == -1) {
		if (event_queue_add_fd_write(ut->queue, uor->s)) return -1;
		return 0;
	}
#if defined(__linux__) || defined(__sun__)
	ssize_t len = sendfile(uor->s, uor->fd, &uor->pos, 128 * 1024);
	if (len > 0) {
        	uor->written += len;
                if (uor->written >= uor->len) {
			return -1;
		}
		return 0;
	}
        else if (len < 0) {
		uwsgi_offload_retry
                uwsgi_error("sendfile()");
	}
#elif defined(__FreeBSD__) || defined(__DragonFly__)
	off_t sbytes = 0;
	int ret = sendfile(uor->fd, uor->s, uor->pos, 0, NULL, &sbytes, 0);
	// transfer finished
	if (ret == -1) {
		uor->pos += sbytes;
		uwsgi_offload_retry
                uwsgi_error("sendfile()");
	}
#elif defined(__APPLE__)
	off_t len = 0;
        int ret = sendfile(uor->fd, uor->s, uor->pos, &len, NULL, 0);
        // transfer finished
        if (ret == -1) {
                uor->pos += len;
                uwsgi_offload_retry
                uwsgi_error("sendfile()");
        }
#endif
	return -1;

}

/*
the offload task starts soon after the call to connect()

	status:
		0 -> waiting for connection on fd
		1 -> sending request to fd (write event)
		2 -> start waiting for read on s and fd
		3 -> write to s
		4 -> write to fd
*/
static int uwsgi_offload_net_transfer(struct uwsgi_thread *ut, struct uwsgi_offload_request *uor, int fd) {
	
	ssize_t rlen;

	// setup
	if (fd == -1) {
		event_queue_add_fd_write(ut->queue, uor->fd);
		return 0;
	}

	switch(uor->status) {
		// waiting for connection
		case 0:
			if (fd == uor->fd) {
				uor->status = 1;
				// ok try to send the request right now...
				return uwsgi_offload_net_transfer(ut, uor, fd);
			}
			return -1;
		// write event (or just connected)
		case 1:
			if (fd == uor->fd) {
				rlen = write(uor->fd, uor->ubuf->buf + uor->written, uor->ubuf->pos-uor->written);	
				if (rlen > 0) {
					uor->written += rlen;
					if (uor->written >= (size_t)uor->ubuf->pos) {
						uor->status = 2;
						if (event_queue_add_fd_read(ut->queue, uor->s)) return -1;
						if (event_queue_fd_write_to_read(ut->queue, uor->fd)) return -1;
					}
					return 0;
				}
				else if (rlen < 0) {
					uwsgi_offload_retry
					uwsgi_error("uwsgi_offload_net_transfer() -> write()");
				}
			}	
			return -1;
		// read event from s or fd
		case 2:
			if (!uor->buf) {
				uor->buf = uwsgi_malloc(4096);
			}
			if (fd == uor->fd) {
				rlen = read(uor->fd, uor->buf, 4096);
				if (rlen > 0) {
					uor->to_write = rlen;
					uor->pos = 0;
					uwsgi_offload_0r_1w(uor->fd, uor->s)
					uor->status = 3;
					return 0;
				}
				if (rlen < 0) {
					uwsgi_offload_retry
					uwsgi_error("uwsgi_offload_net_transfer() -> read()/fd");
				}
			}
			else if (fd == uor->s) {
				rlen = read(uor->s, uor->buf, 4096);
				if (rlen > 0) {
					uor->to_write = rlen;
					uor->pos = 0;
					uwsgi_offload_0r_1w(uor->s, uor->fd)
					uor->status = 4;
					return 0;
				}
				if (rlen < 0) {
					uwsgi_offload_retry
					uwsgi_error("uwsgi_offload_net_transfer() -> read()/s");
				}
			}
			return -1;
		// write event on s
		case 3:
			rlen = write(uor->s, uor->buf + uor->pos, uor->to_write);
			if (rlen > 0) {
				uor->to_write -= rlen;
				uor->pos += rlen;
				if (uor->to_write == 0) {
					if (event_queue_fd_write_to_read(ut->queue, uor->s)) return -1;
					if (event_queue_add_fd_read(ut->queue, uor->fd)) return -1;
					uor->status = 2;
				}
				return 0;
			}
			else if (rlen < 0) {
				uwsgi_offload_retry
				uwsgi_error("uwsgi_offload_net_transfer() -> write()/s");
			}
			return -1;
		// write event on fd
		case 4:
			rlen = write(uor->fd, uor->buf + uor->pos, uor->to_write);
			if (rlen > 0) {
				uor->to_write -= rlen;
				uor->pos += rlen;
				if (uor->to_write == 0) {
					if (event_queue_fd_write_to_read(ut->queue, uor->fd)) return -1;
					if (event_queue_add_fd_read(ut->queue, uor->s)) return -1;
					uor->status = 2;
				}
				return 0;
			}
			else if (rlen < 0) {
				uwsgi_offload_retry
				uwsgi_error("uwsgi_offload_net_transfer() -> write()/fd");
			}
			return -1;
		default:
			break;
	}

	return -1;
}
