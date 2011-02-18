// uWSGI writer

void simple_writer_init(struct wsgi_request *wsgi_req) {}
void simple_writer_end(struct wsgi_request *wsgi_req) {}

ssize_t simple_writer(struct wsgi_request *wsgi_req, char *buf, size_t len) {

	return write(wsgi_req->poll.fd, buf, len);

}

void cache_writer_init(struct wsgi_request *wsgi_req) {
	if (wsgi_req->cache_it) {
		// lock cache write
		if (uwsgi_cache_update_start(wsgi_req->uri, wsgi_req->uri_len)) {
			uwsgi_log("unable to write data to uwsgi cache\n");
			wsgi_req->cache_it = 0;
		}
	}
}

ssize_t cache_writer(struct wsgi_request *wsgi_req, char *buf, size_t len) {

	if (wsgi_req->cache_it) {
		// lock cache write
		if (uwsgi_cache_update(wsgi_req->uri, wsgi_req->uri_len, buf, len, wsgi_req->cache_expires)) {
			uwsgi_log("unable to write data to uwsgi cache\n");
			uwsgi_cache_del(sgi_req->uri, wsgi_req->uri_len);
		}
		// unlock cache
	}
	return write(wsgi_req->poll.fd, buf, len);
}

void cache_writer_end(struct wsgi_request *wsgi_req) {

	if (wsgi_req->cache_it) {
		// finish cache update (lock write it)
		uwsgi_cache_update_finalize(wsgi_req->uri, wsgi_req->uri_len);
	}
}

void memcached_writer_init(struct wsgi_request *wsgi_req) {
	//open connection to memcached and create entry
}

void memcached_writer_end(struct wsgi_request *wsgi_req) {
	// close connection with memcached
}
ssize_t memcached_writer(struct wsgi_request *wsgi_req, char *buf, size_t len) {
}
