#include <uwsgi.h>

#define MEMCACHED_BUFSIZE 8192

extern struct uwsgi_server uwsgi;

/*

	memcached internal router

	route = /^foobar1(.*)/ memcached:addr=127.0.0.1:11211,key=foo$1poo,type=body

*/

struct uwsgi_router_memcached_conf {

	char *addr;

	char *key;
	size_t key_len;

	char *content_type;
	size_t content_type_len;

	// 0 -> full, 1 -> body
	char *type;
	int type_num;
	
};

static size_t memcached_firstline_parse(char *buf, size_t len) {
	// check for "VALUE x 0 0"
	if (len < 11) return 0;
	char *flags = memchr(buf + 6, ' ', len-6);
	if (!flags) return 0;
	size_t skip = (flags-buf)+1;
	if (skip+1 >= len) return 0;
	char *bytes = memchr(buf + skip + 1, ' ', len - (skip+1));
	if (!bytes) return 0;
	skip = (bytes-buf)+1;
	if (skip+1 > len) return 0;
	char *bytes_end = memchr(buf + skip + 1, ' ', len - (skip+1));
	if (bytes_end) {
		return uwsgi_str_num(bytes + 1, bytes_end - (bytes+1));
	}
	else {
		return uwsgi_str_num(bytes + 1, len-skip);
	}
}

static int uwsgi_routing_func_memcached(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){
	// this is the buffer for the memcached response
	char buf[MEMCACHED_BUFSIZE];
	size_t i;
	char last_char = 0;

	struct uwsgi_router_memcached_conf *urmc = (struct uwsgi_router_memcached_conf *) ur->data2;

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

	struct uwsgi_buffer *ub_key = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urmc->key, urmc->key_len);
        if (!ub_key) return UWSGI_ROUTE_BREAK;

	int fd = uwsgi_connect(urmc->addr, 0, 1);
	if (fd < 0) { uwsgi_buffer_destroy(ub_key) ; goto end; }

        // wait for connection;
        int ret = uwsgi.wait_write_hook(fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
        if (ret <= 0) {
		uwsgi_buffer_destroy(ub_key) ;
		close(fd);
		goto end;
        }

	// build the request and send it
	char *cmd = uwsgi_concat3n("get ", 4, ub_key->buf, ub_key->pos, "\r\n", 2);
	if (uwsgi_write_true_nb(fd, cmd, 6+ub_key->pos, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT])) {
		uwsgi_buffer_destroy(ub_key);
		free(cmd);
		close(fd);
		goto end;
	}
	uwsgi_buffer_destroy(ub_key);
	free(cmd);

	// ok, start reading the response...
	// first we need to get a full line;
	size_t found = 0;
	size_t pos = 0;
	for(;;) {
		ssize_t len = read(fd, buf + pos, MEMCACHED_BUFSIZE - pos);
		if (len > 0) {
			pos += len;
			goto read;
		}
		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) goto wait;
		}
		close(fd);
		goto end;
wait:
		ret = uwsgi.wait_read_hook(fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		// when we have a chunk try to read the first line
		if (ret > 0) {
			len = read(fd, buf + pos, MEMCACHED_BUFSIZE - pos);
			if (len > 0) {
				pos += len;
				goto read;
			}
		}
		close(fd);
		goto end;
read:
		for(i=0;i<pos;i++) {
			if (last_char == '\r' && buf[i] == '\n') {
				found = i-1;
				break;
			}
			last_char = buf[i];
		}
		if (found) break;
	}

	// ok parse the first line
	size_t response_size = memcached_firstline_parse(buf, found);

	if (response_size == 0) {
		close(fd);
		goto end;
	}

	if (urmc->type_num == 1) {
		if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) { close(fd); goto end; }
		if (uwsgi_response_add_content_type(wsgi_req, urmc->content_type, urmc->content_type_len)) { close(fd); goto end; }
		if (uwsgi_response_add_content_length(wsgi_req, response_size)) { close(fd); goto end; }
	}
	size_t remains = pos-(found+2);
	if (remains >= response_size) {
		uwsgi_response_write_body_do(wsgi_req, buf+found+2, response_size);
		close(fd);
		goto end;
	}

	// send what we have
	if (uwsgi_response_write_body_do(wsgi_req, buf+found+2, remains)) {
		close(fd);
		goto end;
	}

	// and now start reading til the output is consumed
	response_size -= remains;
	while(response_size > 0) {
		ssize_t len = read(fd, buf, UMIN(MEMCACHED_BUFSIZE, response_size));
		if (len > 0) goto write;
		if (len < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) goto wait2;
                }
		goto error;
wait2:
		ret = uwsgi.wait_read_hook(fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (ret > 0) {
                        len = read(fd, buf, UMIN(MEMCACHED_BUFSIZE, response_size));
			if (len > 0) goto write;
		}
		goto error;
write:
		if (uwsgi_response_write_body_do(wsgi_req, buf, len)) {
			goto error;
        	}
		response_size -= len;
	}

	close(fd);
	return UWSGI_ROUTE_BREAK;

error:
	close(fd);
	
end:
	if (ur->custom)
        	return UWSGI_ROUTE_NEXT;

	return UWSGI_ROUTE_BREAK;
}

static int uwsgi_router_memcached(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_memcached;
        ur->data = args;
        ur->data_len = strlen(args);
	struct uwsgi_router_memcached_conf *urmc = uwsgi_calloc(sizeof(struct uwsgi_router_memcached_conf));
                if (uwsgi_kvlist_parse(ur->data, ur->data_len, ',', '=',
                        "addr", &urmc->addr,
                        "key", &urmc->key,
                        "content_type", &urmc->content_type,
                        "type", &urmc->type, NULL)) {
			uwsgi_log("invalid route syntax: %s\n", args);
		exit(1);
        }

	if (!urmc->key || !urmc->addr) {
		uwsgi_log("invalid route syntax: you need to specify a memcached address and key pattern\n");
		exit(1);
	}

	urmc->key_len = strlen(urmc->key);

        if (!urmc->type) urmc->type = "full";
        if (!urmc->content_type) urmc->content_type = "text/html";

        urmc->content_type_len = strlen(urmc->content_type);

        if (!strcmp(urmc->type, "body")) {
        	urmc->type_num = 1;
        }

        ur->data2 = urmc;
	return 0;
}

static int uwsgi_router_memcached_continue(struct uwsgi_route *ur, char *args) {
	uwsgi_router_memcached(ur, args);
	ur->custom = 1;
	return 0;
}

static void router_memcached_register() {
	uwsgi_register_router("memcached", uwsgi_router_memcached);
	uwsgi_register_router("memcached-continue", uwsgi_router_memcached_continue);
}

struct uwsgi_plugin router_memcached_plugin = {
	.name = "router_memcached",
	.on_load = router_memcached_register,
};
