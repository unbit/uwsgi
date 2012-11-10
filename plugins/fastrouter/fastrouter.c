/*

   uWSGI fastrouter

*/

#include "../../uwsgi.h"
#include "../corerouter/cr.h"

struct uwsgi_fastrouter {
	struct uwsgi_corerouter cr;
} ufr;

extern struct uwsgi_server uwsgi;

struct fastrouter_session {
	struct corerouter_session crs;
	struct uwsgi_buffer *post_buf;
	size_t post_buf_max;
	size_t post_buf_len;
	off_t post_buf_pos;
};

struct uwsgi_option fastrouter_options[] = {
	{"fastrouter", required_argument, 0, "run the fastrouter on the specified port", uwsgi_opt_corerouter, &ufr, 0},
	{"fastrouter-processes", required_argument, 0, "prefork the specified number of fastrouter processes", uwsgi_opt_set_int, &ufr.cr.processes, 0},
	{"fastrouter-workers", required_argument, 0, "prefork the specified number of fastrouter processes", uwsgi_opt_set_int, &ufr.cr.processes, 0},
	{"fastrouter-zerg", required_argument, 0, "attach the fastrouter to a zerg server", uwsgi_opt_corerouter_zerg, &ufr, 0},
	{"fastrouter-use-cache", no_argument, 0, "use uWSGI cache as hostname->server mapper for the fastrouter", uwsgi_opt_true, &ufr.cr.use_cache, 0},

	{"fastrouter-use-pattern", required_argument, 0, "use a pattern for fastrouter hostname->server mapping", uwsgi_opt_corerouter_use_pattern, &ufr, 0},
	{"fastrouter-use-base", required_argument, 0, "use a base dir for fastrouter hostname->server mapping", uwsgi_opt_corerouter_use_base, &ufr, 0},

	{"fastrouter-fallback", required_argument, 0, "fallback to the specified node in case of error", uwsgi_opt_add_string_list, &ufr.cr.fallback, 0},

	{"fastrouter-use-cluster", no_argument, 0, "load balance to nodes subscribed to the cluster", uwsgi_opt_true, &ufr.cr.use_cluster, 0},

	{"fastrouter-use-code-string", required_argument, 0, "use code string as hostname->server mapper for the fastrouter", uwsgi_opt_corerouter_cs, &ufr, 0},
	{"fastrouter-use-socket", optional_argument, 0, "forward request to the specified uwsgi socket", uwsgi_opt_corerouter_use_socket, &ufr, 0},
	{"fastrouter-to", required_argument, 0, "forward requests to the specified uwsgi server (you can specify it multiple times for load balancing)", uwsgi_opt_add_string_list, &ufr.cr.static_nodes, 0},
	{"fastrouter-gracetime", required_argument, 0, "retry connections to dead static nodes after the specified amount of seconds", uwsgi_opt_set_int, &ufr.cr.static_node_gracetime, 0},
	{"fastrouter-events", required_argument, 0, "set the maximum number of concurrent events", uwsgi_opt_set_int, &ufr.cr.nevents, 0},
	{"fastrouter-quiet", required_argument, 0, "do not report failed connections to instances", uwsgi_opt_true, &ufr.cr.quiet, 0},
	{"fastrouter-cheap", no_argument, 0, "run the fastrouter in cheap mode", uwsgi_opt_true, &ufr.cr.cheap, 0},
	{"fastrouter-subscription-server", required_argument, 0, "run the fastrouter subscription server on the spcified address", uwsgi_opt_corerouter_ss, &ufr, 0},
	{"fastrouter-subscription-slot", required_argument, 0, "*** deprecated ***", uwsgi_opt_deprecated, (void *) "useless thanks to the new implementation", 0},

	{"fastrouter-timeout", required_argument, 0, "set fastrouter timeout", uwsgi_opt_set_int, &ufr.cr.socket_timeout, 0},
	{"fastrouter-post-buffering", required_argument, 0, "enable fastrouter post buffering", uwsgi_opt_set_64bit, &ufr.cr.post_buffering, 0},
	{"fastrouter-post-buffering-dir", required_argument, 0, "put fastrouter buffered files to the specified directory", uwsgi_opt_set_str, &ufr.cr.pb_base_dir, 0},

	{"fastrouter-stats", required_argument, 0, "run the fastrouter stats server", uwsgi_opt_set_str, &ufr.cr.stats_server, 0},
	{"fastrouter-stats-server", required_argument, 0, "run the fastrouter stats server", uwsgi_opt_set_str, &ufr.cr.stats_server, 0},
	{"fastrouter-ss", required_argument, 0, "run the fastrouter stats server", uwsgi_opt_set_str, &ufr.cr.stats_server, 0},
	{"fastrouter-harakiri", required_argument, 0, "enable fastrouter harakiri", uwsgi_opt_set_int, &ufr.cr.harakiri, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

ssize_t fr_recv_uwsgi_header(struct corerouter_session *);
ssize_t fr_instance_read_response(struct corerouter_session *);
ssize_t fr_read_body(struct corerouter_session *);

void fr_get_hostname(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	// here i use directly corerouter_session
	struct corerouter_session *cs = (struct corerouter_session *) data;

	//uwsgi_log("%.*s = %.*s\n", keylen, key, vallen, val);
	if (!uwsgi_strncmp("SERVER_NAME", 11, key, keylen) && !cs->hostname_len) {
		cs->hostname = val;
		cs->hostname_len = vallen;
		return;
	}

	if (!uwsgi_strncmp("HTTP_HOST", 9, key, keylen) && !cs->has_key) {
		cs->hostname = val;
		cs->hostname_len = vallen;
		return;
	}

	if (!uwsgi_strncmp("UWSGI_FASTROUTER_KEY", 20, key, keylen)) {
		cs->has_key = 1;
		cs->hostname = val;
		cs->hostname_len = vallen;
		return;
	}

	if (!uwsgi_strncmp("CONTENT_LENGTH", 14, key, keylen)) {
		cs->post_cl = uwsgi_str_num(val, vallen);
		return;
	}
}

ssize_t fr_write_body(struct corerouter_session * cs) {
	struct fastrouter_session *fs = (struct fastrouter_session *) cs;
	ssize_t len = write(cs->instance_fd, fs->post_buf->buf + fs->post_buf_pos, fs->post_buf_len - fs->post_buf_pos);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("fr_write_body()");
		return -1;
	}

	fs->post_buf_pos += len;

	// the body chunk has been sent, start again reading from client and instance
	if (fs->post_buf_pos == (ssize_t) fs->post_buf_len) {
		uwsgi_cr_hook_instance_write(cs, NULL);
		uwsgi_cr_hook_instance_read(cs, fr_instance_read_response);
		uwsgi_cr_hook_read(cs, fr_read_body);
	}

	return len;
}


ssize_t fr_read_body(struct corerouter_session * cs) {
	struct fastrouter_session *fs = (struct fastrouter_session *) cs;
	ssize_t len = read(cs->fd, fs->post_buf->buf, fs->post_buf_max);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("fr_read_body()");
		return -1;
	}

	// connection closed
	if (len == 0)
		return 0;

	fs->post_buf_len = len;
	fs->post_buf_pos = 0;

	// ok we have a body, stop reading from the client and the instance and start writing to the instance
	uwsgi_cr_hook_read(cs, NULL);
	uwsgi_cr_hook_instance_read(cs, NULL);
	uwsgi_cr_hook_instance_write(cs, fr_write_body);

	return len;
}

ssize_t fr_write_response(struct corerouter_session * cs) {
	ssize_t len = write(cs->fd, cs->buffer->buf + cs->buffer_pos, cs->buffer_len - cs->buffer_pos);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("fr_write_response()");
		return -1;
	}

	cs->buffer_pos += len;

	// ok this response chunk is sent, let's wait for another one
	if (cs->buffer_pos == (ssize_t) cs->buffer_len) {
		uwsgi_cr_hook_write(cs, NULL);
		uwsgi_cr_hook_instance_read(cs, fr_instance_read_response);
	}

	return len;
}

ssize_t fr_instance_read_response(struct corerouter_session * cs) {
	ssize_t len = read(cs->instance_fd, cs->buffer->buf, cs->buffer->len);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("fr_instance_read_response()");
		return -1;
	}

	// end of the response
	if (len == 0) {
		return 0;
	}

	cs->buffer_pos = 0;
	cs->buffer_len = len;
	// ok stop reading from the instance, and start writing to the client
	uwsgi_cr_hook_instance_read(cs, NULL);
	uwsgi_cr_hook_write(cs, fr_write_response);
	return len;
}

ssize_t fr_instance_send_request(struct corerouter_session * cs) {
	ssize_t len = write(cs->instance_fd, cs->buffer->buf + cs->buffer_pos, cs->uh.pktsize - cs->buffer_pos);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("fr_instance_send_request()");
		return -1;
	}

	cs->buffer_pos += len;

	// ok the request is sent, we can start sending client body (if any) and we can start waiting
	// for response
	if (cs->buffer_pos == cs->uh.pktsize) {
		cs->buffer_pos = 0;
		// stop writing to the instance
		uwsgi_cr_hook_instance_write(cs, NULL);
		// start reading from the instance
		uwsgi_cr_hook_instance_read(cs, fr_instance_read_response);
		// re-start reading from the client (for body or connection close)
		struct fastrouter_session *fs = (struct fastrouter_session *) cs;
		// allocate a buffer for client body (could be delimited or dynamic)
		fs->post_buf_max = UMAX16;
		if (cs->post_cl > 0) {
			fs->post_buf_max = UMIN(UMAX16, cs->post_cl);
		}
		fs->post_buf = uwsgi_buffer_new(fs->post_buf_max);
		if (!fs->post_buf)
			return -1;
		uwsgi_cr_hook_read(cs, fr_read_body);
	}

	return len;
}

ssize_t fr_instance_send_request_header(struct corerouter_session * cs) {
	ssize_t len = write(cs->instance_fd, &cs->uh + cs->buffer_pos, 4 - cs->buffer_pos);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("fr_instance_send_request_header()");
		return -1;
	}

	cs->buffer_pos += len;

	// ok the request is sent, we can start sending client body (if any) and we can start waiting
	// for response
	if (cs->buffer_pos == 4) {
		cs->buffer_pos = 0;
		uwsgi_cr_hook_instance_write(cs, fr_instance_send_request);
	}

	return len;
}

ssize_t fr_instance_connected(struct corerouter_session * cs) {

	cs->connecting = 0;

	socklen_t solen = sizeof(int);

	// first check for errors
	if (getsockopt(cs->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&cs->soopt), &solen) < 0) {
		uwsgi_error("fr_instance_connected()/getsockopt()");
		cs->instance_failed = 1;
		return -1;
	}

	if (cs->soopt) {
		cs->instance_failed = 1;
		return -1;
	}

	cs->buffer_pos = 0;

	// ok instance is connected, wait for write again
	if (cs->static_node) cs->static_node->custom2++;
	if (cs->un) cs->un->requests++;
	uwsgi_cr_hook_instance_write(cs, fr_instance_send_request_header);
	// return a value > 0
	return 1;
}

ssize_t fr_recv_uwsgi_vars(struct corerouter_session * cs) {
	// increase buffer if needed
	if (uwsgi_buffer_fix(cs->buffer, cs->uh.pktsize))
		return -1;
	ssize_t len = read(cs->fd, cs->buffer->buf + cs->buffer_pos, cs->uh.pktsize - cs->buffer_pos);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("fr_recv_uwsgi_vars()");
		return -1;
	}

	cs->buffer_pos += len;

	// headers received, ready to choose the instance
	if (cs->buffer_pos == cs->uh.pktsize) {
		struct uwsgi_corerouter *ucr = cs->corerouter;
		// find the hostname
		if (uwsgi_hooked_parse(cs->buffer->buf, cs->uh.pktsize, fr_get_hostname, (void *) cs)) {
			return -1;
		}
		// check the hostname;
		if (cs->hostname_len == 0)
			return -1;
		// find an instance using the key
		if (cs->corerouter->mapper(cs->corerouter, cs))
			return -1;
		// check instance
		if (cs->instance_address_len == 0) {
			// if fallback nodes are configured, trigger them
			if (ucr->fallback) {
				cs->instance_failed = 1;
			}
			return -1;
		}

		// stop receiving from the client
		uwsgi_cr_hook_read(cs, NULL);

		// start async connect
		cs->instance_fd = uwsgi_connectn(cs->instance_address, cs->instance_address_len, 0, 1);
		if (cs->instance_fd < 0) {
			cs->instance_failed = 1;
			cs->soopt = errno;
			return -1;
		}
		// map the instance
		cs->corerouter->cr_table[cs->instance_fd] = cs;
		// wait for connection
		cs->connecting = 1;
		uwsgi_cr_hook_instance_write(cs, fr_instance_connected);
	}

	return len;
}

ssize_t fr_recv_uwsgi_header(struct corerouter_session * cs) {
	ssize_t len = read(cs->fd, cs->buffer->buf + cs->buffer_pos, 4 - cs->buffer_pos);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("fr_recv_uwsgi_header()");
		return -1;
	}

	cs->buffer_pos += len;

	// header ready
	if (cs->buffer_pos == 4) {
		memcpy(&cs->uh, cs->buffer->buf, 4);
		cs->buffer_pos = 0;
		uwsgi_cr_hook_read(cs, fr_recv_uwsgi_vars);
	}

	return len;
}

void fr_session_close(struct corerouter_session *cs) {
	struct fastrouter_session *fr = (struct fastrouter_session *) cs;
	if (fr->post_buf) {
		uwsgi_buffer_destroy(fr->post_buf);
	}
}

void fastrouter_alloc_session(struct uwsgi_corerouter *ucr, struct uwsgi_gateway_socket *ugs, struct corerouter_session *cs, struct sockaddr *sa, socklen_t s_len) {
	cs->close = fr_session_close;
	// set the first hook
	uwsgi_cr_hook_read(cs, fr_recv_uwsgi_header);
}

int fastrouter_init() {

	ufr.cr.session_size = sizeof(struct fastrouter_session);
	ufr.cr.alloc_session = fastrouter_alloc_session;
	uwsgi_corerouter_init((struct uwsgi_corerouter *) &ufr);

	return 0;
}

void fastrouter_setup() {
	ufr.cr.name = uwsgi_str("uWSGI fastrouter");
	ufr.cr.short_name = uwsgi_str("fastrouter");
}


struct uwsgi_plugin fastrouter_plugin = {

	.name = "fastrouter",
	.options = fastrouter_options,
	.init = fastrouter_init,
	.on_load = fastrouter_setup
};
