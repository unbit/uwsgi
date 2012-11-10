/*

   uWSGI rawrouter

*/

#include "../../uwsgi.h"
#include "../corerouter/cr.h"

struct uwsgi_rawrouter {
	struct uwsgi_corerouter cr;
	int xclient;
} urr;

extern struct uwsgi_server uwsgi;

struct rawrouter_session {
	struct corerouter_session crs;
	in_addr_t ip_addr;
	// XCLIENT ADDR=xxx\r\n
	char xclient[13+INET_ADDRSTRLEN+2];
	size_t xclient_len;
	off_t xclient_pos;
	size_t xclient_remains;
	// placeholder for \r\n
	size_t xclient_rn;
};

struct uwsgi_option rawrouter_options[] = {
	{"rawrouter", required_argument, 0, "run the rawrouter on the specified port", uwsgi_opt_undeferred_corerouter, &urr, 0},
	{"rawrouter-processes", required_argument, 0, "prefork the specified number of rawrouter processes", uwsgi_opt_set_int, &urr.cr.processes, 0},
	{"rawrouter-workers", required_argument, 0, "prefork the specified number of rawrouter processes", uwsgi_opt_set_int, &urr.cr.processes, 0},
	{"rawrouter-zerg", required_argument, 0, "attach the rawrouter to a zerg server", uwsgi_opt_corerouter_zerg, &urr, 0},
	{"rawrouter-use-cache", no_argument, 0, "use uWSGI cache as hostname->server mapper for the rawrouter", uwsgi_opt_true, &urr.cr.use_cache, 0},

	{"rawrouter-use-pattern", required_argument, 0, "use a pattern for rawrouter hostname->server mapping", uwsgi_opt_corerouter_use_pattern, &urr, 0},
	{"rawrouter-use-base", required_argument, 0, "use a base dir for rawrouter hostname->server mapping", uwsgi_opt_corerouter_use_base, &urr, 0},

	{"rawrouter-fallback", required_argument, 0, "fallback to the specified node in case of error", uwsgi_opt_add_string_list, &urr.cr.fallback, 0},

	{"rawrouter-use-cluster", no_argument, 0, "load balance to nodes subscribed to the cluster", uwsgi_opt_true, &urr.cr.use_cluster, 0},

	{"rawrouter-use-code-string", required_argument, 0, "use code string as hostname->server mapper for the rawrouter", uwsgi_opt_corerouter_cs, &urr, 0},
	{"rawrouter-use-socket", optional_argument, 0, "forward request to the specified uwsgi socket", uwsgi_opt_corerouter_use_socket, &urr, 0},
	{"rawrouter-to", required_argument, 0, "forward requests to the specified uwsgi server (you can specify it multiple times for load balancing)", uwsgi_opt_add_string_list, &urr.cr.static_nodes, 0},
	{"rawrouter-gracetime", required_argument, 0, "retry connections to dead static nodes after the specified amount of seconds", uwsgi_opt_set_int, &urr.cr.static_node_gracetime, 0},
	{"rawrouter-events", required_argument, 0, "set the maximum number of concurrent events", uwsgi_opt_set_int, &urr.cr.nevents, 0},
	{"rawrouter-max-retries", required_argument, 0, "set the maximum number of retries/fallbacks to other nodes", uwsgi_opt_set_int, &urr.cr.max_retries, 0},
	{"rawrouter-quiet", required_argument, 0, "do not report failed connections to instances", uwsgi_opt_true, &urr.cr.quiet, 0},
	{"rawrouter-cheap", no_argument, 0, "run the rawrouter in cheap mode", uwsgi_opt_true, &urr.cr.cheap, 0},
	{"rawrouter-subscription-server", required_argument, 0, "run the rawrouter subscription server on the spcified address", uwsgi_opt_corerouter_ss, &urr, 0},
	{"rawrouter-subscription-slot", required_argument, 0, "*** deprecated ***", uwsgi_opt_deprecated, (void *) "useless thanks to the new implementation", 0},

	{"rawrouter-timeout", required_argument, 0, "set rawrouter timeout", uwsgi_opt_set_int, &urr.cr.socket_timeout, 0},

	{"rawrouter-stats", required_argument, 0, "run the rawrouter stats server", uwsgi_opt_set_str, &urr.cr.stats_server, 0},
	{"rawrouter-stats-server", required_argument, 0, "run the rawrouter stats server", uwsgi_opt_set_str, &urr.cr.stats_server, 0},
	{"rawrouter-ss", required_argument, 0, "run the rawrouter stats server", uwsgi_opt_set_str, &urr.cr.stats_server, 0},
	{"rawrouter-harakiri", required_argument, 0, "enable rawrouter harakiri", uwsgi_opt_set_int, &urr.cr.harakiri, 0},

	{"rawrouter-xclient", no_argument, 0, "use the xclient protocol to pass the client addres", uwsgi_opt_true, &urr.xclient, 0},

	{0, 0, 0, 0, 0, 0, 0},
};

ssize_t rr_instance_read(struct corerouter_session *);
ssize_t rr_read(struct corerouter_session *);

// write to backend
ssize_t rr_instance_write(struct corerouter_session * cs) {
	ssize_t len = write(cs->instance_fd, cs->buffer->buf + cs->buffer_pos, cs->buffer_len - cs->buffer_pos);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("fr_instance_write()");
		return -1;
	}

	cs->buffer_pos += len;

	// the chunk has been sent, start (again) reading from client and instance
	if (cs->buffer_pos == (ssize_t) cs->buffer_len) {
		uwsgi_cr_hook_instance_write(cs, NULL);
		uwsgi_cr_hook_instance_read(cs, rr_instance_read);
		uwsgi_cr_hook_read(cs, rr_read);
	}

	return len;
}

// write to client
ssize_t rr_write(struct corerouter_session * cs) {
	ssize_t len = write(cs->fd, cs->buffer->buf + cs->buffer_pos, cs->buffer_len - cs->buffer_pos);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("rr_write()");
		return -1;
	}

	cs->buffer_pos += len;

	// ok this response chunk is sent, let's wait for another one
	if (cs->buffer_pos == (ssize_t) cs->buffer_len) {
		uwsgi_cr_hook_write(cs, NULL);
		uwsgi_cr_hook_instance_read(cs, rr_instance_read);
	}

	return len;
}

ssize_t rr_instance_read(struct corerouter_session * cs) {
	ssize_t len = read(cs->instance_fd, cs->buffer->buf, cs->buffer->len);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("rr_instance_read()");
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
	uwsgi_cr_hook_write(cs, rr_write);
	return len;
}

ssize_t rr_xclient_write(struct corerouter_session *);

ssize_t rr_xclient_read(struct corerouter_session * cs) {
	struct rawrouter_session *rr = (struct rawrouter_session *) cs;
	cs->buffer_len = cs->buffer->len;
        ssize_t len = read(cs->instance_fd, cs->buffer->buf + cs->buffer_pos, cs->buffer_len - cs->buffer_pos);
	if (len < 0) {
                cr_try_again;
                uwsgi_error("rr_xclient_read()");
                return -1;
        }
	if (len == 0) return 0;

	char *ptr = cs->buffer->buf + cs->buffer_pos;
	ssize_t i;
	for(i=0;i<len;i++) {
		if (rr->xclient_rn == 1) {
			if (ptr[i] != '\n') {
				return -1;
			}
			// banner received
			cs->buffer_pos = len - (i+1);
			uwsgi_cr_hook_instance_read(cs, NULL);
			uwsgi_cr_hook_instance_write(cs, rr_xclient_write);
			return len;
		}
		else if (ptr[i] == '\r') {
			rr->xclient_rn = 1;
		}
	}

	cs->buffer_pos += len;
	return len;
}

ssize_t rr_xclient_write(struct corerouter_session * cs) {
	struct rawrouter_session *rr = (struct rawrouter_session *) cs;
	ssize_t len = write(cs->instance_fd, rr->xclient + rr->xclient_pos, rr->xclient_len - rr->xclient_pos);
	if (len < 0) {
                cr_try_again;
                uwsgi_error("rr_xclient_write()");
                return -1;
        }

	rr->xclient_pos += len;
	if (rr->xclient_pos == (ssize_t) rr->xclient_len) {
		uwsgi_cr_hook_instance_write(cs, NULL);
		if (cs->buffer_pos > 0) {
			// send remaining data...
			uwsgi_cr_hook_write(cs, rr_write);	
		}
		else {
			uwsgi_cr_hook_instance_read(cs, rr_instance_read);
			uwsgi_cr_hook_read(cs, rr_read);
		}
	}

	return len;
}

ssize_t rr_instance_connected(struct corerouter_session * cs) {

	cs->connecting = 0;

	socklen_t solen = sizeof(int);

	// first check for errors
	if (getsockopt(cs->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&cs->soopt), &solen) < 0) {
		uwsgi_error("rr_instance_connected()/getsockopt()");
		cs->instance_failed = 1;
		return -1;
	}

	if (cs->soopt) {
		cs->instance_failed = 1;
		return -1;
	}

	cs->buffer_pos = 0;

	// ok instance is connected, begin...
	if (cs->static_node) cs->static_node->custom2++;
	if (cs->un) cs->un->requests++;

	uwsgi_cr_hook_instance_write(cs, NULL);
	if (urr.xclient) {
		uwsgi_cr_hook_instance_read(cs, rr_xclient_read);
		return 1;
	}
	uwsgi_cr_hook_instance_read(cs, rr_instance_read);
	uwsgi_cr_hook_read(cs, rr_read);
	// return a value > 0
	return 1;
}

ssize_t rr_read(struct corerouter_session * cs) {
	ssize_t len = read(cs->fd, cs->buffer->buf, cs->buffer->len);
	if (len < 0) {
		cr_try_again;
		uwsgi_error("rr_recv()");
		return -1;
	}

	if (len == 0) return 0;

	cs->buffer_pos = 0;
	cs->buffer_len = len;

        uwsgi_cr_hook_read(cs, NULL);
        uwsgi_cr_hook_instance_read(cs, NULL);
        uwsgi_cr_hook_instance_write(cs, rr_instance_write);

	return len;
}

int rr_retry(struct uwsgi_corerouter *ucr, struct corerouter_session *cs) {

	if (cs->instance_address_len > 0) goto retry;

	if (ucr->mapper(ucr, cs)) {
                        cs->instance_failed = 1;
                        return -1;
                }

                if (cs->instance_address_len == 0) {
                        cs->instance_failed = 1;
                        return -1;
                }

retry:
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
	// wait for connection
        uwsgi_cr_hook_instance_write(cs, rr_instance_connected);
	return 0;
}

void rawrouter_alloc_session(struct uwsgi_corerouter *ucr, struct uwsgi_gateway_socket *ugs, struct corerouter_session *cs, struct sockaddr *sa, socklen_t s_len) {

	// use the address as hostname
        cs->hostname = cs->ugs->name;
        cs->hostname_len = cs->ugs->name_len;

	if (sa && sa->sa_family == AF_INET) {
		struct rawrouter_session *rr = (struct rawrouter_session *) cs;
                rr->ip_addr = ((struct sockaddr_in *) sa)->sin_addr.s_addr;
		if (urr.xclient) {
			if (!inet_ntop(AF_INET, &rr->ip_addr, rr->xclient+13, INET_ADDRSTRLEN)) {
                		uwsgi_error("rawrouter_alloc_session() -> inet_ntop()");
				cs->instance_failed = 1;
				return;
        		}
			// fix string
			size_t ip_addr_len = strlen(rr->xclient+13);
			memcpy(rr->xclient,"XCLIENT ADDR=", 13);
			rr->xclient[13+ip_addr_len] = '\r';
			rr->xclient[13+ip_addr_len+1] = '\n';
			rr->xclient_len = 13 + ip_addr_len + 2;
		}
        }

        // the mapper hook
        if (ucr->mapper(ucr, cs)) {
			cs->instance_failed = 1;
			return;
		}

                if (cs->instance_address_len == 0) {
                        cs->instance_failed = 1;
                        return;
                }

		// ok, now we could retry
		cs->retry = rr_retry;

                // start async connect
                cs->instance_fd = uwsgi_connectn(cs->instance_address, cs->instance_address_len, 0, 1);
                if (cs->instance_fd < 0) {
                        cs->instance_failed = 1;
                        cs->soopt = errno;
                        return;
                }
        // map the instance
        cs->corerouter->cr_table[cs->instance_fd] = cs;
        // wait for connection
	cs->connecting = 1;
        uwsgi_cr_hook_instance_write(cs, rr_instance_connected);
}

int rawrouter_init() {

	urr.cr.session_size = sizeof(struct rawrouter_session);
	urr.cr.alloc_session = rawrouter_alloc_session;
	uwsgi_corerouter_init((struct uwsgi_corerouter *) &urr);

	return 0;
}

void rawrouter_setup() {
	urr.cr.name = uwsgi_str("uWSGI rawrouter");
	urr.cr.short_name = uwsgi_str("rawrouter");
}


struct uwsgi_plugin rawrouter_plugin = {

	.name = "rawrouter",
	.options = rawrouter_options,
	.init = rawrouter_init,
	.on_load = rawrouter_setup
};
