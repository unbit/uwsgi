/*

   uWSGI httprouter

*/

#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include "../corerouter/cr.h"

struct uwsgi_http {

	struct uwsgi_corerouter cr;

	uint8_t modifier1;
	struct uwsgi_string_list *http_vars;
	int manage_expect;

	int raw_body;
	int keepalive;

#ifdef UWSGI_SSL
	char *https_session_context;
	int https_export_cert;
#endif

} uhttp;

#ifdef UWSGI_SSL

#define UWSGI_HTTP_NOSSL	0
#define UWSGI_HTTP_SSL		1
#define UWSGI_HTTP_FORCE_SSL	2

void uwsgi_opt_https(char *opt, char *value, void *cr) {
        struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;
        char *client_ca = NULL;

        // build socket, certificate and key file
        char *sock = uwsgi_str(value);
        char *crt = strchr(sock, ',');
        if (!crt) {
                uwsgi_log("invalid https syntax must be socket,crt,key\n");
                exit(1);
        }
        *crt = '\0'; crt++;
        char *key = strchr(crt, ',');
        if (!key) {
                uwsgi_log("invalid https syntax must be socket,crt,key\n");
                exit(1);
        }
        *key = '\0'; key++;

        char *ciphers = strchr(key, ',');
        if (ciphers) {
                *ciphers = '\0'; ciphers++;
                client_ca = strchr(ciphers, ',');
                if (client_ca) {
                        *client_ca = '\0'; client_ca++;
                }
        }

        struct uwsgi_gateway_socket *ugs = uwsgi_new_gateway_socket(sock, ucr->name);
        // ok we have the socket, initialize ssl if required
        if (!uwsgi.ssl_initialized) {
                uwsgi_ssl_init();
        }

        // initialize ssl context
	char *name = uhttp.https_session_context;
	if (!name) {
		name = uwsgi_concat3(ucr->short_name, "-", ugs->name);
	}
        ugs->ctx = uwsgi_ssl_new_server_context(name, crt, key, ciphers, client_ca);
	if (!ugs->ctx) {
		exit(1);
	}
        // set the ssl mode
        ugs->mode = UWSGI_HTTP_SSL;

        ucr->has_sockets++;
}

void uwsgi_opt_http_to_https(char *opt, char *value, void *cr) {
        struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;

        char *sock = uwsgi_str(value);
        char *port = strchr(sock, ',');
        if (port) {
                *port = '\0';
                port++;
        }

        struct uwsgi_gateway_socket *ugs = uwsgi_new_gateway_socket(sock, ucr->name);

        // set context to the port
        ugs->ctx = port;
        // force SSL mode
        ugs->mode = UWSGI_HTTP_FORCE_SSL;

        ucr->has_sockets++;
}

#endif

struct uwsgi_option http_options[] = {
	{"http", required_argument, 0, "add an http router/server on the specified address", uwsgi_opt_corerouter, &uhttp, 0},
#ifdef UWSGI_SSL
	{"https", required_argument, 0, "add an https router/server on the specified address with specified certificate and key", uwsgi_opt_https, &uhttp, 0},
	{"https-export-cert", no_argument, 0, "export uwsgi variable HTTPS_CC containing the raw client certificate", uwsgi_opt_true, &uhttp.https_export_cert, 0},
	{"https-session-context", required_argument, 0, "set the session id context to the specified value", uwsgi_opt_set_str, &uhttp.https_session_context, 0},
	{"http-to-https", required_argument, 0, "add an http router/server on the specified address and redirect all of the requests to https", uwsgi_opt_http_to_https, &uhttp, 0},
#endif
	{"http-processes", required_argument, 0, "set the number of http processes to spawn", uwsgi_opt_set_int, &uhttp.cr.processes, 0},
	{"http-workers", required_argument, 0, "set the number of http processes to spawn", uwsgi_opt_set_int, &uhttp.cr.processes, 0},
	{"http-var", required_argument, 0, "add a key=value item to the generated uwsgi packet", uwsgi_opt_add_string_list, &uhttp.http_vars, 0},
	{"http-to", required_argument, 0, "forward requests to the specified node (you can specify it multiple time for lb)", uwsgi_opt_add_string_list, &uhttp.cr.static_nodes, 0 },
	{"http-zerg", required_argument, 0, "attach the http router to a zerg server", uwsgi_opt_corerouter_zerg, &uhttp, 0 },
	{"http-fallback", required_argument, 0, "fallback to the specified node in case of error", uwsgi_opt_add_string_list, &uhttp.cr.fallback, 0},
	{"http-modifier1", required_argument, 0, "set uwsgi protocol modifier1", uwsgi_opt_set_int, &uhttp.modifier1, 0},
	{"http-use-cache", no_argument, 0, "use uWSGI cache as key->value virtualhost mapper", uwsgi_opt_true, &uhttp.cr.use_cache, 0},
	{"http-use-pattern", required_argument, 0, "use the specified pattern for mapping requests to unix sockets", uwsgi_opt_corerouter_use_pattern, &uhttp, 0},
	{"http-use-base", required_argument, 0, "use the specified base for mapping requests to unix sockets", uwsgi_opt_corerouter_use_base, &uhttp, 0},
	{"http-use-cluster", no_argument, 0, "load balance to nodes subscribed to the cluster", uwsgi_opt_true, &uhttp.cr.use_cluster, 0},
	{"http-events", required_argument, 0, "set the number of concurrent http async events", uwsgi_opt_set_int, &uhttp.cr.nevents, 0},
	{"http-subscription-server", required_argument, 0, "enable the subscription server", uwsgi_opt_corerouter_ss, &uhttp, 0},
	{"http-timeout", required_argument, 0, "set internal http socket timeout", uwsgi_opt_set_int, &uhttp.cr.socket_timeout, 0},
	{"http-manage-expect", no_argument, 0, "manage the Expect HTTP request header", uwsgi_opt_true, &uhttp.manage_expect, 0},
	{"http-keepalive", no_argument, 0, "experimental HTTP keepalive support (non-pipelined) requests (requires backend support)", uwsgi_opt_true, &uhttp.keepalive, 0},

	{"http-raw-body", no_argument, 0, "blindly send HTTP body to backends (required for WebSockets and Icecast support)", uwsgi_opt_true, &uhttp.raw_body, 0},

	{"http-use-code-string", required_argument, 0, "use code string as hostname->server mapper for the http router", uwsgi_opt_corerouter_cs, &uhttp, 0},
        {"http-use-socket", optional_argument, 0, "forward request to the specified uwsgi socket", uwsgi_opt_corerouter_use_socket, &uhttp, 0},
        {"http-gracetime", required_argument, 0, "retry connections to dead static nodes after the specified amount of seconds", uwsgi_opt_set_int, &uhttp.cr.static_node_gracetime, 0},

	{"http-quiet", required_argument, 0, "do not report failed connections to instances", uwsgi_opt_true, &uhttp.cr.quiet, 0},
        {"http-cheap", no_argument, 0, "run the http router in cheap mode", uwsgi_opt_true, &uhttp.cr.cheap, 0},

	{"http-stats", required_argument, 0, "run the http router stats server", uwsgi_opt_set_str, &uhttp.cr.stats_server, 0},
	{"http-stats-server", required_argument, 0, "run the http router stats server", uwsgi_opt_set_str, &uhttp.cr.stats_server, 0},
	{"http-ss", required_argument, 0, "run the http router stats server", uwsgi_opt_set_str, &uhttp.cr.stats_server, 0},
	{"http-harakiri", required_argument, 0, "enable http router harakiri", uwsgi_opt_set_int, &uhttp.cr.harakiri, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

struct http_session {

	struct corerouter_session cs;

	int rnrn;

	char *port;
	int port_len;

	char *request_uri;
	uint16_t request_uri_len;

	char *path_info;
	uint16_t path_info_len;

	size_t received_body;

#ifdef UWSGI_SSL
	SSL *ssl;
	X509 *ssl_client_cert;
	char *ssl_client_dn;
	BIO *ssl_bio;
	char *ssl_cc;
	int force_ssl;
	struct uwsgi_buffer *force_ssl_buf;
#endif

	struct uwsgi_buffer *uwsgi_req;
	int send_expect_100;

	in_addr_t ip_addr;
	char ip[INET_ADDRSTRLEN];

	struct uwsgi_buffer *post_buf;
        size_t post_buf_max;
        size_t post_buf_len;
        off_t post_buf_pos;


};

#ifdef UWSGI_SSL
int uwsgi_http_ssl_shutdown(struct http_session *, int);
#endif

int http_add_uwsgi_header(struct http_session *hs, char *hh, uint16_t hhlen) {

	struct corerouter_session *cs = &hs->cs;
	struct uwsgi_buffer *buf = hs->uwsgi_req;

	int i;
	int status = 0;
	char *val = hh;
	uint16_t keylen = 0, vallen = 0;
	int prefix = 0;
	char strsize[2];

	for (i = 0; i < hhlen; i++) {
		if (!status) {
			hh[i] = toupper((int) hh[i]);
			if (hh[i] == '-')
				hh[i] = '_';
			if (hh[i] == ':') {
				status = 1;
				keylen = i;
			}
		}
		else if (status == 1 && hh[i] != ' ') {
			status = 2;
			val += i;
			vallen++;
		}
		else if (status == 2) {
			vallen++;
		}
	}

	if (!keylen)
		return -1;

	if (!uwsgi_strncmp("HOST", 4, hh, keylen)) {
		cs->hostname = val;
		cs->hostname_len = vallen;
	}

	if (!uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		cs->post_cl = uwsgi_str_num(val, vallen);
	}

	if (uwsgi_strncmp("CONTENT_TYPE", 12, hh, keylen) && uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		keylen += 5;
		prefix = 1;
	}

	strsize[0] = (uint8_t) (keylen & 0xff);
	strsize[1] = (uint8_t) ((keylen >> 8) & 0xff);

	if (uwsgi_buffer_append(buf, strsize, 2)) return -1;

	if (prefix) {
		if (uwsgi_buffer_append(buf, "HTTP_", 5)) return -1;
	}

	if (uwsgi_buffer_append(buf, hh, keylen - (prefix * 5))) return -1;

	strsize[0] = (uint8_t) (vallen & 0xff);
	strsize[1] = (uint8_t) ((vallen >> 8) & 0xff);

	if (uwsgi_buffer_append(buf, strsize, 2)) return -1;
	if (uwsgi_buffer_append(buf, val, vallen)) return -1;

	return 0;
}


int http_add_uwsgi_var(struct http_session *hs, char *key, uint16_t keylen, char *val, uint16_t vallen) {

	struct uwsgi_buffer *buf = hs->uwsgi_req;
	char strsize[2];

	strsize[0] = (uint8_t) (keylen & 0xff);
	strsize[1] = (uint8_t) ((keylen >> 8) & 0xff);

	if (uwsgi_buffer_append(buf, strsize, 2)) return -1;
        if (uwsgi_buffer_append(buf, key, keylen)) return -1;

	strsize[0] = (uint8_t) (vallen & 0xff);
	strsize[1] = (uint8_t) ((vallen >> 8) & 0xff);

	if (uwsgi_buffer_append(buf, strsize, 2)) return -1;
        if (uwsgi_buffer_append(buf, val, vallen)) return -1;

	return 0;
}

int http_parse(struct http_session *h_session, size_t http_req_len) {

	char *ptr = h_session->cs.buffer->buf;
	char *watermark = ptr + http_req_len;
	char *base = ptr;
	char *query_string = NULL;

	h_session->uwsgi_req = uwsgi_buffer_new(uwsgi.page_size);
	if (!h_session->uwsgi_req) return -1;
	h_session->uwsgi_req->limit = UMAX16;

	// REQUEST_METHOD 
	while (ptr < watermark) {
		if (*ptr == ' ') {
			if (http_add_uwsgi_var(h_session, "REQUEST_METHOD", 14, base, ptr - base)) return -1;
			ptr++;
			break;
		}
		ptr++;
	}

	// REQUEST_URI / PATH_INFO / QUERY_STRING
	base = ptr;
	while (ptr < watermark) {
		if (*ptr == '?' && !query_string) {
			// PATH_INFO must be url-decoded !!!
			h_session->path_info_len = ptr - base;
			h_session->path_info = uwsgi_malloc(h_session->path_info_len);
			http_url_decode(base, &h_session->path_info_len, h_session->path_info);
			if (http_add_uwsgi_var(h_session, "PATH_INFO", 9, h_session->path_info, h_session->path_info_len)) return -1;
			query_string = ptr + 1;
		}
		else if (*ptr == ' ') {
			h_session->request_uri = base;
			h_session->request_uri_len = ptr - base;
			if (http_add_uwsgi_var(h_session, "REQUEST_URI", 11, base, ptr - base)) return -1;
			if (!query_string) {
				// PATH_INFO must be url-decoded !!!
				h_session->path_info_len = ptr - base;
				h_session->path_info = uwsgi_malloc(h_session->path_info_len);
				http_url_decode(base, &h_session->path_info_len, h_session->path_info);
				if (http_add_uwsgi_var(h_session, "PATH_INFO", 9, h_session->path_info, h_session->path_info_len)) return -1;
				if (http_add_uwsgi_var(h_session, "QUERY_STRING", 12, "", 0)) return -1;
			}
			else {
				if (http_add_uwsgi_var(h_session, "QUERY_STRING", 12, query_string, ptr - query_string)) return -1;
			}
			ptr++;
			break;
		}
		ptr++;
	}

	// SERVER_PROTOCOL
	base = ptr;
	while (ptr < watermark) {
		if (*ptr == '\r') {
			if (ptr + 1 >= watermark)
				return 0;
			if (*(ptr + 1) != '\n')
				return 0;
			if (http_add_uwsgi_var(h_session, "SERVER_PROTOCOL", 15, base, ptr - base)) return -1;
			ptr += 2;
			break;
		}
		ptr++;
	}

	// SCRIPT_NAME
	if (http_add_uwsgi_var(h_session, "SCRIPT_NAME", 11, "", 0)) return -1;

	// SERVER_NAME
	if (http_add_uwsgi_var(h_session, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len)) return -1;
	h_session->cs.hostname = uwsgi.hostname;
	h_session->cs.hostname_len = uwsgi.hostname_len;

	// SERVER_PORT
	if (http_add_uwsgi_var(h_session, "SERVER_PORT", 11, h_session->port, h_session->port_len)) return -1;

	// UWSGI_ROUTER
	if (http_add_uwsgi_var(h_session, "UWSGI_ROUTER", 12, "http", 4)) return -1;

#ifdef UWSGI_SSL
	// HTTPS (adapted from nginx)
	if (h_session->cs.ugs->mode == UWSGI_HTTP_SSL) {
		if (http_add_uwsgi_var(h_session, "HTTPS", 5, "on", 2)) return -1;
		h_session->ssl_client_cert = SSL_get_peer_certificate(h_session->ssl);
		if (h_session->ssl_client_cert) {
			X509_NAME *name = X509_get_subject_name(h_session->ssl_client_cert);
			if (name) {
				h_session->ssl_client_dn = X509_NAME_oneline(name, NULL, 0);
				if (http_add_uwsgi_var(h_session, "HTTPS_DN", 8, h_session->ssl_client_dn, strlen(h_session->ssl_client_dn))) return -1;
			}
			if (uhttp.https_export_cert) {
			h_session->ssl_bio = BIO_new(BIO_s_mem());
			if (h_session->ssl_bio) {
				if (PEM_write_bio_X509(h_session->ssl_bio, h_session->ssl_client_cert) > 0) {
					size_t cc_len = BIO_pending(h_session->ssl_bio);
					h_session->ssl_cc = uwsgi_malloc(cc_len);
					BIO_read(h_session->ssl_bio, h_session->ssl_cc, cc_len);
					if (http_add_uwsgi_var(h_session, "HTTPS_CC", 8, h_session->ssl_cc, cc_len)) return -1;
				}
			}
			}
		}
	}
	else if (h_session->cs.ugs->mode == UWSGI_HTTP_FORCE_SSL) {
		h_session->force_ssl = 1;
	}
#endif

	// REMOTE_ADDR
	if (inet_ntop(AF_INET, &h_session->ip_addr, h_session->ip, INET_ADDRSTRLEN)) {
		if (http_add_uwsgi_var(h_session, "REMOTE_ADDR", 11, h_session->ip, strlen(h_session->ip))) return -1;
	}
	else {
		uwsgi_error("inet_ntop()");
	}


	//HEADERS

	base = ptr;

	while (ptr < watermark) {
		if (*ptr == '\r') {
			if (ptr + 1 >= watermark)
				break;
			if (*(ptr + 1) != '\n')
				break;
			// multiline header ?
			if (ptr + 2 < watermark) {
				if (*(ptr + 2) == ' ' || *(ptr + 2) == '\t') {
					ptr += 2;
					continue;
				}
			}

			// this is an hack with dumb/wrong/useless error checking
			if (uhttp.manage_expect) {
				if (!uwsgi_strncmp("Expect: 100-continue", 20, base, ptr - base)) {
					h_session->send_expect_100 = 1;
				}
			}
			if (http_add_uwsgi_header(h_session, base, ptr - base)) return -1;
			ptr++;
			base = ptr + 1;
		}
		ptr++;
	}

	struct uwsgi_string_list *hv = uhttp.http_vars;
	while (hv) {
		char *equal = strchr(hv->value, '=');
		if (equal) {
			if (http_add_uwsgi_var(h_session, hv->value, equal - hv->value, equal + 1, strlen(equal + 1))) return -1;
		}
		hv = hv->next;
	}

	return 0;

}

ssize_t hr_instance_read_response(struct corerouter_session *);
ssize_t hr_read_body(struct corerouter_session *);
#ifdef UWSGI_SSL
ssize_t hr_read_ssl_body(struct corerouter_session *);

ssize_t hr_send_force_https(struct corerouter_session * cs) {
	struct http_session *hs = (struct http_session *) cs;

	if (!hs->force_ssl_buf) {
		hs->force_ssl_buf = uwsgi_buffer_new(uwsgi.page_size);
        	if (!hs->force_ssl_buf) return -1;
		if (uwsgi_buffer_append(hs->force_ssl_buf, "HTTP/1.0 301 Moved Permanently\r\nLocation: https://", 50)) return -1;		
		char *colon = memchr(cs->hostname, ':', cs->hostname_len);
		if (colon) {
			if (uwsgi_buffer_append(hs->force_ssl_buf, cs->hostname, colon-cs->hostname)) return -1;
		}
		else {
			if (uwsgi_buffer_append(hs->force_ssl_buf, cs->hostname, cs->hostname_len)) return -1;
		}
		if (cs->ugs->ctx) {
			if (uwsgi_buffer_append(hs->force_ssl_buf, ":", 1)) return -1;
			if (uwsgi_buffer_append(hs->force_ssl_buf,cs->ugs->ctx, strlen(cs->ugs->ctx))) return -1;
		}
		if (uwsgi_buffer_append(hs->force_ssl_buf, hs->request_uri, hs->request_uri_len)) return -1;
		if (uwsgi_buffer_append(hs->force_ssl_buf, "\r\n\r\n", 4)) return -1;
	}

        ssize_t len = write(cs->fd, hs->force_ssl_buf->buf + cs->buffer_pos, hs->force_ssl_buf->pos - cs->buffer_pos);
        if (len < 0) {
        	cr_try_again;
                uwsgi_error("hr_send_force_https()");
                return -1;
	}

        cs->buffer_pos += len;
	if (cs->buffer_pos == hs->force_ssl_buf->pos) {
		return 0;
	}
	return len;
}

#endif

ssize_t hr_write_body(struct corerouter_session * cs) {
	struct http_session *hs = (struct http_session *) cs;
        ssize_t len = write(cs->instance_fd, hs->post_buf->buf + hs->post_buf_pos, hs->post_buf_len - hs->post_buf_pos);
        if (len < 0) {
                cr_try_again;
                uwsgi_error("hr_write_body()");
                return -1;
        }

        hs->post_buf_pos += len;

        // the body chunk has been sent, start again reading from client and instance
        if (hs->post_buf_pos == (ssize_t) hs->post_buf_len) {
                uwsgi_cr_hook_instance_write(cs, NULL);
                uwsgi_cr_hook_instance_read(cs, hr_instance_read_response);
#ifdef UWSGI_SSL
		if (!hs->ssl) {
#endif
                	uwsgi_cr_hook_read(cs, hr_read_body);
#ifdef UWSGI_SSL
		}
		else {
                	uwsgi_cr_hook_read(cs, hr_read_ssl_body);
		}
#endif
        }

        return len;
}

#ifdef UWSGI_SSL
ssize_t hr_read_ssl_body(struct corerouter_session * cs) {
        struct http_session *hs = (struct http_session *) cs;
        int ret = SSL_read(hs->ssl, hs->post_buf->buf, hs->post_buf_max);
        if (ret > 0) {
                // fix waiting
                if (cs->event_hook_write) {
                        uwsgi_cr_hook_write(cs, NULL);
                }
		int ret2 = SSL_pending(hs->ssl);
                if (ret2 > 0) {
			if (uwsgi_buffer_fix(hs->post_buf, hs->post_buf->len + ret2 )) return -1;
                        if (SSL_read(hs->ssl, hs->post_buf->buf + ret, ret2) != ret2) {
                                return -1;
                        }
                        ret += ret2;
                }
		hs->post_buf_len = ret;
        	hs->post_buf_pos = 0;
                uwsgi_cr_hook_read(cs, NULL);
		uwsgi_cr_hook_instance_read(cs, NULL);
        	uwsgi_cr_hook_instance_write(cs, hr_write_body);
		return ret;
        }
        if (ret == 0) return 0;
        int err = SSL_get_error(hs->ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
                if (cs->event_hook_write) {
                        uwsgi_cr_hook_write(cs, NULL);
                        uwsgi_cr_hook_read(cs, hr_read_ssl_body);
                }
                errno = EINPROGRESS;
                return -1;
        }

        else if (err == SSL_ERROR_WANT_WRITE) {
                if (cs->event_hook_read) {
                        uwsgi_cr_hook_read(cs, NULL);
                        uwsgi_cr_hook_write(cs, hr_read_ssl_body);
                }
                errno = EINPROGRESS;
                return -1;
        }

        else if (err == SSL_ERROR_SYSCALL) {
                uwsgi_error("hr_read_ssl_body()");
        }

        else if (err == SSL_ERROR_SSL && uwsgi.ssl_verbose) {
                ERR_print_errors_fp(stderr);
        }

        return -1;
}
#endif



ssize_t hr_read_body(struct corerouter_session * cs) {
        struct http_session *hs = (struct http_session *) cs;
        ssize_t len = read(cs->fd, hs->post_buf->buf, hs->post_buf_max);
        if (len < 0) {
                cr_try_again;
                uwsgi_error("hr_read_body()");
                return -1;
        }

        // connection closed
        if (len == 0)
                return 0;

        hs->post_buf_len = len;
        hs->post_buf_pos = 0;

        // ok we have a body, stop reading from the client and the instance and start writing to the instance
        uwsgi_cr_hook_read(cs, NULL);
        uwsgi_cr_hook_instance_read(cs, NULL);
        uwsgi_cr_hook_instance_write(cs, hr_write_body);

        return len;
}

#ifdef UWSGI_SSL
ssize_t hr_write_ssl_response(struct corerouter_session * cs) {
	struct http_session *hs = (struct http_session *) cs;
        int ret = SSL_write(hs->ssl, cs->buffer->buf + cs->buffer_pos, cs->buffer_len - cs->buffer_pos);

	if (ret > 0) {
        	cs->buffer_pos += ret;
		if (cs->event_hook_read) {
			uwsgi_cr_hook_read(cs, NULL);
		}
		// could be a partial write
		uwsgi_cr_hook_write(cs, hr_write_ssl_response);
        	// ok this response chunk is sent, let's wait for another one
        	if (cs->buffer_pos == (ssize_t) cs->buffer_len) {
                	uwsgi_cr_hook_write(cs, NULL);
                	uwsgi_cr_hook_instance_read(cs, hr_instance_read_response);
        	}
		return ret;
	}

	int err = SSL_get_error(hs->ssl, ret);
        if (err == SSL_ERROR_WANT_READ) {
		if (cs->event_hook_write) {
			uwsgi_cr_hook_write(cs, NULL);
			uwsgi_cr_hook_read(cs, hr_write_ssl_response);
		}
                errno = EINPROGRESS;
                return -1;
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
		if (cs->event_hook_read) {
			uwsgi_cr_hook_read(cs, NULL);
			uwsgi_cr_hook_write(cs, hr_write_ssl_response);
		}
                errno = EINPROGRESS;
                return -1;
        }

        else if (err == SSL_ERROR_SYSCALL) {
                uwsgi_error("hr_write_ssl_response()");
        }

        else if (err == SSL_ERROR_SSL && uwsgi.ssl_verbose) {
                ERR_print_errors_fp(stderr);
        }

        else if (err == SSL_ERROR_ZERO_RETURN) {
                return 0;
        }

        return -1;
}
#endif

ssize_t hr_write_response(struct corerouter_session * cs) {
        ssize_t len = write(cs->fd, cs->buffer->buf + cs->buffer_pos, cs->buffer_len - cs->buffer_pos);
        if (len < 0) {
                cr_try_again;
                uwsgi_error("hr_write_response()");
                return -1;
        }

        cs->buffer_pos += len;

        // ok this response chunk is sent, let's wait for another one
        if (cs->buffer_pos == (ssize_t) cs->buffer_len) {
                uwsgi_cr_hook_write(cs, NULL);
                uwsgi_cr_hook_instance_read(cs, hr_instance_read_response);
        }

        return len;
}


ssize_t hr_instance_read_response(struct corerouter_session * cs) {
        ssize_t len = read(cs->instance_fd, cs->buffer->buf, cs->buffer->len);
        if (len < 0) {
                cr_try_again;
                uwsgi_error("hr_instance_read_response()");
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
#ifdef UWSGI_SSL
	struct http_session *hs = (struct http_session *) cs;
	if (!hs->ssl) {
#endif
        	uwsgi_cr_hook_write(cs, hr_write_response);
#ifdef UWSGI_SSL
	}
	else {
        	uwsgi_cr_hook_write(cs, hr_write_ssl_response);
	}
#endif
        return len;
}

int hr_start_waiting(struct corerouter_session * cs) {
	struct http_session *hs = (struct http_session *) cs;
	// stop writing to the instance
                uwsgi_cr_hook_instance_write(cs, NULL);
                // start reading from the instance
                uwsgi_cr_hook_instance_read(cs, hr_instance_read_response);
                // re-start reading from the client (for body or connection close)
                // allocate a buffer for client body (could be delimited or dynamic)
                hs->post_buf_max = UMAX16;
                if (cs->post_cl > 0) {
                        hs->post_buf_max = UMIN(UMAX16, cs->post_cl);
                }
                hs->post_buf = uwsgi_buffer_new(hs->post_buf_max);
                if (!hs->post_buf)
                        return -1;
#ifdef UWSGI_SSL
		if (!hs->ssl) {
#endif
               		uwsgi_cr_hook_read(cs, hr_read_body);
#ifdef UWSGI_SSL
		}
		else {
               		uwsgi_cr_hook_read(cs, hr_read_ssl_body);
		}
#endif
	return 0;
}

ssize_t hr_post_remains(struct corerouter_session * cs) {
	char *ptr = (cs->buffer->buf + cs->buffer->pos) - cs->post_remains;
	ssize_t len = write(cs->instance_fd, ptr + cs->buffer_pos, cs->post_remains - cs->buffer_pos);
	if (len < 0) {
                cr_try_again;
                uwsgi_error("hr_post_remains()");
                return -1;
        }

	cs->buffer_pos += len;
	if (cs->buffer_pos == (ssize_t) cs->post_remains) {
		if (hr_start_waiting(cs)) return -1;
	}

	return len;
}

ssize_t hr_instance_send_request(struct corerouter_session * cs) {
	struct http_session *hs = (struct http_session *) cs;
        ssize_t len = write(cs->instance_fd, hs->uwsgi_req->buf + cs->buffer_pos, cs->uh.pktsize - cs->buffer_pos);
        if (len < 0) {
                cr_try_again;
                uwsgi_error("hr_instance_send_request()");
                return -1;
        }

        cs->buffer_pos += len;

        // ok the request is sent, we can start sending client body (if any) and we can start waiting
        // for response
        if (cs->buffer_pos == cs->uh.pktsize) {
                cs->buffer_pos = 0;
		// some HTTP body left ?
		if (cs->post_remains > 0) {
			uwsgi_cr_hook_instance_write(cs, hr_post_remains);
			return len;
		}
		if (hr_start_waiting(cs)) return -1;
        }

        return len;
}


ssize_t hr_instance_send_request_header(struct corerouter_session * cs) {
#ifdef __BIG_ENDIAN__
	// on the first round fix endianess
	if (cs->buffer_pos == 0) {
		cs->uh.pktsize = uwsgi_swap16(cs->uh.pktsize);
	}
#endif
        ssize_t len = write(cs->instance_fd, &cs->uh + cs->buffer_pos, 4 - cs->buffer_pos);
        if (len < 0) {
                cr_try_again;
                uwsgi_error("hr_instance_send_request_header()");
                return -1;
        }

        cs->buffer_pos += len;

        // ok the request is sent, we can start sending client body (if any) and we can start waiting
        // for response
        if (cs->buffer_pos == 4) {
                cs->buffer_pos = 0;
#ifdef __BIG_ENDIAN__
	// on the last round restore endianess
		cs->uh.pktsize = uwsgi_swap16(cs->uh.pktsize);
#endif
                uwsgi_cr_hook_instance_write(cs, hr_instance_send_request);
        }

        return len;
}

ssize_t hr_send_expect_continue(struct corerouter_session * cs) {
	char *msg = "HTTP/1.0 100 Continue\r\n\r\n" ;
	ssize_t len;

#ifdef UWSGI_SSL
	struct http_session *hs = (struct http_session *) cs;
	if (!hs->ssl) {
#endif
		len = write(cs->fd, msg + cs->buffer_pos, 25 - cs->buffer_pos);
		if (len < 0) {
			cr_try_again;
                	uwsgi_error("hr_send_expect_continue()");
                	return -1;
		}

		cs->buffer_pos += len;
#ifdef UWSGI_SSL
	}
	else {
		int ret = SSL_write(hs->ssl, msg + cs->buffer_pos, 25 - cs->buffer_pos);
		if (ret > 0) {
			len = ret;
			cs->buffer_pos += ret;
			if (cs->event_hook_read) {
                        	uwsgi_cr_hook_read(cs, NULL);
                	}
                	// could be a partial write
                	uwsgi_cr_hook_write(cs, hr_send_expect_continue);
			goto done;
		}
		int err = SSL_get_error(hs->ssl, ret);
        	if (err == SSL_ERROR_WANT_READ) {
                	if (cs->event_hook_write) {
                        	uwsgi_cr_hook_write(cs, NULL);
                        	uwsgi_cr_hook_read(cs, hr_write_ssl_response);
                	}
                	errno = EINPROGRESS;
                	return -1;
        	}
        	else if (err == SSL_ERROR_WANT_WRITE) {
                	if (cs->event_hook_read) {
                        	uwsgi_cr_hook_read(cs, NULL);
                        	uwsgi_cr_hook_write(cs, hr_write_ssl_response);
                	}
                	errno = EINPROGRESS;
                	return -1;
        	}

        	else if (err == SSL_ERROR_SYSCALL) {
                	uwsgi_error("hr_write_ssl_response()");
        	}

        	else if (err == SSL_ERROR_SSL && uwsgi.ssl_verbose) {
                	ERR_print_errors_fp(stderr);
        	}

        	else if (err == SSL_ERROR_ZERO_RETURN) {
                	return 0;
        	}

        	return -1;
	}
done:
#endif

	if (cs->buffer_pos == 25) {
		cs->buffer_pos = 0;
		uwsgi_cr_hook_write(cs, NULL);
		uwsgi_cr_hook_instance_write(cs, hr_instance_send_request_header);
	}

	return len;
}

ssize_t hr_instance_connected(struct corerouter_session * cs) {

	cs->connecting = 0;
	socklen_t solen = sizeof(int);

        // first check for errors
        if (getsockopt(cs->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&cs->soopt), &solen) < 0) {
                uwsgi_error("hr_instance_connected()/getsockopt()");
                cs->instance_failed = 1;
                return -1;
        }

        if (cs->soopt) {
                cs->instance_failed = 1;
                return -1;
        }

        cs->buffer_pos = 0;
	cs->uh.modifier1 = cs->modifier1;
	cs->uh.modifier2 = 0;
	struct http_session *hs = (struct http_session *) cs;
	cs->uh.pktsize = hs->uwsgi_req->pos;

	// check for expect/continue
	if (hs->send_expect_100) {
        	uwsgi_cr_hook_write(cs, hr_send_expect_continue);
		return 1;
	}
        // ok instance is connected, wait for write again
	if (cs->static_node) cs->static_node->custom2++;
        if (cs->un) cs->un->requests++;
        uwsgi_cr_hook_instance_write(cs, hr_instance_send_request_header);
        // return a value > 0
        return 1;
}

ssize_t hs_http_manage(struct corerouter_session *, ssize_t);

#ifdef UWSGI_SSL
ssize_t hr_recv_http_ssl(struct corerouter_session * cs) {
	// be sure buffer does not grow over 64k
        cs->buffer->limit = UMAX16;
        // try to always leave 4k available
        if (uwsgi_buffer_ensure(cs->buffer, uwsgi.page_size)) return -1;
	struct http_session *hs = (struct http_session *) cs;
	int ret = SSL_read(hs->ssl, cs->buffer->buf + cs->buffer_pos, cs->buffer->len - cs->buffer_pos);
	if (ret > 0) {
		// fix waiting
		if (cs->event_hook_write) {
			uwsgi_cr_hook_write(cs, NULL);
			uwsgi_cr_hook_read(cs, hr_recv_http_ssl);
		}
		int ret2 = SSL_pending(hs->ssl);
		if (ret2 > 0) {
			if (uwsgi_buffer_fix(cs->buffer, cs->buffer->len + ret2 )) return -1;
			if (SSL_read(hs->ssl, cs->buffer->buf + cs->buffer_pos + ret, ret2) != ret2) {
				return -1;
			}
			ret += ret2;
		}
		return hs_http_manage(cs, ret);
	}
	if (ret == 0) return 0;
	int err = SSL_get_error(hs->ssl, ret);
	
	if (err == SSL_ERROR_WANT_READ) {
                if (cs->event_hook_write) {
                        uwsgi_cr_hook_write(cs, NULL);
                        uwsgi_cr_hook_read(cs, hr_recv_http_ssl);
                }
                errno = EINPROGRESS;
                return -1;
        }

        else if (err == SSL_ERROR_WANT_WRITE) {
                if (cs->event_hook_read) {
                        uwsgi_cr_hook_read(cs, NULL);
                        uwsgi_cr_hook_write(cs, hr_recv_http_ssl);
                }
                errno = EINPROGRESS;
                return -1;
        }

        else if (err == SSL_ERROR_SYSCALL) {
                uwsgi_error("hr_recv_http_ssl()");
        }

        else if (err == SSL_ERROR_SSL && uwsgi.ssl_verbose) {
                ERR_print_errors_fp(stderr);
        }

        return -1;
}
#endif

ssize_t hr_recv_http(struct corerouter_session * cs) {
	// be sure buffer does not grow over 64k
	cs->buffer->limit = UMAX16;
	// try to always leave 4k available
	if (uwsgi_buffer_ensure(cs->buffer, uwsgi.page_size)) return -1;
	ssize_t len = read(cs->fd, cs->buffer->buf + cs->buffer_pos, cs->buffer->len - cs->buffer_pos);
	if (len < 0) {
		cr_try_again;
                uwsgi_error("hr_recv_http()");
                return -1;
        }
	return hs_http_manage(cs, len);
}

ssize_t hs_http_manage(struct corerouter_session * cs, ssize_t len) {
	// fix buffer usage (TODO a bit ugly...)
	cs->buffer->pos += len;

	// read until \r\n\r\n is found
	int j;
	char *ptr = cs->buffer->buf + cs->buffer_pos;
	struct http_session *hs = (struct http_session *) cs;
	cs->buffer_pos += len;
	for (j = 0; j < len; j++) {
		if (*ptr == '\r' && (hs->rnrn == 0 || hs->rnrn == 2)) {
			hs->rnrn++;
		}
		else if (*ptr == '\r') {
			hs->rnrn = 1;
		}
		else if (*ptr == '\n' && hs->rnrn == 1) {
			hs->rnrn = 2;
		}
		else if (*ptr == '\n' && hs->rnrn == 3) {
			cs->post_remains = len - (j + 1);
			// parse HTTP request
			size_t http_req_len = (cs->buffer_pos-len)+j;
			if (http_parse(hs, http_req_len)) return -1;
			// check for a valid hostname
			if (cs->hostname_len == 0) return -1;

#ifdef UWSGI_SSL
			if (hs->force_ssl) {
				cs->buffer_pos = 0;
                		uwsgi_cr_hook_read(cs, NULL);
                		uwsgi_cr_hook_write(cs, hr_send_force_https);
				break;
			}
#endif

			// get instance name
			if (cs->corerouter->mapper(cs->corerouter, cs))
				return -1;

			struct uwsgi_corerouter *ucr = cs->corerouter;

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
                	uwsgi_cr_hook_instance_write(cs, hr_instance_connected);
			break;
		}
		else {
			hs->rnrn = 0;
		}
		ptr++;
	}
	
	return len;
}

void hr_session_close(struct corerouter_session *cs) {
	struct http_session *hs = (struct http_session *) cs;
	if (hs->path_info) {
		free(hs->path_info);
	}
	if (hs->uwsgi_req) {
		uwsgi_buffer_destroy(hs->uwsgi_req);
	}
	if (hs->post_buf) {
		uwsgi_buffer_destroy(hs->post_buf);
	}
}

#ifdef UWSGI_SSL
void hr_session_ssl_close(struct corerouter_session *cs) {
	hr_session_close(cs);
	struct http_session *hs = (struct http_session *) cs;
	SSL_shutdown(hs->ssl);
	if (hs->ssl_client_dn) {
                OPENSSL_free(hs->ssl_client_dn);
        }

        if (hs->ssl_cc) {
                free(hs->ssl_cc);
        }

        if (hs->ssl_bio) {
                BIO_free(hs->ssl_bio);
        }

        if (hs->ssl_client_cert) {
                X509_free(hs->ssl_client_cert);
        }

        SSL_free(hs->ssl);
}
#endif

void http_alloc_session(struct uwsgi_corerouter *ucr, struct uwsgi_gateway_socket *ugs, struct corerouter_session *cs, struct sockaddr *sa, socklen_t s_len) {
	struct http_session *hs = (struct http_session *) cs;
	cs->modifier1 = uhttp.modifier1;
	if (sa && sa->sa_family == AF_INET) {
		hs->ip_addr = ((struct sockaddr_in *) sa)->sin_addr.s_addr;
	}

	hs->rnrn = 0;

	hs->port = ugs->port;
	hs->port_len = ugs->port_len;
#ifdef UWSGI_SSL
	if (ugs->mode == UWSGI_HTTP_SSL) {
		if (ugs->mode == UWSGI_HTTP_FORCE_SSL) {
			uwsgi_cr_hook_write(cs, hr_send_force_https);
			cs->close = hr_session_close;
			return;
		}
		hs->ssl = SSL_new(ugs->ctx);		
		SSL_set_fd(hs->ssl, cs->fd);
		SSL_set_accept_state(hs->ssl);
		uwsgi_cr_hook_read(cs, hr_recv_http_ssl);
		cs->close = hr_session_ssl_close;
	}
	else {
#endif
		uwsgi_cr_hook_read(cs, hr_recv_http);
		cs->close = hr_session_close;
#ifdef UWSGI_SSL
	}
#endif
}

void http_setup() {
	uhttp.cr.name = uwsgi_str("uWSGI http");
	uhttp.cr.short_name = uwsgi_str("http");
}


int http_init() {

	uhttp.cr.session_size = sizeof(struct http_session);
	uhttp.cr.alloc_session = http_alloc_session;
	if (uhttp.cr.has_sockets && !uwsgi.sockets && !uwsgi_corerouter_has_backends(&uhttp.cr)) {
		uwsgi_new_socket(uwsgi_concat2("127.0.0.1:0", ""));
		uhttp.cr.use_socket = 1;
		uhttp.cr.socket_num = 0;
	}
	uwsgi_corerouter_init((struct uwsgi_corerouter *) &uhttp);

	return 0;
}

struct uwsgi_plugin http_plugin = {

	.name = "http",
	.options = http_options,
	.init = http_init,
	.on_load = http_setup,
};
