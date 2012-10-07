/*

   uWSGI http

   requires:

   - async
   - caching
   - pcre (optional)

*/

#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include "../corerouter/cr.h"

#ifdef __sun__
#define MAX_HTTP_VEC IOV_MAX*64
#else
#ifdef IOV_MAX
#define MAX_HTTP_VEC IOV_MAX
#else
#define MAX_HTTP_VEC 128
#endif
#endif

#ifdef UWSGI_SSL
#define UWSGI_HTTP_SSL 1
#define UWSGI_HTTP_FORCE_SSL 2
#define HTTP_SSL_STATUS_SHUTDOWN 10
#endif

struct uwsgi_http {

	struct uwsgi_corerouter cr;

	uint8_t modifier1;
	struct uwsgi_string_list *http_vars;
	int manage_expect;

	int raw_body;

	int keepalive;
#ifdef UWSGI_SSL
	int https_export_cert;
#endif

} uhttp;


#ifdef UWSGI_SSL
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
	ugs->ctx = uwsgi_ssl_new_server_context(uwsgi_concat3(ucr->short_name, "-", ugs->name),crt, key, ciphers, client_ca);
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
	{"http-keepalive", no_argument, 0, "support HTTP keepalive (non-pipelined) requests (requires backend support)", uwsgi_opt_true, &uhttp.keepalive, 0},

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

	struct corerouter_session crs;

	struct uwsgi_header uh;

	int rnrn;
	char *ptr;

	char *port;
	int port_len;

	struct iovec iov[MAX_HTTP_VEC];
	int iov_len;
	char uss[MAX_HTTP_VEC * 2];

	char buffer[UMAX16];
	size_t buffer_len;
	char path_info[UMAX16];
	uint16_t path_info_len;

	char *request_uri;
	uint16_t request_uri_len;

	size_t received_body;

#ifdef UWSGI_SSL
	SSL *ssl;
	X509 *ssl_client_cert;
	char *ssl_client_dn;
	BIO *ssl_bio;
	char *ssl_cc;
#endif

	in_addr_t ip_addr;
	char ip[INET_ADDRSTRLEN];

};

#ifdef UWSGI_SSL
int uwsgi_http_ssl_shutdown(struct http_session *, int);
#endif

uint16_t http_add_uwsgi_header(struct http_session *h_session, struct iovec *iov, char *strsize1, char *strsize2, char *hh, uint16_t hhlen, int *c) {

	int i;
	int status = 0;
	char *val = hh;
	uint16_t keylen = 0, vallen = 0;
	int prefix = 0;

	if (*c >= MAX_HTTP_VEC)
		return 0;

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
		return 0;

	if ((*c) + 4 >= MAX_HTTP_VEC)
		return 0;

	if (!uwsgi_strncmp("HOST", 4, hh, keylen)) {
		h_session->crs.hostname = val;
		h_session->crs.hostname_len = vallen;
	}

	if (!uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		h_session->crs.post_cl = uwsgi_str_num(val, vallen);
	}

	if (uwsgi_strncmp("CONTENT_TYPE", 12, hh, keylen) && uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		keylen += 5;
		prefix = 1;
		if ((*c) + 5 >= MAX_HTTP_VEC)
			return 0;
	}

	strsize1[0] = (uint8_t) (keylen & 0xff);
	strsize1[1] = (uint8_t) ((keylen >> 8) & 0xff);

	iov[*c].iov_base = strsize1;
	iov[*c].iov_len = 2;
	*c += 1;

	if (prefix) {
		iov[*c].iov_base = "HTTP_";
		iov[*c].iov_len = 5;
		*c += 1;
	}

	iov[*c].iov_base = hh;
	iov[*c].iov_len = keylen - (prefix * 5);
	*c += 1;

	strsize2[0] = (uint8_t) (vallen & 0xff);
	strsize2[1] = (uint8_t) ((vallen >> 8) & 0xff);

	iov[*c].iov_base = strsize2;
	iov[*c].iov_len = 2;
	*c += 1;

	iov[*c].iov_base = val;
	iov[*c].iov_len = vallen;
	*c += 1;

	return 2 + keylen + 2 + vallen;
}


uint16_t http_add_uwsgi_var(struct iovec * iov, char *strsize1, char *strsize2, char *key, uint16_t keylen, char *val, uint16_t vallen, int *c) {

	if ((*c) + 4 >= MAX_HTTP_VEC)
		return 0;

	strsize1[0] = (uint8_t) (keylen & 0xff);
	strsize1[1] = (uint8_t) ((keylen >> 8) & 0xff);

	iov[*c].iov_base = strsize1;
	iov[*c].iov_len = 2;
	*c += 1;

	iov[*c].iov_base = key;
	iov[*c].iov_len = keylen;
	*c += 1;

	strsize2[0] = (uint8_t) (vallen & 0xff);
	strsize2[1] = (uint8_t) ((vallen >> 8) & 0xff);

	iov[*c].iov_base = strsize2;
	iov[*c].iov_len = 2;
	*c += 1;

	iov[*c].iov_base = val;
	iov[*c].iov_len = vallen;
	*c += 1;

	return 2 + keylen + 2 + vallen;
}

int http_parse(struct http_session *h_session) {

	char *ptr = h_session->buffer;
	char *watermark = h_session->ptr;
	char *base = ptr;
	// leave a slot for uwsgi header
	int c = 1;
	char *query_string = NULL;
	char *protocol = NULL;
	size_t protocol_len = 0;

	// REQUEST_METHOD 
	while (ptr < watermark) {
		if (*ptr == ' ') {
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "REQUEST_METHOD", 14, base, ptr - base, &c);
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
			http_url_decode(base, &h_session->path_info_len, h_session->path_info);
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "PATH_INFO", 9, h_session->path_info, h_session->path_info_len, &c);
			query_string = ptr + 1;
		}
		else if (*ptr == ' ') {
			h_session->request_uri = base;
			h_session->request_uri_len = ptr - base;
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "REQUEST_URI", 11, base, ptr - base, &c);
			if (!query_string) {
				// PATH_INFO must be url-decoded !!!
				h_session->path_info_len = ptr - base;
				http_url_decode(base, &h_session->path_info_len, h_session->path_info);
				h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "PATH_INFO", 9, h_session->path_info, h_session->path_info_len, &c);
				h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "QUERY_STRING", 12, "", 0, &c);
			}
			else {
				h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "QUERY_STRING", 12, query_string, ptr - query_string, &c);
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
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "SERVER_PROTOCOL", 15, base, ptr - base, &c);
			protocol = base;
			protocol_len = ptr - base;
			ptr += 2;
			break;
		}
		ptr++;
	}

	// SCRIPT_NAME
	h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "SCRIPT_NAME", 11, "", 0, &c);

	// SERVER_NAME
	h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len, &c);
	h_session->crs.hostname = uwsgi.hostname;
	h_session->crs.hostname_len = uwsgi.hostname_len;

	// SERVER_PORT
	h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "SERVER_PORT", 11, h_session->port, h_session->port_len, &c);

	// UWSGI_ROUTER
	h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "UWSGI_ROUTER", 12, "http", 4, &c);

#ifdef UWSGI_SSL
	// HTTPS (adapted from nginx)
	if (h_session->crs.ugs->mode == UWSGI_HTTP_SSL) {
		h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "HTTPS", 5, "on", 2, &c);
		h_session->ssl_client_cert = SSL_get_peer_certificate(h_session->ssl);
		if (h_session->ssl_client_cert) {
			X509_NAME *name = X509_get_subject_name(h_session->ssl_client_cert);
			if (name) {
				h_session->ssl_client_dn = X509_NAME_oneline(name, NULL, 0);
				h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "HTTPS_DN", 8, h_session->ssl_client_dn, strlen(h_session->ssl_client_dn), &c);
			}
			if (uhttp.https_export_cert) {
			h_session->ssl_bio = BIO_new(BIO_s_mem());
			if (h_session->ssl_bio) {
				if (PEM_write_bio_X509(h_session->ssl_bio, h_session->ssl_client_cert) > 0) {
					size_t cc_len = BIO_pending(h_session->ssl_bio);
					h_session->ssl_cc = uwsgi_malloc(cc_len);
					BIO_read(h_session->ssl_bio, h_session->ssl_cc, cc_len);
					h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "HTTPS_CC", 8, h_session->ssl_cc, cc_len, &c);
				}
			}
			}
		}
	}
#endif

	// REMOTE_ADDR
	if (inet_ntop(AF_INET, &h_session->ip_addr, h_session->ip, INET_ADDRSTRLEN)) {
		h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, "REMOTE_ADDR", 11, h_session->ip, strlen(h_session->ip), &c);
	}
	else {
		uwsgi_error("inet_ntop()");
	}


	//HEADERS

	base = ptr;

	while (ptr < watermark) {
		if (*ptr == '\r') {
			if (ptr + 1 >= watermark)
				return 0;
			if (*(ptr + 1) != '\n')
				return 0;
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
					if (h_session->crs.send(&uhttp.cr, &h_session->crs, protocol, protocol_len) == (ssize_t) protocol_len)
						h_session->crs.send(&uhttp.cr, &h_session->crs, " 100 Continue\r\n\r\n", 17);
				}
			}
			h_session->uh.pktsize += http_add_uwsgi_header(h_session, h_session->iov, h_session->uss + c, h_session->uss + c + 2, base, ptr - base, &c);
			ptr++;
			base = ptr + 1;
		}
		ptr++;
	}

	struct uwsgi_string_list *hv = uhttp.http_vars;
	while (hv) {
		char *equal = strchr(hv->value, '=');
		if (equal) {
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss + c, h_session->uss + c + 2, hv->value, equal - hv->value, equal + 1, strlen(equal + 1), &c);
		}
		hv = hv->next;
	}

	// security check
	if (c >= MAX_HTTP_VEC-4) {
		uwsgi_log("too much headers in request. skipping it.\n");
		return 0;
	}

	return c;

}

void uwsgi_http_switch_events(struct uwsgi_corerouter *ucr, struct corerouter_session *cs, int interesting_fd) {

	ssize_t len;
	int j;
	struct http_session *hs = (struct http_session *) cs;
#ifndef __sun__
	struct msghdr msg;
	union {
		struct cmsghdr cmsg;
		char control[CMSG_SPACE(sizeof(int))];
	} msg_control;
	struct cmsghdr *cmsg;
#endif
	char bbuf[UMAX16];
	socklen_t solen = sizeof(int);

	switch (cs->status) {


	case COREROUTER_STATUS_RECV_HDR:
		if (interesting_fd == -1) {
			goto choose_node;
		}


		len = cs->recv(&uhttp.cr, cs, hs->buffer + cs->pos, UMAX16 - cs->pos);
#ifdef UWSGI_EVENT_USE_PORT
		event_queue_add_fd_read(ucr->queue, cs->fd);
#endif
		if (len <= 0) {
			// check for blocking operation on non-blocking socket
                        if (len < 0 && errno == EINPROGRESS) break;
			corerouter_close_session(ucr, cs);
			break;
		}

		cs->pos += len;

		for (j = 0; j < len; j++) {
			if (*hs->ptr == '\r' && (hs->rnrn == 0 || hs->rnrn == 2)) {
				hs->rnrn++;
			}
			else if (*hs->ptr == '\r') {
				hs->rnrn = 1;
			}
			else if (*hs->ptr == '\n' && hs->rnrn == 1) {
				hs->rnrn = 2;
			}
			else if (*hs->ptr == '\n' && hs->rnrn == 3) {

				hs->ptr++;
				cs->post_remains = len - (j + 1);
				hs->iov_len = http_parse(hs);

				if (hs->iov_len == 0 || cs->hostname_len == 0) {
					corerouter_close_session(ucr, cs);
					break;
				}

#ifdef UWSGI_SSL
				if (cs->ugs->mode == UWSGI_HTTP_FORCE_SSL) {
					if (hs->request_uri_len > 0) {
						char *https_url;
						char *colon = memchr(cs->hostname, ':', cs->hostname_len);
						if (colon) {
							if (cs->ugs->ctx) {
								https_url = uwsgi_concat4n(cs->hostname, colon-cs->hostname, ":", 1, cs->ugs->ctx, strlen(cs->ugs->ctx), hs->request_uri, hs->request_uri_len);
							}
							else {
								https_url = uwsgi_concat2n(cs->hostname, colon-cs->hostname, hs->request_uri, hs->request_uri_len);
							}
						}
						else {
							if (cs->ugs->ctx) {
								https_url = uwsgi_concat4n(cs->hostname, cs->hostname_len, ":", 1, cs->ugs->ctx, strlen(cs->ugs->ctx), hs->request_uri, hs->request_uri_len);
							}
							else {
								https_url = uwsgi_concat2n(cs->hostname, cs->hostname_len, hs->request_uri, hs->request_uri_len);
							}
						}
						struct iovec iov[4];
						iov[0].iov_base = "HTTP/1.0 301 Moved Permanently\r\n";
						iov[0].iov_len = 32;
						iov[1].iov_base = "Location: https://";
						iov[1].iov_len = 18;
						iov[2].iov_base = https_url;
						iov[2].iov_len = strlen(https_url);
						iov[3].iov_base = "\r\n\r\n";
						iov[3].iov_len = 4;
						if (writev(cs->fd, iov, 4) <= 0) {
							uwsgi_error("writev()");
						}
						free(https_url);
					}		
					corerouter_close_session(ucr, cs);
					break;
				}
#endif

				// the mapper hook
			      choose_node:
				if (ucr->mapper(ucr, cs))
					break;


				// no address found
				if (!cs->instance_address_len) {
					// if fallback nodes are configured, trigger them
					if (ucr->fallback) {
						cs->instance_failed = 1;
					}
					corerouter_close_session(ucr, cs);
					break;
				}


				cs->pass_fd = is_unix(cs->instance_address, cs->instance_address_len);

				cs->instance_fd = uwsgi_connectn(cs->instance_address, cs->instance_address_len, 0, 1);

				if (cs->instance_fd < 0) {
					cs->instance_failed = 1;
					cs->soopt = errno;
					corerouter_close_session(ucr, cs);
					break;
				}


				cs->status = COREROUTER_STATUS_CONNECTING;
				ucr->cr_table[cs->instance_fd] = cs;
				event_queue_add_fd_write(ucr->queue, cs->instance_fd);
				break;


			}
			else {
				hs->rnrn = 0;
			}

			hs->ptr++;
		}


		break;


	case COREROUTER_STATUS_CONNECTING:

		if (interesting_fd == cs->instance_fd) {

			if (getsockopt(cs->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&cs->soopt), &solen) < 0) {
				uwsgi_error("getsockopt()");
				cs->instance_failed = 1;
				corerouter_close_session(ucr, cs);
				break;
			}

			if (cs->soopt) {
				cs->instance_failed = 1;
				corerouter_close_session(ucr, cs);
				break;
			}


#ifdef __BIG_ENDIAN__
			hs->uh.pktsize = uwsgi_swap16(cs->uh.pktsize);
#endif
			hs->uh.modifier1 = cs->modifier1;

			hs->iov[0].iov_base = &hs->uh;
			hs->iov[0].iov_len = 4;

			if (cs->post_remains > 0) {
				hs->iov[hs->iov_len].iov_base = hs->ptr;
				if (cs->post_remains > cs->post_cl) {
					cs->post_remains = cs->post_cl;
				}
				hs->iov[hs->iov_len].iov_len = cs->post_remains;
				hs->received_body += cs->post_remains;
				hs->iov_len++;
			}

			// increment node requests counter
                        if (cs->un)
                                cs->un->requests++;

#ifndef __sun__
			// fd passing: PERFORMANCE EXTREME BOOST !!!
			if (cs->pass_fd && !cs->post_remains && !uwsgi.no_fd_passing) {
				msg.msg_name = NULL;
				msg.msg_namelen = 0;
				msg.msg_iov = hs->iov;
				msg.msg_iovlen = hs->iov_len;
				msg.msg_flags = 0;
				msg.msg_control = &msg_control;
				msg.msg_controllen = sizeof(msg_control);

				cmsg = CMSG_FIRSTHDR(&msg);
				cmsg->cmsg_len = CMSG_LEN(sizeof(int));
				cmsg->cmsg_level = SOL_SOCKET;
				cmsg->cmsg_type = SCM_RIGHTS;

				memcpy(CMSG_DATA(cmsg), &cs->fd, sizeof(int));

				if (sendmsg(cs->instance_fd, &msg, 0) < 0) {
					uwsgi_error("sendmsg()");
				}

				corerouter_close_session(ucr, cs);
				break;
			}

#endif
#ifdef __sun__
			if (hs->iov_len > IOV_MAX) {
				int remains = hs->iov_len;
				int iov_len;
				while (remains) {
					if (remains > IOV_MAX) {
						iov_len = IOV_MAX;
					}
					else {
						iov_len = remains;
					}
					if (writev(cs->instance_fd, hs->iov + (hs->iov_len - remains), iov_len) <= 0) {
						uwsgi_error("writev()");
						corerouter_close_session(ucr, cs);
						break;
					}
					remains -= iov_len;
				}
			}
#else
			if (writev(cs->instance_fd, hs->iov, hs->iov_len) <= 0) {
				uwsgi_error("writev()");
				corerouter_close_session(ucr, cs);
				break;
			}
#endif

			event_queue_fd_write_to_read(ucr->queue, cs->instance_fd);
			cs->status = COREROUTER_STATUS_RESPONSE;
		}

		break;

	case COREROUTER_STATUS_RESPONSE:

		// data from instance
		if (interesting_fd == cs->instance_fd) {
			// retry later
			if (cs->instance_stopped) {
				break;
			}
			// writable ?
			if (cs->instance_fd_state) {
				len = cs->instance_send(&uhttp.cr, cs, NULL, 0);
#ifdef UWSGI_EVENT_USE_PORT
				event_queue_add_fd_write(ucr->queue, cs->instance_fd);
#endif
                        	if (len <= 0) {
                                	if (len < 0 && errno == EINPROGRESS) break;
                                	corerouter_close_session(ucr, cs);
                        	}
                                break;
			}

			len = cs->instance_recv(&uhttp.cr, cs, hs->buffer, UMAX16);
#ifdef UWSGI_EVENT_USE_PORT
			event_queue_add_fd_read(ucr->queue, cs->instance_fd);
#endif
			if (len <=  0) {
				if (len < 0 && errno == EINPROGRESS) break;
/*
Keep-Alive implementation.
As soon as the backend close the connection, enable it.
The server will start waiting for another request (for a maximum of --http-socket seconds timeout)
To have a reliable implementation, we need to reset a bunch of values
*/
				if (len == 0) {
					if (uhttp.keepalive) {
#ifdef UWSGI_DEBUG
						uwsgi_log("Keep-Alive enabled\n");
#endif
						cs->keepalive = 1;
						corerouter_close_session(ucr, cs);
					cs->status = COREROUTER_STATUS_RECV_HDR;
					hs->ptr = hs->buffer;
					hs->rnrn = 0;
					cs->pos = 0;
					hs->received_body = 0;
					cs->post_cl = 0;
					cs->instance_fd = -1;
					hs->uh.pktsize = 0;
					cs->post_remains = 0;
					cs->instance_address_len = 0;
					cs->hostname_len = 0;
					break;
					}
#ifdef UWSGI_SSL
					if (cs->ugs->mode == UWSGI_HTTP_SSL) {
						int ssd_ret = SSL_shutdown(hs->ssl);
						// it could fail or success, in both cases close the connection
						if (ssd_ret != 0) {
							corerouter_close_session(ucr, cs);
							break;
						}
						cs->status = HTTP_SSL_STATUS_SHUTDOWN;
						if (uwsgi_http_ssl_shutdown(hs, 1) != 0) {
							corerouter_close_session(ucr, cs);
						}
						break;
					}
					// something to send in the queue ?
					if (cs->write_queue) {
						cs->write_queue_close = 1;
						break;
					}
#endif
				}
				corerouter_close_session(ucr, cs);
				break;
			}

			hs->buffer_len = len;
			len = cs->send(&uhttp.cr, cs, hs->buffer, len);
			if (len <= 0) {
				if (len < 0 && errno == EINPROGRESS) break;
				// check for blocking operation non non-blocking socket
				corerouter_close_session(ucr, cs);
				break;
			}

                        if (cs->un) {
                                // update transfer statistics
                                cs->un->transferred += len;

                                // update node rpm
                                time_t now = uwsgi_now();
                                time_t target_ts = now / 60;

                                // first check for clock jumps
                                if (cs->un->rpm_timecheck == 0 || cs->un->rpm_timecheck > (now/60) || ((now/60) - cs->un->rpm_timecheck) > 70) {
                                        // if clock go back or jumps to the future than just reset everything
                                        cs->un->rpm_timecheck = target_ts;
                                        cs->un->last_minute_requests = 1;
                                } else if (cs->un->rpm_timecheck != target_ts) {
                                        // clock did not jumped, this is next minute
                                        cs->un->requests_per_minute = cs->un->last_minute_requests;
                                        cs->un->rpm_timecheck = target_ts;
                                        cs->un->last_minute_requests = 1;
                                } else {
                                        cs->un->last_minute_requests++;
                                }
                        }
		}

		// body from client or client ready to receive
		else if (interesting_fd == cs->fd) {

			// writable ?
			if (cs->fd_state) {
				len = cs->send(&uhttp.cr, cs, hs->buffer,hs->buffer_len);
#ifdef UWSGI_EVENT_USE_PORT
				event_queue_add_fd_write(ucr->queue, cs->fd);
#endif
                        	if (len <= 0) {
                                	if (len < 0 && errno == EINPROGRESS) break;
                                	corerouter_close_session(ucr, cs);
                        	}
                                break;
			}

			len = cs->recv(&uhttp.cr, cs, bbuf, UMAX16);
#ifdef UWSGI_EVENT_USE_PORT
			event_queue_add_fd_read(ucr->queue, cs->fd);
#endif
			if (len <= 0) {
				// check for blocking operation on non-blocking socket
                        	if (len < 0 && errno == EINPROGRESS) break;
				corerouter_close_session(ucr, cs);
				break;
			}

			if (cs->post_cl == 0 && uhttp.raw_body) goto raw;

			// avoid pipelined input
			if (hs->received_body >= cs->post_cl) {
				break;
			}


			if (len + hs->received_body > cs->post_cl) {
				len = cs->post_cl - hs->received_body;
			}

raw:
			len = cs->instance_send(&uhttp.cr, cs, bbuf, len);

			if (len <= 0) {
				if (len < 0 && errno == EINPROGRESS) break;
				corerouter_close_session(ucr, cs);
				break;
			}

			hs->received_body += len;

		}

		break;

#ifdef UWSGI_SSL
		case HTTP_SSL_STATUS_SHUTDOWN:
			if (uwsgi_http_ssl_shutdown(hs, 0) != 0) {
				corerouter_close_session(ucr, cs);
			}
			break;
#endif


		// fallback to destroy !!!
	default:
		uwsgi_log("unknown event: closing session\n");
		corerouter_close_session(ucr, cs);
		break;
	}

}

void http_setup() {
	uhttp.cr.name = uwsgi_str("uWSGI http");
	uhttp.cr.short_name = uwsgi_str("http");
}

#ifdef UWSGI_SSL
int uwsgi_http_ssl_shutdown(struct http_session *hs, int state) {
	int ret = 0;
	if (!state) {
		ret = SSL_shutdown(hs->ssl);
	}
	if (ret == 1) return 1;
	int err = SSL_get_error(hs->ssl, ret);
        if (err == SSL_ERROR_WANT_READ) {
                if (hs->crs.fd_state) {
                        event_queue_fd_write_to_read(uhttp.cr.queue, hs->crs.fd);
                        hs->crs.fd_state = 0;
                }
                return 0;
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
                if (!hs->crs.fd_state) {
                        event_queue_fd_read_to_write(uhttp.cr.queue, hs->crs.fd);
                        hs->crs.fd_state = 1;
                }
                return 0;
        }
        return -1;
}
ssize_t uwsgi_http_ssl_recv(struct uwsgi_corerouter *cr, struct corerouter_session *cs, char *buf, size_t len) {
	struct http_session *hs = (struct http_session *) cs;
	int ret = SSL_read(hs->ssl, buf, len);
	if (ret > 0) {
                if (hs->crs.fd_state) {
                        event_queue_fd_write_to_read(cr->queue, hs->crs.fd);
                        hs->crs.fd_state = 0;
                }
                return ret;
        }
	if (ret == 0) return 0;
        int err = SSL_get_error(hs->ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
                if (hs->crs.fd_state) {
                        event_queue_fd_write_to_read(cr->queue, hs->crs.fd);
                        hs->crs.fd_state = 0;
                }
                errno = EINPROGRESS;
		return -1;
        }

        else if (err == SSL_ERROR_WANT_WRITE) {
                if (!hs->crs.fd_state) {
                        event_queue_fd_read_to_write(cr->queue, hs->crs.fd);
                        hs->crs.fd_state = 1;
                }
                errno = EINPROGRESS;
		return -1;
        }
	
	else if (err == SSL_ERROR_SYSCALL) {
        	uwsgi_error("SSL_read()");
	}

	else if (err == SSL_ERROR_SSL && uwsgi.ssl_verbose) {
		ERR_print_errors_fp(stderr);
	}

        return -1;

}

ssize_t uwsgi_http_ssl_send(struct uwsgi_corerouter *cr, struct corerouter_session *cs, char *buf, size_t len) {
	struct http_session *hs = (struct http_session *) cs;
        int ret = SSL_write(hs->ssl, buf, len);
	if (ret > 0) {
		if (cs->instance_stopped) {
			event_queue_add_fd_read(cr->queue, cs->instance_fd);
			cs->instance_stopped = 0;	
		}
		if (cs->fd_state) {
			event_queue_fd_write_to_read(cr->queue, cs->fd);
			cs->fd_state = 0;
		}
		return ret;
	}
	int err = SSL_get_error(hs->ssl, ret);
	if (err == SSL_ERROR_WANT_READ) {
		if (cs->instance_fd != -1) {
			event_queue_del_fd(cr->queue, cs->instance_fd, event_queue_read());
			cs->instance_stopped = 1;
		}
		if (cs->fd_state) {
			event_queue_fd_write_to_read(cr->queue, cs->fd);
			cs->fd_state = 0;
		}
		errno = EINPROGRESS;
		return -1;
	}
	else if (err == SSL_ERROR_WANT_WRITE) {
		if (cs->instance_fd != -1) {
			event_queue_del_fd(cr->queue, cs->instance_fd, event_queue_read());
			cs->instance_stopped = 1;
		}
		if (!cs->fd_state) {
			event_queue_fd_read_to_write(cr->queue, cs->fd);
			cs->fd_state = 1;
		}
		errno = EINPROGRESS;
		return -1;
	}

	else if (err == SSL_ERROR_SYSCALL) {
		uwsgi_error("SSL_write()");
	}

	else if (err == SSL_ERROR_SSL && uwsgi.ssl_verbose) {
		ERR_print_errors_fp(stderr);
	}
	
	else if (err == SSL_ERROR_ZERO_RETURN) {
		return 0;
	}

	return -1;
}

// free ssl memory
void uwsgi_ssl_close(struct uwsgi_corerouter *ucr, struct corerouter_session *cs) {
	struct http_session *hs = (struct http_session *) cs;

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

	if (!cs->keepalive)
		SSL_free(hs->ssl);

}
#endif


ssize_t uwsgi_http_nb_send(struct uwsgi_corerouter *cr, struct corerouter_session *cs, char *buf, size_t len) {
        struct http_session *hs = (struct http_session *) cs;
        ssize_t ret = write(cs->fd, buf, len);
        if (ret == (ssize_t) len) {
                if (cs->instance_stopped) {
                        event_queue_add_fd_read(cr->queue, cs->instance_fd);
                        cs->instance_stopped = 0;
                }
                if (cs->fd_state) {
                        event_queue_fd_write_to_read(cr->queue, cs->fd);
                        cs->fd_state = 0;
                }
                return len;
        }
        else if (ret == 0) {
                return -1;
        }
        else if (ret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                        if (cs->instance_fd != -1) {
                                event_queue_del_fd(cr->queue, cs->instance_fd, event_queue_read());
                                cs->instance_stopped = 1;
                        }
                        if (!cs->fd_state) {
                                event_queue_fd_read_to_write(cr->queue, cs->fd);
                                cs->fd_state = 1;
                        }
                        errno = EINPROGRESS;
                        return -1;
                }
                uwsgi_error("write()");
                return -1;
        }

        // partial write
        hs->buffer_len -= ret;
        memcpy(hs->buffer, hs->buffer + ret, hs->buffer_len);
        if (cs->instance_fd != -1) {
                event_queue_del_fd(cr->queue, cs->instance_fd, event_queue_read());
                cs->instance_stopped = 1;
        }
        if (!cs->fd_state) {
                event_queue_fd_read_to_write(cr->queue, cs->fd);
                cs->fd_state = 1;
        }

        errno = EINPROGRESS;
        return -1;
}


void http_alloc_session(struct uwsgi_corerouter *ucr, struct uwsgi_gateway_socket *ugs, struct corerouter_session *cs, struct sockaddr *sa, socklen_t s_len) {
	struct http_session *hs = (struct http_session *) cs;
	hs->ptr = hs->buffer;
	cs->modifier1 = uhttp.modifier1;
	cs->send = uwsgi_http_nb_send;
	if (sa && sa->sa_family == AF_INET) {
		hs->ip_addr = ((struct sockaddr_in *) sa)->sin_addr.s_addr;
	}
	if (ugs) {
		hs->port = ugs->port;
		hs->port_len = ugs->port_len;
#ifdef UWSGI_SSL
		if (ugs->mode == UWSGI_HTTP_SSL) {
			hs->ssl = SSL_new(ugs->ctx);		
			SSL_set_fd(hs->ssl, cs->fd);
			SSL_set_accept_state(hs->ssl);
			cs->recv = uwsgi_http_ssl_recv;
			cs->send = uwsgi_http_ssl_send;
			cs->close = uwsgi_ssl_close;
		}
#endif
	}
}

int http_init() {

	uhttp.cr.session_size = sizeof(struct http_session);
	uhttp.cr.switch_events = uwsgi_http_switch_events;
	uhttp.cr.alloc_session = http_alloc_session;
	if (uhttp.cr.has_sockets && !uwsgi.sockets && !uwsgi_courerouter_has_has_backends(&uhttp.cr)) {
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
