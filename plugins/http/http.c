/*

   uWSGI HTTP router

*/

#include "common.h"

struct uwsgi_http uhttp;

struct uwsgi_option http_options[] = {
	{"http", required_argument, 0, "add an http router/server on the specified address", uwsgi_opt_corerouter, &uhttp, 0},
#ifdef UWSGI_SSL
	{"https", required_argument, 0, "add an https router/server on the specified address with specified certificate and key", uwsgi_opt_https, &uhttp, 0},
	{"https2", required_argument, 0, "add an https/spdy router/server using keyval options", uwsgi_opt_https2, &uhttp, 0},
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
	{"http-keepalive", optional_argument, 0, "HTTP 1.1 keepalive support (non-pipelined) requests", uwsgi_opt_set_int, &uhttp.keepalive, 0},
	{"http-auto-chunked", no_argument, 0, "automatically transform output to chunked encoding during HTTP 1.1 keepalive (if needed)", uwsgi_opt_true, &uhttp.auto_chunked, 0},

	{"http-raw-body", no_argument, 0, "blindly send HTTP body to backends (required for WebSockets and Icecast support in backends)", uwsgi_opt_true, &uhttp.raw_body, 0},
#ifdef UWSGI_SSL
	{"http-websockets", no_argument, 0, "automatically handshake websockets connections", uwsgi_opt_true, &uhttp.websockets, 0},
#endif

	{"http-use-code-string", required_argument, 0, "use code string as hostname->server mapper for the http router", uwsgi_opt_corerouter_cs, &uhttp, 0},
        {"http-use-socket", optional_argument, 0, "forward request to the specified uwsgi socket", uwsgi_opt_corerouter_use_socket, &uhttp, 0},
        {"http-gracetime", required_argument, 0, "retry connections to dead static nodes after the specified amount of seconds", uwsgi_opt_set_int, &uhttp.cr.static_node_gracetime, 0},

	{"http-quiet", required_argument, 0, "do not report failed connections to instances", uwsgi_opt_true, &uhttp.cr.quiet, 0},
        {"http-cheap", no_argument, 0, "run the http router in cheap mode", uwsgi_opt_true, &uhttp.cr.cheap, 0},

	{"http-stats", required_argument, 0, "run the http router stats server", uwsgi_opt_set_str, &uhttp.cr.stats_server, 0},
	{"http-stats-server", required_argument, 0, "run the http router stats server", uwsgi_opt_set_str, &uhttp.cr.stats_server, 0},
	{"http-ss", required_argument, 0, "run the http router stats server", uwsgi_opt_set_str, &uhttp.cr.stats_server, 0},
	{"http-harakiri", required_argument, 0, "enable http router harakiri", uwsgi_opt_set_int, &uhttp.cr.harakiri, 0},
	{"http-stud-prefix", required_argument, 0, "expect a stud prefix (1byte family + 4/16 bytes address) on connections from the specified address", uwsgi_opt_add_addr_list, &uhttp.stud_prefix, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

int http_add_uwsgi_header(struct corerouter_peer *peer, char *hh, uint16_t hhlen) {

	struct uwsgi_buffer *out = peer->out;
	struct http_session *hr = (struct http_session *) peer->session;

	int i;
	int status = 0;
	char *val = hh;
	uint16_t keylen = 0, vallen = 0;
	int prefix = 0;

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
		peer->key = val;
		peer->key_len = vallen;
	}

#ifdef UWSGI_SSL
	if (hr->websockets) {
		if (!uwsgi_strncmp("UPGRADE", 7, hh, keylen)) {
			if (!uwsgi_strnicmp(val, vallen, "websocket", 9)) {
				hr->websockets++;
			}
		}
		else if (!uwsgi_strncmp("CONNECTION", 10, hh, keylen)) {
			if (!uwsgi_strnicmp(val, vallen, "Upgrade", 7)) {
				hr->websockets++;
			}
		}
		else if (!uwsgi_strncmp("SEC_WEBSOCKET_VERSION", 21, hh, keylen)) {
				hr->websockets++;
		}
		else if (!uwsgi_strncmp("ORIGIN", 6, hh, keylen)) {
			hr->origin = val;
			hr->origin_len = vallen;
		}
		else if (!uwsgi_strncmp("SEC_WEBSOCKET_KEY", 17, hh, keylen)) {
			hr->websocket_key = val;
			hr->websocket_key_len = vallen;
		}
	}	
#endif

	if (!uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		hr->content_length = uwsgi_str_num(val, vallen);
		hr->session.can_keepalive = 0;
	}

	// in the future we could support chunked requests...
	if (!uwsgi_strncmp("TRANSFER_ENCODING", 17, hh, keylen)) {
		hr->session.can_keepalive = 0;
	}

	if (uwsgi_strncmp("CONTENT_TYPE", 12, hh, keylen) && uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		keylen += 5;
		prefix = 1;
	}

	if (!uwsgi_strncmp("CONNECTION", 10, hh, keylen)) {
		if (!uwsgi_strnicmp(val, vallen, "close", 5)) {
			hr->session.can_keepalive = 0;
		}
	}

	if (uwsgi_buffer_u16le(out, keylen)) return -1;

	if (prefix) {
		if (uwsgi_buffer_append(out, "HTTP_", 5)) return -1;
	}

	if (uwsgi_buffer_append(out, hh, keylen - (prefix * 5))) return -1;

	if (uwsgi_buffer_u16le(out, vallen)) return -1;
	if (uwsgi_buffer_append(out, val, vallen)) return -1;

	return 0;
}


int http_headers_parse(struct corerouter_peer *peer) {

	struct http_session *hr = (struct http_session *) peer->session;

	char *ptr = peer->session->main_peer->in->buf;
	char *watermark = ptr + hr->headers_size;
	char *base = ptr;
	char *query_string = NULL;

	peer->out = uwsgi_buffer_new(uwsgi.page_size);
	// force this buffer to be destroyed as soon as possibile
	peer->out_need_free = 1;
	peer->out->limit = UMAX16;
	// leave space for the uwsgi header
	peer->out->pos = 4;
	peer->out_pos = 0;

	struct uwsgi_buffer *out = peer->out;

	// REQUEST_METHOD 
	while (ptr < watermark) {
		if (*ptr == ' ') {
			if (uwsgi_buffer_append_keyval(out, "REQUEST_METHOD", 14, base, ptr - base)) return -1;
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
			hr->path_info_len = ptr - base;
			hr->path_info = uwsgi_malloc(hr->path_info_len);
			http_url_decode(base, &hr->path_info_len, hr->path_info);
			if (uwsgi_buffer_append_keyval(out, "PATH_INFO", 9, hr->path_info, hr->path_info_len)) return -1;
			query_string = ptr + 1;
		}
		else if (*ptr == ' ') {
			hr->request_uri = base;
			hr->request_uri_len = ptr - base;
			if (uwsgi_buffer_append_keyval(out, "REQUEST_URI", 11, base, ptr - base)) return -1;
			if (!query_string) {
				// PATH_INFO must be url-decoded !!!
				hr->path_info_len = ptr - base;
				hr->path_info = uwsgi_malloc(hr->path_info_len);
				http_url_decode(base, &hr->path_info_len, hr->path_info);
				if (uwsgi_buffer_append_keyval(out, "PATH_INFO", 9, hr->path_info, hr->path_info_len)) return -1;
				if (uwsgi_buffer_append_keyval(out, "QUERY_STRING", 12, "", 0)) return -1;
			}
			else {
				if (uwsgi_buffer_append_keyval(out, "QUERY_STRING", 12, query_string, ptr - query_string)) return -1;
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
			if (uwsgi_buffer_append_keyval(out, "SERVER_PROTOCOL", 15, base, ptr - base)) return -1;
			if (uhttp.keepalive && !uwsgi_strncmp("HTTP/1.1", 8, base, ptr-base)) {
				hr->session.can_keepalive = 1;
			}
			ptr += 2;
			break;
		}
		ptr++;
	}

	// SCRIPT_NAME
	if (uwsgi_buffer_append_keyval(out, "SCRIPT_NAME", 11, "", 0)) return -1;

	// SERVER_NAME
	if (uwsgi_buffer_append_keyval(out, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len)) return -1;
	peer->key = uwsgi.hostname;
	peer->key_len = uwsgi.hostname_len;

	// SERVER_PORT
	if (uwsgi_buffer_append_keyval(out, "SERVER_PORT", 11, hr->port, hr->port_len)) return -1;

	// UWSGI_ROUTER
	if (uwsgi_buffer_append_keyval(out, "UWSGI_ROUTER", 12, "http", 4)) return -1;

	// stud HTTPS
	if (hr->stud_prefix_pos > 0) {
		if (uwsgi_buffer_append_keyval(out, "HTTPS", 5, "on", 2)) return -1;
	}

#ifdef UWSGI_SSL
	if (hr_https_add_vars(hr, out)) return -1;
#endif

	// REMOTE_ADDR
	if (uwsgi_buffer_append_keyipv4(out, "REMOTE_ADDR", 11, &hr->ip_addr)) return -1;

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
					hr->send_expect_100 = 1;
				}
			}
			if (http_add_uwsgi_header(peer, base, ptr - base)) return -1;
			ptr++;
			base = ptr + 1;
		}
		ptr++;
	}

	struct uwsgi_string_list *hv = uhttp.http_vars;
	while (hv) {
		char *equal = strchr(hv->value, '=');
		if (equal) {
			if (uwsgi_buffer_append_keyval(out, hv->value, equal - hv->value, equal + 1, strlen(equal + 1))) return -1;
		}
		hv = hv->next;
	}

	return 0;

}


/*

// TODO fix it for ssl
ssize_t hr_send_expect_continue(struct corerouter_peer *main_peer) {
	struct corerouter_session *cs = main_peer->cs;
	char *msg = "HTTP/1.0 100 Continue\r\n\r\n" ;
	ssize_t len = -1;

#ifdef UWSGI_SSL
	struct http_session *hr = (struct http_session *) cs;
	if (!hr->ssl) {
#endif
		len = write(main_peer->fd, msg + cs->buffer_pos, 25 - cs->buffer_pos);
		if (len < 0) {
			cr_try_again;
                	uwsgi_error("hr_send_expect_continue()");
                	return -1;
		}

		cs->buffer_pos += len;
#ifdef UWSGI_SSL
	}
#endif

	if (cs->buffer_pos == 25) {
		cs->buffer_pos = 0;
		uwsgi_cr_set_hooks(main_peer, NULL, NULL);
		uwsgi_cr_set_hooks(cs->peers, NULL, hr_instance_send_request_header);
	}

	return len;
}

*/

ssize_t hr_instance_write(struct corerouter_peer *peer) {
	ssize_t len = cr_write(peer, "hr_instance_write()");
        // end on empty write
        if (!len) { peer->session->can_keepalive = 0; return 0; }

        // the chunk has been sent, start (again) reading from client and instances
        if (cr_write_complete(peer)) {
		// destroy the buffer used for the uwsgi packet
		if (peer->out_need_free == 1) {
			uwsgi_buffer_destroy(peer->out);
			peer->out_need_free = 0;
			peer->out = NULL;
			// reset the main_peer input stream
			peer->session->main_peer->in->pos = 0;
		}
		// reset the stream (main_peer->in = peer->out)
		else {
			peer->out->pos = 0;
		}
                cr_reset_hooks(peer);
        }

        return len;
}

#ifdef UWSGI_SSL
// here we use the peer input buffer as the main_peer output
int hr_websocket_handshake(struct corerouter_peer* peer) {
	char sha1[20];
	struct http_session *hr = (struct http_session *) peer->session;
	if (uwsgi_buffer_append(peer->in, "HTTP/1.1 101 Web Socket Protocol Handshake\r\n", 44)) return -1;
	if (uwsgi_buffer_append(peer->in, "Upgrade: WebSocket\r\n", 20)) return -1;
	if (uwsgi_buffer_append(peer->in, "Connection: Upgrade\r\n", 21)) return -1;
	if (uwsgi_buffer_append(peer->in, "Sec-WebSocket-Origin: ", 22)) return -1;
	if (hr->origin_len > 0) {
		if (uwsgi_buffer_append(peer->in, hr->origin, hr->origin_len)) return -1;
	}
	else {
		if (uwsgi_buffer_append(peer->in, "*", 1)) return -1;
	}
	if (uwsgi_buffer_append(peer->in, "\r\nSec-WebSocket-Accept: ", 24)) return -1;
	if (!uwsgi_sha1_2n(hr->websocket_key, hr->websocket_key_len, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36, sha1)) return -1;
	if (uwsgi_buffer_append_base64(peer->in, sha1, 20)) return -1;
	if (uwsgi_buffer_append(peer->in, "\r\n\r\n", 4)) return -1;

	peer->session->main_peer->out = peer->in;
	peer->session->main_peer->out_pos = 0;
	return 0;
}

ssize_t hr_websocket_handshake_write(struct corerouter_peer *main_peer) {
	struct http_session *hr = (struct http_session *) main_peer->session;
	ssize_t len = cr_write(main_peer, "hr_websocket_handshake_write()");
        // end on empty write
        if (!len) return 0;

        // ok handshake sent, let's write the uwsgi packet
        if (cr_write_complete(main_peer)) {
                // reset the original input buffer
                main_peer->out->pos = 0;
		// enable raw body
		hr->raw_body = 1;
		cr_write_to_backend(main_peer->session->peers, hr_instance_write);
        }

        return len;
}
#endif

// write to the client
ssize_t hr_write(struct corerouter_peer *main_peer) {
        ssize_t len = cr_write(main_peer, "hr_write()");
        // end on empty write
        if (!len) return 0;

        // ok this response chunk is sent, let's start reading again
        if (cr_write_complete(main_peer)) {
                // reset the original read buffer
                main_peer->out->pos = 0;
                cr_reset_hooks(main_peer);
        }

        return len;
}

ssize_t hr_instance_connected(struct corerouter_peer* peer) {

	struct http_session *hr = (struct http_session *) peer->session;
	
	cr_peer_connected(peer, "hr_instance_connected()");

	// prepare for write
	peer->out_pos = 0;

#ifdef UWSGI_SSL
	if (hr->websockets > 2 && hr->websocket_key_len > 0) {
		// write websocket handshake
		if (hr_websocket_handshake(peer)) return -1;
		cr_write_to_main(peer, hr_websocket_handshake_write);
		return 1;
	}
#endif
	if (hr->send_expect_100) {
	}

	// change the write hook (we are already monitoring for write)
	peer->hook_write = hr_instance_write;
	// and directly call it (optimistic approach...)
        return hr_instance_write(peer);
}

// check if the response allows for keepalive
int hr_check_response_keepalive(struct corerouter_peer *peer) {
	struct http_session *hr = (struct http_session *) peer->session;
	struct uwsgi_buffer *ub = peer->in;
	size_t i;
	for(i=0;i<ub->pos;i++) {
                char c = ub->buf[i];
                if (c == '\r' && (peer->r_parser_status == 0 || peer->r_parser_status == 2)) {
                        peer->r_parser_status++;
                }
                else if (c == '\r') {
                        peer->r_parser_status = 1;
                }
                else if (c == '\n' && peer->r_parser_status == 1) {
                        peer->r_parser_status = 2;
                }
                // parsing done
                else if (c == '\n' && peer->r_parser_status == 3) {
			// end of headers
			peer->r_parser_status = 4;
			if (http_response_parse(hr, ub, i+1)) {
				return -1;
			}
			return 0;
		}
                else {
                        peer->r_parser_status = 0;
                }
        }

	return 1;

}

// data from instance
ssize_t hr_instance_read(struct corerouter_peer *peer) {
        peer->in->limit = UMAX16;
	if (uwsgi_buffer_ensure(peer->in, uwsgi.page_size)) return -1;
	struct http_session *hr = (struct http_session *) peer->session;
        ssize_t len = cr_read(peer, "hr_instance_read()");
        if (!len) {
		if (hr->session.can_keepalive) {
			peer->session->main_peer->disabled = 0;
			hr->rnrn = 0;
			if (uhttp.keepalive > 1) {
				int orig_timeout = peer->session->corerouter->socket_timeout;
				peer->session->corerouter->socket_timeout = uhttp.keepalive;
				peer->session->main_peer->timeout = corerouter_reset_timeout(peer->session->corerouter, peer->session->main_peer);
				peer->session->corerouter->socket_timeout = orig_timeout;
			}
			if (hr->force_chunked) {
				if (!hr->last_chunked) {
					hr->last_chunked = uwsgi_buffer_new(3);
					if (uwsgi_buffer_insert_chunked(hr->last_chunked, 0, 0)) return -1;
				}
				peer->session->main_peer->out = hr->last_chunked;
				peer->session->main_peer->out_pos = 0;
				cr_write_to_main(peer, hr->func_write);
			}
			else {
				cr_reset_hooks(peer);
			}
		}
		return 0;
	}

	// need to parse response headers
	if (hr->session.can_keepalive) {
		if (peer->r_parser_status != 4) {
			int ret = hr_check_response_keepalive(peer);
			if (ret < 0) return -1;
			if (ret > 0) {
				return 1;
			}
		}
		else if (hr->force_chunked) {
			if (uwsgi_buffer_insert_chunked(peer->in, 0, len)) return -1;
			if (uwsgi_buffer_append(peer->in, "\r\n", 2)) return -1;
		}
	}

        // set the input buffer as the main output one
        peer->session->main_peer->out = peer->in;
        peer->session->main_peer->out_pos = 0;

	// set the default hook in case of blocking writes (optimistic approach)
        cr_write_to_main(peer, hr->func_write);
	return 1;
}



ssize_t http_parse(struct corerouter_peer *main_peer) {
	struct corerouter_session *cs = main_peer->session;
	struct http_session *hr = (struct http_session *) cs;

	// is it http body ?
	if (hr->rnrn == 4) {
		if (hr->content_length == 0 && !hr->raw_body) {
			// ignore data...
			main_peer->in->pos = 0;
			return 1;
		}
		else {
			if (hr->content_length) {
				if (main_peer->in->pos > hr->content_length) {
					main_peer->in->pos = hr->content_length;
					hr->content_length = 0;
				}		
				else {
					hr->content_length -= main_peer->in->pos;
				}
			}
		}
		main_peer->session->peers->out = main_peer->in;
		main_peer->session->peers->out_pos = 0;
		cr_write_to_backend(main_peer->session->peers, hr_instance_write);
		return 1;
	}

	// read until \r\n\r\n is found
	size_t j;
	size_t len = main_peer->in->pos;
	char *ptr = main_peer->in->buf;

	for (j = 0; j < len; j++) {
		if (*ptr == '\r' && (hr->rnrn == 0 || hr->rnrn == 2)) {
			hr->rnrn++;
		}
		else if (*ptr == '\r') {
			hr->rnrn = 1;
		}
		else if (*ptr == '\n' && hr->rnrn == 1) {
			hr->rnrn = 2;
		}
		else if (*ptr == '\n' && hr->rnrn == 3) {
			hr->rnrn = 4;
			hr->headers_size = j;

			// for security
			if ((j+1) <= len) {
				hr->remains = len - (j+1);
			}

			struct uwsgi_corerouter *ucr = main_peer->session->corerouter;

			// create a new peer
                	struct corerouter_peer *new_peer = uwsgi_cr_peer_add(main_peer->session);
			// default hook
			new_peer->last_hook_read = hr_instance_read;
		
			// parse HTTP request
			if (http_headers_parse(new_peer)) return -1;

			// check for a valid hostname
			if (new_peer->key_len == 0) return -1;

#ifdef UWSGI_SSL
			if (hr->force_ssl) {
				//hr_send_force_https;
				break;
			}
#endif
			// find an instance using the key
                	if (ucr->mapper(ucr, new_peer))
                        	return -1;

                	// check instance
                	if (new_peer->instance_address_len == 0)
                        	return -1;

			uint16_t pktsize = new_peer->out->pos-4;
        		// fix modifiers
        		new_peer->out->buf[0] = new_peer->session->main_peer->modifier1;
        		new_peer->out->buf[3] = new_peer->session->main_peer->modifier2;
        		// fix pktsize
        		new_peer->out->buf[1] = (uint8_t) (pktsize & 0xff);
        		new_peer->out->buf[2] = (uint8_t) ((pktsize >> 8) & 0xff);

			if (hr->remains > 0) {
				hr->session.can_keepalive = 0;
				if (hr->content_length < hr->remains) { 
					hr->remains = hr->content_length;
					hr->content_length = 0;
				}
				else {
					hr->content_length -= hr->remains;
				}
				if (uwsgi_buffer_append(new_peer->out, main_peer->in->buf + hr->headers_size + 1, hr->remains)) return -1;
			}

			if (hr->session.can_keepalive) {
				main_peer->disabled = 1;
				// stop reading from the client
				if (uwsgi_cr_set_hooks(main_peer, NULL, NULL)) return -1;
			}

                	cr_connect(new_peer, hr_instance_connected);
			break;
		}
		else {
			hr->rnrn = 0;
		}
		ptr++;
	}
	
	return 1;
}

// read from client
ssize_t hr_read(struct corerouter_peer *main_peer) {
        // try to always leave 4k available (this will dinamically increase the buffer...)
        if (uwsgi_buffer_ensure(main_peer->in, uwsgi.page_size)) return -1;
        ssize_t len = cr_read(main_peer, "hr_read()");
        if (!len) return 0;

        return http_parse(main_peer);
}



void hr_session_close(struct corerouter_session *cs) {
	struct http_session *hr = (struct http_session *) cs;
	if (hr->path_info) {
		free(hr->path_info);
	}

	if (hr->last_chunked) {
		uwsgi_buffer_destroy(hr->last_chunked);
	}
}

ssize_t hr_recv_stud4(struct corerouter_peer * main_peer) {
	struct http_session *hr = (struct http_session *) main_peer->session;
	ssize_t len = read(main_peer->fd, hr->stud_prefix + hr->stud_prefix_pos, hr->stud_prefix_remains - hr->stud_prefix_pos);
	if (len < 0) {
                cr_try_again;
                uwsgi_error("hr_recv_stud4()");
                return -1;
        }

	hr->stud_prefix_pos += len;

        if (hr->stud_prefix_pos == hr->stud_prefix_remains) {
		if (hr->stud_prefix[0] != AF_INET) {
			uwsgi_log("[uwsgi-http] invalid stud prefix\n");
			return -1;
		}
		// set the passed ip address
		memcpy(&hr->ip_addr, hr->stud_prefix + 1, 4);
		
		// optimistic approach
		main_peer->hook_read = hr_read;
		return hr_read(main_peer);
        }

        return len;

}

int http_alloc_session(struct uwsgi_corerouter *ucr, struct uwsgi_gateway_socket *ugs, struct corerouter_session *cs, struct sockaddr *sa, socklen_t s_len) {
	struct http_session *hr = (struct http_session *) cs;
	// set the modifier1
	cs->main_peer->modifier1 = uhttp.modifier1;
	// default hook
	cs->main_peer->last_hook_read = hr_read;

	if (uhttp.raw_body) {
		hr->raw_body = 1;
	}
#ifdef UWSGI_SSL
	// websockets ?
	if (uhttp.websockets) {
		hr->websockets = 1;
	}
#endif
	hr->func_write = hr_write;

	// be sure buffer does not grow over 64k
        cs->main_peer->in->limit = UMAX16;

	if (sa && sa->sa_family == AF_INET) {
		hr->ip_addr = ((struct sockaddr_in *) sa)->sin_addr.s_addr;

		struct uwsgi_string_list *usl = uhttp.stud_prefix;
		while(usl) {
			if (!memcmp(&hr->ip_addr, usl->value, 4)) {
				hr->stud_prefix_remains = 5;
				cs->main_peer->last_hook_read = hr_recv_stud4;
				break;
			}
			usl = usl->next;
		}

	}

	hr->rnrn = 0;

	hr->port = ugs->port;
	hr->port_len = ugs->port_len;
	switch(ugs->mode) {
#ifdef UWSGI_SSL
		case UWSGI_HTTP_SSL:
			hr_setup_ssl(hr, ugs);
			break;
		case UWSGI_HTTP_FORCE_SSL:
			uwsgi_cr_set_hooks(cs->main_peer, NULL, hr_send_force_https);
			break;
#endif
		default:
			uwsgi_cr_set_hooks(cs->main_peer, cs->main_peer->last_hook_read, NULL);
			cs->close = hr_session_close;
			break;
	}

	return 0;
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
