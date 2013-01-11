/*

   uWSGI HTTPS router

*/

#include "common.h"

#ifdef UWSGI_SSL

extern struct uwsgi_http uhttp;

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

void uwsgi_opt_https2(char *opt, char *value, void *cr) {
        struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;

	char *s_addr = NULL;
	char *s_cert = NULL;
	char *s_key = NULL;
	char *s_ciphers = NULL;
	char *s_clientca = NULL;
	char *s_spdy = NULL;

	if (uwsgi_kvlist_parse(value, strlen(value), ',', '=',
                        "addr", &s_addr,
                        "cert", &s_cert,
                        "crt", &s_cert,
                        "key", &s_key,
                        "ciphers", &s_ciphers,
                        "clientca", &s_clientca,
                        "client_ca", &s_clientca,
                        "spdy", &s_spdy,
                	NULL)) {
		uwsgi_log("error parsing --https2 option\n");
		exit(1);
        }

	if (!s_addr || !s_cert || !s_key) {
		uwsgi_log("--https2 option needs addr, cert and key items\n");
		exit(1);
	}

        struct uwsgi_gateway_socket *ugs = uwsgi_new_gateway_socket(s_addr, ucr->name);
        // ok we have the socket, initialize ssl if required
        if (!uwsgi.ssl_initialized) {
                uwsgi_ssl_init();
        }

        // initialize ssl context
        char *name = uhttp.https_session_context;
        if (!name) {
                name = uwsgi_concat3(ucr->short_name, "-", ugs->name);
        }

#ifdef UWSGI_SPDY
	if (s_spdy) {
        	uhttp.spdy_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		uhttp.spdy3_settings = uwsgi_buffer_new(uwsgi.page_size);
		if (uwsgi_buffer_append(uhttp.spdy3_settings, "\x80\x03\x00\x04\x01", 5)) goto spdyerror;
		if (uwsgi_buffer_u24be(uhttp.spdy3_settings, (8 * 2) + 4)) goto spdyerror;
		if (uwsgi_buffer_u32be(uhttp.spdy3_settings, 2)) goto spdyerror;

		// SETTINGS_ROUND_TRIP_TIME
		if (uwsgi_buffer_append(uhttp.spdy3_settings, "\x01\x00\x00\x03", 4)) goto spdyerror;
		if (uwsgi_buffer_u32be(uhttp.spdy3_settings, 30 * 1000)) goto spdyerror;
		// SETTINGS_INITIAL_WINDOW_SIZE
		if (uwsgi_buffer_append(uhttp.spdy3_settings, "\x01\x00\x00\x07", 4)) goto spdyerror;
		if (uwsgi_buffer_u32be(uhttp.spdy3_settings, 8192)) goto spdyerror;

		uhttp.spdy3_settings_size = uhttp.spdy3_settings->pos;
	}
#endif

        ugs->ctx = uwsgi_ssl_new_server_context(name, s_cert, s_key, s_ciphers, s_clientca);
        if (!ugs->ctx) {
                exit(1);
        }
#ifdef UWSGI_SPDY
	if (s_spdy) {
        	SSL_CTX_set_info_callback(ugs->ctx, uwsgi_spdy_info_cb);
        	SSL_CTX_set_next_protos_advertised_cb(ugs->ctx, uwsgi_spdy_npn, NULL);
	}
#endif
        // set the ssl mode
        ugs->mode = UWSGI_HTTP_SSL;

        ucr->has_sockets++;

	return;

spdyerror:
	uwsgi_log("unable to inizialize SPDY settings buffers\n");
	exit(1);
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

ssize_t hr_send_force_https(struct corerouter_peer *main_peer) {
	return -1;
}
/*
	struct corerouter_session *cs = main_peer->cs;
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

        ssize_t len = write(main_peer->fd, hs->force_ssl_buf->buf + cs->buffer_pos, hs->force_ssl_buf->pos - cs->buffer_pos);
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
*/

int hr_https_add_vars(struct http_session *hr, struct uwsgi_buffer *out) {
// HTTPS (adapted from nginx)
        if (hr->session.ugs->mode == UWSGI_HTTP_SSL) {
                if (uwsgi_buffer_append_keyval(out, "HTTPS", 5, "on", 2)) return -1;
                hr->ssl_client_cert = SSL_get_peer_certificate(hr->ssl);
                if (hr->ssl_client_cert) {
                        X509_NAME *name = X509_get_subject_name(hr->ssl_client_cert);
                        if (name) {
                                hr->ssl_client_dn = X509_NAME_oneline(name, NULL, 0);
                                if (uwsgi_buffer_append_keyval(out, "HTTPS_DN", 8, hr->ssl_client_dn, strlen(hr->ssl_client_dn))) return -1;
                        }
                        if (uhttp.https_export_cert) {
                        hr->ssl_bio = BIO_new(BIO_s_mem());
                        if (hr->ssl_bio) {
                                if (PEM_write_bio_X509(hr->ssl_bio, hr->ssl_client_cert) > 0) {
                                        size_t cc_len = BIO_pending(hr->ssl_bio);
                                        hr->ssl_cc = uwsgi_malloc(cc_len);
                                        BIO_read(hr->ssl_bio, hr->ssl_cc, cc_len);
                                        if (uwsgi_buffer_append_keyval(out, "HTTPS_CC", 8, hr->ssl_cc, cc_len)) return -1;
                                }
                        }
                        }
                }
        }
        else if (hr->session.ugs->mode == UWSGI_HTTP_FORCE_SSL) {
                hr->force_ssl = 1;
        }

	return 0;
}

void hr_session_ssl_close(struct corerouter_session *cs) {
	hr_session_close(cs);
	struct http_session *hr = (struct http_session *) cs;
	SSL_shutdown(hr->ssl);
	if (hr->ssl_client_dn) {
                OPENSSL_free(hr->ssl_client_dn);
        }

        if (hr->ssl_cc) {
                free(hr->ssl_cc);
        }

        if (hr->ssl_bio) {
                BIO_free(hr->ssl_bio);
        }

        if (hr->ssl_client_cert) {
                X509_free(hr->ssl_client_cert);
        }

	if (hr->spdy_ping) {
		uwsgi_buffer_destroy(hr->spdy_ping);
	}

        SSL_free(hr->ssl);
}

ssize_t hr_ssl_write(struct corerouter_peer *main_peer) {
        struct corerouter_session *cs = main_peer->session;
        struct http_session *hr = (struct http_session *) cs;

        int ret = SSL_write(hr->ssl, main_peer->out->buf + main_peer->out_pos, main_peer->out->pos - main_peer->out_pos);
        if (ret > 0) {
                main_peer->out_pos += ret;
                if (main_peer->out->pos == main_peer->out_pos) {
			// reset the buffer (if needed)
			main_peer->out->pos = 0;
                        cr_reset_hooks(main_peer);
                }
                return ret;
        }
        if (ret == 0) return 0;
        int err = SSL_get_error(hr->ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
                cr_reset_hooks_and_read(main_peer, hr_ssl_write);
                return 1;
        }

        else if (err == SSL_ERROR_WANT_WRITE) {
                cr_write_to_main(main_peer, hr_ssl_write);
                return 1;
        }

        else if (err == SSL_ERROR_SYSCALL) {
                uwsgi_error("hr_ssl_write()");
        }

        else if (err == SSL_ERROR_SSL && uwsgi.ssl_verbose) {
                ERR_print_errors_fp(stderr);
        }

        return -1;
}

ssize_t hr_ssl_read(struct corerouter_peer *main_peer) {
        struct corerouter_session *cs = main_peer->session;
        struct http_session *hr = (struct http_session *) cs;

        // try to always leave 4k available
        if (uwsgi_buffer_ensure(main_peer->in, uwsgi.page_size)) return -1;
        int ret = SSL_read(hr->ssl, main_peer->in->buf + main_peer->in->pos, main_peer->in->len - main_peer->in->pos);
        if (ret > 0) {
                // fix the buffer
                main_peer->in->pos += ret;
                // check for pending data
                int ret2 = SSL_pending(hr->ssl);
                if (ret2 > 0) {
                        if (uwsgi_buffer_fix(main_peer->in, main_peer->in->len + ret2 )) {
                                uwsgi_log("[uwsgi-https] cannot fix the buffer to %d\n", main_peer->in->len + ret2);
                                return -1;
                        }
                        if (SSL_read(hr->ssl, main_peer->in->buf + main_peer->in->pos, ret2) != ret2) {
                                uwsgi_log("[uwsgi-https] SSL_read() on %d bytes of pending data failed\n", ret2);
                                return -1;
                        }
                        // fix the buffer
                        main_peer->in->pos += ret2;
                }
                if (hr->spdy) {
                        uwsgi_log("RUNNING THE SPDY PARSER FOR %d bytes\n", main_peer->in->pos);
                        return spdy_parse(main_peer);
                }
                return http_parse(main_peer);
        }
        if (ret == 0) return 0;
        int err = SSL_get_error(hr->ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
                cr_reset_hooks_and_read(main_peer, hr_ssl_read);
                return 1;
        }

        else if (err == SSL_ERROR_WANT_WRITE) {
                cr_write_to_main(main_peer, hr_ssl_read);
                return 1;
        }

        else if (err == SSL_ERROR_SYSCALL) {
                uwsgi_error("hr_ssl_read()");
        }

        else if (err == SSL_ERROR_SSL && uwsgi.ssl_verbose) {
                ERR_print_errors_fp(stderr);
        }

        return -1;
}

void hr_setup_ssl(struct http_session *hr, struct uwsgi_gateway_socket *ugs) {
 	hr->ssl = SSL_new(ugs->ctx);
        SSL_set_fd(hr->ssl, hr->session.main_peer->fd);
        SSL_set_accept_state(hr->ssl);
#ifdef UWSGI_SPDY
        SSL_set_ex_data(hr->ssl, uhttp.spdy_index, hr);
#endif
        uwsgi_cr_set_hooks(hr->session.main_peer, hr_ssl_read, NULL);
        hr->session.close = hr_session_ssl_close;
	hr->func_write = hr_ssl_write;
}

#endif
