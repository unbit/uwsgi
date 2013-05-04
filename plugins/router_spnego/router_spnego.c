#include <uwsgi.h>

#include <gssapi/gssapi.h>

extern struct uwsgi_server uwsgi;

/*

	At the first request (without authentication) uWSGI sends back a token
	The client resend-the request with its token
	Following requests could need a new token or are simply accepted

*/

// log errors...
static void uwsgi_spnego_err(const char *func, OM_uint32 err_maj, OM_uint32 err_min) {

	OM_uint32 ret;
	OM_uint32 min_stat;
	OM_uint32 msg_ctx = 0;
	gss_buffer_desc status_string;

	ret = gss_display_status (&min_stat,
                                       err_maj,
                                       GSS_C_GSS_CODE,
                                       GSS_C_NO_OID,
                                       &msg_ctx,
                                       &status_string);

	if (GSS_ERROR(ret)) return;

	uwsgi_log("[uwsgi-spnego] %s() error (major): %.*s\n", func, status_string.length, status_string.value);

	gss_release_buffer(&min_stat, &status_string);
	
	ret = gss_display_status (&min_stat,
                                       err_min,
                                       GSS_C_MECH_CODE,
                                       GSS_C_NULL_OID,
                                       &msg_ctx,
                                       &status_string);

	if (GSS_ERROR(ret)) return;

	if (status_string.length > 0) {
        	uwsgi_log("[uwsgi-spnego] %s() error (minor): %.*s\n",func, status_string.length, status_string.value);
	}
	if (status_string.value) {
		gss_release_buffer(&min_stat, &status_string);
	}
	
}

static char *uwsgi_spnego_new_token(struct wsgi_request *wsgi_req, struct uwsgi_route *ur, char *token_buf, size_t token_buf_len, size_t *b64_len) {

        char *b64 = NULL;

        OM_uint32 ret;
        OM_uint32 min_ret;

	gss_buffer_desc service = GSS_C_EMPTY_BUFFER;
	struct uwsgi_buffer *ub = NULL;

	if (ur->data_len) {
		char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        	uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);

        	ub = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, ur->data, ur->data_len);
		if (!ub) goto end;
        	service.value = ub->buf;
        	service.length = ub->pos;
	}

        gss_name_t server_name = GSS_C_NO_NAME;
        gss_name_t client_name = GSS_C_NO_NAME;
        gss_ctx_id_t context = GSS_C_NO_CONTEXT;
        gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;

        gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
        token.value = token_buf;
        token.length = token_buf_len;

        if (service.length == 0) {
                service.value = "HTTP";
                service.length = 4;
        }

        ret = gss_import_name(&min_ret, &service, GSS_C_NT_HOSTBASED_SERVICE, &server_name);
        if (GSS_ERROR(ret)) {
                uwsgi_spnego_err("gss_import_name", ret, min_ret);
		goto end;
        }


        ret = gss_acquire_cred(&min_ret, server_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &cred, NULL, NULL);
        if (GSS_ERROR(ret)) {
                uwsgi_spnego_err("gss_acquire_cred", ret, min_ret);
		goto end;
        }

        gss_buffer_desc output = GSS_C_EMPTY_BUFFER;


        ret = gss_accept_sec_context(&min_ret, &context, cred, &token, GSS_C_NO_CHANNEL_BINDINGS, &client_name, NULL, &output, NULL, NULL, NULL);

        if (GSS_ERROR(ret)) {
                uwsgi_spnego_err("gss_accept_sec_context", ret, min_ret);
		if (output.value) {
			gss_release_buffer(&min_ret, &output);
		}
                goto end;
        }

        if (output.length) {
                b64 = uwsgi_base64_encode(output.value, output.length, b64_len);
		if (output.value) {
                	gss_release_buffer(&min_ret, &output);
		}
                if (!b64) {
                        goto end;
                }

                ret = gss_display_name(&min_ret, client_name, &output, NULL);
                if (GSS_ERROR(ret)) {
                        uwsgi_spnego_err("gss_display_name", ret, min_ret);
			if (output.value) {
				gss_release_buffer(&min_ret, &output);
			}
                        free(b64);
			b64 = NULL;
                        goto end;
                }
                wsgi_req->remote_user = uwsgi_req_append(wsgi_req, "REMOTE_USER", 11, output.value, output.length);
		if (!wsgi_req->remote_user) {
			if (output.value) {
                		gss_release_buffer(&min_ret, &output);
			}
                        free(b64);
			b64 = NULL;
                        goto end;
		}
		wsgi_req->remote_user_len = output.length;
		if (output.value) {
                	gss_release_buffer(&min_ret, &output);
		}
                if (!wsgi_req->remote_user) {
			wsgi_req->remote_user_len = 0;
                        free(b64);
			b64 = NULL;
                        goto end;
                }
        }
end:
        if (server_name != GSS_C_NO_NAME) {
                gss_release_name(&min_ret, &server_name);
        }

        if (client_name != GSS_C_NO_NAME) {
                gss_release_name(&min_ret, &client_name);
        }

	if (cred != GSS_C_NO_CREDENTIAL) {
		gss_release_cred(&min_ret, &cred);
	}

        if (context != GSS_C_NO_CONTEXT) {
                gss_delete_sec_context(&min_ret, &context, GSS_C_NO_BUFFER);
        }


	if (ub) {
		uwsgi_buffer_destroy(ub);
	}

        return b64;
}


static int uwsgi_routing_func_spnego(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

        char *negotiate = NULL;
        size_t negotiate_len = 0;
        size_t b64_len = 0;

        // check for "Negotiate " string at least
        if (wsgi_req->authorization_len > 10) {
                if (strncmp(wsgi_req->authorization, "Negotiate ", 10))
                        goto forbidden;

                char *token = uwsgi_base64_decode(wsgi_req->authorization+10, wsgi_req->authorization_len-10, &b64_len);
                if (token) {
                        negotiate = uwsgi_spnego_new_token(wsgi_req, ur, token, b64_len, &negotiate_len);
                        free(token);
                        if (negotiate) {
                                char *auth_header = uwsgi_concat2n("WWW-Authenticate: Negotiate ", 28, negotiate, negotiate_len);
				free(negotiate);
                                uwsgi_additional_header_add(wsgi_req, auth_header, negotiate_len + 28);
                                free(auth_header);
                                return UWSGI_ROUTE_NEXT;

                        }
			if (ur->custom) return UWSGI_ROUTE_NEXT;
                }
        }

forbidden:
	if (uwsgi_response_prepare_headers(wsgi_req, "401 Authorization Required", 26)) goto end;
	if (uwsgi_response_add_connection_close(wsgi_req)) goto end;
	if (uwsgi_response_add_content_type(wsgi_req, "text/plain", 10)) goto end;

	if (negotiate && negotiate_len) {
		char *neg_token = uwsgi_concat2n("Negotiate ", 10, negotiate, negotiate_len);
		int ret = uwsgi_response_add_header(wsgi_req, "WWW-Authenticate", 16, neg_token, 10 + negotiate_len);
		free(neg_token);
		if (ret) goto end;
	}
	else {
		if (uwsgi_response_add_header(wsgi_req, "WWW-Authenticate", 16, "Negotiate", 9)) goto end;
	}

        uwsgi_response_write_body_do(wsgi_req, "Unauthorized", 12);
end:
	if (ur->custom) return UWSGI_ROUTE_NEXT;
        return UWSGI_ROUTE_BREAK;
}



static int uwsgi_router_spnego(struct uwsgi_route *ur, char *args) {

        ur->func = uwsgi_routing_func_spnego;
	ur->data = args ;
	if (args) {
		ur->data_len = strlen(args);
	}

        return 0;
}

static int uwsgi_router_spnego_next(struct uwsgi_route *ur, char *args) {
	ur->custom = 1;
	return uwsgi_router_spnego(ur, args);
}

static void router_spnego_register(void) {
	uwsgi_register_router("spnego", uwsgi_router_spnego);
	uwsgi_register_router("spnego-next", uwsgi_router_spnego_next);
}

struct uwsgi_plugin router_spnego_plugin = {
	.name = "router_spnego",
	.on_load = router_spnego_register,
};
