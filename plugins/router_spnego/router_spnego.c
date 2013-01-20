#include "../../uwsgi.h"

#ifdef UWSGI_ROUTING

#include <gssapi/gssapi.h>

extern struct uwsgi_server uwsgi;

// log errors...
static void uwsgi_spnego_err(OM_uint32 err_maj, OM_uint32 err_min) {

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

	if (GSS_ERROR(ret)) {
		return;
	}

	uwsgi_log("[uwsgi-spnego] error: %.*s\n", status_string.length, status_string.value);

	gss_release_buffer(&min_stat, &status_string);
	
	ret = gss_display_status (&min_stat,
                                       err_min,
                                       GSS_C_MECH_CODE,
                                       GSS_C_NULL_OID,
                                       &msg_ctx,
                                       &status_string);

	if (GSS_ERROR(ret)) {
		return;
	}


        uwsgi_log("[uwsgi-spnego] error: %.*s\n", status_string.length, status_string.value);

	gss_release_buffer(&min_stat, &status_string);
	
}

static char *uwsgi_spnego_new_token(struct wsgi_request *wsgi_req, gss_cred_id_t cred, char *token_buf, size_t token_buf_len, size_t *b64_len) {

        char *b64 = NULL;

        OM_uint32 ret;
        OM_uint32 min_ret;

        gss_ctx_id_t context = GSS_C_NO_CONTEXT;
        gss_name_t client_name = GSS_C_NO_NAME;

        gss_buffer_desc output = GSS_C_EMPTY_BUFFER;

        gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
        token.value = token_buf;
        token.length = token_buf_len;


        ret = gss_accept_sec_context(&min_ret, &context, cred, &token, GSS_C_NO_CHANNEL_BINDINGS, &client_name, NULL, &output, NULL, NULL, NULL);

        if (GSS_ERROR(ret)) {
                uwsgi_spnego_err(ret, min_ret);
                goto end;
        }

        if (output.length) {
                b64 = uwsgi_base64_encode(output.value, output.length, b64_len);
                gss_release_buffer(&min_ret, &output);
                if (!b64) {
                        goto end;
                }

                ret = gss_display_name(&min_ret, client_name, &output, NULL);
                if (GSS_ERROR(ret)) {
                        uwsgi_spnego_err(ret, min_ret);
                        free(b64);
			b64 = NULL;
                        goto end;
                }
                wsgi_req->remote_user = uwsgi_req_append(wsgi_req, "REMOTE_USER", 11, output.value, output.length);
		wsgi_req->remote_user_len = output.length;
                gss_release_buffer(&min_ret, &output);
                if (!wsgi_req->remote_user) {
			wsgi_req->remote_user_len = 0;
                        uwsgi_spnego_err(ret, min_ret);
                        free(b64);
			b64 = NULL;
                        goto end;
                }
        }
end:
        if (context != GSS_C_NO_CONTEXT) {
                gss_delete_sec_context(&min_ret, &context, GSS_C_NO_BUFFER);
        }
        if (client_name != GSS_C_NO_NAME) {
                gss_release_name(&min_ret, &client_name);
        }
        return b64;
}


static int uwsgi_routing_func_spnego(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

        char *negotiate = NULL;
        size_t negotiate_len = 0;
        struct uwsgi_buffer *ub = NULL;
        size_t b64_len = 0;

        // check for "Negotiate " string at least
        if (wsgi_req->authorization_len > 10) {
                if (strncmp(wsgi_req->authorization, "Negotiate ", 10))
                        goto forbidden;

                char *token = uwsgi_base64_decode(wsgi_req->authorization+10, wsgi_req->authorization_len-10, &b64_len);
                if (token && b64_len) {
                        negotiate = uwsgi_spnego_new_token(wsgi_req, ur->data2, token, b64_len, &negotiate_len);
                        free(token);
                        if (negotiate) {
                                char *auth_header = uwsgi_concat2n("WWW-Authenticate: Negotiate ", 28, negotiate, negotiate_len);
				free(negotiate);
                                uwsgi_additional_header_add(wsgi_req, auth_header, negotiate_len + 28);
                                free(auth_header);
                                if (ur->custom)
                                        return UWSGI_ROUTE_CONTINUE;
                                return UWSGI_ROUTE_GOON;

                        }
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

        uwsgi_response_write_body(wsgi_req, "Unauthorized", 12);
end:
        return UWSGI_ROUTE_BREAK;
}



static int uwsgi_router_spnego(struct uwsgi_route *ur, char *args) {

        ur->func = uwsgi_routing_func_spnego;

	OM_uint32 ret;
        OM_uint32 min_ret;

	gss_buffer_desc service = GSS_C_EMPTY_BUFFER;
	service.value = args;
	service.length = strlen(args);

	if (service.length == 0) {
		service.value = "HTTP";
		service.length = 4;
	}

	gss_name_t server_name = GSS_C_NO_NAME;

	ret = gss_import_name(&min_ret, &service, GSS_C_NT_HOSTBASED_SERVICE, &server_name);
	if (GSS_ERROR(ret)) {
                uwsgi_spnego_err(ret, min_ret);
		exit(1);
	}	

	gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;

	ret = gss_acquire_cred(&min_ret, server_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &cred, NULL, NULL);
	if (GSS_ERROR(ret)) {
                uwsgi_spnego_err(ret, min_ret);
		exit(1);
	}	
	
	ur->data2 = cred;

        return 0;
}

static int uwsgi_router_spnego_last(struct uwsgi_route *ur, char *args) {
	uwsgi_router_spnego(ur, args);
	ur->custom = 1;
	return 0;
}


static void router_spnego_register(void) {

	uwsgi_register_router("spnego", uwsgi_router_spnego);
	uwsgi_register_router("spnego-last", uwsgi_router_spnego_last);
}

struct uwsgi_plugin router_spnego_plugin = {

	.name = "router_spnego",
	.on_load = router_spnego_register,
};
#else
struct uwsgi_plugin router_spnego_plugin = {
	.name = "router_spnego",
};
#endif
