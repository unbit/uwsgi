#include "../../uwsgi.h"

#ifdef UWSGI_ROUTING

#ifdef __linux__
#include <crypt.h>
#elif defined(__CYGWIN__)
#include <crypt.h>
pthread_mutex_t ur_basicauth_crypt_mutex;
#else
pthread_mutex_t ur_basicauth_crypt_mutex;
#endif

extern struct uwsgi_server uwsgi;

static uint16_t htpasswd_check(char *filename, char *auth) {

	char line[1024];

	char *colon = strchr(auth, ':');
	if (!colon) return 0;

	FILE *htpasswd = fopen(filename, "r");
	if (!htpasswd) {
		return 0;
	}
	while(fgets(line, 1024, htpasswd)) {
		char *colon2 = strchr(line, ':');
		if (!colon2) break;	

		char *cpwd = colon2+1;
		size_t clen = strlen(cpwd);
		if (clen < 13) break;

		if (clen > 13) cpwd[13] = 0;

#ifdef __linux__
		struct crypt_data cd;
		cd.initialized = 0;
		// we do as nginx here
		cd.current_salt[0] = ~cpwd[0];
		char *crypted = crypt_r( colon+1, cpwd, &cd);
#else
		if (uwsgi.threads > 1) pthread_mutex_lock(&ur_basicauth_crypt_mutex);
		char *crypted = crypt( colon+1, cpwd);
		if (uwsgi.threads > 1) pthread_mutex_unlock(&ur_basicauth_crypt_mutex);
#endif
		if (!crypted) continue;

		if (!strcmp( crypted, cpwd )) {
			if (!uwsgi_strncmp(auth, colon-auth, line, colon2-line)) {
				fclose(htpasswd);
				return colon-auth;
			}
		}
	}
	
	fclose(htpasswd);

	return 0;
}

int uwsgi_routing_func_basicauth(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	if (wsgi_req->authorization_len > 7 && ur->data2_len > 0) {
		if (strncmp(wsgi_req->authorization, "Basic ", 6))
			goto forbidden;

		size_t auth_len = 0;
		char *auth = uwsgi_base64_decode(wsgi_req->authorization+6, wsgi_req->authorization_len-6, &auth_len);
		if (auth) {
			if (!ur->custom) {
				// check htpasswd-like file
				uint16_t ulen = htpasswd_check(ur->data2, auth);
				if (ulen > 0) {
					wsgi_req->remote_user = uwsgi_req_append(wsgi_req, "REMOTE_USER", 11, auth, ulen); 
					if (wsgi_req->remote_user)
						wsgi_req->remote_user_len = ulen;
					free(auth);
					if (ur->data3_len > 0)
						return UWSGI_ROUTE_CONTINUE;
					return UWSGI_ROUTE_GOON;
				}
			}
			else {
				if (!uwsgi_strncmp(auth, auth_len, ur->data2, ur->data2_len)) {
					wsgi_req->remote_user = uwsgi_req_append(wsgi_req, "REMOTE_USER", 11, auth, ur->custom); 
					if (wsgi_req->remote_user)
						wsgi_req->remote_user_len = ur->custom;
					free(auth);
					if (ur->data3_len > 0)
						return UWSGI_ROUTE_CONTINUE;
					return UWSGI_ROUTE_GOON;
				}
			}
			free(auth);
			if (ur->is_last)
				goto forbidden;
			return UWSGI_ROUTE_NEXT;
		}
	}

forbidden:
	if (uwsgi_response_prepare_headers(wsgi_req, "401 Authorization Required", 26)) goto end;
	char *realm = uwsgi_concat3n("Basic realm=\"", 13, ur->data, ur->data_len, "\"", 1);
	int ret = uwsgi_response_add_header(wsgi_req, "WWW-Authenticate", 16, realm, 13 + ur->data_len + 1);
	free(realm);
	if (ret) goto end;
	uwsgi_response_write_body_do(wsgi_req, "Unauthorized", 12);
end:
	return UWSGI_ROUTE_BREAK;
}

#ifndef __linux__
void router_basicauth_init_lock() {
	pthread_mutex_init(&ur_basicauth_crypt_mutex, NULL);
}
#endif

static int uwsgi_router_basicauth(struct uwsgi_route *ur, char *args) {

	ur->func = uwsgi_routing_func_basicauth;

	char *comma = strchr(args, ',');
	if (!comma) {
		uwsgi_log("invalid route syntax: %s\n", args);
                exit(1);
	}

	*comma = 0;

	char *colon = strchr(comma+1, ':');
	// is an htpasswd-like file ?
	if (!colon) {
		ur->custom = 0;
	}
	else {
		ur->custom = colon-(comma+1);
	}

	ur->data = args;
	ur->data_len = strlen(args);

	ur->data2 = comma+1;
	ur->data2_len = strlen(ur->data2);

	return 0;
}

static int uwsgi_router_basicauth_last(struct uwsgi_route *ur, char *args) {
	uwsgi_router_basicauth(ur, args);
	ur->data3_len = 1;
	return 0;
}


void router_basicauth_register(void) {

	uwsgi_register_router("basicauth", uwsgi_router_basicauth);
	uwsgi_register_router("basicauth-last", uwsgi_router_basicauth_last);
}

struct uwsgi_plugin router_basicauth_plugin = {

	.name = "router_basicauth",
	.on_load = router_basicauth_register,
#ifndef __linux__
	.enable_threads = router_basicauth_init_lock,
#endif
};
#else
struct uwsgi_plugin router_basicauth_plugin = {
	.name = "router_basicauth",
};
#endif
