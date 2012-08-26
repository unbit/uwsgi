#include "../../uwsgi.h"

#ifdef UWSGI_ROUTING

#ifdef __linux__
#include <crypt.h>
#else
#ifdef UWSGI_THREADING
pthread_mutex_t ur_basicauth_crypt_mutex;
#endif
#endif

extern struct uwsgi_server uwsgi;

// this algo is based on nginx one (the fastest i have tested)
static char *http_basic_auth_get(char *authorization, uint16_t len) {

	uint16_t i;
	static uint8_t table64[] = {
        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
        	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
        	77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
        	77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        	77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
	};

	for (i = 0; i < len; i++) {
		if (authorization[i] == '=')
			break;

		// check for invalid content
		if (table64[ (uint8_t) authorization[i] ] == 77) {
			return NULL;
		}
	}

	// check for invalid length
	if (i % 4 == 1)
		return NULL;

	uint16_t dst_len = (((len+3)/4) * 3) + 1;
	char *dst = uwsgi_malloc(dst_len);

	char *ptr = dst;
	uint8_t *src = (uint8_t *) authorization;
	while(i > 3) {
		*ptr++= (char) ( table64[src[0]] << 2 | table64[src[1]] >> 4);
		*ptr++= (char) ( table64[src[1]] << 4 | table64[src[2]] >> 2);
		*ptr++= (char) ( table64[src[2]] << 6 | table64[src[3]]);

		src+=4;
		i-=4;
	}

	if (i > 1) {
		*ptr++= (char) ( table64[src[0]] << 2 | table64[src[1]] >> 4);
	}

	if (i > 2) {
		*ptr++= (char) ( table64[src[1]] << 4 | table64[src[2]] >> 2);
	}

	*ptr++= 0;	

	return dst;
	
}

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

        struct iovec iov[4];

        if (wsgi_req->protocol_len > 0) {
        	iov[0].iov_base = wsgi_req->protocol;
        	iov[0].iov_len = wsgi_req->protocol_len;
	}
	else {
        	iov[0].iov_base = "HTTP/1.0";
        	iov[0].iov_len = 8;
	}

	// chec for "Basic =" string at least
	if (wsgi_req->authorization_len > 7 && ur->data2_len > 0) {
		if (strncmp(wsgi_req->authorization, "Basic ", 6))
			goto forbidden;

		char *auth = http_basic_auth_get(wsgi_req->authorization+6, wsgi_req->authorization_len-6);
		if (auth) {
			if (!ur->custom) {
				// check htpasswd-like file
				uint16_t ulen = htpasswd_check(ur->data2, auth);
				if (ulen > 0) {
					wsgi_req->remote_user = uwsgi_req_append(wsgi_req, "REMOTE_USER", 11, auth, ulen); 
					if (wsgi_req->remote_user)
						wsgi_req->remote_user_len = ulen;
					free(auth);
					return UWSGI_ROUTE_CONTINUE;
				}
			}
			else {
				if (!strcmp(auth, ur->data2)) {
					wsgi_req->remote_user = uwsgi_req_append(wsgi_req, "REMOTE_USER", 11, auth, ur->custom); 
					if (wsgi_req->remote_user)
						wsgi_req->remote_user_len = ur->custom;
					free(auth);
					return UWSGI_ROUTE_CONTINUE;
				}
			}
			free(auth);
			if (ur->is_last)
				goto forbidden;
			return UWSGI_ROUTE_NEXT;
		}
	}

forbidden:
        iov[1].iov_base = " 401 Authorization Required\r\nWWW-Authenticate: Basic realm=\"";
        iov[1].iov_len = 60 ;

	iov[2].iov_base = ur->data;
	iov[2].iov_len = ur->data_len;

	iov[3].iov_base = "\"\r\n\r\n";
	iov[3].iov_len = 5;

        wsgi_req->headers_size = wsgi_req->socket->proto_writev_header(wsgi_req, iov, 4);

	wsgi_req->response_size = wsgi_req->socket->proto_write(wsgi_req,"Unauthorized", 12);

	wsgi_req->status = 401;

	return UWSGI_ROUTE_BREAK;
}

#ifndef __linux__
void router_basicauth_init_lock() {
	pthread_mutex_init(&ur_basicauth_crypt_mutex, NULL);
}
#endif

int uwsgi_router_basicauth(struct uwsgi_route *ur, char *args) {

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


void router_basicauth_register(void) {

	uwsgi_register_router("basicauth", uwsgi_router_basicauth);
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
