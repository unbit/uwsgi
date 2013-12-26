#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_radius_conf {
	char *realm;
	uint16_t realm_len;
	char *server;
	char *secret;
	uint16_t secret_len;
	char *nas_port_str;
	uint32_t nas_port;
	char *nas_address_str;
	uint32_t nas_address;
};

static uint16_t uwsgi_radius_auth(struct uwsgi_radius_conf *urc, char *auth, size_t auth_len) {
	static uint8_t packet_identifier = 0;
	char access_request[4096];
	char hash[4096];
	// md5 result
	char md5_hash[16];

	size_t i;
	char *password = memchr(auth, ':', auth_len);
	if (!password) return 0;
	char *username = auth;
	uint16_t username_len = password - auth;
	password++;
	uint16_t password_len = auth_len - (username_len+1);

	int fd = uwsgi_connect_udp(urc->server);
	if (fd < 0) return 0;

	uwsgi_socket_nb(fd);

	// start generating authenticator
	char authenticator[16];
	for(i=0;i<16;i++) authenticator[i] = rand();	

	// generate the User-Password attribute
	char *md5 = authenticator;

	// step 1 pad to 16 bytes boundary
	size_t pwd16_len = password_len + (16 - (password_len % 16));
	if (pwd16_len > 128) return 0;
	
	// compute the whole packet size
	uint16_t access_request_len = 4 + 16 + 2 + username_len + 2 + pwd16_len + 6 + 6;
	memset(access_request, 0, access_request_len);
	if (access_request_len > 4096) return 0;
	char *pwd16_buf = access_request + (access_request_len - (pwd16_len + 6 + 6));
	memcpy(pwd16_buf, password, password_len);

	// allocate a buffer for the hash
	if (urc->secret_len + 16 > 4096) return 0;
	memcpy(hash, urc->secret, urc->secret_len);
	
	for(i=0;i<pwd16_len;i+=16) {
		// append the last md5 to the hash (after the secret)
		memcpy(hash + urc->secret_len, md5, 16);
		// calculate its md5
		if (!uwsgi_md5(hash, urc->secret_len + 16, md5_hash)) {
			goto end;
		}	
		size_t j;
		// set md5 to the new result
		md5 = &pwd16_buf[i];
		// xor the result (we use the authenticator as destination buffer)
		for(j=0;j<16;j++) {
			md5[j] = md5_hash[j] ^ md5[j];
		}
	}

	// complete the packet
	packet_identifier++;
	access_request[0] = 1;
	access_request[1] = packet_identifier;
        access_request[2] = (uint8_t) ((access_request_len >> 8) & 0xff);
	access_request[3] = (uint8_t) (access_request_len & 0xff);
	memcpy(access_request + 4, authenticator, 16);
	access_request[4 + 16] = 1;
	access_request[4 + 16 + 1] = username_len + 2;
	memcpy(access_request + (4 + 16 + 2), username, username_len);
	access_request[4 + 16 + 2 + username_len] = 2;
	access_request[4 + 16 + 2 + username_len + 1] = pwd16_len + 2;
	// add nas port
	access_request[4 + 16 + 2 + username_len + 2 + pwd16_len] = 5;
	access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 1] = 6;
	access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 2] = (uint8_t) ((urc->nas_port >> 24) & 0xff);
	access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 3] = (uint8_t) ((urc->nas_port >> 16) & 0xff);
	access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 4] = (uint8_t) ((urc->nas_port >> 8) & 0xff);
	access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 5] = (uint8_t) (urc->nas_port & 0xff);
	// add nas address
	access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 6] = 4;
        access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 6 + 1] = 6;
        access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 6 + 2] = (uint8_t) ((urc->nas_address >> 24) & 0xff);
        access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 6 + 3] = (uint8_t) ((urc->nas_address >> 16) & 0xff);
        access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 6 + 4] = (uint8_t) ((urc->nas_address >> 8) & 0xff);
        access_request[4 + 16 + 2 + username_len + 2 + pwd16_len + 6 + 5] = (uint8_t) (urc->nas_address & 0xff);
	
	if (write(fd, access_request, access_request_len) != access_request_len) {
		goto end;
	}

	// now wait for the response
	int ret = uwsgi.wait_read_hook(fd, uwsgi.socket_timeout); 	
	if (ret <= 0) goto end;

	ssize_t rlen = read(fd, access_request, access_request_len);
	// we need at least 4 + 16
	if (rlen >= 20) {
		char response_authenticator[16];
		if (access_request[1] != packet_identifier) goto end;
		if (rlen + urc->secret_len > 4096) goto end;
		// get the authenticator
		memcpy(response_authenticator, access_request+4, 16);	
		// append the secret
		memcpy(access_request+rlen, urc->secret, urc->secret_len);
		// change the authenticator
		memcpy(access_request+4, authenticator, 16);
		// compute the md5
		if (!uwsgi_md5(access_request, rlen + urc->secret_len, md5_hash)) {
                        goto end;
                }	
		if (memcmp(md5_hash, response_authenticator, 16)) goto end;
		// Access-Accept
		if (access_request[0] == 2) {
			close(fd);
			return username_len;
		}
	}

end:
	close(fd);
	return 0;
}

static int uwsgi_routing_func_radius(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	struct uwsgi_radius_conf *urc = (struct uwsgi_radius_conf *) ur->data2;

	// skip if already authenticated
        if (wsgi_req->remote_user_len > 0) {
                return UWSGI_ROUTE_NEXT;
        }

        if (wsgi_req->authorization_len > 7) {
                if (strncmp(wsgi_req->authorization, "Basic ", 6))
                        goto forbidden;

                size_t auth_len = 0;
                char *auth = uwsgi_base64_decode(wsgi_req->authorization+6, wsgi_req->authorization_len-6, &auth_len);
                if (auth) {
                	uint16_t rlen = uwsgi_radius_auth(urc, auth, auth_len);
			if (rlen > 0) {
                        	wsgi_req->remote_user = uwsgi_req_append(wsgi_req, "REMOTE_USER", 11, auth, rlen);
				free(auth);
                                if (!wsgi_req->remote_user) goto forbidden;
                                wsgi_req->remote_user_len = rlen;
				return UWSGI_ROUTE_NEXT;
                        }
			free(auth);
                        if (ur->custom) return UWSGI_ROUTE_NEXT;
                }
        }

forbidden:
        if (uwsgi_response_prepare_headers(wsgi_req, "401 Authorization Required", 26)) goto end;
        char *realm = uwsgi_concat3n("Basic realm=\"", 13, urc->realm, urc->realm_len, "\"", 1);
	// no need to check for errors
        uwsgi_response_add_header(wsgi_req, "WWW-Authenticate", 16, realm, 13 + urc->realm_len + 1);
        free(realm);
        uwsgi_response_write_body_do(wsgi_req, "Unauthorized", 12);
end:
        return UWSGI_ROUTE_BREAK;
}

static int uwsgi_router_radius(struct uwsgi_route *ur, char *args) {
	ur->func = uwsgi_routing_func_radius;
	ur->data = args;
	ur->data_len = strlen(args);
	struct uwsgi_radius_conf *urc = uwsgi_calloc(sizeof(struct uwsgi_radius_conf));
        if (uwsgi_kvlist_parse(ur->data, ur->data_len, ',', '=',
                        "realm", &urc->realm,
                        "server", &urc->server,
                        "secret", &urc->secret,
                        "nas_port", &urc->nas_port_str,
                        "nas_address", &urc->nas_address_str,
                        NULL)) {
                        uwsgi_log("invalid route syntax: %s\n", args);
                        exit(1);
                }

	if (!urc->realm || !urc->server || !urc->secret) {
		uwsgi_log("invalid radius route syntax: you need to specify a realm a server and a secret\n");
                exit(1);
	}

	urc->realm_len = strlen(urc->realm);
	urc->secret_len = strlen(urc->secret);

	if (urc->nas_port_str) {
		urc->nas_port = strtoul(urc->nas_port_str, NULL, 10);
	}

	if (!urc->nas_address_str) {
		urc->nas_address_str = uwsgi.hostname;
	}

	struct hostent *he = gethostbyname(urc->nas_address_str);
	if (he) {
		if (he->h_addr_list[0]) {
			memcpy(&urc->nas_address, he->h_addr_list[0], 4);
			urc->nas_address = htonl(urc->nas_address);
		}
	}
        ur->data2 = urc;
        return 0;
}

static int uwsgi_router_radius_next(struct uwsgi_route *ur, char *args) {
	ur->custom = 1;
	return uwsgi_router_radius(ur, args);
}

static void router_radius_register(void) {
	uwsgi_register_router("radius", uwsgi_router_radius);
	uwsgi_register_router("radius-next", uwsgi_router_radius_next);
}

struct uwsgi_plugin router_radius_plugin = {
	.name = "router_radius",
	.on_load = router_radius_register,
};
