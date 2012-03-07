
#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

uint16_t proto_base_add_uwsgi_header(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, char *val, uint16_t vallen) {


	int i;
	char *buffer = wsgi_req->buffer + wsgi_req->uh.pktsize;
	char *watermark = wsgi_req->buffer + uwsgi.buffer_size;
	char *ptr = buffer;


	for (i = 0; i < keylen; i++) {
		if (key[i] == '-') {
			key[i] = '_';
		}
		else {
			key[i] = toupper((int)key[i]);
		}
	}

	if (uwsgi_strncmp("CONTENT_TYPE", 12, key, keylen) && uwsgi_strncmp("CONTENT_LENGTH", 14, key, keylen)) {
		if (buffer + keylen + vallen + 2 + 2 + 5 >= watermark) {
			uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, key, vallen, val);
			return 0;
		}
		*ptr++ = (uint8_t) ((keylen + 5) & 0xff);
		*ptr++ = (uint8_t) (((keylen + 5) >> 8) & 0xff);
		memcpy(ptr, "HTTP_", 5);
		ptr += 5;
		memcpy(ptr, key, keylen);
		ptr += keylen;
		keylen += 5;
	}
	else {
		if (buffer + keylen + vallen + 2 + 2 >= watermark) {
			uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, key, vallen, val);
			return 0;
		}
		*ptr++ = (uint8_t) (keylen & 0xff);
		*ptr++ = (uint8_t) ((keylen >> 8) & 0xff);
		memcpy(ptr, key, keylen);
		ptr += keylen;
	}

	*ptr++ = (uint8_t) (vallen & 0xff);
	*ptr++ = (uint8_t) ((vallen >> 8) & 0xff);
	memcpy(ptr, val, vallen);

#ifdef UWSGI_DEBUG
	uwsgi_log("add uwsgi var: %.*s = %.*s\n", keylen, key, vallen, val);
#endif

	return keylen + vallen + 2 + 2;
}



uint16_t proto_base_add_uwsgi_var(struct wsgi_request * wsgi_req, char *key, uint16_t keylen, char *val, uint16_t vallen) {


	char *buffer = wsgi_req->buffer + wsgi_req->uh.pktsize;
	char *watermark = wsgi_req->buffer + uwsgi.buffer_size;
	char *ptr = buffer;

	if (buffer + keylen + vallen + 2 + 2 >= watermark) {
		uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, key, vallen, val);
		return 0;
	}


	*ptr++ = (uint8_t) (keylen & 0xff);
	*ptr++ = (uint8_t) ((keylen >> 8) & 0xff);
	memcpy(ptr, key, keylen);
	ptr += keylen;

	*ptr++ = (uint8_t) (vallen & 0xff);
	*ptr++ = (uint8_t) ((vallen >> 8) & 0xff);
	memcpy(ptr, val, vallen);

#ifdef UWSGI_DEBUG
	uwsgi_log("add uwsgi var: %.*s = %.*s\n", keylen, key, vallen, val);
#endif

	return keylen + vallen + 2 + 2;
}


int uwsgi_proto_base_accept(struct wsgi_request *wsgi_req, int fd) {

	wsgi_req->c_len = sizeof(struct sockaddr_un);
	return accept(fd, (struct sockaddr *) &wsgi_req->c_addr, (socklen_t *) & wsgi_req->c_len);
}

void uwsgi_proto_base_close(struct wsgi_request *wsgi_req) {

	if (wsgi_req->async_post) {
		fclose(wsgi_req->async_post);
		if (wsgi_req->body_as_file) {
			close(wsgi_req->poll.fd);
		}
	}
	else {
		close(wsgi_req->poll.fd);
	}
}
