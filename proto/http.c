/* async http protocol parser */

#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

static uint16_t http_add_uwsgi_header(struct wsgi_request *wsgi_req, char *hh, int hhlen) {

	char *buffer = wsgi_req->buffer + wsgi_req->uh.pktsize;
	char *watermark = wsgi_req->buffer + uwsgi.buffer_size;

	int i;
	int status = 0;
	char *val = hh;
	uint16_t keylen = 0, vallen = 0;
	int prefix = 0;
	char *ptr = buffer;

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

	if (uwsgi_strncmp("CONTENT_TYPE", 12, hh, keylen) && uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		if (!uwsgi_strncmp("IF_MODIFIED_SINCE", 17, hh, keylen)) {
        		wsgi_req->if_modified_since = val;
                	wsgi_req->if_modified_since_len = vallen;
        	}
		else if (!uwsgi_strncmp("AUTHORIZATION", 13, hh, keylen)) {
        		wsgi_req->authorization = val;
                	wsgi_req->authorization_len = vallen;
		}
		else if (!uwsgi_strncmp("X_FORWARDED_SSL", 15, hh, keylen)) {
			if (vallen == 2 && val[0] == 'o' && val[1] == 'n') {
				wsgi_req->scheme = "https";
				wsgi_req->scheme_len = 5;
			}
		}
		else if (uwsgi.vhost_host && !uwsgi_strncmp("HOST", 4, hh, keylen)) {
        		wsgi_req->host = val;
                	wsgi_req->host_len = vallen;
        	}
		keylen += 5;
		prefix = 1;
	}
	else if (!uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		wsgi_req->post_cl = uwsgi_str_num(val, vallen);
	}
	else if (!uwsgi_strncmp("CONTENT_TYPE", 12, hh, keylen)) {
		wsgi_req->content_type = val;
		wsgi_req->content_type_len = vallen;
	}

	if (buffer + keylen + vallen + 2 + 2 >= watermark) {
		if (prefix) {
			uwsgi_log("[WARNING] unable to add HTTP_%.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, hh, vallen, val);
		}
		else {
			uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, hh, vallen, val);
		}
		return 0;
	}


	*ptr++ = (uint8_t) (keylen & 0xff);
	*ptr++ = (uint8_t) ((keylen >> 8) & 0xff);

	if (prefix) {
		memcpy(ptr, "HTTP_", 5);
		ptr += 5;
		memcpy(ptr, hh, keylen - 5);
		ptr += (keylen - 5);
	}
	else {
		memcpy(ptr, hh, keylen);
		ptr += keylen;
	}

	*ptr++ = (uint8_t) (vallen & 0xff);
	*ptr++ = (uint8_t) ((vallen >> 8) & 0xff);
	memcpy(ptr, val, vallen);

#ifdef UWSGI_DEBUG
	uwsgi_log("add uwsgi var: %.*s = %.*s\n", keylen - (prefix * 5), hh, vallen, val);
#endif

	return 2 + keylen + 2 + vallen;
}


static int http_parse(struct wsgi_request *wsgi_req, char *watermark) {

	char *ptr = wsgi_req->proto_parser_buf;
	char *base = ptr;
	char *query_string = NULL;
	char ip[INET_ADDRSTRLEN+1];
	struct sockaddr_in *http_sin = (struct sockaddr_in *) &wsgi_req->c_addr;

	wsgi_req->path_info_pos = -1;

	// REQUEST_METHOD 
	while (ptr < watermark) {
		if (*ptr == ' ') {
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_METHOD", 14, base, ptr - base);
			wsgi_req->method = (wsgi_req->buffer + wsgi_req->uh.pktsize) - (ptr - base);
			wsgi_req->method_len = ptr - base;
			ptr++;
			break;
		}
		ptr++;
	}

	// REQUEST_URI / PATH_INFO / QUERY_STRING
	base = ptr;
	while (ptr < watermark) {
		if (*ptr == '?' && !query_string) {
			if (watermark + (ptr - base) < (char *)(wsgi_req->proto_parser_buf + uwsgi.buffer_size)) {
				wsgi_req->path_info = watermark;
				wsgi_req->path_info_len = ptr - base;
				http_url_decode(base, &wsgi_req->path_info_len, wsgi_req->path_info);
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, wsgi_req->path_info, wsgi_req->path_info_len);
				wsgi_req->path_info = (wsgi_req->buffer + wsgi_req->uh.pktsize) - (ptr - base);
				wsgi_req->path_info_len = ptr - base;
			}
			else {
				uwsgi_log("not enough space in wsgi_req http proto_parser_buf to encode PATH_INFO, consider tuning it with --buffer-size\n");
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, base, ptr - base);
				wsgi_req->path_info = (wsgi_req->buffer + wsgi_req->uh.pktsize) - (ptr - base);
				wsgi_req->path_info_len = ptr - base;
			}
			wsgi_req->path_info_pos = 3;
			query_string = ptr + 1;
		}
		else if (*ptr == ' ') {
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11, base, ptr - base);
			wsgi_req->uri = (wsgi_req->buffer + wsgi_req->uh.pktsize) - (ptr - base);
			wsgi_req->uri_len = ptr - base;
			
			if (!query_string) {
				if (watermark + (ptr - base) < (char *)(wsgi_req->proto_parser_buf + uwsgi.buffer_size)) {
                                	wsgi_req->path_info = watermark;
                                	wsgi_req->path_info_len = ptr - base;
                                	http_url_decode(base, &wsgi_req->path_info_len, wsgi_req->path_info);
                                	wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, wsgi_req->path_info, wsgi_req->path_info_len);
					wsgi_req->path_info = (wsgi_req->buffer + wsgi_req->uh.pktsize) - (ptr - base);
					wsgi_req->path_info_len = ptr - base;
                        	}
				else {
					uwsgi_log("not enough space in wsgi_req http proto_parser_buf to encode PATH_INFO, consider tuning it with --buffer-size\n");
					wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, base, ptr - base);
					wsgi_req->path_info = (wsgi_req->buffer + wsgi_req->uh.pktsize) - (ptr - base);
					wsgi_req->path_info_len = ptr - base;
				}
				wsgi_req->path_info_pos = 5;
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "QUERY_STRING", 12, "", 0);
			}
			else {
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "QUERY_STRING", 12, query_string, ptr - query_string);
				wsgi_req->query_string = (wsgi_req->buffer + wsgi_req->uh.pktsize) - (ptr - query_string);
				wsgi_req->query_string_len = ptr - query_string;
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
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_PROTOCOL", 15, base, ptr - base);
			wsgi_req->protocol = (wsgi_req->buffer + wsgi_req->uh.pktsize) - (ptr - base);
			wsgi_req->protocol_len = ptr - base;
			ptr += 2;
			break;
		}
		ptr++;
	}

	// SCRIPT_NAME
	if (!uwsgi.manage_script_name) {
		wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SCRIPT_NAME", 11, "", 0);
	}
	

	// SERVER_NAME
	wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len);
	wsgi_req->host = uwsgi.hostname;
	wsgi_req->host_len = uwsgi.hostname_len;

	// SERVER_PORT
	char *server_port = strchr(wsgi_req->socket->name, ':');
	if (server_port) {
		wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, server_port+1, strlen(server_port+1));
	}
	else {
		wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, "80", 2);
	}

	// REMOTE_ADDR
	memset(ip, 0, INET_ADDRSTRLEN+1);
	if (inet_ntop(AF_INET, (void *) &http_sin->sin_addr.s_addr, ip, INET_ADDRSTRLEN)) {
		wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REMOTE_ADDR", 11, ip, strlen(ip));
		wsgi_req->remote_addr = (wsgi_req->buffer + wsgi_req->uh.pktsize) - strlen(ip);
		wsgi_req->remote_addr_len = strlen(ip);
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
			wsgi_req->uh.pktsize += http_add_uwsgi_header(wsgi_req, base, ptr - base);
			ptr++;
			base = ptr + 1;
		}
		ptr++;
	}

	return 0;

}



int uwsgi_proto_http_parser(struct wsgi_request *wsgi_req) {

	ssize_t len;
	int j;
	char *ptr;
	ssize_t remains;
	// TODO make this buffer configurable
	char post_buf[8192];
	char *post_tail = NULL;

	// first round ? this memory area will be freed by async_loop
	if (!wsgi_req->proto_parser_buf) {
		wsgi_req->proto_parser_buf = uwsgi_malloc(uwsgi.buffer_size);
	}

	if (wsgi_req->post_cl) {
		remains = wsgi_req->post_cl - wsgi_req->proto_parser_pos;
		if (remains > 0) {
			remains = UMIN(remains, 8192);
			len = read(wsgi_req->poll.fd, post_buf, remains);
			if (len <= 0) {
				if (len < 0)
					uwsgi_error("read()");
				return -1;
			}

			if (!fwrite(post_buf, len, 1, wsgi_req->async_post)) {
				uwsgi_error("fwrite()");
				return -1;
			}
			wsgi_req->proto_parser_pos += len;

			if (wsgi_req->proto_parser_pos < wsgi_req->post_cl)
				return UWSGI_AGAIN;

		}
		rewind(wsgi_req->async_post);
		wsgi_req->body_as_file = 1;
		return UWSGI_OK;
	}

	len = read(wsgi_req->poll.fd, wsgi_req->proto_parser_buf + wsgi_req->proto_parser_pos, uwsgi.buffer_size - wsgi_req->proto_parser_pos);
	if (len <= 0) {
		free(wsgi_req->proto_parser_buf);
		if (len < 0) {
			uwsgi_error("recv()");
		}
		// this is simple ping packet
		else { return -2; }
		return -1;
	}

	ptr = wsgi_req->proto_parser_buf + wsgi_req->proto_parser_pos;

	wsgi_req->proto_parser_pos += len;

	for (j = 0; j < len; j++) {
		if (*ptr == '\r' && (wsgi_req->proto_parser_status == 0 || wsgi_req->proto_parser_status == 2)) {
			wsgi_req->proto_parser_status++;
		}
		else if (*ptr == '\r') {
			wsgi_req->proto_parser_status = 1;
		}
		else if (*ptr == '\n' && wsgi_req->proto_parser_status == 1) {
			wsgi_req->proto_parser_status = 2;
		}
		else if (*ptr == '\n' && wsgi_req->proto_parser_status == 3) {
			ptr++;
			remains = len - (j + 1);
			if (remains > 0) {
				post_tail = uwsgi_malloc(remains);
				memcpy(post_tail, ptr, remains);
			}
			http_parse(wsgi_req, ptr);
			//is there a Content_Length ?
			if (wsgi_req->post_cl > 0) {
				wsgi_req->async_post = tmpfile();
				if (!wsgi_req->async_post) {
					free(wsgi_req->proto_parser_buf);
					uwsgi_error("tmpfile()");
					return -1;
				}
				wsgi_req->proto_parser_pos = 0;
				remains = UMIN((size_t) remains, wsgi_req->post_cl);
				if (remains && post_tail) {
					if (!fwrite(post_tail, remains, 1, wsgi_req->async_post)) {
						free(post_tail);
						free(wsgi_req->proto_parser_buf);
						uwsgi_error("fwrite()");
						return -1;
					}
					free(post_tail);
					wsgi_req->proto_parser_pos += remains;
					if (wsgi_req->proto_parser_pos >= wsgi_req->post_cl) {
						free(wsgi_req->proto_parser_buf);
						rewind(wsgi_req->async_post);
						wsgi_req->body_as_file = 1;
						return UWSGI_OK;
					}
				}
				return UWSGI_AGAIN;
			}
			free(wsgi_req->proto_parser_buf);
			return UWSGI_OK;
		}
		else {
			wsgi_req->proto_parser_status = 0;
		}
		ptr++;
	}

	return UWSGI_AGAIN;
}

void uwsgi_httpize_var(char *buf, size_t len) {
	size_t i;
	int upper = 1;
	for(i=0;i<len;i++) {
		if (upper) {
			upper = 0;
			continue;
		}

		if (buf[i] == '_') {
			buf[i] = '-';
			upper = 1;
			continue;
		}

		buf[i] = tolower( (int) buf[i]);
	}
}

struct uwsgi_buffer *uwsgi_to_http(struct wsgi_request *wsgi_req, char *host, uint16_t host_len) {

        struct uwsgi_buffer *ub = uwsgi_buffer_new(4096);

        if (uwsgi_buffer_append(ub, wsgi_req->method, wsgi_req->method_len)) goto clear;
        if (uwsgi_buffer_append(ub, " ", 1)) goto clear;

        if (uwsgi_buffer_append(ub, wsgi_req->uri, wsgi_req->uri_len)) goto clear;

        if (uwsgi_buffer_append(ub, " HTTP/1.0\r\n", 11)) goto clear;

        int i;
	char *x_forwarded_for = NULL;
	size_t x_forwarded_for_len = 0;

        // starting adding headers
        for(i=0;i<wsgi_req->var_cnt;i++) {
		if (!uwsgi_starts_with(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, "HTTP_", 5)) {

			char *header = wsgi_req->hvec[i].iov_base+5;
			size_t header_len = wsgi_req->hvec[i].iov_len-5;

			if (host && !uwsgi_strncmp(header, header_len, "HOST", 4)) goto next;

			if (!uwsgi_strncmp(header, header_len, "CONNECTION", 10)) goto next;
			if (!uwsgi_strncmp(header, header_len, "KEEP_ALIVE", 10)) goto next;
			if (!uwsgi_strncmp(header, header_len, "X_FORWARDED_FOR", 15)) {
				x_forwarded_for = wsgi_req->hvec[i+1].iov_base;
				x_forwarded_for_len = wsgi_req->hvec[i+1].iov_len;
				goto next;
			}

			if (uwsgi_buffer_append(ub, header, header_len)) goto clear;

			// transofmr uwsgi var to http header
			uwsgi_httpize_var((ub->buf+ub->pos) - header_len, header_len);

			if (uwsgi_buffer_append(ub, ": ", 2)) goto clear;
			if (uwsgi_buffer_append(ub, wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len)) goto clear;
			if (uwsgi_buffer_append(ub, "\r\n", 2)) goto clear;

		}
next:
		i++;
        }


	// append custom Host (if needed)
	if (host) {
		if (uwsgi_buffer_append(ub, "Host: ", 6)) goto clear;
		if (uwsgi_buffer_append(ub, host, host_len)) goto clear;
		if (uwsgi_buffer_append(ub, "\r\n", 2)) goto clear;
	}

	// append required headers
	if (uwsgi_buffer_append(ub, "Connection: close\r\n", 19)) goto clear;
	if (uwsgi_buffer_append(ub, "X-Forwarded-For: ", 17)) goto clear;


	if (x_forwarded_for_len > 0) {
		if (uwsgi_buffer_append(ub, x_forwarded_for, x_forwarded_for_len)) goto clear;
		if (uwsgi_buffer_append(ub, ", ", 2)) goto clear;
	}

	if (uwsgi_buffer_append(ub, wsgi_req->remote_addr, wsgi_req->remote_addr_len)) goto clear;

	if (uwsgi_buffer_append(ub, "\r\n\r\n", 4)) goto clear;

	return ub;
clear:
        uwsgi_buffer_destroy(ub);
        return NULL;
}

