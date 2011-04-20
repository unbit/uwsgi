#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

#ifdef UWSGI_JSON
#include <jansson.h>
#endif

static uint16_t http_add_uwsgi_var(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, char *val, uint16_t vallen) {


        char *buffer = wsgi_req->buffer+wsgi_req->uh.pktsize;
        char *watermark = wsgi_req->buffer+uwsgi.buffer_size;
        char *ptr = buffer;

        if (buffer+keylen+vallen+2+2 >= watermark) {
                uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, key, vallen, val);
                return 0;
        }


        *ptr++= (uint8_t) (keylen & 0xff);
        *ptr++= (uint8_t) ((keylen >> 8) & 0xff);
        memcpy(ptr, key, keylen); ptr+=keylen;

        *ptr++= (uint8_t) (vallen & 0xff);
        *ptr++= (uint8_t) ((vallen >> 8) & 0xff);
        memcpy(ptr, val, vallen);
	
#ifdef UWSGI_DEBUG
        uwsgi_log("add uwsgi var: %.*s = %.*s\n", keylen, key, vallen, val);
#endif

        return keylen+vallen+2+2;
}

static uint16_t http_add_uwsgi_header(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, char *val, uint16_t vallen) {


	int i;
        char *buffer = wsgi_req->buffer+wsgi_req->uh.pktsize;
        char *watermark = wsgi_req->buffer+uwsgi.buffer_size;
        char *ptr = buffer;


	for(i=0;i<keylen;i++) {
		if (key[i] == '-') {
			key[i] = '_';
		}
		else {
			key[i] = toupper(key[i]);
		}
	}

	if (uwsgi_strncmp("CONTENT_TYPE", 12, key, keylen) && uwsgi_strncmp("CONTENT_LENGTH", 14, key, keylen)) {
        	if (buffer+keylen+vallen+2+2+5 >= watermark) {
                	uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, key, vallen, val);
                	return 0;
        	}
        	*ptr++= (uint8_t) ((keylen+5) & 0xff);
        	*ptr++= (uint8_t) (((keylen+5) >> 8) & 0xff);
        	memcpy(ptr, "HTTP_", 5); ptr+=5;
        	memcpy(ptr, key, keylen); ptr+=keylen;
		keylen+=5;
	}
	else {
        	if (buffer+keylen+vallen+2+2 >= watermark) {
                	uwsgi_log("[WARNING] unable to add %.*s=%.*s to uwsgi packet, consider increasing buffer size\n", keylen, key, vallen, val);
                	return 0;
        	}
        	*ptr++= (uint8_t) (keylen & 0xff);
        	*ptr++= (uint8_t) ((keylen >> 8) & 0xff);
        	memcpy(ptr, key, keylen); ptr+=keylen;
	}

        *ptr++= (uint8_t) (vallen & 0xff);
        *ptr++= (uint8_t) ((vallen >> 8) & 0xff);
        memcpy(ptr, val, vallen);

#ifdef UWSGI_DEBUG
        uwsgi_log("add uwsgi var: %.*s = %.*s\n", keylen, key, vallen, val);
#endif

        return keylen+vallen+2+2;
}

// dumb/fake tnetstring implementation...all is a string
static int uwsgi_mongrel2_tnetstring_parse(struct wsgi_request *wsgi_req, char *buf, int len) {

	char *ptr = buf;
	char *watermark = buf+len;
	char *base;
	char *key = NULL; uint16_t keylen = 0;
	char *val = NULL; uint16_t vallen = 0;
	uint16_t script_name_len = 0;
	char *query_string = NULL; uint16_t query_string_len = 0;
	int async_upload = 0;

	while(ptr < watermark) {

		base = ptr;

		while (ptr < watermark) { if (*ptr == ':') break; ptr++; }
		// end of stream
		if (*ptr != ':') break;

		keylen = uwsgi_str_num(base, (ptr-base)); 

		// empty keys are not allowed
		if (!keylen) break;

		ptr++;
		key = ptr;
		ptr+=keylen+1;

		base = ptr;

		while (ptr < watermark) { if (*ptr == ':') break; ptr++; }
		// end of stream
		if (*ptr != ':') break;

		vallen = uwsgi_str_num(base, (ptr-base)); 
		ptr++;
		val = ptr;
		ptr+=vallen+1;

		if (key[0] < 97) {
			if (!uwsgi_strncmp("METHOD", 6, key, keylen)) {
				wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "REQUEST_METHOD", 14, val, vallen);
			}
			else if (!uwsgi_strncmp("VERSION", 7, key, keylen)) {
				wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "SERVER_PROTOCOL", 15, val, vallen);
			}
			else if (!uwsgi_strncmp("QUERY", 5, key, keylen)) {
				wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "QUERY_STRING", 12, val, vallen);
				query_string = val;
				query_string_len = vallen;
			}
			else if (!uwsgi_strncmp("PATTERN", 7, key, keylen)) {
				wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "SCRIPT_NAME", 11, val, vallen);
				script_name_len = vallen-1;
			}
			else if (!uwsgi_strncmp("PATH", 4, key, keylen)) {
				wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, val+script_name_len, vallen-script_name_len);
				if (query_string_len) {
					char *request_uri = uwsgi_concat3n(val, vallen, "?", 1, query_string, query_string_len);
					wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11 , request_uri, vallen+1+query_string_len );
					free(request_uri);
				}
				else {
					wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11, val, vallen);
				}
			}
		}
		else {
			// add header
			if (!uwsgi_strncmp("host", 4, key, keylen)) {
				char *colon = strchr(val, ':');
				if (colon) {
					wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, colon+1, (colon+1)-val);
				}
				else {
					wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, "80", 2);
				}
			}
			else if (!uwsgi_strncmp("content-length", 14, key, keylen)) {
				wsgi_req->post_cl = uwsgi_str_num(val, vallen);
			}
			else if (!uwsgi_strncmp("x-mongrel2-upload-done", 22, key, keylen)) {
				char *post_filename = uwsgi_concat2n(val, vallen, "", 0);
				wsgi_req->async_post = fopen(post_filename, "r");
				if (!wsgi_req->async_post) {
					uwsgi_error_open(post_filename);
					free(post_filename);
					wsgi_req->do_not_log = 1;	
				}
				async_upload += 2;
				free(post_filename);
			}
			else if (!uwsgi_strncmp("x-mongrel2-upload-start", 23, key, keylen)) {
				async_upload += 1;
			}
			wsgi_req->uh.pktsize += http_add_uwsgi_header(wsgi_req, key, keylen, val, vallen);
		}	
	}
	
	wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len);

	// reject uncomplete upload
	if (async_upload == 1) {
		return -1;
	}
	return 0;
}

int uwsgi_proto_zeromq_parser(struct wsgi_request *wsgi_req) {

	return UWSGI_OK;
}

int uwsgi_proto_zeromq_accept(struct wsgi_request *wsgi_req, int fd) {

	zmq_msg_t message;
	char *ptr;
	char *req_uuid = NULL; int req_uuid_len = 0;
	char *req_id = NULL; int req_id_len = 0;
	char *req_path = NULL; int req_path_len = 0;
	char *req_body_size = NULL; int req_body_size_len = 0;
#ifdef UWSGI_JSON
	json_t *root;
        json_error_t error;
	void *json_iter;
	json_t *json_value;
	char *json_key, *json_val;
#endif
	char *query_string = NULL; int query_string_len = 0;
	int script_name_len = 0;
	int i;
	int resp_id_len;
	uint32_t events = 0;
	size_t events_len = sizeof(uint32_t);
	

	if (uwsgi.edge_triggered == 0) {
		if (zmq_getsockopt(uwsgi.zmq_pull, ZMQ_EVENTS, &events, &events_len) < 0) {
			uwsgi_error("zmq_getsockopt()");
			uwsgi.edge_triggered = 0;
			return -1;
		}
	}
	
	if (events & ZMQ_POLLIN || uwsgi.edge_triggered) {
		wsgi_req->do_not_add_to_async_queue = 1;
		wsgi_req->proto_parser_status = 0;
		zmq_msg_init(&message);
		if (zmq_recv(uwsgi.zmq_pull, &message, uwsgi.zeromq_recv_flag) < 0) {
			if (errno == EAGAIN) {
				uwsgi.edge_triggered = 0;
			}
			else {
				uwsgi_error("zmq_recv()");
			}
			zmq_msg_close(&message);
			return -1;
		}
		uwsgi.edge_triggered = 1;
		wsgi_req->proto_parser_pos = zmq_msg_size(&message); 	
		//uwsgi_log("%.*s\n", (int) wsgi_req->proto_parser_pos, zmq_msg_data(&message));
		if (wsgi_req->proto_parser_pos > 65536) {
			uwsgi_log("too much big message %d\n", wsgi_req->proto_parser_pos);
			zmq_msg_close(&message);
			return -1;
		}
		wsgi_req->proto_parser_buf = uwsgi_malloc(wsgi_req->proto_parser_pos);

		ptr = zmq_msg_data(&message);
		for(i=0;i<(int)wsgi_req->proto_parser_pos;i++) {
			if (ptr[i] == ' ') {
				// get uuid
				if (wsgi_req->proto_parser_status == 0) {
					req_uuid = ptr;
					req_uuid_len = i;
					wsgi_req->proto_parser_status = 1;
				}
				// get req_id
				else if (wsgi_req->proto_parser_status == 1) {
					req_id = req_uuid+req_uuid_len+1;
					req_id_len = (ptr+i) - req_id;
					wsgi_req->proto_parser_status = 2;
				}
				// get path
				else if (wsgi_req->proto_parser_status == 2) {
					req_path = req_id+req_id_len+1;
					req_path_len = (ptr+i) - req_path;
					wsgi_req->proto_parser_status = 3;
				}
			}
			// get body size;
			else if (ptr[i] == ':') {
				if (wsgi_req->proto_parser_status == 3) {
					req_body_size = req_path+req_path_len+1;
					req_body_size_len = (ptr+i) - req_body_size;
					// check if remaining bytes < wsgi_req->proto_parser_pos
					memcpy(wsgi_req->proto_parser_buf, ptr+i+1, uwsgi_str_num(req_body_size, req_body_size_len));
					((char *)wsgi_req->proto_parser_buf)[uwsgi_str_num(req_body_size, req_body_size_len)] = 0;
					wsgi_req->proto_parser_status = 4;
					break;
				}
			}
		}


		if (wsgi_req->proto_parser_status >= 4) {
			// ok ready to parse json data and build uwsgi request
			if (ptr[i+uwsgi_str_num(req_body_size, req_body_size_len)+1] == '}') {
				if (uwsgi_mongrel2_tnetstring_parse(wsgi_req, wsgi_req->proto_parser_buf, uwsgi_str_num(req_body_size, req_body_size_len))) {
					zmq_msg_close(&message);
					free(wsgi_req->proto_parser_buf);
					wsgi_req->do_not_log = 1;
					return -1;
				}
			}
			else {
#ifdef UWSGI_JSON
#ifdef UWSGI_DEBUG
			uwsgi_log("JSON %c: %s\n", ptr[i+uwsgi_str_num(req_body_size, req_body_size_len)+1], wsgi_req->proto_parser_buf);
#endif
			root = json_loads(wsgi_req->proto_parser_buf, 0, &error);
			if (!root) {
                		uwsgi_log("error parsing JSON data: line %d %s\n", error.line, error.text);
				zmq_msg_close(&message);
				free(wsgi_req->proto_parser_buf);
				wsgi_req->do_not_log = 1;
                		return -1;
        		}

			json_value = json_object_get(root, "METHOD");
			if (json_is_string(json_value)) {
				json_val = (char *)json_string_value(json_value);
				if (!strcmp(json_val, "JSON")) {
					json_decref(root);
					zmq_msg_close(&message);
					free(wsgi_req->proto_parser_buf);
					wsgi_req->do_not_log = 1;
                			return -1;
				}
				wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "REQUEST_METHOD", 14, json_val, strlen(json_val)); 
			}

			json_value = json_object_get(root, "x-mongrel2-upload-done");
			if (json_is_string(json_value)) {
				json_val = (char *)json_string_value(json_value);
				wsgi_req->async_post = fopen(json_val, "r");
				if (!wsgi_req->async_post) {
					json_decref(root);
					zmq_msg_close(&message);
					free(wsgi_req->proto_parser_buf);
					wsgi_req->do_not_log = 1;
                			return -1;
				}
			}
			else {
				json_value = json_object_get(root, "x-mongrel2-upload-start");
				if (json_is_string(json_value)) {
					json_decref(root);
					zmq_msg_close(&message);
					free(wsgi_req->proto_parser_buf);
					wsgi_req->do_not_log = 1;
                			return -1;
				}
			}

		
			json_value = json_object_get(root, "VERSION");
			if (json_is_string(json_value)) {
				json_val = (char *)json_string_value(json_value);
				wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "SERVER_PROTOCOL", 15, json_val, strlen(json_val)); 
			}

			json_value = json_object_get(root, "QUERY");
			if (json_is_string(json_value)) {
				query_string = (char *)json_string_value(json_value);
				query_string_len = strlen(query_string);
				wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "QUERY_STRING", 12, query_string, query_string_len); 
			}


			json_value = json_object_get(root, "PATTERN");
			if (json_is_string(json_value)) {
				json_val = (char *)json_string_value(json_value);
				wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "SCRIPT_NAME", 11, json_val, strlen(json_val)-1); 
				script_name_len = strlen(json_val)-1;
			}

			json_value = json_object_get(root, "PATH");
			if (json_is_string(json_value)) {
				json_val = (char *)json_string_value(json_value);
				wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, json_val+script_name_len, strlen(json_val+script_name_len)); 
				if (query_string_len) {
					char *request_uri = uwsgi_concat3n(json_val, strlen(json_val), "?", 1, query_string, query_string_len);
					wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11 , request_uri, strlen(json_val)+1+query_string_len );
					free(request_uri);
				}
				else {
					wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11, json_val, strlen(json_val));
				}
			}

			json_value = json_object_get(root, "host");
			if (json_is_string(json_value)) {
				json_val = (char *)json_string_value(json_value);
				char *colon = strchr(json_val, ':');
				if (colon) {
					wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, colon+1, strlen(colon+1)); 
				}
				else {
					wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, "80", 2); 
				}
			}

			json_value = json_object_get(root, "content-length");
			if (json_is_string(json_value)) {
                                json_val = (char *)json_string_value(json_value);
				wsgi_req->post_cl = atoi(json_val);
                        }

			wsgi_req->uh.pktsize += http_add_uwsgi_var(wsgi_req, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len);

			json_iter = json_object_iter(root);

			while(json_iter) {
				json_key = (char *)json_object_iter_key(json_iter);
				// is it a header ?
				if (json_key[0] >= 97) {
					json_value = json_object_iter_value(json_iter);
					if (json_is_string(json_value)) {
						json_val = (char *)json_string_value(json_value);
						wsgi_req->uh.pktsize += http_add_uwsgi_header(wsgi_req, json_key, strlen(json_key), json_val, strlen(json_val));
					}
				}
				json_iter = json_object_iter_next(root, json_iter);
			}

				json_decref(root);
#else
				uwsgi_log("JSON support not enabled. skip request\n");
#endif
			}

			memcpy(wsgi_req->proto_parser_buf, req_uuid, req_uuid_len);
			((char *)wsgi_req->proto_parser_buf)[req_uuid_len] = ' ';
			resp_id_len = uwsgi_num2str2(req_id_len, wsgi_req->proto_parser_buf+req_uuid_len+1);
			((char *)wsgi_req->proto_parser_buf)[req_uuid_len+1+resp_id_len] = ':';

			memcpy((char *)wsgi_req->proto_parser_buf+req_uuid_len+1+resp_id_len+1, req_id, req_id_len);

			((char *)wsgi_req->proto_parser_buf)[req_uuid_len+1+resp_id_len+1+req_id_len] = ',';
			((char *)wsgi_req->proto_parser_buf)[req_uuid_len+1+resp_id_len+1+req_id_len+1] = ' ';
			wsgi_req->proto_parser_pos = (uint64_t) req_uuid_len+1+resp_id_len+1+req_id_len+1+1;

			// handle post data
			if (wsgi_req->post_cl > 0 && !wsgi_req->async_post) {
				ptr = zmq_msg_data(&message) + i + uwsgi_str_num(req_body_size, req_body_size_len) + 2 ;
				int post_size = (int) zmq_msg_size(&message);
				for(i=0;i<post_size;i++) {
					if (ptr[i] == ':') {
						break;
					}
				}

				uwsgi_log("post_size: %.*s\n", i, ptr);
				wsgi_req->post_cl = uwsgi_str_num(ptr, i);
				// is it good ?
				if (i+(int)wsgi_req->post_cl < post_size) {
					wsgi_req->async_post = tmpfile();
					fwrite(ptr+i+1, wsgi_req->post_cl, 1, wsgi_req->async_post);
					rewind(wsgi_req->async_post);
					wsgi_req->body_as_file = 1;
					//uwsgi_log("%.*s\n", wsgi_req->post_cl, ptr+i+1);
				}
			}
			
		}

		zmq_msg_close(&message);

		return 0;
	}

	return -1;
}

static void uwsgi_proto_zeromq_free(void *data, void *hint) {
	free(data);
}

void uwsgi_proto_zeromq_close(struct wsgi_request *wsgi_req) {
	zmq_msg_t reply;

	//uwsgi_log("CLOSING |%.*s|\n", (int)wsgi_req->proto_parser_pos, wsgi_req->proto_parser_buf);
	// check for already freed wsgi_req->proto_parser_buf/wsgi_req->proto_parser_pos
	if (!wsgi_req->proto_parser_pos) return;

	zmq_msg_init_data(&reply, wsgi_req->proto_parser_buf, wsgi_req->proto_parser_pos, uwsgi_proto_zeromq_free, NULL);
	if (zmq_send(uwsgi.zmq_pub, &reply, 0)) {
		uwsgi_error("zmq_send()");
	}
	zmq_msg_close(&reply);

	if (wsgi_req->async_post && wsgi_req->body_as_file) {
		fclose(wsgi_req->async_post);
	}

}


ssize_t uwsgi_proto_zeromq_writev_header(struct wsgi_request *wsgi_req, struct iovec *iovec, size_t iov_len) {
        int i;
        ssize_t len;
        ssize_t ret = 0;

        for(i=0;i<(int)iov_len;i++) {
                len = uwsgi_proto_zeromq_write(wsgi_req, iovec[i].iov_base, iovec[i].iov_len);
                if (len <= 0) {
                        return len;
                }
                ret += len;
        }

        return ret;
}

ssize_t uwsgi_proto_zeromq_writev(struct wsgi_request *wsgi_req, struct iovec *iovec, size_t iov_len) {
        return uwsgi_proto_zeromq_writev_header(wsgi_req, iovec, iov_len);
}

ssize_t uwsgi_proto_zeromq_write(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	zmq_msg_t reply;
	char *zmq_body;

	if (len == 0) return 0;

	zmq_body = uwsgi_concat2n(wsgi_req->proto_parser_buf, (int) wsgi_req->proto_parser_pos, buf, (int) len);

	//uwsgi_log("|%.*s|\n", (int)wsgi_req->proto_parser_pos+len, zmq_body);

	zmq_msg_init_data(&reply, zmq_body, wsgi_req->proto_parser_pos+len, uwsgi_proto_zeromq_free, NULL);
	if (zmq_send(uwsgi.zmq_pub, &reply, 0)) {
		uwsgi_error("zmq_send()");
		zmq_msg_close(&reply);
		return -1;
	}	
	zmq_msg_close(&reply);

	return len;
}

ssize_t uwsgi_proto_zeromq_write_header(struct wsgi_request *wsgi_req, char *buf, size_t len) {
        return uwsgi_proto_zeromq_write(wsgi_req, buf, len);
}

ssize_t uwsgi_proto_zeromq_sendfile(struct wsgi_request *wsgi_req) {

        ssize_t len;
        char buf[65536];
        size_t remains = wsgi_req->sendfile_fd_size-wsgi_req->sendfile_fd_pos;

        wsgi_req->sendfile_fd_chunk = 65536;


        if (uwsgi.async > 1) {
                len = read(wsgi_req->sendfile_fd, buf, UMIN(remains, wsgi_req->sendfile_fd_chunk));
                if (len != (int)UMIN(remains, wsgi_req->sendfile_fd_chunk)) {
                        uwsgi_error("read()");
                        return -1;
                }
                wsgi_req->sendfile_fd_pos+=len;
                return uwsgi_proto_zeromq_write(wsgi_req, buf, len);
        }

        while(remains) {
                len = read(wsgi_req->sendfile_fd, buf, UMIN(remains, wsgi_req->sendfile_fd_chunk));
                if (len != (int)UMIN(remains, wsgi_req->sendfile_fd_chunk)) {
                        uwsgi_error("read()");
                        return -1;
                }
                wsgi_req->sendfile_fd_pos+=len;
		len = uwsgi_proto_zeromq_write(wsgi_req, buf, len);
                remains = wsgi_req->sendfile_fd_size-wsgi_req->sendfile_fd_pos;
        }

        return wsgi_req->sendfile_fd_pos;

}

