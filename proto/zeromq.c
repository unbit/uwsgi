#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

#ifdef UWSGI_JSON
#include <jansson.h>

static char *uwsgi_mongrel2_json_get_string(json_t * node, const char *json_key) {

	json_t *json_value = json_object_get(node, json_key);
	if (json_is_string(json_value)) {
		return (char *) json_string_value(json_value);
	}

	return NULL;
}

static uint16_t uwsgi_mongrel2_json_add(struct wsgi_request *wsgi_req, json_t * node, const char *json_key, char *key, uint16_t keylen, char **extra, size_t * extra_len) {

	char *json_val;
	json_t *json_value = json_object_get(node, json_key);
	if (json_is_string(json_value)) {
		json_val = (char *) json_string_value(json_value);
		// invalid value ?
		if (strlen(json_val) > 0xffff)
			return 0;
		if (extra) {
			*extra = json_val;
			*extra_len = strlen(json_val);
		}
		return proto_base_add_uwsgi_var(wsgi_req, key, keylen, json_val, strlen(json_val));
	}

	return 0;

}

static int uwsgi_mongrel2_json_parse(json_t * root, struct wsgi_request *wsgi_req) {

	char *json_val;
	char *query_string = NULL;
	size_t query_string_len = 0;
	size_t script_name_len = 0;
	void *json_iter;
	char *json_key;
	json_t *json_value;

	if ((json_val = uwsgi_mongrel2_json_get_string(root, "METHOD"))) {
		if (!strcmp(json_val, "JSON")) {
			return -1;
		}
		wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_METHOD", 14, json_val, strlen(json_val));
	}

	if ((json_val = uwsgi_mongrel2_json_get_string(root, "x-mongrel2-upload-done"))) {
		wsgi_req->async_post = fopen(json_val, "r");
		if (!wsgi_req->async_post) {
			uwsgi_error_open(json_val);
			return -1;
		}
	}
	else if (uwsgi_mongrel2_json_get_string(root, "x-mongrel2-upload-start")) {
		return -1;
	}


	wsgi_req->uh.pktsize += uwsgi_mongrel2_json_add(wsgi_req, root, "VERSION", "SERVER_PROTOCOL", 15, NULL, NULL);
	wsgi_req->uh.pktsize += uwsgi_mongrel2_json_add(wsgi_req, root, "QUERY", "QUERY_STRING", 12, &query_string, &query_string_len);
	if (query_string == NULL) {
		// always set QUERY_STRING
		wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "QUERY_STRING", 12, "", 0);
	}

	// set SCRIPT_NAME to an empty value
	wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SCRIPT_NAME", 11, "", 0);

	if ((json_val = uwsgi_mongrel2_json_get_string(root, "PATH"))) {
		wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, json_val + script_name_len, strlen(json_val + script_name_len));
		if (query_string_len) {
			char *request_uri = uwsgi_concat3n(json_val, strlen(json_val), "?", 1, query_string, query_string_len);
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11, request_uri, strlen(json_val) + 1 + query_string_len);
			free(request_uri);
		}
		else {
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11, json_val, strlen(json_val));
		}
	}

	if ((json_val = uwsgi_mongrel2_json_get_string(root, "host"))) {
		char *colon = strchr(json_val, ':');
		if (colon) {
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, colon + 1, strlen(colon + 1));
		}
		else {
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, "80", 2);
		}
	}

	if ((json_val = uwsgi_mongrel2_json_get_string(root, "content-length"))) {
		wsgi_req->post_cl = atoi(json_val);
	}

	wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len);

	json_iter = json_object_iter(root);

	while (json_iter) {
		json_key = (char *) json_object_iter_key(json_iter);
		// is it a header ?
		if (json_key[0] >= 97) {
			json_value = json_object_iter_value(json_iter);
			if (json_is_string(json_value)) {
				json_val = (char *) json_string_value(json_value);
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_header(wsgi_req, json_key, strlen(json_key), json_val, strlen(json_val));
			}
		}
		json_iter = json_object_iter_next(root, json_iter);
	}

	return 0;

}

#endif

// dumb/fake tnetstring implementation...all is a string
static int uwsgi_mongrel2_tnetstring_parse(struct wsgi_request *wsgi_req, char *buf, int len) {

	char *ptr = buf;
	char *watermark = buf + len;
	char *key = NULL;
	size_t keylen = 0;
	char *val = NULL;
	size_t vallen = 0;
	uint16_t script_name_len = 0;
	char *query_string = NULL;
	uint16_t query_string_len = 0;
	int async_upload = 0;

	// set an empty SCRIPT_NAME
	wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SCRIPT_NAME", 11, "", 0);

	while (ptr < watermark) {

		ptr = uwsgi_netstring(ptr, len - (ptr - buf), &key, &keylen);
		if (ptr == NULL)
			break;
		// empty keys are not allowed
		if (keylen == 0)
			break;

		if (ptr >= watermark)
			break;

		ptr = uwsgi_netstring(ptr, len - (ptr - buf), &val, &vallen);
		if (ptr == NULL)
			break;


		if (key[0] < 97) {
			if (!uwsgi_strncmp("METHOD", 6, key, keylen)) {
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_METHOD", 14, val, vallen);
			}
			else if (!uwsgi_strncmp("VERSION", 7, key, keylen)) {
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_PROTOCOL", 15, val, vallen);
			}
			else if (!uwsgi_strncmp("QUERY", 5, key, keylen)) {
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "QUERY_STRING", 12, val, vallen);
				query_string = val;
				query_string_len = vallen;
			}
			else if (!uwsgi_strncmp("PATH", 4, key, keylen)) {
				wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "PATH_INFO", 9, val + script_name_len, vallen - script_name_len);
				if (query_string_len) {
					char *request_uri = uwsgi_concat3n(val, vallen, "?", 1, query_string, query_string_len);
					wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11, request_uri, vallen + 1 + query_string_len);
					free(request_uri);
				}
				else {
					wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "REQUEST_URI", 11, val, vallen);
				}
			}
		}
		else {
			// add header
			if (!uwsgi_strncmp("host", 4, key, keylen)) {
				char *colon = strchr(val, ':');
				if (colon) {
					wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, colon + 1, (colon + 1) - val);
				}
				else {
					wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_PORT", 11, "80", 2);
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
					wsgi_req->do_not_log = 1;
				}
				async_upload += 2;
				free(post_filename);
			}
			else if (!uwsgi_strncmp("x-mongrel2-upload-start", 23, key, keylen)) {
				async_upload += 1;
			}
			wsgi_req->uh.pktsize += proto_base_add_uwsgi_header(wsgi_req, key, keylen, val, vallen);
		}
	}

	wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len);

	if (query_string == NULL) {
                // always set QUERY_STRING
                wsgi_req->uh.pktsize += proto_base_add_uwsgi_var(wsgi_req, "QUERY_STRING", 12, "", 0);
        }

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
	char *req_uuid = NULL;
	size_t req_uuid_len = 0;
	char *req_id = NULL;
	size_t req_id_len = 0;
	char *req_path = NULL;
	size_t req_path_len = 0;
#ifdef UWSGI_JSON
	json_t *root;
	json_error_t error;
#endif
	char *mongrel2_req = NULL;
	size_t mongrel2_req_size = 0;
	int resp_id_len;
	uint32_t events = 0;
	char *message_ptr;
	size_t message_size = 0;
	char *post_data;


#ifdef ZMQ_EVENTS
	size_t events_len = sizeof(uint32_t);
	if (uwsgi.edge_triggered == 0) {
		if (zmq_getsockopt(pthread_getspecific(uwsgi.zmq_pull), ZMQ_EVENTS, &events, &events_len) < 0) {
			uwsgi_error("zmq_getsockopt()");
			uwsgi.edge_triggered = 0;
			return -1;
		}
	}
#endif

	if (events & ZMQ_POLLIN || uwsgi.edge_triggered) {
		wsgi_req->do_not_add_to_async_queue = 1;
		wsgi_req->proto_parser_status = 0;
		zmq_msg_init(&message);
		if (zmq_recv(pthread_getspecific(uwsgi.zmq_pull), &message, uwsgi.zeromq_recv_flag) < 0) {
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
		message_size = zmq_msg_size(&message);
		//uwsgi_log("%.*s\n", (int) wsgi_req->proto_parser_pos, zmq_msg_data(&message));
		if (message_size > 0xffff) {
			uwsgi_log("too much big message %d\n", message_size);
			zmq_msg_close(&message);
			wsgi_req->do_not_log = 1;
			return -1;
		}

		message_ptr = zmq_msg_data(&message);

		// warning mongrel2_req_size will contains a bad value, but this is not a problem...
		post_data = uwsgi_split4(message_ptr, message_size, ' ', &req_uuid, &req_uuid_len, &req_id, &req_id_len, &req_path, &req_path_len, &mongrel2_req, &mongrel2_req_size);
		if (post_data == NULL) {
			uwsgi_log("cannot parse message (split4 phase)\n");
			zmq_msg_close(&message);
			wsgi_req->do_not_log = 1;
			return -1;
		}

		// fix post_data, mongrel2_req and mongrel2_req_size
		post_data = uwsgi_netstring(mongrel2_req, message_size - (mongrel2_req - message_ptr), &mongrel2_req, &mongrel2_req_size);
		if (post_data == NULL) {
			uwsgi_log("cannot parse message (body netstring phase)\n");
			zmq_msg_close(&message);
			wsgi_req->do_not_log = 1;
			return -1;
		}

		// ok ready to parse tnetstring/json data and build uwsgi request
		if (mongrel2_req[mongrel2_req_size] == '}') {
			if (uwsgi_mongrel2_tnetstring_parse(wsgi_req, mongrel2_req, mongrel2_req_size)) {
				zmq_msg_close(&message);
				wsgi_req->do_not_log = 1;
				return -1;
			}
		}
		else {
#ifdef UWSGI_JSON
#ifdef UWSGI_DEBUG
			uwsgi_log("JSON %d: %.*s\n", mongrel2_req_size, mongrel2_req_size, mongrel2_req);
#endif
			// add a zero to the end of buf
			mongrel2_req[mongrel2_req_size] = 0;
			root = json_loads(mongrel2_req, 0, &error);
			if (!root) {
				uwsgi_log("error parsing JSON data: line %d %s\n", error.line, error.text);
				zmq_msg_close(&message);
				wsgi_req->do_not_log = 1;
				return -1;
			}

			if (uwsgi_mongrel2_json_parse(root, wsgi_req)) {
				json_decref(root);
				zmq_msg_close(&message);
				wsgi_req->do_not_log = 1;
				return -1;
			}

			json_decref(root);
#else
			uwsgi_log("JSON support not enabled (recompile uWSGI with libjansson support, or re-configure mongrel2 with \"protocol='tnetstring'\". skip request\n");
#endif
		}

		// pre-build the mongrel2 response_header
		wsgi_req->proto_parser_buf = uwsgi_malloc(req_uuid_len + 1 + 11 + 1 + req_id_len + 1 + 1);
		memcpy(wsgi_req->proto_parser_buf, req_uuid, req_uuid_len);
		((char *) wsgi_req->proto_parser_buf)[req_uuid_len] = ' ';
		resp_id_len = uwsgi_num2str2(req_id_len, wsgi_req->proto_parser_buf + req_uuid_len + 1);
		((char *) wsgi_req->proto_parser_buf)[req_uuid_len + 1 + resp_id_len] = ':';

		memcpy((char *) wsgi_req->proto_parser_buf + req_uuid_len + 1 + resp_id_len + 1, req_id, req_id_len);

		memcpy((char *) wsgi_req->proto_parser_buf + req_uuid_len + 1 + resp_id_len + 1 + req_id_len, ", ", 2);
		wsgi_req->proto_parser_pos = (uint64_t) req_uuid_len + 1 + resp_id_len + 1 + req_id_len + 1 + 1;

		// handle post data
		if (wsgi_req->post_cl > 0 && !wsgi_req->async_post) {
			if (uwsgi_netstring(post_data, message_size - (post_data - message_ptr), &message_ptr, &wsgi_req->post_cl)) {
#ifdef UWSGI_DEBUG
				uwsgi_log("post_size: %d\n", wsgi_req->post_cl);
#endif
				wsgi_req->async_post = tmpfile();
				if (fwrite(message_ptr, wsgi_req->post_cl, 1, wsgi_req->async_post) != 1) {
					uwsgi_error("fwrite()");
					zmq_msg_close(&message);
					return -1;
				}
				rewind(wsgi_req->async_post);
				wsgi_req->body_as_file = 1;
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

	// check for already freed wsgi_req->proto_parser_buf/wsgi_req->proto_parser_pos
	if (!wsgi_req->proto_parser_pos)
		return;

	zmq_msg_init_data(&reply, wsgi_req->proto_parser_buf, wsgi_req->proto_parser_pos, uwsgi_proto_zeromq_free, NULL);
	if (uwsgi.threads > 1) pthread_mutex_lock(&uwsgi.zmq_lock);
	if (zmq_send(uwsgi.zmq_pub, &reply, 0)) {
		uwsgi_error("zmq_send()");
	}
	if (uwsgi.threads > 1) pthread_mutex_unlock(&uwsgi.zmq_lock);
	zmq_msg_close(&reply);

	if (wsgi_req->async_post && wsgi_req->body_as_file) {
		fclose(wsgi_req->async_post);
	}

}


ssize_t uwsgi_proto_zeromq_writev_header(struct wsgi_request *wsgi_req, struct iovec *iovec, size_t iov_len) {
	int i;
	ssize_t len;
	ssize_t ret = 0;

	for (i = 0; i < (int) iov_len; i++) {
		len = uwsgi_proto_zeromq_write(wsgi_req, iovec[i].iov_base, iovec[i].iov_len);
		if (len <= 0) {
			return len;
		}
		ret += len;
	}

	return ret;
}

ssize_t uwsgi_proto_zeromq_writev(struct wsgi_request * wsgi_req, struct iovec * iovec, size_t iov_len) {
	return uwsgi_proto_zeromq_writev_header(wsgi_req, iovec, iov_len);
}

ssize_t uwsgi_proto_zeromq_write(struct wsgi_request * wsgi_req, char *buf, size_t len) {
	zmq_msg_t reply;
	char *zmq_body;

	if (len == 0)
		return 0;

	zmq_body = uwsgi_concat2n(wsgi_req->proto_parser_buf, (int) wsgi_req->proto_parser_pos, buf, (int) len);

	//uwsgi_log("|%.*s|\n", (int)wsgi_req->proto_parser_pos+len, zmq_body);

	zmq_msg_init_data(&reply, zmq_body, wsgi_req->proto_parser_pos + len, uwsgi_proto_zeromq_free, NULL);
	if (uwsgi.threads > 1) pthread_mutex_lock(&uwsgi.zmq_lock);
	if (zmq_send(uwsgi.zmq_pub, &reply, 0)) {
		uwsgi_error("zmq_send()");
		if (uwsgi.threads > 1) pthread_mutex_unlock(&uwsgi.zmq_lock);
		zmq_msg_close(&reply);
		return -1;
	}
	if (uwsgi.threads > 1) pthread_mutex_unlock(&uwsgi.zmq_lock);
	zmq_msg_close(&reply);

	return len;
}

ssize_t uwsgi_proto_zeromq_write_header(struct wsgi_request * wsgi_req, char *buf, size_t len) {
	return uwsgi_proto_zeromq_write(wsgi_req, buf, len);
}

ssize_t uwsgi_proto_zeromq_sendfile(struct wsgi_request * wsgi_req) {

	ssize_t len;
	char buf[65536];
	size_t remains = wsgi_req->sendfile_fd_size - wsgi_req->sendfile_fd_pos;

	wsgi_req->sendfile_fd_chunk = 65536;

	if (uwsgi.async > 1) {
		len = read(wsgi_req->sendfile_fd, buf, UMIN(remains, wsgi_req->sendfile_fd_chunk));
		if (len != (int) UMIN(remains, wsgi_req->sendfile_fd_chunk)) {
			uwsgi_error("read()");
			return -1;
		}
		wsgi_req->sendfile_fd_pos += len;
		return uwsgi_proto_zeromq_write(wsgi_req, buf, len);
	}

	while (remains) {
		len = read(wsgi_req->sendfile_fd, buf, UMIN(remains, wsgi_req->sendfile_fd_chunk));
		if (len != (int) UMIN(remains, wsgi_req->sendfile_fd_chunk)) {
			uwsgi_error("read()");
			return -1;
		}
		wsgi_req->sendfile_fd_pos += len;
		len = uwsgi_proto_zeromq_write(wsgi_req, buf, len);
		remains = wsgi_req->sendfile_fd_size - wsgi_req->sendfile_fd_pos;
	}

	return wsgi_req->sendfile_fd_pos;

}
