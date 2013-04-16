#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

#define UWSGI_SSI_MAX_ARGS 8

/*

	uWSGI server side includes implementation

*/


struct uwsgi_ssi_arg {
	char *key;
	size_t key_len;
	char *value;
	size_t val_len;
};

struct uwsgi_ssi_cmd {
	char *name;
	size_t name_len;
	struct uwsgi_buffer *(*func)(struct wsgi_request *, struct uwsgi_ssi_arg *, int);
	struct uwsgi_ssi_cmd *next;
};

struct uwsgi_ssi_cmd *uwsgi_ssi_commands = NULL;

static struct uwsgi_ssi_cmd* uwsgi_ssi_get_cmd(char *name, size_t name_len) {
	struct uwsgi_ssi_cmd *usc = uwsgi_ssi_commands;
	while(usc) {
		if (!uwsgi_strncmp(usc->name, usc->name_len, name, name_len)) {
			return usc;
		}
		usc = usc->next;
	}
	return NULL;
}

static struct uwsgi_ssi_cmd *uwsgi_register_ssi_command(char *name, struct uwsgi_buffer *(*func)(struct wsgi_request *, struct uwsgi_ssi_arg *, int)) {
	struct uwsgi_ssi_cmd *old_usc = NULL,*usc = uwsgi_ssi_commands;
        while(usc) {
                if (!strcmp(usc->name, name)) {
                        return usc;
                }
                old_usc = usc;
                usc = usc->next;
        }

        usc = uwsgi_calloc(sizeof(struct uwsgi_ssi_cmd));
        usc->name = name;
        usc->name_len = strlen(name);
        usc->func = func;

        if (old_usc) {
                old_usc->next = usc;
        }
        else {
                uwsgi_ssi_commands = usc;
        }

        return usc;
}

static int uwsgi_ssi_parse_args(struct wsgi_request *wsgi_req, char *buf, size_t len, struct uwsgi_ssi_arg *argv, int *argc) {
	// status [0]null/= [1]" [2]" [3]\s
	size_t i;
	uint8_t status = 0;
	char *key = buf;
	size_t key_len = 0;
	char *value = NULL;
	size_t val_len = 0;
	for(i=0;i<len;i++) {
		switch(status) {
			case 0:
				if (buf[i] == '=') {
					status = 1;
				}
				else {
					key_len++;
				}
				break;
			case 1:
				if (buf[i] == '"') {
					status = 2;
				}
				else {
					return -1;
				}
				break;
			case 2:
				if (buf[i] == '"') {
					status = 3;	
					argv[*argc].key = key; argv[*argc].key_len = key_len;
					argv[*argc].value = value; argv[*argc].val_len = val_len;
					*argc = *argc+1;
					if (*argc >= UWSGI_SSI_MAX_ARGS) {
						return -1;
					}
					key = NULL;
					key_len = 0;
					value = NULL;
					val_len = 0;
				}
				else {
					if (!value) {
						value = buf + i;
					}
					val_len++;
				}
				break;
			case 3:
				if (!isspace((int)buf[i])) {
					key = buf + i;
					key_len = 1;
					status = 0;
				}
				break;
			default:
				return -1;
		}
	}
	return 0;
}

static struct uwsgi_buffer *uwsgi_ssi_parse_command(struct wsgi_request *wsgi_req, char *buf, size_t len) {

	// storage for arguments
	struct uwsgi_ssi_arg argv[UWSGI_SSI_MAX_ARGS];
	int argc = 0;

	// first remove white spaces from the begin and the end
	char *cmd = buf;
	size_t cmd_len = len;
        size_t i;
        for(i=0;i<len;i++) {
                if (isspace((int)buf[i])) {
                        cmd++;
                        cmd_len--;
                }
                else {
                        break;
                }
        }

        // then rstrip (skipping the first char...)
        for(i=(len-1);i>0;i--) {
                if (isspace((int)buf[i])) {
                        cmd_len--;
                }
                else {
                        break;
                }
        }

	// now get the command
	char *ssi_cmd = cmd;
	size_t ssi_cmd_len = 0;
	int found = 0;

	for(i=0;i<cmd_len;i++) {
		if (isspace(cmd[i])) {
			found = 1;
			break;
		}
		ssi_cmd_len++;
	}

	struct uwsgi_ssi_cmd *usc = uwsgi_ssi_get_cmd(ssi_cmd, ssi_cmd_len);
	if (!usc) return NULL ;

	if (!found) goto run;

	// now split the args
	char *cmd_args = cmd + ssi_cmd_len + 1;
	size_t cmd_args_len = cmd_len - (ssi_cmd_len + 1);

	for(i=(ssi_cmd_len + 1);i<cmd_len;i++) {
		if (isspace((int)cmd[i])) {
			cmd_args++;
			cmd_args_len--;
		}
		else {
			break;
		}
	}

	if (uwsgi_ssi_parse_args(wsgi_req, cmd_args, cmd_args_len, argv, &argc)) {
		return NULL;
	}

run:
	return usc->func(wsgi_req, argv, argc);
}

static struct uwsgi_buffer *uwsgi_ssi_parse(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	size_t i;
	uint8_t status = 0;
	char *cmd = NULL;
	size_t cmd_len = 0;
	struct uwsgi_buffer *ub = uwsgi_buffer_new(len);
	// parsing status 0[null] 1[<] 2[!] 3[-] 4[-] 5[#/-] 6[-] 7[>]
        // on status 6-7-8 the reset action come back to 5 instead of 0 
	for(i=0;i<len;i++) {
		switch(status) {
			case 0:
				if (buf[i] == '<') {
					status = 1;
				}
				else {
					if (uwsgi_buffer_append(ub, &buf[i], 1)) goto error;
				}
				break;
			case 1:
				status = 0;
				if (buf[i] == '!') {
					status = 2;
				}
				else {
					if (uwsgi_buffer_append(ub, "<", 1)) goto error;
					if (uwsgi_buffer_append(ub, &buf[i], 1)) goto error;
				}
				break;
			case 2:
				status = 0;
				if (buf[i] == '-') {
					status = 3;
				}
				else {
					if (uwsgi_buffer_append(ub, "<!", 2)) goto error;
					if (uwsgi_buffer_append(ub, &buf[i], 1)) goto error;
				}
				break;
			case 3:
				status = 0;
				if (buf[i] == '-') {
					status = 4;
				}
				else {
					if (uwsgi_buffer_append(ub, "<!-", 3)) goto error;
					if (uwsgi_buffer_append(ub, &buf[i], 1)) goto error;
				}
				break;
			case 4:
				status = 0;
				if (buf[i] == '#') {
					status = 5;
				}
				else {
					if (uwsgi_buffer_append(ub, "<!--", 4)) goto error;
					if (uwsgi_buffer_append(ub, &buf[i], 1)) goto error;
				}
				break;
			case 5:
				if (buf[i] == '-') {
					status = 6;
					break;
				}
				if (!cmd) {
					cmd = buf+i;
				}
				cmd_len++;
				break;
			case 6:
				status = 5;
				if (buf[i] == '-') {
					status = 7;
				}
				else {
					cmd_len+=2;
				}
				break;
			case 7:
				status = 5;
				if (buf[i] == '>') {
					status = 0;
					struct uwsgi_buffer *ub_cmd = uwsgi_ssi_parse_command(wsgi_req, cmd, cmd_len);
					if (ub_cmd) {
						if (uwsgi_buffer_append(ub, ub_cmd->buf, ub_cmd->pos)) {
							uwsgi_buffer_destroy(ub_cmd);
							goto error;
						}
						uwsgi_buffer_destroy(ub_cmd);
					}
					cmd = NULL;
					cmd_len = 0;	
                                }
                                else {
                                        cmd_len+=3;
                                }
				break;
			default:
				goto error;
		}
	}

	return ub;

error:
	uwsgi_buffer_destroy(ub);
	return NULL;
}

static int uwsgi_ssi_request(struct wsgi_request *wsgi_req) {
	struct uwsgi_buffer *ub = NULL;

	if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }

	if (!wsgi_req->document_root_len || !wsgi_req->path_info_len) {
		uwsgi_log("[uwsgi-ssi] DOCUMENT_ROOT and PATH_INFO must be defined !!!\n");
		uwsgi_500(wsgi_req);
		return UWSGI_OK;
	}

	char *filename = uwsgi_concat3n(wsgi_req->document_root, wsgi_req->document_root_len, "/", 1, wsgi_req->path_info, wsgi_req->path_info_len);
	size_t filename_len = wsgi_req->document_root_len + 1 + wsgi_req->path_info_len;
	
	// we expand the path for future security implementations
	char *real_filename = uwsgi_expand_path(filename, filename_len, NULL);
	free(filename);
	if (!real_filename) {
		uwsgi_404(wsgi_req);
		return UWSGI_OK;
	}

	struct uwsgi_buffer *ub_ssi = uwsgi_buffer_from_file(real_filename);
	free(real_filename);
	if (!ub_ssi) {
		uwsgi_500(wsgi_req);
		return UWSGI_OK;
	}

	ub = uwsgi_ssi_parse(wsgi_req, ub_ssi->buf, ub_ssi->pos);
	uwsgi_buffer_destroy(ub_ssi);
	if (!ub) {
               	uwsgi_500(wsgi_req);
		return UWSGI_OK;
	}
	// prepare headers
       	if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) {
               	uwsgi_500(wsgi_req);
               	goto end;
       	}
       	// content_length
       	if (uwsgi_response_add_content_length(wsgi_req, ub->pos)) {
               	uwsgi_500(wsgi_req);
               	goto end;
       	}
       	// content_type
       	if (uwsgi_response_add_content_type(wsgi_req, "text/html", 9)) {
               	uwsgi_500(wsgi_req);
               	goto end;
       	}

	uwsgi_response_write_body_do(wsgi_req, ub->buf, ub->pos);
end:
	if (ub) {
		uwsgi_buffer_destroy(ub);
	}
	return UWSGI_OK;
}

static char *uwsgi_ssi_get_arg(struct uwsgi_ssi_arg *argv, int argc, char *key, size_t key_len, size_t *val_len) {
	int i;
	for(i=0;i<argc;i++) {
		struct uwsgi_ssi_arg *arg = &argv[i];
		if (!uwsgi_strncmp(arg->key, arg->key_len, key, key_len)) {
			*val_len = arg->val_len;	
			return arg->value;
		}
	}

	return NULL;
}

// echo command
static struct uwsgi_buffer *ssi_cmd_echo(struct wsgi_request *wsgi_req, struct uwsgi_ssi_arg *argv, int argc) {
	size_t var_len = 0;
	char *var = uwsgi_ssi_get_arg(argv, argc, "var", 3, &var_len);

	if (!var || var_len == 0) return NULL;

	uint16_t rlen = 0;
	char *value = uwsgi_get_var(wsgi_req, var, var_len, &rlen);
	if (!value) return NULL;
	if (rlen == 0) return NULL;

	struct uwsgi_buffer *ub = uwsgi_buffer_new(rlen);
	if (uwsgi_buffer_append(ub, value, rlen)) {
		uwsgi_buffer_destroy(ub);
		return NULL;
	}

	return ub;
};

// printenv command
static struct uwsgi_buffer *ssi_cmd_printenv(struct wsgi_request *wsgi_req, struct uwsgi_ssi_arg *argv, int argc) {
        struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);
	int i;
	for (i = 0; i < wsgi_req->var_cnt; i += 2) {
        	if (uwsgi_buffer_append(ub, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len)) goto error;
		if (uwsgi_buffer_append(ub, "=", 1)) goto error;
        	if (uwsgi_buffer_append(ub, wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len)) goto error;
		if (uwsgi_buffer_append(ub, "\n", 1)) goto error;
	}

        return ub;
error:
	uwsgi_buffer_destroy(ub);
	return NULL;
};

// include command
static struct uwsgi_buffer *ssi_cmd_include(struct wsgi_request *wsgi_req, struct uwsgi_ssi_arg *argv, int argc) {
	size_t var_len = 0;
        char *var = uwsgi_ssi_get_arg(argv, argc, "file", 4, &var_len);
	if (!var || var_len == 0) return NULL;

	char *filename = uwsgi_concat2n(var, var_len, "", 0);

	struct uwsgi_buffer *ub = uwsgi_buffer_from_file(filename);

	free(filename);

	return ub;
}

// cache command (uWSGI specific)
static struct uwsgi_buffer *ssi_cmd_cache(struct wsgi_request *wsgi_req, struct uwsgi_ssi_arg *argv, int argc) {
        size_t var_len = 0;
        char *var = uwsgi_ssi_get_arg(argv, argc, "key", 3, &var_len);
        if (!var || var_len == 0) return NULL;

	size_t cache_len = 0;
	char *cache = uwsgi_ssi_get_arg(argv, argc, "name", 4, &cache_len);
        char *cache_name = NULL;

	if (cache && cache_len) {
		cache_name = uwsgi_concat2n(cache, cache_len, "", 0);
	}

	uint64_t rlen = 0;
	char *value = uwsgi_cache_magic_get(var, var_len, &rlen, NULL, cache_name);
	if (cache_name) free(cache_name);
	struct uwsgi_buffer *ub = NULL;
	if (value) {
        	ub = uwsgi_buffer_new(rlen);
		if (uwsgi_buffer_append(ub, value, rlen)) {
			free(value);
			uwsgi_buffer_destroy(ub);
			return NULL;
		}
		free(value);
	}

        return ub;
}


static int uwsgi_routing_func_ssi(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){

	struct uwsgi_buffer *ub = NULL;

        char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *) (((char *)(wsgi_req))+ur->subject_len);

        struct uwsgi_buffer *ub_filename = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, ur->data, ur->data_len);
        if (!ub_filename) goto end;

	struct uwsgi_buffer *ub_ssi = uwsgi_buffer_from_file(ub_filename->buf);
	uwsgi_buffer_destroy(ub_filename);
	if (!ub_ssi) goto end;

	ub = uwsgi_ssi_parse(wsgi_req, ub_ssi->buf, ub_ssi->pos);
	uwsgi_buffer_destroy(ub_ssi);
	if (!ub) goto end;

        if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) goto end;
        if (uwsgi_response_add_content_length(wsgi_req, ub->pos)) goto end;
        if (uwsgi_response_add_content_type(wsgi_req, "text/html", 9)) goto end;

        uwsgi_response_write_body_do(wsgi_req, ub->buf, ub->pos);
	
end:
	if (ub) uwsgi_buffer_destroy(ub);
        return UWSGI_ROUTE_BREAK;
}


static int uwsgi_router_ssi(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_ssi;
        ur->data = args;
        ur->data_len = strlen(args);
        return 0;
}


static int uwsgi_ssi_init() {
	uwsgi_register_ssi_command("echo", ssi_cmd_echo);
	uwsgi_register_ssi_command("printenv", ssi_cmd_printenv);
	uwsgi_register_ssi_command("include", ssi_cmd_include);
	uwsgi_register_ssi_command("cache", ssi_cmd_cache);
	return 0;
}


static void uwsgi_ssi_register_router() {
	uwsgi_register_router("ssi", uwsgi_router_ssi);
}

static void uwsgi_ssi_log(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

struct uwsgi_plugin ssi_plugin = {
	.name = "ssi",
	.modifier1 = 19,
	.init = uwsgi_ssi_init,
	.request = uwsgi_ssi_request,
	.after_request = uwsgi_ssi_log,
	.on_load = uwsgi_ssi_register_router,
};
