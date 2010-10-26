#include "buffer.h"
#include "server.h"
#include "keyvalue.h"
#include "log.h"

#include "http_chunk.h"
#include "fdevent.h"
#include "connections.h"
#include "response.h"
#include "joblist.h"

#include "plugin.h"

#include "inet_ntop_cache.h"
#include "crc32.h"

#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include <stdio.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#include "sys-socket.h"

#define data_uwsgi data_fastcgi
#define data_uwsgi_init data_fastcgi_init

#ifdef __linux__
#include <endian.h>
#elif __sun__
#elif __APPLE__
#include <libkern/OSByteOrder.h>
#else
#include <machine/endian.h>
#endif


#ifdef __BIG_ENDIAN__
static uint16_t uwsgi_swap16(uint16_t x) {
	return (uint16_t) ((x & 0xff) << 8 | (x & 0xff00) >> 8);
}
#endif


/**
 *
 * the uwsgi module is based on the proxy module
 *
 * 30.12.2009 Roberto De Ioris first public release
 *
 */

typedef struct __attribute__((packed)) {
	uint8_t		modifier1;
	uint16_t	pktsize;
	uint8_t		modifier2;
} uwsgi_header;

typedef struct {
	array *extensions;
	unsigned short debug;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	buffer *parse_response;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

typedef enum {
	UWSGI_STATE_INIT,
	UWSGI_STATE_CONNECT,
	UWSGI_STATE_PREPARE_WRITE,
	UWSGI_STATE_WRITE,
	UWSGI_STATE_READ,
	UWSGI_STATE_ERROR
} uwsgi_connection_state_t;

typedef struct {
	uwsgi_connection_state_t state;
	time_t state_timestamp;

	data_uwsgi *host;

	buffer *response;
	buffer *response_header;

	chunkqueue *wb;

	int fd; /* fd to the uwsgi process */
	int fde_ndx; /* index into the fd-event buffer */

	size_t path_info_offset; /* start of path_info in uri.path */

	connection *remote_conn;  /* dump pointer */
	plugin_data *plugin_data; /* dump pointer */
} handler_ctx;


static handler_t uwsgi_handle_fdevent(void *s, void *ctx, int revents);

static handler_ctx * handler_ctx_init() {
	handler_ctx * hctx;


	hctx = calloc(1, sizeof(*hctx));

	hctx->state = UWSGI_STATE_INIT;
	hctx->host = NULL;

	hctx->response = buffer_init();
	hctx->response_header = buffer_init();

	hctx->wb = chunkqueue_init();

	hctx->fd = -1;
	hctx->fde_ndx = -1;


	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	buffer_free(hctx->response);
	buffer_free(hctx->response_header);
	chunkqueue_free(hctx->wb);

	free(hctx);
}

INIT_FUNC(mod_uwsgi_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	p->parse_response = buffer_init();

	return p;
}


FREE_FUNC(mod_uwsgi_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	buffer_free(p->parse_response);

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (s) {

				array_free(s->extensions);

				free(s);
			}
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_uwsgi_set_defaults) {
	plugin_data *p = p_d;
	data_unset *du;
	size_t i = 0;

	config_values_t cv[] = {
		{ "uwsgi.server",              NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "uwsgi.debug",               NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ NULL,                        NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		array *ca;

		s = malloc(sizeof(plugin_config));
		s->extensions    = array_init();
		s->debug         = 0;

		cv[0].destination = s->extensions;
		cv[1].destination = &(s->debug);


		p->config_storage[i] = s;
		ca = ((data_config *)srv->config_context->data[i])->value;

		if (0 != config_insert_values_global(srv, ca, cv)) {
			return HANDLER_ERROR;
		}

		if (NULL != (du = array_get_element(ca, "uwsgi.server"))) {
			size_t j;
			data_array *da = (data_array *)du;

			if (du->type != TYPE_ARRAY) {
				log_error_write(srv, __FILE__, __LINE__, "sss",
						"unexpected type for key: ", "uwsgi.server", "array of strings");

				return HANDLER_ERROR;
			}

			/*
			 * uwsgi.server = ( "<ext>" => ...,
			 *                  "<ext>" => ... )
			 */

			for (j = 0; j < da->value->used; j++) {
				data_array *da_ext = (data_array *)da->value->data[j];
				size_t n;

				if (da_ext->type != TYPE_ARRAY) {
					log_error_write(srv, __FILE__, __LINE__, "sssbs",
							"unexpected type for key: ", "uwsgi.server",
							"[", da->value->data[j]->key, "](string)");

					return HANDLER_ERROR;
				}

				/*
				 * uwsgi.server = ( "<ext>" =>
				 *                     ( "<host>" => ( ... ),
				 *                       "<host>" => ( ... )
				 *                     ),
				 *                    "<ext>" => ... )
				 */

				for (n = 0; n < da_ext->value->used; n++) {
					data_array *da_host = (data_array *)da_ext->value->data[n];

					data_uwsgi *df;
					data_array *dfa;

					config_values_t pcv[] = {
						{ "host",              NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },      /* 0 */
						{ "port",              NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
						{ NULL,                NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
					};

					if (da_host->type != TYPE_ARRAY) {
						log_error_write(srv, __FILE__, __LINE__, "ssSBS",
								"unexpected type for key:",
								"uwsgi.server",
								"[", da_ext->value->data[n]->key, "](string)");

						return HANDLER_ERROR;
					}

					df = data_uwsgi_init();

					df->port = 3031;

					buffer_copy_string_buffer(df->key, da_host->key);

					pcv[0].destination = df->host;
					pcv[1].destination = &(df->port);

					if (0 != config_insert_values_internal(srv, da_host->value, pcv)) {
						return HANDLER_ERROR;
					}

					if (buffer_is_empty(df->host)) {
						log_error_write(srv, __FILE__, __LINE__, "sbbbs",
								"missing key (string):",
								da->key,
								da_ext->key,
								da_host->key,
								"host");

						return HANDLER_ERROR;
					}

					/* if extension already exists, take it */

					if (NULL == (dfa = (data_array *)array_get_element(s->extensions, da_ext->key->ptr))) {
						dfa = data_array_init();

						buffer_copy_string_buffer(dfa->key, da_ext->key);

						array_insert_unique(dfa->value, (data_unset *)df);
						array_insert_unique(s->extensions, (data_unset *)dfa);
					} else {
						array_insert_unique(dfa->value, (data_unset *)df);
					}
				}
			}
		}
	}

	return HANDLER_GO_ON;
}

static void uwsgi_connection_close(server *srv, handler_ctx *hctx) {
	plugin_data *p;
	connection *con;

	if (NULL == hctx) return;

	p    = hctx->plugin_data;
	con  = hctx->remote_conn;

	if (hctx->fd != -1) {
		fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
		fdevent_unregister(srv->ev, hctx->fd);

		close(hctx->fd);
		srv->cur_fds--;
	}

	handler_ctx_free(hctx);
	con->plugin_ctx[p->id] = NULL;
}

static int uwsgi_establish_connection(server *srv, handler_ctx *hctx) {
	struct sockaddr *uwsgi_addr;
	struct sockaddr_in uwsgi_addr_in;
#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
	struct sockaddr_in6 uwsgi_addr_in6;
#endif
	socklen_t servlen;

	plugin_data *p    = hctx->plugin_data;
	data_uwsgi *host= hctx->host;
	int uwsgi_fd       = hctx->fd;


#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
	if (strstr(host->host->ptr, ":")) {
		memset(&uwsgi_addr_in6, 0, sizeof(uwsgi_addr_in6));
		uwsgi_addr_in6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, host->host->ptr, (char *) &uwsgi_addr_in6.sin6_addr);
		uwsgi_addr_in6.sin6_port = htons(host->port);
		servlen = sizeof(uwsgi_addr_in6);
		uwsgi_addr = (struct sockaddr *) &uwsgi_addr_in6;
	} else
#endif
	{
		memset(&uwsgi_addr_in, 0, sizeof(uwsgi_addr_in));
		uwsgi_addr_in.sin_family = AF_INET;
		uwsgi_addr_in.sin_addr.s_addr = inet_addr(host->host->ptr);
		uwsgi_addr_in.sin_port = htons(host->port);
		servlen = sizeof(uwsgi_addr_in);
		uwsgi_addr = (struct sockaddr *) &uwsgi_addr_in;
	}


	if (-1 == connect(uwsgi_fd, uwsgi_addr, servlen)) {
		if (errno == EINPROGRESS || errno == EALREADY) {
			if (p->conf.debug) {
				log_error_write(srv, __FILE__, __LINE__, "sd",
						"connect delayed:", uwsgi_fd);
			}

			return 1;
		} else {

			log_error_write(srv, __FILE__, __LINE__, "sdsd",
					"connect failed:", uwsgi_fd, strerror(errno), errno);

			return -1;
		}
	}
	if (p->conf.debug) {
		log_error_write(srv, __FILE__, __LINE__, "sd",
				"connect succeeded: ", uwsgi_fd);
	}

	return 0;
}

static void uwsgi_add_var(buffer *b, char * key, uint16_t keylen, char *val, uint16_t vallen) {

#ifdef __BIG_ENDIAN__
	uint16_t uwlen;

	uwlen = uwsgi_swap16(keylen);
	buffer_append_memory(b, (char *) &uwlen, 2); buffer_append_memory(b, key, keylen);
	uwlen = uwsgi_swap16(vallen);
	buffer_append_memory(b, (char *) &uwlen, 2); buffer_append_memory(b, val, vallen);
#else
	buffer_append_memory(b, (char *) &keylen, 2); buffer_append_memory(b, key, keylen);
	buffer_append_memory(b, (char *) &vallen, 2); buffer_append_memory(b, val, vallen);
#endif


}

static int uwsgi_create_env(server *srv, handler_ctx *hctx) {
	size_t i;

	char buf[32];
	uwsgi_header *uh;
	const char *s;
#ifdef HAVE_IPV6
	char b2[INET6_ADDRSTRLEN + 1];
#endif


	connection *con   = hctx->remote_conn;
	server_socket *srv_sock = con->srv_socket;
	buffer *b;

	/* build header */

	b = chunkqueue_get_append_buffer(hctx->wb);

	/* make space for uwsgi header */
	buffer_append_memory(b, "\0\0\0\0", 4);

	/* set WSGI vars */
	s = get_http_method_name(con->request.http_method);
	uwsgi_add_var(b, "REQUEST_METHOD", 14, (char *) s, strlen(s));

	if (!buffer_is_empty(con->uri.query)) {
		uwsgi_add_var(b, "QUERY_STRING", 12, con->uri.query->ptr, con->uri.query->used-1);
	} else {
		uwsgi_add_var(b, "QUERY_STRING", 12, "", 0);
	}

	s = get_http_version_name(con->request.http_version);
	uwsgi_add_var(b, "SERVER_PROTOCOL", 15, (char *) s, strlen(s));


	if (con->server_name->used) {
		size_t len = con->server_name->used - 1;
		char *colon = strchr(con->server_name->ptr, ':');
		if (colon) len = colon - con->server_name->ptr;
		uwsgi_add_var(b, "SERVER_NAME", 11, con->server_name->ptr, len);

	} else {
#ifdef HAVE_IPV6
		s = inet_ntop(srv_sock->addr.plain.sa_family,
				srv_sock->addr.plain.sa_family == AF_INET6 ?
				(const void *) &(srv_sock->addr.ipv6.sin6_addr) :
				(const void *) &(srv_sock->addr.ipv4.sin_addr),
				b2, sizeof(b2)-1);
#else
		s = inet_ntoa(srv_sock->addr.ipv4.sin_addr);
#endif
		uwsgi_add_var(b, "SERVER_NAME", 11, (char *)s, strlen(s));
	}

	LI_ltostr(buf,
#ifdef HAVE_IPV6
			ntohs(srv_sock->addr.plain.sa_family ? srv_sock->addr.ipv6.sin6_port : srv_sock->addr.ipv4.sin_port)
#else
			ntohs(srv_sock->addr.ipv4.sin_port)
#endif
			);

	uwsgi_add_var(b, "SERVER_PORT", 11, buf, strlen(buf));
	uwsgi_add_var(b, "REQUEST_URI", 11, con->request.orig_uri->ptr, con->request.orig_uri->used-1);

	LI_ltostr(buf,
#ifdef HAVE_IPV6
			ntohs(con->dst_addr.plain.sa_family ? con->dst_addr.ipv6.sin6_port : con->dst_addr.ipv4.sin_port)
#else
			ntohs(con->dst_addr.ipv4.sin_port)
#endif
			);
	uwsgi_add_var(b, "REMOTE_PORT", 11, buf, strlen(buf));

	if (!buffer_is_empty(con->authed_user)) {
		uwsgi_add_var(b, "REMOTE_USER", 11,
				CONST_BUF_LEN(con->authed_user));
	}



	s = inet_ntop_cache_get_ip(srv, &(con->dst_addr));
	uwsgi_add_var(b, "REMOTE_ADDR", 11, (char *)s, strlen(s));

	if (hctx->path_info_offset > 1) {
		uwsgi_add_var(b, "SCRIPT_NAME", 11, con->uri.path->ptr, hctx->path_info_offset);
		if (strlen(con->uri.path->ptr + hctx->path_info_offset) > 0) {
			uwsgi_add_var(b, "PATH_INFO", 9, con->uri.path->ptr + hctx->path_info_offset, strlen(con->uri.path->ptr + hctx->path_info_offset));
		}
		else {
			uwsgi_add_var(b, "PATH_INFO", 9, "/", 1);
		}
	}
	else {
		uwsgi_add_var(b, "SCRIPT_NAME", 11, "", 0);
		uwsgi_add_var(b, "PATH_INFO", 9, con->uri.path->ptr, strlen(con->uri.path->ptr));
	}


	for (i = 0; i < con->request.headers->used; i++) {
		data_string *ds;
		ds = (data_string *)con->request.headers->data[i];

		if (ds->value->used && ds->key->used) {
			size_t j;
			buffer_reset(srv->tmp_buf);
			if (!strcasecmp(ds->key->ptr, "CONTENT-TYPE") || !strcasecmp(ds->key->ptr, "CONTENT-LENGTH")) {
				buffer_prepare_append(srv->tmp_buf, ds->key->used + 2);
			}
			else {
				buffer_prepare_append(srv->tmp_buf, ds->key->used + 7);
				buffer_append_memory(srv->tmp_buf, "HTTP_", 5);
			}
			for (j = 0; j < ds->key->used - 1; j++) {
				srv->tmp_buf->ptr[srv->tmp_buf->used++] = light_isalpha(ds->key->ptr[j]) ? ds->key->ptr[j] & ~32 : '_';
			}
			srv->tmp_buf->ptr[srv->tmp_buf->used++] = '\0';
			uwsgi_add_var(b, srv->tmp_buf->ptr, srv->tmp_buf->used-1, ds->value->ptr, ds->value->used-1);
		}
	}

	for (i = 0; i < con->environment->used; i++) {
		data_string *ds;
		ds = (data_string *)con->environment->data[i];
		if (ds->value->used && ds->key->used) {
			size_t j;
			buffer_reset(srv->tmp_buf);
			buffer_prepare_append(srv->tmp_buf, ds->key->used + 2);
			for (j = 0; j < ds->key->used - 1; j++) {
				srv->tmp_buf->ptr[srv->tmp_buf->used++] = light_isalnum((unsigned char)ds->key->ptr[j]) ? toupper((unsigned char)ds->key->ptr[j]) : '_';
			}

			srv->tmp_buf->ptr[srv->tmp_buf->used++] = '\0';
			uwsgi_add_var(b, srv->tmp_buf->ptr, srv->tmp_buf->used-1, ds->value->ptr, ds->value->used-1);
		}
	}


	uh = (uwsgi_header *) b->ptr;
	uh->modifier1 = (uint8_t) 0;
#ifdef __BIG_ENDIAN__
	uh->pktsize = uwsgi_swap16((uint16_t) b->used - 4);
#else
	uh->pktsize = b->used - 4;
#endif
	uh->modifier2 = (uint8_t) 0;

	b->used++; /* fix size */

	hctx->wb->bytes_in += b->used -1;
	/* body */

	if (con->request.content_length) {
		chunkqueue *req_cq = con->request_content_queue;
		chunk *req_c;
		off_t offset;

		/* something to send ? */
		for (offset = 0, req_c = req_cq->first; offset != req_cq->bytes_in; req_c = req_c->next) {
			off_t weWant = req_cq->bytes_in - offset;
			off_t weHave = 0;

			/* we announce toWrite octects
			 * now take all the request_content chunk that we need to fill this request
			 * */

			switch (req_c->type) {
				case FILE_CHUNK:
					weHave = req_c->file.length - req_c->offset;

					if (weHave > weWant) weHave = weWant;

					chunkqueue_append_file(hctx->wb, req_c->file.name, req_c->offset, weHave);

					req_c->offset += weHave;
					req_cq->bytes_out += weHave;

					hctx->wb->bytes_in += weHave;

					break;
				case MEM_CHUNK:
					/* append to the buffer */
					weHave = req_c->mem->used - 1 - req_c->offset;

					if (weHave > weWant) weHave = weWant;

					b = chunkqueue_get_append_buffer(hctx->wb);
					buffer_append_memory(b, req_c->mem->ptr + req_c->offset, weHave);
					b->used++; /* add virtual \0 */

					req_c->offset += weHave;
					req_cq->bytes_out += weHave;

					hctx->wb->bytes_in += weHave;

					break;
				default:
					break;
			}

			offset += weHave;
		}

	}

	return 0;
}

static int uwsgi_set_state(server *srv, handler_ctx *hctx, uwsgi_connection_state_t state) {
	hctx->state = state;
	hctx->state_timestamp = srv->cur_ts;

	return 0;
}


static int uwsgi_response_parse(server *srv, connection *con, plugin_data *p, buffer *in) {
	char *s, *ns;
	int http_response_status = -1;

	UNUSED(srv);

	/* \r\n -> \0\0 */

	buffer_copy_string_buffer(p->parse_response, in);

	for (s = p->parse_response->ptr; NULL != (ns = strstr(s, "\r\n")); s = ns + 2) {
		char *key, *value;
		int key_len;
		data_string *ds;
		int copy_header;

		ns[0] = '\0';
		ns[1] = '\0';

		if (-1 == http_response_status) {
			/* The first line of a Response message is the Status-Line */

			for (key=s; *key && *key != ' '; key++);

			if (*key) {
				http_response_status = (int) strtol(key, NULL, 10);
				if (http_response_status <= 0) http_response_status = 502;
			} else {
				http_response_status = 502;
			}

			con->http_status = http_response_status;
			con->parsed_response |= HTTP_STATUS;
			continue;
		}

		if (NULL == (value = strchr(s, ':'))) {
			/* now we expect: "<key>: <value>\n" */

			continue;
		}

		key = s;
		key_len = value - key;

		value++;
		/* strip WS */
		while (*value == ' ' || *value == '\t') value++;

		copy_header = 1;

		switch(key_len) {
			case 4:
				if (0 == strncasecmp(key, "Date", key_len)) {
					con->parsed_response |= HTTP_DATE;
				}
				break;
			case 8:
				if (0 == strncasecmp(key, "Location", key_len)) {
					con->parsed_response |= HTTP_LOCATION;
				}
				break;
			case 10:
				if (0 == strncasecmp(key, "Connection", key_len)) {
					copy_header = 0;
				}
				break;
			case 14:
				if (0 == strncasecmp(key, "Content-Length", key_len)) {
					con->response.content_length = strtol(value, NULL, 10);
					con->parsed_response |= HTTP_CONTENT_LENGTH;
				}
				break;
			default:
				break;
		}

		if (copy_header) {
			if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
				ds = data_response_init();
			}
			buffer_copy_string_len(ds->key, key, key_len);
			buffer_copy_string(ds->value, value);

			array_insert_unique(con->response.headers, (data_unset *)ds);
		}
	}

	return 0;
}


static int uwsgi_demux_response(server *srv, handler_ctx *hctx) {
	int fin = 0;
	int b;
	ssize_t r;

	plugin_data *p    = hctx->plugin_data;
	connection *con   = hctx->remote_conn;
	int uwsgi_fd       = hctx->fd;

	/* check how much we have to read */
	if (ioctl(hctx->fd, FIONREAD, &b)) {
		log_error_write(srv, __FILE__, __LINE__, "sd",
				"ioctl failed: ",
				uwsgi_fd);
		return -1;
	}


	if (p->conf.debug) {
		log_error_write(srv, __FILE__, __LINE__, "sd",
				"uwsgi - have to read:", b);
	}

	if (b > 0) {
		if (hctx->response->used == 0) {
			/* avoid too small buffer */
			buffer_prepare_append(hctx->response, b + 1);
			hctx->response->used = 1;
		} else {
			buffer_prepare_append(hctx->response, b);
		}

		if (-1 == (r = read(hctx->fd, hctx->response->ptr + hctx->response->used - 1, b))) {
			if (errno == EAGAIN) return 0;
			log_error_write(srv, __FILE__, __LINE__, "sds",
					"unexpected end-of-file (perhaps the uwsgi process died):",
					uwsgi_fd, strerror(errno));
			return -1;
		}

		/* this should be catched by the b > 0 above */
		assert(r);

		hctx->response->used += r;
		hctx->response->ptr[hctx->response->used - 1] = '\0';

#if 0
		log_error_write(srv, __FILE__, __LINE__, "sdsbs",
				"demux: Response buffer len", hctx->response->used, ":", hctx->response, ":");
#endif

		if (0 == con->got_response) {
			con->got_response = 1;
			buffer_prepare_copy(hctx->response_header, 128);
		}

		if (0 == con->file_started) {
			char *c;

			/* search for the \r\n\r\n in the string */
			if (NULL != (c = buffer_search_string_len(hctx->response, "\r\n\r\n", 4))) {
				size_t hlen = c - hctx->response->ptr + 4;
				size_t blen = hctx->response->used - hlen - 1;
				/* found */

				buffer_append_string_len(hctx->response_header, hctx->response->ptr, c - hctx->response->ptr + 4);
#if 0
				log_error_write(srv, __FILE__, __LINE__, "sb", "Header:", hctx->response_header);
#endif
				/* parse the response header */
				uwsgi_response_parse(srv, con, p, hctx->response_header);

				/* enable chunked-transfer-encoding */
				if (con->request.http_version == HTTP_VERSION_1_1 &&
						!(con->parsed_response & HTTP_CONTENT_LENGTH)) {
					con->response.transfer_encoding = HTTP_TRANSFER_ENCODING_CHUNKED;
				}

				con->file_started = 1;
				if (blen) {
					http_chunk_append_mem(srv, con, c + 4, blen + 1);
					joblist_append(srv, con);
				}
				hctx->response->used = 0;
			}
		} else {
			http_chunk_append_mem(srv, con, hctx->response->ptr, hctx->response->used);
			joblist_append(srv, con);
			hctx->response->used = 0;
		}

	} else {
		/* reading from upstream done */
		con->file_finished = 1;

		http_chunk_append_mem(srv, con, NULL, 0);
		joblist_append(srv, con);

		fin = 1;
	}

	return fin;
}


static handler_t uwsgi_write_request(server *srv, handler_ctx *hctx) {
	data_uwsgi *host= hctx->host;
	plugin_data *p    = hctx->plugin_data;
	connection *con   = hctx->remote_conn;

	int ret;

	if (!host ||
			(!host->host->used || !host->port)) return -1;

	switch(hctx->state) {
		case UWSGI_STATE_INIT:
#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
			if (strstr(host->host->ptr,":")) {
				if (-1 == (hctx->fd = socket(AF_INET6, SOCK_STREAM, 0))) {
					log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed: ", strerror(errno));
					return HANDLER_ERROR;
				}
			} else
#endif
			{
				if (-1 == (hctx->fd = socket(AF_INET, SOCK_STREAM, 0))) {
					log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed: ", strerror(errno));
					return HANDLER_ERROR;
				}
			}
			hctx->fde_ndx = -1;

			srv->cur_fds++;

			fdevent_register(srv->ev, hctx->fd, uwsgi_handle_fdevent, hctx);

			if (-1 == fdevent_fcntl_set(srv->ev, hctx->fd)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "fcntl failed: ", strerror(errno));

				return HANDLER_ERROR;
			}

			/* fall through */

		case UWSGI_STATE_CONNECT:
			/* try to finish the connect() */
			if (hctx->state == UWSGI_STATE_INIT) {
				/* first round */
				switch (uwsgi_establish_connection(srv, hctx)) {
					case 1:
						uwsgi_set_state(srv, hctx, UWSGI_STATE_CONNECT);

						/* connection is in progress, wait for an event and call getsockopt() below */

						fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);

						return HANDLER_WAIT_FOR_EVENT;
					case -1:
						/* if ECONNREFUSED choose another connection -> FIXME */
						hctx->fde_ndx = -1;

						return HANDLER_ERROR;
					default:
						/* everything is ok, go on */
						break;
				}
			} else {
				int socket_error;
				socklen_t socket_error_len = sizeof(socket_error);

				/* we don't need it anymore */
				fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);

				/* try to finish the connect() */
				if (0 != getsockopt(hctx->fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len)) {
					log_error_write(srv, __FILE__, __LINE__, "ss",
							"getsockopt failed:", strerror(errno));

					return HANDLER_ERROR;
				}
				if (socket_error != 0) {
					log_error_write(srv, __FILE__, __LINE__, "ss",
							"establishing connection failed:", strerror(socket_error),
							"port:", hctx->host->port);

					return HANDLER_ERROR;
				}
				if (p->conf.debug) {
					log_error_write(srv, __FILE__, __LINE__,  "s", "uwsgi - connect - delayed success");
				}
			}

			uwsgi_set_state(srv, hctx, UWSGI_STATE_PREPARE_WRITE);
			/* fall through */
		case UWSGI_STATE_PREPARE_WRITE:
			uwsgi_create_env(srv, hctx);

			uwsgi_set_state(srv, hctx, UWSGI_STATE_WRITE);

			/* fall through */
		case UWSGI_STATE_WRITE:;
							   ret = srv->network_backend_write(srv, con, hctx->fd, hctx->wb);

							   chunkqueue_remove_finished_chunks(hctx->wb);

							   if (-1 == ret) { /* error on our side */
								   log_error_write(srv, __FILE__, __LINE__, "ssd", "write failed:", strerror(errno), errno);

								   return HANDLER_WAIT_FOR_EVENT;
							   } else if (-2 == ret) { /* remote close */
								   log_error_write(srv, __FILE__, __LINE__, "ssd", "write failed, remote connection close:", strerror(errno), errno);

								   return HANDLER_WAIT_FOR_EVENT;
							   }

							   if (hctx->wb->bytes_out == hctx->wb->bytes_in) {
								   uwsgi_set_state(srv, hctx, UWSGI_STATE_READ);

								   fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
								   fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
							   } else {
								   fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);

								   return HANDLER_WAIT_FOR_EVENT;
							   }

							   return HANDLER_WAIT_FOR_EVENT;
		case UWSGI_STATE_READ:
							   /* waiting for a response */
							   return HANDLER_WAIT_FOR_EVENT;
		default:
							   log_error_write(srv, __FILE__, __LINE__, "s", "(debug) unknown state");
							   return HANDLER_ERROR;
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_uwsgi_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(extensions);
	PATCH(debug);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("uwsgi.server"))) {
				PATCH(extensions);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("uwsgi.debug"))) {
				PATCH(debug);
			}
		}
	}

	return 0;
}
#undef PATCH

SUBREQUEST_FUNC(mod_uwsgi_handle_subrequest) {
	plugin_data *p = p_d;

	handler_ctx *hctx = con->plugin_ctx[p->id];
	data_uwsgi *host;

	if (NULL == hctx) return HANDLER_GO_ON;

	mod_uwsgi_patch_connection(srv, con, p);

	host = hctx->host;

	/* not my job */
	if (con->mode != p->id) return HANDLER_GO_ON;

	/* ok, create the request */
	switch(uwsgi_write_request(srv, hctx)) {
		case HANDLER_ERROR:
			log_error_write(srv, __FILE__, __LINE__,  "sbdd", "uwsgi-server disabled:",
					host->host,
					host->port,
					hctx->fd);

			/* disable this server */
			host->is_disabled = 1;
			host->disable_ts = srv->cur_ts;

			uwsgi_connection_close(srv, hctx);

			/* reset the enviroment and restart the sub-request */
			buffer_reset(con->physical.path);
			con->mode = DIRECT;

			joblist_append(srv, con);

			/* mis-using HANDLER_WAIT_FOR_FD to break out of the loop
			 * and hope that the childs will be restarted
			 *
			 */

			return HANDLER_WAIT_FOR_FD;
		case HANDLER_WAIT_FOR_EVENT:
			return HANDLER_WAIT_FOR_EVENT;
		case HANDLER_WAIT_FOR_FD:
			return HANDLER_WAIT_FOR_FD;
		default:
			break;
	}

	if (con->file_started == 1) {
		return HANDLER_FINISHED;
	} else {
		return HANDLER_WAIT_FOR_EVENT;
	}
}

static handler_t uwsgi_handle_fdevent(void *s, void *ctx, int revents) {
	server      *srv  = (server *)s;
	handler_ctx *hctx = ctx;
	connection  *con  = hctx->remote_conn;
	plugin_data *p    = hctx->plugin_data;


	if ((revents & FDEVENT_IN) &&
			hctx->state == UWSGI_STATE_READ) {

		if (p->conf.debug) {
			log_error_write(srv, __FILE__, __LINE__, "sd",
					"uwsgi: fdevent-in", hctx->state);
		}

		switch (uwsgi_demux_response(srv, hctx)) {
			case 0:
				break;
			case 1:
				hctx->host->usage--;

				/* we are done */
				uwsgi_connection_close(srv, hctx);

				joblist_append(srv, con);
				return HANDLER_FINISHED;
			case -1:
				if (con->file_started == 0) {
					/* nothing has been send out yet, send a 500 */
					connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
					con->http_status = 500;
					con->mode = DIRECT;
				} else {
					/* response might have been already started, kill the connection */
					connection_set_state(srv, con, CON_STATE_ERROR);
				}

				joblist_append(srv, con);
				return HANDLER_FINISHED;
		}
	}

	if (revents & FDEVENT_OUT) {
		if (p->conf.debug) {
			log_error_write(srv, __FILE__, __LINE__, "sd",
					"uwsgi: fdevent-out", hctx->state);
		}

		if (hctx->state == UWSGI_STATE_CONNECT ||
				hctx->state == UWSGI_STATE_WRITE) {
			/* we are allowed to send something out
			 *
			 * 1. in a unfinished connect() call
			 * 2. in a unfinished write() call (long POST request)
			 */
			return mod_uwsgi_handle_subrequest(srv, con, p);
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sd",
					"uwsgi: out", hctx->state);
		}
	}

	/* perhaps this issue is already handled */
	if (revents & FDEVENT_HUP) {
		if (p->conf.debug) {
			log_error_write(srv, __FILE__, __LINE__, "sd",
					"uwsgi: fdevent-hup", hctx->state);
		}

		if (hctx->state == UWSGI_STATE_CONNECT) {
			/* connect() -> EINPROGRESS -> HUP */

			/**
			 * what is uwsgi is doing if it can't reach the next hop ?
			 *
			 */

			uwsgi_connection_close(srv, hctx);
			joblist_append(srv, con);

			con->http_status = 503;
			con->mode = DIRECT;

			return HANDLER_FINISHED;
		}

		con->file_finished = 1;

		uwsgi_connection_close(srv, hctx);
		joblist_append(srv, con);
	} else if (revents & FDEVENT_ERR) {
		/* kill all connections to the uwsgi process */

		log_error_write(srv, __FILE__, __LINE__, "sd", "uwsgi-FDEVENT_ERR, but no HUP", revents);

		joblist_append(srv, con);
		uwsgi_connection_close(srv, hctx);
	}

	return HANDLER_FINISHED;
}

static handler_t mod_uwsgi_check_extension(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	size_t s_len;
	int max_usage = INT_MAX;
	int ndx = -1;
	size_t k;
	buffer *fn;
	data_array *extension = NULL;
	size_t path_info_offset;

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	/* Possibly, we processed already this request */
	if (con->file_started == 1) return HANDLER_GO_ON;

	mod_uwsgi_patch_connection(srv, con, p);

	fn = con->uri.path;

	if (fn->used == 0) {
		return HANDLER_ERROR;
	}

	s_len = fn->used - 1;


	path_info_offset = 0;

	if (p->conf.debug) {
		log_error_write(srv, __FILE__, __LINE__,  "s", "uwsgi - start");
	}

	/* check if extension matches */
	for (k = 0; k < p->conf.extensions->used; k++) {
		data_array *ext = NULL;
		size_t ct_len;

		ext = (data_array *)p->conf.extensions->data[k];

		if (ext->key->used == 0) continue;

		ct_len = ext->key->used - 1;

		if (s_len < ct_len) continue;

		/* check extension in the form "/uwsgi_pattern" */
		if (*(ext->key->ptr) == '/') {
			if (strncmp(fn->ptr, ext->key->ptr, ct_len) == 0) {
				path_info_offset = ct_len;
				extension = ext;
				break;
			}
		} else if (0 == strncmp(fn->ptr + s_len - ct_len, ext->key->ptr, ct_len)) {
			/* check extension in the form ".fcg" */
			extension = ext;
			break;
		}
	}

	if (NULL == extension) {
		return HANDLER_GO_ON;
	}

	if (p->conf.debug) {
		log_error_write(srv, __FILE__, __LINE__,  "s", "uwsgi - ext found");
	}

	if (extension->value->used == 1) {
		if ( ((data_uwsgi *)extension->value->data[0])->is_disabled ) {
			ndx = -1;
		} else {
			ndx = 0;
		}
	} else if (extension->value->used != 0) {

		/* fair balancing */
		if (p->conf.debug) {
			log_error_write(srv, __FILE__, __LINE__,  "s",
					"uwsgi - used fair balancing");
		}

		for (k = 0, ndx = -1, max_usage = INT_MAX; k < extension->value->used; k++) {
			data_uwsgi *host = (data_uwsgi *)extension->value->data[k];

			if (host->is_disabled) continue;

			if (host->usage < max_usage) {
				max_usage = host->usage;

				ndx = k;
			}
		}

	}

	/* found a server */
	if (ndx != -1) {
		data_uwsgi *host = (data_uwsgi *)extension->value->data[ndx];

		/*
		 * if check-local is disabled, use the uri.path handler
		 *
		 */

		/* init handler-context */
		handler_ctx *hctx;
		hctx = handler_ctx_init();

		hctx->path_info_offset = path_info_offset;
		hctx->remote_conn      = con;
		hctx->plugin_data      = p;
		hctx->host             = host;

		con->plugin_ctx[p->id] = hctx;

		host->usage++;

		con->mode = p->id;

		if (p->conf.debug) {
			log_error_write(srv, __FILE__, __LINE__,  "sbd",
					"uwsgi - found a host",
					host->host, host->port);
		}

		return HANDLER_GO_ON;
	} else {
		/* no handler found */
		con->http_status = 500;

		log_error_write(srv, __FILE__, __LINE__,  "sb",
				"no uwsgi-handler found for:",
				fn);

		return HANDLER_FINISHED;
	}
	return HANDLER_GO_ON;
}

static handler_t mod_uwsgi_connection_close_callback(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;

	uwsgi_connection_close(srv, con->plugin_ctx[p->id]);

	return HANDLER_GO_ON;
}

/**
 *
 * the trigger re-enables the disabled connections after the timeout is over
 *
 * */

TRIGGER_FUNC(mod_uwsgi_trigger) {
	plugin_data *p = p_d;

	if (p->config_storage) {
		size_t i, n, k;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;

			/* get the extensions for all configs */

			for (k = 0; k < s->extensions->used; k++) {
				data_array *extension = (data_array *)s->extensions->data[k];

				/* get all hosts */
				for (n = 0; n < extension->value->used; n++) {
					data_uwsgi *host = (data_uwsgi *)extension->value->data[n];

					if (!host->is_disabled ||
							srv->cur_ts - host->disable_ts < 5) continue;

					log_error_write(srv, __FILE__, __LINE__,  "sbd",
							"uwsgi - re-enabled:",
							host->host, host->port);

					host->is_disabled = 0;
				}
			}
		}
	}

	return HANDLER_GO_ON;
}


int mod_uwsgi_plugin_init(plugin *p);
int mod_uwsgi_plugin_init(plugin *p) {
	p->version      = LIGHTTPD_VERSION_ID;
	p->name         = buffer_init_string("uwsgi");

	p->init         = mod_uwsgi_init;
	p->cleanup      = mod_uwsgi_free;
	p->set_defaults = mod_uwsgi_set_defaults;
	p->connection_reset        = mod_uwsgi_connection_close_callback; /* end of req-resp cycle */
	p->handle_connection_close = mod_uwsgi_connection_close_callback; /* end of client connection */
	p->handle_uri_clean        = mod_uwsgi_check_extension;
	p->handle_subrequest       = mod_uwsgi_handle_subrequest;
	p->handle_trigger          = mod_uwsgi_trigger;

	p->data         = NULL;

	return 0;
}
