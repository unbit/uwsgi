/*

 *** uWSGI/mod_Ruwsgi ***

 Copyright 2009-2010 Roger Florkowski <rflorkowski@mypublisher.com>
 Copyright 2009-2010 Unbit S.a.s. <info@unbit.it>

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


*/

#define MOD_UWSGI_VERSION "1.0"

#include "ap_config.h"
#include "apr_version.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_core.h"
#include "http_request.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "util_script.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <time.h>
#include <poll.h>

#define DEFAULT_TIMEOUT  60 /* default socket timeout */
#define DEFAULT_CGIMODE  0  /* not enabled */

#define UNSET 0
#define ENABLED 1
#define DISABLED 2

#if APR_MAJOR_VERSION == 0
#define apr_socket_send apr_send
#define GET_PORT(port, addr) apr_sockaddr_port_get(&(port), addr)
#define CREATE_SOCKET(sock, family, pool) \
	apr_socket_create(sock, family, SOCK_STREAM, pool)
#else
#define GET_PORT(port, addr) ((port) = (addr)->port)
#define CREATE_SOCKET(sock, family, pool) \
	apr_socket_create(sock, family, SOCK_STREAM, APR_PROTO_TCP, pool)
#endif

typedef struct {
	char *path;
	char *addr;
	apr_port_t port;
} mount_entry;

/*
 * Configuration record.  Used per-directory configuration data.
 */
typedef struct {
	mount_entry mount;
	int enabled; /* mod_uwsgi is enabled from this directory */
	int timeout;
	int cgi_mode;
	uint8_t modifier1;
	uint8_t modifier2;
} uwsgi_cfg;

/* Server level configuration */
typedef struct {
	apr_array_header_t *mounts;
	int timeout;
	int cgi_mode;
} uwsgi_server_cfg;

module AP_MODULE_DECLARE_DATA uwsgi_module;

/*
 * Locate our directory configuration record for the current request.
 */
	static uwsgi_cfg *
our_dconfig(request_rec *r)
{
	return (uwsgi_cfg *) ap_get_module_config(r->per_dir_config, &uwsgi_module);
}

static uwsgi_server_cfg *our_sconfig(server_rec *s)
{
	return (uwsgi_server_cfg *) ap_get_module_config(s->module_config,
			&uwsgi_module);
}

	static int
mount_entry_matches(const char *url, const char *prefix,
		const char **path_info)
{
	int i;
	for (i=0; prefix[i] != '\0'; i++) {
		if (url[i] == '\0' || url[i] != prefix[i])
			return 0;
	}
	if (url[i] == '\0' || url[i] == '/') {
		*path_info = url + i;
		return 1;
	}
	return 0;
}

static int uwsgi_translate(request_rec *r)
{
	uwsgi_cfg *cfg = our_dconfig(r);

	if (cfg->enabled == DISABLED) {
		return DECLINED;
	}

	if (cfg->mount.addr != UNSET) {
		ap_assert(cfg->mount.port != UNSET);
		r->handler = "uwsgi-handler";
		r->filename = r->uri;
		return OK;
	}
	else {
		int i;
		uwsgi_server_cfg *scfg = our_sconfig(r->server);
		mount_entry *entries = (mount_entry *) scfg->mounts->elts;
		for (i = 0; i < scfg->mounts->nelts; ++i) {
			const char *path_info;
			mount_entry *mount = &entries[i];
			if (mount_entry_matches(r->uri, mount->path, &path_info)) {
				r->handler = "uwsgi-handler";
				r->path_info = apr_pstrdup(r->pool, path_info);
				r->filename = r->uri;
				ap_set_module_config(r->request_config, &uwsgi_module, mount);
				return OK;
			}
		}
	}
	return DECLINED;
}

static int uwsgi_map_location(request_rec *r)
{
	if (r->handler && strcmp(r->handler, "uwsgi-handler") == 0) {
		return OK; /* We don't want directory walk. */
	}
	return DECLINED;
}


#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
static void log_err(const char *file, int line, int ami, request_rec *r,
		apr_status_t status, const char *msg)
{
	ap_log_rerror(file, line, APLOG_MODULE_INDEX, APLOG_ERR, status, r, "uwsgi: %s", msg);
#else
static void log_err(const char *file, int line, request_rec *r,
                apr_status_t status, const char *msg)
{

	ap_log_rerror(file, line, APLOG_ERR, status, r, "uwsgi: %s", msg);
#endif
}

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
static void log_debug(const char *file, int line, int ami, request_rec *r, const
		char *msg)
{
	/*
	   ap_log_rerror(file, line, APLOG_DEBUG, APR_SUCCESS, r, msg);
	   ap_log_rerror(file, line, APLOG_WARNING, APR_SUCCESS, r, "uwsgi: %s", msg);
	   */
	ap_log_rerror(file, line, APLOG_MODULE_INDEX, APLOG_DEBUG, APR_SUCCESS, r, "uwsgi: %s", msg);
#else
static void log_debug(const char *file, int line, request_rec *r, const
		char *msg) {
	ap_log_rerror(file, line, APLOG_DEBUG, APR_SUCCESS, r, "uwsgi: %s", msg);
#endif
}

/* buffered socket implementation (buckets are overkill) */

#define BUFFER_SIZE 8000

struct sockbuff {
	apr_socket_t *sock;
	char buf[BUFFER_SIZE];
	int used;
};

static void binit(struct sockbuff *s, apr_socket_t *sock)
{
	s->sock = sock;
	s->used = 0;
}

static apr_status_t sendall(apr_socket_t *sock, char *buf, apr_size_t len)
{
	apr_status_t rv;
	apr_size_t n;
	while (len > 0) {
		n = len;
		if ((rv = apr_socket_send(sock, buf, &n))) return rv;
		buf += n;
		len -= n;
	}
	return APR_SUCCESS;
}

static apr_status_t bflush(struct sockbuff *s)
{
	apr_status_t rv;
	ap_assert(s->used >= 0 && s->used <= BUFFER_SIZE);
	if (s->used) {
		if ((rv = sendall(s->sock, s->buf, s->used))) return rv;
		s->used = 0;
	}
	return APR_SUCCESS;
}

static apr_status_t bwrite(struct sockbuff *s, char *buf, apr_size_t len)
{
	apr_status_t rv;
	if (len >= BUFFER_SIZE - s->used) {
		if ((rv = bflush(s))) return rv;
		while (len >= BUFFER_SIZE) {
			if ((rv = sendall(s->sock, buf, BUFFER_SIZE))) return rv;
			buf += BUFFER_SIZE;
			len -= BUFFER_SIZE;
		}
	}
	if (len > 0) {
		ap_assert(len < BUFFER_SIZE - s->used);
		memcpy(s->buf + s->used, buf, len);
		s->used += len;
	}
	return APR_SUCCESS;
}

static apr_status_t bputs(struct sockbuff *s, char *buf)
{
	return bwrite(s, buf, strlen(buf));
}

static apr_status_t bputc(struct sockbuff *s, char c)
{
	char buf[1];
	buf[0] = c;
	return bwrite(s, buf, 1);
}

static apr_status_t bputh(struct sockbuff *s, unsigned short h)
{
	return bwrite(s, (char *)&h, 2);
}

#define CONFIG_VALUE(value, fallback) ((value) != UNSET ? (value) : (fallback))

	static apr_status_t
open_socket(apr_socket_t **sock, request_rec *r)
{
	int timeout;
	int retries = 4;
	int sleeptime = 1;
	apr_status_t rv;
	apr_sockaddr_t *sockaddr;
	uwsgi_server_cfg *scfg = our_sconfig(r->server);
	uwsgi_cfg *cfg = our_dconfig(r);
	mount_entry *m = (mount_entry *) ap_get_module_config(r->request_config,
			&uwsgi_module);
	if (!m) {
		m = &cfg->mount;
	}

	timeout = CONFIG_VALUE(cfg->timeout, CONFIG_VALUE(scfg->timeout,
				DEFAULT_TIMEOUT));
	rv = apr_sockaddr_info_get(&sockaddr,
			CONFIG_VALUE(m->addr, "localhost"),
			APR_UNSPEC,
			CONFIG_VALUE(m->port, 5000),
			0,
			r->pool);
	if (rv) {
		log_err(APLOG_MARK, r, rv, "apr_sockaddr_info_get() error");
		return rv;
	}

restart:
	*sock = NULL;
	rv = CREATE_SOCKET(sock, sockaddr->family, r->pool);
	if (rv) {
		log_err(APLOG_MARK, r, rv, "apr_socket_create() error");
		return rv;
	}

	rv = apr_socket_timeout_set(*sock, apr_time_from_sec(timeout));
	if (rv) {
		log_err(APLOG_MARK, r, rv, "apr_socket_timeout_set() error");
		return rv;
	}

	rv = apr_socket_connect(*sock, sockaddr);
	if (rv) {
		apr_socket_close(*sock);
		if ((APR_STATUS_IS_ECONNREFUSED(rv) |
					APR_STATUS_IS_EINPROGRESS(rv)) && retries > 0) {
			/* server may be temporarily down, retry */
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, rv, r,
					"uwsgi: connection failed, retrying");
			apr_sleep(apr_time_from_sec(sleeptime));
			--retries;
			sleeptime *= 2;
			goto restart;
		}
		log_err(APLOG_MARK, r, rv, "uwsgi: can't connect to server");
		return rv;
	}

#ifdef APR_TCP_NODELAY
	/* disable Nagle, we don't send small packets */
	apr_socket_opt_set(*sock, APR_TCP_NODELAY, 1);
#endif

	return APR_SUCCESS;
}

/* This code is a duplicate of what's in util_script.c.  We can't use
 * r->unparsed_uri because it gets changed if there was a redirect. */
static char *original_uri(request_rec *r)
{
	char *first, *last;

	if (r->the_request == NULL) {
		return (char *) apr_pcalloc(r->pool, 1);
	}

	first = r->the_request;     /* use the request-line */

	while (*first && !apr_isspace(*first)) {
		++first;                /* skip over the method */
	}
	while (apr_isspace(*first)) {
		++first;                /*   and the space(s)   */
	}

	last = first;
	while (*last && !apr_isspace(*last)) {
		++last;                 /* end at next whitespace */
	}

	return apr_pstrmemdup(r->pool, first, last - first);
}

static char *lookup_name(apr_table_t *t, const char *name)
{
	const apr_array_header_t *hdrs_arr = apr_table_elts(t);
	apr_table_entry_t *hdrs = (apr_table_entry_t *) hdrs_arr->elts;
	int i;

	for (i = 0; i < hdrs_arr->nelts; ++i) {
		if (hdrs[i].key == NULL)
			continue;

		if (strcasecmp(hdrs[i].key, name) == 0)
			return hdrs[i].val;
	}
	return NULL;
}

static char *lookup_header(request_rec *r, const char *name)
{
	return lookup_name(r->headers_in, name);
}

static void add_header(apr_table_t *t, const char *name, const char *value)
{
	if (name != NULL && value != NULL)
		apr_table_addn(t, name, value);
}

static int find_path_info(const char *uri, const char *path_info)
{
	int n;
	n = strlen(uri) - strlen(path_info);
	ap_assert(n >= 0);
	return n;
}

static char *http2env(apr_pool_t *p, const char *name)
{
	char *env_name = apr_pstrcat(p, "HTTP_", name, NULL);
	char *cp;

	for (cp = env_name + 5; *cp != 0; cp++) {
		if (*cp == '-') {
			*cp = '_';
		}
		else {
			*cp = apr_toupper(*cp);
		}
	}

	return env_name;
}

	static apr_status_t
send_headers(request_rec *r, struct sockbuff *s)
{
	int i;
	const apr_array_header_t *hdrs_arr, *env_arr;
	apr_table_entry_t *hdrs, *env;
	char *buf;
	unsigned short int n = 0;
	apr_table_t *t;
	apr_status_t rv = 0;
	apr_port_t  port = 0;
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
	GET_PORT(port, r->useragent_addr);
#else
	GET_PORT(port, r->connection->remote_addr);
#endif
	uwsgi_cfg *cfg = our_dconfig(r);

	log_debug(APLOG_MARK,r, "sending headers");
	t = apr_table_make(r->pool, 40);
	if (!t)
		return APR_ENOMEM;

	/* headers to send */

	/* CONTENT_LENGTH must come first and always be present */
	buf = lookup_header(r, "Content-Length");
	if (buf == NULL)
		buf = "0";
	add_header(t, "CONTENT_LENGTH",  buf);

	add_header(t, "REQUEST_METHOD", (char *) r->method);
	add_header(t, "QUERY_STRING", r->args ? r->args : "");
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
	add_header(t, "SERVER_SOFTWARE", ap_get_server_description());
#else
	add_header(t, "SERVER_SOFTWARE", ap_get_server_version());
#endif
	add_header(t, "SERVER_ADMIN", r->server->server_admin);
	add_header(t, "SERVER_NAME", (char *) ap_get_server_name(r));
	add_header(t, "SERVER_PORT", apr_psprintf(r->pool, "%u",ap_get_server_port(r)));
	add_header(t, "SERVER_ADDR", r->connection->local_ip);
	add_header(t, "SERVER_PROTOCOL", r->protocol);

	add_header(t, "REQUEST_URI", original_uri(r));
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
	add_header(t, "REMOTE_ADDR", r->useragent_ip);
#else
	add_header(t, "REMOTE_ADDR", r->connection->remote_ip);
#endif
	add_header(t, "REMOTE_PORT", apr_psprintf(r->pool, "%d", port));
	add_header(t, "REMOTE_USER", r->user);
	add_header(t, "DOCUMENT_ROOT", (char *) ap_document_root(r));

	if (r->path_info) {
		int path_info_start = find_path_info(r->uri, r->path_info);
		add_header(t, "SCRIPT_NAME", apr_pstrndup(r->pool, r->uri,
					path_info_start));
		add_header(t, "PATH_INFO", r->path_info);
	}
	else {
		/* skip PATH_INFO, don't know it */
		add_header(t, "SCRIPT_NAME", r->uri);
	}

	add_header(t, "CONTENT_TYPE", lookup_header(r, "Content-type"));

	/* HTTP headers */
	hdrs_arr = apr_table_elts(r->headers_in);
	hdrs = (apr_table_entry_t *) hdrs_arr->elts;
	for (i = 0; i < hdrs_arr->nelts; ++i) {
		if (hdrs[i].key) {
			add_header(t, http2env(r->pool, hdrs[i].key), hdrs[i].val);
		}
	}

	/* environment variables */
	env_arr = apr_table_elts(r->subprocess_env);
	env = (apr_table_entry_t*) env_arr->elts;
	for (i = 0; i < env_arr->nelts; ++i) {
		add_header(t, env[i].key, env[i].val);
	}

	hdrs_arr = apr_table_elts(t);
	hdrs = (apr_table_entry_t*) hdrs_arr->elts;

	/* calculate length of header data */
	for (i = 0; i < hdrs_arr->nelts; ++i) {
		n += strlen(hdrs[i].key);
		n += strlen(hdrs[i].val);
		n += 4;        /* XXX */
	}
	log_debug(APLOG_MARK,r, apr_psprintf(r->pool, "pktheader size is %u", n));
	log_debug(APLOG_MARK,r, apr_psprintf(r->pool, "num headers %u", hdrs_arr->nelts));

	/* write pkt header */
	rv = bputc(s, cfg->modifier1);   /* marker */
	if (rv) return rv;
	rv = bputh(s, n);   /* length of header data */
	if (rv) return rv;
	rv = bputc(s, cfg->modifier2);   /* marker */
	if (rv) return rv;

	/* write out headers */
	for (i = 0; i < hdrs_arr->nelts; ++i) {
		rv = bputh(s, strlen(hdrs[i].key));     /* length */
		if (rv) return rv;
		rv = bputs(s, hdrs[i].key);             /* key */
		if (rv) return rv;
		rv = bputh(s, strlen(hdrs[i].val));     /* length */
		if (rv) return rv;
		rv = bputs(s, hdrs[i].val);             /* data */
		if (rv) return rv;
	}

	return APR_SUCCESS;
}

static apr_status_t send_request_body(request_rec *r, struct sockbuff *s)
{
	if (ap_should_client_block(r)) {
		char buf[BUFFER_SIZE];
		apr_status_t rv;
		apr_off_t len;

		while ((len = ap_get_client_block(r, buf, sizeof buf)) > 0) {
			if ((rv = bwrite(s, buf, len))) return rv;
		}
		if (len == -1)
			return HTTP_INTERNAL_SERVER_ERROR; /* what to return? */
	}
	return APR_SUCCESS;
}

static int uwsgi_handler(request_rec *r)
{
	apr_status_t rv = 0;
	int cgi_mode, http_status = 0;
	struct sockbuff s;
	apr_socket_t *sock;
	apr_bucket_brigade *bb = NULL;
	apr_bucket *b          = NULL;
	const char *location;
	uwsgi_cfg *cfg = our_dconfig(r);
	uwsgi_server_cfg *scfg = our_sconfig(r->server);

	if (strcmp(r->handler, "uwsgi-handler"))
		return DECLINED;

	http_status = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
	if (http_status != OK)
		return http_status;

	log_debug(APLOG_MARK, r, "connecting to server");

	rv = open_socket(&sock, r);
	if (rv) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	binit(&s, sock);

	rv = send_headers(r, &s);
	if (rv) {
		log_err(APLOG_MARK, r, rv, "error sending request headers");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	rv = send_request_body(r, &s);
	if (rv) {
		log_err(APLOG_MARK, r, rv, "error sending request body");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	rv = bflush(&s);
	if (rv) {
		log_err(APLOG_MARK, r, rv, "error sending request");
		return HTTP_INTERNAL_SERVER_ERROR;
	}


	log_debug(APLOG_MARK, r, "reading response headers");
	bb = apr_brigade_create(r->connection->pool, r->connection->bucket_alloc);

	cgi_mode = CONFIG_VALUE(cfg->cgi_mode, CONFIG_VALUE(scfg->cgi_mode, DEFAULT_CGIMODE));
	if (!cgi_mode) {

		/* receive implemented with http-0.9 based protocol */
		apr_interval_time_t timeout;
		char buf[4096];
		apr_pollfd_t pollfd = {r->pool, APR_POLL_SOCKET, APR_POLLIN, 0, { NULL }, NULL };
		pollfd.desc.s = sock;
		timeout = CONFIG_VALUE(cfg->timeout, CONFIG_VALUE(scfg->timeout,
					DEFAULT_TIMEOUT)) * 1000 * 1000;
		r->assbackwards = 1;       /* XXX */

		for(;;) {
			apr_int32_t nsds;
			apr_size_t len;

			if ((rv = apr_poll(&pollfd, 1, &nsds, timeout)) == APR_TIMEUP) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: recv() timeout");
				break;
			}
			if (rv != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: poll() %s", strerror(errno));
				break;
			}

			len = 4096;
			rv = apr_socket_recv(sock, buf, &len);
			if (rv == APR_SUCCESS) {
				apr_brigade_write(bb, NULL, NULL, buf, len);
			}
			else if (rv == APR_EOF) {
				break;
			}
			else {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: recv() %s", strerror(errno));
			}

		}
		log_debug(APLOG_MARK,r, "recv finished");
		b = apr_bucket_flush_create(r->connection->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(bb, b);
		b = apr_bucket_eos_create(r->connection->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(bb, b);

	} else {

		/* receive implemented with http-1.x based protocol */
		b = apr_bucket_socket_create(sock, r->connection->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(bb, b);
		b = apr_bucket_eos_create(r->connection->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(bb, b);

		rv = ap_scan_script_header_err_brigade(r, bb, NULL);
		if (rv) {
			if (rv == HTTP_INTERNAL_SERVER_ERROR) {
				log_err(APLOG_MARK, r, rv, "error reading response headers");
			}
			else {
				/* Work around an Apache bug whereby the returned status is
				 * ignored and status_line is used instead.  This bug is
				 * present at least in 2.0.54.
				 */
				r->status_line = NULL;
			}
			apr_brigade_destroy(bb);
			return rv;
		}

		location = apr_table_get(r->headers_out, "Location");

		if (location && location[0] == '/' &&
				((r->status == HTTP_OK) || ap_is_HTTP_REDIRECT(r->status))) {

			apr_brigade_destroy(bb);

			/* Internal redirect -- fake-up a pseudo-request */
			r->status = HTTP_OK;

			/* This redirect needs to be a GET no matter what the original
			 * method was.
			 */
			r->method = apr_pstrdup(r->pool, "GET");
			r->method_number = M_GET;

			ap_internal_redirect_handler(location, r);
			return OK;
		}
	}

	rv = ap_pass_brigade(r->output_filters, bb);
	if (rv) {
		log_err(APLOG_MARK, r, rv, "ap_pass_brigade()");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}


static int uwsgi_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
		server_rec *base_server)
{
	ap_add_version_component(p, "mod_uwsgi/" MOD_UWSGI_VERSION);
	return OK;
}

	static void *
uwsgi_create_dir_config(apr_pool_t *p, char *dirspec)
{
	uwsgi_cfg *cfg = apr_pcalloc(p, sizeof(uwsgi_cfg));

	cfg->enabled = UNSET;
	cfg->mount.addr = UNSET;
	cfg->mount.port = UNSET;
	cfg->timeout = UNSET;
	cfg->cgi_mode = UNSET;
	cfg->modifier1 = UNSET;
	cfg->modifier2 = UNSET;

	return cfg;
}

#define MERGE(b, n, a) (n->a == UNSET ? b->a : n->a)

	static void *
uwsgi_merge_dir_config(apr_pool_t *p, void *basev, void *newv)
{
	uwsgi_cfg* cfg = apr_pcalloc(p, sizeof(uwsgi_cfg));
	uwsgi_cfg* base = basev;
	uwsgi_cfg* new = newv;

	cfg->enabled = MERGE(base, new, enabled);
	cfg->mount.addr = MERGE(base, new, mount.addr);
	cfg->mount.port = MERGE(base, new, mount.port);
	cfg->timeout = MERGE(base, new, timeout);
	cfg->cgi_mode = MERGE(base, new, cgi_mode);
	cfg->modifier1 = MERGE(base, new, modifier1);
	cfg->modifier2 = MERGE(base, new, modifier2);

	return cfg;
}

	static void *
uwsgi_create_server_config(apr_pool_t *p, server_rec *s)
{
	uwsgi_server_cfg *c =
		(uwsgi_server_cfg *) apr_pcalloc(p, sizeof(uwsgi_server_cfg));

	c->mounts = apr_array_make(p, 20, sizeof(mount_entry));
	c->timeout = UNSET;
	c->cgi_mode = UNSET;
	return c;
}

	static void *
uwsgi_merge_server_config(apr_pool_t *p, void *basev, void *overridesv)
{
	uwsgi_server_cfg *c = (uwsgi_server_cfg *)
		apr_pcalloc(p, sizeof(uwsgi_server_cfg));
	uwsgi_server_cfg *base = (uwsgi_server_cfg *) basev;
	uwsgi_server_cfg *overrides = (uwsgi_server_cfg *) overridesv;

	c->mounts = apr_array_append(p, overrides->mounts, base->mounts);
	c->timeout = MERGE(base, overrides, timeout);
	c->cgi_mode = MERGE(base, overrides, cgi_mode);
	return c;
}

	static const char *
cmd_uwsgi_mount(cmd_parms *cmd, void *dummy, const char *path, const char *addr)
{
	int n;
	apr_status_t rv;
	char *scope_id = NULL; /* A ip6 parameter - not used here. */
	uwsgi_server_cfg *scfg = our_sconfig(cmd->server);
	mount_entry *new = apr_array_push(scfg->mounts);
	n = strlen(path);
	while (n > 0 && path[n-1] == '/') {
		n--; /* strip trailing slashes */
	}
	new->path = apr_pstrndup(cmd->pool, path, n);
	rv = apr_parse_addr_port(&new->addr, &scope_id, &new->port, addr,
			cmd->pool);
	if (rv)
		return "error parsing address:port string";
	return NULL;
}

	static const char *
cmd_uwsgi_server(cmd_parms *cmd, void *pcfg, const char *addr_and_port)
{
	apr_status_t rv;
	uwsgi_cfg *cfg = pcfg;
	char *scope_id = NULL; /* A ip6 parameter - not used here. */

	if (cmd->path == NULL)
		return "not a server command";

	rv = apr_parse_addr_port(&cfg->mount.addr, &scope_id, &cfg->mount.port,
			addr_and_port, cmd->pool);
	if (rv)
		return "error parsing address:port string";

	return NULL;
}

	static const char *
cmd_uwsgi_handler(cmd_parms* cmd, void* pcfg, int flag)
{
	uwsgi_cfg *cfg = pcfg;

	if (cmd->path == NULL) /* server command */
		return "not a server command";

	if (flag)
		cfg->enabled = ENABLED;
	else
		cfg->enabled = DISABLED;

	return NULL;
}

	static const char *
cmd_uwsgi_timeout(cmd_parms *cmd, void* pcfg, const char *strtimeout)
{
	uwsgi_cfg *dcfg = pcfg;
	int timeout = atoi(strtimeout);

	if (cmd->path == NULL) {
		uwsgi_server_cfg *scfg = our_sconfig(cmd->server);
		scfg->timeout = timeout;
	}
	else {
		dcfg->timeout = timeout;
	}

	return NULL;
}

	static const char *
cmd_uwsgi_force_cgi_mode(cmd_parms *cmd, void *pcfg, const char *value)
{
	int cgi_mode;

	if (!strcmp("yes", value) || !strcmp("on", value) || !strcmp("enable", value) || !strcmp("1", value)) {
		cgi_mode = 1;
	}
	else {
		cgi_mode = 0;
	}

	if (cmd->path == NULL) {
		uwsgi_server_cfg *scfg = our_sconfig(cmd->server);
		scfg->cgi_mode = cgi_mode;
	}
	else {
		uwsgi_cfg *dcfg = pcfg;
		dcfg->cgi_mode = cgi_mode;
	}

	return NULL;
}

	static const char *
cmd_uwsgi_modifier1(cmd_parms *cmd, void *pcfg, const char *value)
{
	uwsgi_cfg *cfg = pcfg;
	int val;

	if (cmd->path == NULL) /* server command */
		return "not a server command";

	val = atoi(value);
	if (val < 0 || val > 255) {
		return "ignored uWSGImodifier1. Value must be between 0 and 255";
	}
	else {
		cfg->modifier1 = (uint8_t) val;
	}

	return NULL;
}

	static const char *
cmd_uwsgi_modifier2(cmd_parms *cmd, void *pcfg, const char *value)
{
	uwsgi_cfg *cfg = pcfg;
	int val;

	if (cmd->path == NULL) /* server command */
		return "not a server command";

	val = atoi(value);
	if (val < 0 || val > 255) {
		return "ignored uWSGImodifier2. Value must be between 0 and 255";
	}
	else {
		cfg->modifier2 = (uint8_t) val;
	}

	return NULL;
}

static const command_rec uwsgi_cmds[] = {
	AP_INIT_TAKE2("uWSGImount", cmd_uwsgi_mount, NULL, RSRC_CONF,
			"path prefix and address of UWSGI server"),
	AP_INIT_TAKE1("uWSGIserver", cmd_uwsgi_server, NULL, ACCESS_CONF,
			"Address and port of an UWSGI server (e.g. localhost:4000)"),
	AP_INIT_FLAG( "uWSGIhandler", cmd_uwsgi_handler, NULL, ACCESS_CONF,
			"On or Off to enable or disable the UWSGI handler"),
	AP_INIT_TAKE1("uWSGIserverTimeout", cmd_uwsgi_timeout, NULL, ACCESS_CONF|RSRC_CONF,
			"Timeout (in seconds) for communication with the UWSGI server."),
	AP_INIT_TAKE1("uWSGIforceCGImode", cmd_uwsgi_force_cgi_mode, NULL, ACCESS_CONF|RSRC_CONF,
			"Force uWSGI CGI mode for perfect integration with apache filter"),
	AP_INIT_TAKE1("uWSGImodifier1", cmd_uwsgi_modifier1, NULL, ACCESS_CONF,
			"Set uWSGI modifier1"),
	AP_INIT_TAKE1("uWSGImodifier2", cmd_uwsgi_modifier2, NULL, ACCESS_CONF,
			"Set uWSGI modifier2"),
	/*
	   AP_INIT_TAKE12("uWSGIsocket", cmd_uwsgi_socket, NULL, RSRC_CONF|ACCESS_CONF,
	   "Absolute path and optional timeout in seconds of uwsgi server socket"),
	   AP_INIT_TAKE1("uWSGIsocket2", cmd_uwsgi_socket2, NULL, RSRC_CONF|ACCESS_CONF,
	   "Absolute path of failover uwsgi server socket"),
	   AP_INIT_TAKE1("uWSGIforceScriptName", cmd_uwsgi_force_script_name, NULL, ACCESS_CONF,
	   "Fix for PATH_INFO/SCRIPT_NAME when the location has filesystem correspondence"),
	   */
	{NULL}
};

static void uwsgi_register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(uwsgi_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(uwsgi_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(uwsgi_translate, NULL, NULL, APR_HOOK_LAST);
	ap_hook_map_to_storage(uwsgi_map_location, NULL, NULL, APR_HOOK_FIRST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA uwsgi_module = {
	STANDARD20_MODULE_STUFF,
	uwsgi_create_dir_config,       /* create per-dir config structs */
	uwsgi_merge_dir_config,        /* merge per-dir config structs */
	uwsgi_create_server_config,    /* create per-server config structs */
	uwsgi_merge_server_config,     /* merge per-server config structs */
	uwsgi_cmds,                    /* table of config file commands */
	uwsgi_register_hooks,          /* register hooks */
};

