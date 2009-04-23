/* 
        
    *** uWSGI/mod_uwsgi ***

    Copyright 2009 Unbit S.a.s.
        
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

To compile:
	apxs2 -i -c mod_uwsgi.c

Configure:

LoadModule uwsgi_module <path_of_apache_modules>/mod_uwsgi.so
<Location XXX>
	SetHandler uwsgi-handler
</Location>

*/

#include "apr_strings.h"
#include "httpd.h"
#include "http_log.h"
#include "http_config.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <time.h>

#define MAX_VARS 64
#define DEFAULT_SOCK "/tmp/uwsgi.sock"

typedef struct {
	struct sockaddr_un s_addr ;
	int addr_size;
	struct timeval socket_timeout;
} uwsgi_cfg;

module AP_MODULE_DECLARE_DATA uwsgi_module;

static int uwsgi_add_var(struct iovec *vec, int i, char *key, char *value, unsigned short *pkt_size) {

	vec[i].iov_base = &vec[i+1].iov_len ;
	vec[i].iov_len = 2 ;
	vec[i+1].iov_base = key ;
	vec[i+1].iov_len = strlen(key) ;
	vec[i+2].iov_base = &vec[i+3].iov_len ;
	vec[i+2].iov_len = 2 ;
	vec[i+3].iov_base = value ;
	vec[i+3].iov_len = strlen(value) ;

	*pkt_size+= vec[i+1].iov_len + vec[i+3].iov_len + 4 ;

	return i+4;
}

static void *uwsgi_server_config(apr_pool_t *p, server_rec *s) {

	uwsgi_cfg *c = (uwsgi_cfg *) apr_pcalloc(p, sizeof(uwsgi_cfg));
	strcpy(c->s_addr.sun_path, DEFAULT_SOCK);
        c->s_addr.sun_family = AF_UNIX;
	c->addr_size = strlen(DEFAULT_SOCK) + ( (void *)&c->s_addr.sun_path - (void *)&c->s_addr ) ;
	c->socket_timeout.tv_sec = 0 ;
	c->socket_timeout.tv_usec = 0 ;

	return c;
}

static void *uwsgi_dir_config(apr_pool_t *p, char *dir) {

	uwsgi_cfg *c = (uwsgi_cfg *) apr_pcalloc(p, sizeof(uwsgi_cfg));
	strcpy(c->s_addr.sun_path, DEFAULT_SOCK);
        c->s_addr.sun_family = AF_UNIX;
        c->addr_size = strlen(DEFAULT_SOCK) + ( (void *)&c->s_addr.sun_path - (void *)&c->s_addr ) ;
	c->socket_timeout.tv_sec = 0 ;
	c->socket_timeout.tv_usec = 0 ;

	return c;
}

static int uwsgi_handler(request_rec *r) {
        int uwsgi_socket ;

	uwsgi_cfg *c = ap_get_module_config(r->per_dir_config, &uwsgi_module);

	struct iovec uwsgi_vars[(MAX_VARS*4)+1] ;
	int vecptr = 1 ;
	char pkt_header[4];
	unsigned short pkt_size = 0;
	char buf[4096] ;
	int cnt;

	apr_bucket_brigade *bb;

	if (strcmp(r->handler, "uwsgi-handler"))
        	return DECLINED;

	
	if (c == NULL) {
		c = ap_get_module_config(r->server->module_config, &uwsgi_module);
	}
	
        uwsgi_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	
	if (uwsgi_socket < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: socket() %s", strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (c->socket_timeout.tv_sec > 0) {
		setsockopt(uwsgi_socket, SOL_SOCKET, SO_SNDTIMEO, &c->socket_timeout, sizeof(struct timeval));
		setsockopt(uwsgi_socket, SOL_SOCKET, SO_RCVTIMEO, &c->socket_timeout, sizeof(struct timeval));
	}

	if (connect(uwsgi_socket, (struct sockaddr *) &c->s_addr, c->addr_size ) < 0) {
		if (c->s_addr.sun_path[0] == 0)
			c->s_addr.sun_path[0] = '@';
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: connect(\"%s\") %s", c->s_addr.sun_path, strerror(errno));
		if (c->s_addr.sun_path[0] == '@')
			c->s_addr.sun_path[0] = 0;
		close(uwsgi_socket);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

		
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "REQUEST_METHOD", (char *) r->method, &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "QUERY_STRING", r->args ? r->args : "", &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SERVER_NAME", (char *) ap_get_server_name(r), &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SERVER_PORT", apr_psprintf(r->pool, "%u",ap_get_server_port(r)), &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SERVER_PROTOCOL", r->protocol, &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "REQUEST_URI", r->uri, &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "REMOTE_ADDR", r->connection->remote_ip, &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "REMOTE_USER", r->user ? r->args : "", &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "DOCUMENT_ROOT", (char *) ap_document_root(r), &pkt_size) ;
	if (r->path_info) {
		vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SCRIPT_NAME", apr_pstrndup(r->pool, r->uri, (strlen(r->uri) - strlen(r->path_info) )) , &pkt_size) ;
		vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "PATH_INFO", r->path_info, &pkt_size) ;
	}
	else {
		vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "PATH_INFO", "", &pkt_size) ;
	}

	uwsgi_vars[0].iov_base = pkt_header;
	uwsgi_vars[0].iov_len = 4;

	pkt_header[0] = 0 ;
	memcpy(pkt_header+1, &pkt_size, 2);
	pkt_header[3] = 0 ;

	cnt = writev( uwsgi_socket, uwsgi_vars, vecptr );
	if (cnt < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: writev() %s", strerror(errno));
		close(uwsgi_socket);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	else if (cnt != pkt_size+4) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: writev() returned wrong size");
		close(uwsgi_socket);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	
	if (ap_should_client_block(r)) {
		while ((cnt = ap_get_client_block(r, buf, 4096)) > 0) {
			send( uwsgi_socket, buf, cnt, 0);
		}
	}

	r->assbackwards = 1 ;

	bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

	while( (cnt = recv(uwsgi_socket, buf, 4096, 0)) > 0) {
		apr_brigade_write(bb, NULL, NULL, buf, cnt);
	}

	if (cnt < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: recv() %s", strerror(errno));
	}

	close(uwsgi_socket);
	
	return ap_pass_brigade(r->output_filters, bb);;
}

static const char * cmd_uwsgi_socket(cmd_parms *cmd, void *cfg, const char *path, const char *timeout) {

	uwsgi_cfg *c ;

	if (cfg) {
		c = cfg ;
	}
	else {
		c = ap_get_module_config(cmd->server->module_config, &uwsgi_module);
	}

	if (strlen(path) < 104) {
		strcpy(c->s_addr.sun_path, path);
		c->addr_size = strlen(path) + ( (void *)&c->s_addr.sun_path - (void *)&c->s_addr ) ;
		// abstract namespace ??
		if (path[0] == '@') {
			c->s_addr.sun_path[0] = 0 ;
		}
	}

	if (timeout) {
		c->socket_timeout.tv_sec = atoi(timeout);
	}

	return NULL ;
}

static const command_rec uwsgi_cmds[] = {
	AP_INIT_TAKE12("uWSGIsocket", cmd_uwsgi_socket, NULL, RSRC_CONF|ACCESS_CONF, "Absolute path and optional timeout in seconds of uwsgi server socket"),	
	{NULL}
};

static void register_hooks(apr_pool_t *p) {
    ap_hook_handler(uwsgi_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA uwsgi_module = {

    STANDARD20_MODULE_STUFF,
    uwsgi_dir_config,
    NULL,
    uwsgi_server_config,
    NULL,
    uwsgi_cmds,
    register_hooks
};
