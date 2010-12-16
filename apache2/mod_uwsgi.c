/* 
        
*** uWSGI/mod_uwsgi ***

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


To compile:
(Linux)
	apxs2 -i -c mod_uwsgi.c
(OSX)
	sudo apxs -i -a -c mod_uwsgi.c
(OSX Universal binary)
	sudo apxs -i -a -c -Wc,"-arch ppc -arch i386 -arch x86_64" -Wl,"-arch ppc -arch i386 -arch x86_64" mod_uwsgi.c


Configure:

LoadModule uwsgi_module <path_of_apache_modules>/mod_uwsgi.so
<Location XXX>
	SetHandler uwsgi-handler
</Location>

*/

#include "apr_strings.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <time.h>
#include <poll.h>
#include <fcntl.h>


#define MAX_VARS 64
#define DEFAULT_SOCK "/tmp/uwsgi.sock"

typedef struct {
	union {
		struct sockaddr x_addr ;
		struct sockaddr_un u_addr ;
		struct sockaddr_in i_addr ;
	} s_addr;
	int addr_size;
	union {
		struct sockaddr x_addr ;
		struct sockaddr_un u_addr ;
		struct sockaddr_in i_addr ;
	} s_addr2;
	int addr_size2;
	int socket_timeout;
	uint8_t modifier1;
	uint8_t modifier2;
	char script_name[256];
	char scheme[9];
	int cgi_mode ;
} uwsgi_cfg;

module AP_MODULE_DECLARE_DATA uwsgi_module;

#if APR_IS_BIGENDIAN
static uint16_t uwsgi_swap16(uint16_t x) {
	return (uint16_t) ((x & 0xff) << 8 | (x & 0xff00) >> 8);
}
#endif

static int uwsgi_add_var(struct iovec *vec, int i, char *key, char *value, uint16_t *pkt_size) {


#if APR_IS_BIGENDIAN
	char *ptr;
	vec[i+2].iov_base = key ;
	vec[i+2].iov_len = strlen(key) ;
#else
	vec[i+1].iov_base = key ;
	vec[i+1].iov_len = strlen(key) ;
#endif

#if APR_IS_BIGENDIAN
	ptr = (char *) &vec[i+2].iov_len;
	vec[i].iov_base = ptr+sizeof(long)-1 ;
	vec[i].iov_len = 1 ;
	vec[i+1].iov_base = ptr+sizeof(long)-2 ;
	vec[i+1].iov_len = 1 ;
#else
	vec[i].iov_base = &vec[i+1].iov_len ;
	vec[i].iov_len = 2 ;
#endif


#if APR_IS_BIGENDIAN
        vec[i+5].iov_base = value ;
        vec[i+5].iov_len = strlen(value) ;
#else
        vec[i+3].iov_base = value ;
        vec[i+3].iov_len = strlen(value) ;
#endif

#if APR_IS_BIGENDIAN
	ptr = (char *) &vec[i+5].iov_len;
        vec[i+3].iov_base = ptr+sizeof(long)-1 ;
        vec[i+3].iov_len = 1 ;
        vec[i+4].iov_base = ptr+sizeof(long)-2 ;
        vec[i+4].iov_len = 1 ;
#else
        vec[i+2].iov_base = &vec[i+3].iov_len ;
        vec[i+2].iov_len = 2 ;
#endif


#if APR_IS_BIGENDIAN
	*pkt_size+= vec[i+2].iov_len + vec[i+5].iov_len + 4 ;
#else
	*pkt_size+= vec[i+1].iov_len + vec[i+3].iov_len + 4 ;
#endif

#if APR_IS_BIGENDIAN
	return i+6;
#else
	return i+4;
#endif
}

static void *uwsgi_server_config(apr_pool_t *p, server_rec *s) {

	uwsgi_cfg *c = (uwsgi_cfg *) apr_pcalloc(p, sizeof(uwsgi_cfg));
	strcpy(c->s_addr.u_addr.sun_path, DEFAULT_SOCK);
        c->s_addr.u_addr.sun_family = AF_UNIX;
	c->addr_size = strlen(DEFAULT_SOCK) + ( (void *)&c->s_addr.u_addr.sun_path - (void *)&c->s_addr ) ;
	c->socket_timeout = 0 ;
	c->modifier1 = 0 ;
	c->modifier2 = 0 ;
	c->cgi_mode = 0 ;

	return c;
}

static void *uwsgi_dir_config(apr_pool_t *p, char *dir) {

	uwsgi_cfg *c = (uwsgi_cfg *) apr_pcalloc(p, sizeof(uwsgi_cfg));
	strcpy(c->s_addr.u_addr.sun_path, DEFAULT_SOCK);
        c->s_addr.u_addr.sun_family = AF_UNIX;
        c->addr_size = strlen(DEFAULT_SOCK) + ( (void *)&c->s_addr.u_addr.sun_path - (void *)&c->s_addr ) ;
	c->socket_timeout = 0 ;
	c->modifier1 = 0 ;
	c->modifier2 = 0 ;
	c->cgi_mode = 0 ;

	return c;
}

static int timed_connect(struct pollfd *fdpoll , struct sockaddr *addr, int addr_size, int timeout, request_rec *r) {

	int arg, ret;
	int soopt ;
	socklen_t solen = sizeof(int) ;
	int cnt;
	/* set non-blocking socket */

	arg = fcntl(fdpoll->fd, F_GETFL, NULL) ;
	if (arg < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: unable to set non-blocking socket: %s", strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	arg |= O_NONBLOCK;
	if (fcntl(fdpoll->fd, F_SETFL, arg) < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: unable to set non-blocking socket: %s", strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ret = connect(fdpoll->fd, addr, addr_size) ;
	if (ret < 0) {
		/* check what happened */
	
		// in progress ?
		if (errno == EINPROGRESS) { 
			if (timeout < 1)
				timeout = 3;
			fdpoll->events = POLLOUT ;
			cnt = poll(fdpoll, 1, timeout*1000) ;	
			/* check for errors */
			if (cnt < 0 && errno != EINTR) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: unable to connect to uWSGI server: %s", strerror(errno));
				return HTTP_BAD_GATEWAY;
			}
			/* something hapened on the socket ... */
			else if (cnt > 0) {
				if (getsockopt(fdpoll->fd, SOL_SOCKET, SO_ERROR, (void*)(&soopt), &solen) < 0) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: unable to connect to uWSGI server: %s", strerror(errno));
					return HTTP_BAD_GATEWAY;
				}
				/* is something bad ? */
				if (soopt) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: unable to connect to uWSGI server: %s", strerror(errno));
					return HTTP_BAD_GATEWAY;
				}
			}
			/* timeout */
			else {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: unable to connect to uWSGI server: connect() timeout");
				return HTTP_GATEWAY_TIME_OUT;
			}
		}	
		else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: unable to connect to uWSGI server: %s", strerror(errno));
			return HTTP_BAD_GATEWAY;
		}
	}

	/* re-set blocking socket */
	arg &= (~O_NONBLOCK);
	if (fcntl(fdpoll->fd, F_SETFL, arg) < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: unable to re-set blocking socket: %s", strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return 0 ;
	
}

static int uwsgi_handler(request_rec *r) {

	struct pollfd uwsgi_poll;

	uwsgi_cfg *c = ap_get_module_config(r->per_dir_config, &uwsgi_module);

#if APR_IS_BIGENDIAN
	struct iovec uwsgi_vars[(MAX_VARS*6)+1] ;
#else
	struct iovec uwsgi_vars[(MAX_VARS*4)+1] ;
#endif
	int vecptr = 1 ;
	char pkt_header[4];
	uint16_t pkt_size = 0;
	char buf[4096] ;
	int i ;
	ssize_t cnt ;
	const apr_array_header_t *headers;
	apr_table_entry_t *h;
	char *penv, *cp;
	int ret;
	apr_status_t hret ;
	apr_bucket *b  = NULL;

	char uwsgi_http_status[13] ;
	int uwsgi_http_status_read = 0;
	
	apr_bucket_brigade *bb;

	if (strcmp(r->handler, "uwsgi-handler"))
        	return DECLINED;

	cnt = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
	if (cnt != OK) {
		return cnt;
	}

	
	if (c == NULL) {
		c = ap_get_module_config(r->server->module_config, &uwsgi_module);
	}
	

	uwsgi_poll.fd = socket(c->s_addr.x_addr.sa_family, SOCK_STREAM, 0);
	if (uwsgi_poll.fd < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: unable to create socket: %s", strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ( (ret = timed_connect(&uwsgi_poll, (struct sockaddr *) &c->s_addr, c->addr_size, c->socket_timeout, r) ) != 0) {

		close(uwsgi_poll.fd);

		if (c->addr_size2 > 0) {

			uwsgi_poll.fd = socket(c->s_addr2.x_addr.sa_family, SOCK_STREAM, 0);
			if (uwsgi_poll.fd < 0) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: unable to create failover socket: %s", strerror(errno));
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: trying failover server.");

			if ( (ret = timed_connect(&uwsgi_poll, (struct sockaddr *) &c->s_addr2, c->addr_size2, c->socket_timeout, r)) != 0) {

				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: failover connect failed.");

				close(uwsgi_poll.fd);

				return ret ;
			}
		}
		else {
			return ret ;
		}
	}


		
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "REQUEST_METHOD", (char *) r->method, &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "QUERY_STRING", r->args ? r->args : "", &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SERVER_NAME", (char *) ap_get_server_name(r), &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SERVER_PORT", apr_psprintf(r->pool, "%u",ap_get_server_port(r)), &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SERVER_PROTOCOL", r->protocol, &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "REQUEST_URI", r->unparsed_uri, &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "REMOTE_ADDR", r->connection->remote_ip, &pkt_size) ;
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "REMOTE_USER", r->user ? r->user : "", &pkt_size) ;
	if (r->user) {
		vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "AUTH_TYPE", (char *) ap_auth_type(r), &pkt_size) ;
	}
	vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "DOCUMENT_ROOT", (char *) ap_document_root(r), &pkt_size) ;

	if (c->scheme[0] != 0) {
		vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "UWSGI_SCHEME", c->scheme, &pkt_size) ;
	}

	if (c->script_name[0] == '/') {
		if (c->script_name[1] == 0) {
			vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SCRIPT_NAME", "", &pkt_size) ;
			vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "PATH_INFO", r->uri, &pkt_size) ;
		}
		else {
			vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SCRIPT_NAME", c->script_name, &pkt_size) ;
			vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "PATH_INFO", r->uri+strlen(c->script_name), &pkt_size) ;
		}
	}
	else {
		if (r->path_info) {
			if (strlen(r->path_info) <= 0) {
				vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SCRIPT_NAME", "", &pkt_size) ;
				vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "PATH_INFO", r->uri, &pkt_size) ;
			}
			else {
				vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SCRIPT_NAME", apr_pstrndup(r->pool, r->uri, (strlen(r->uri) - strlen(r->path_info) )) , &pkt_size) ;
				vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "PATH_INFO", r->path_info, &pkt_size) ;
			}
		}
		else {
			vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "SCRIPT_NAME", "", &pkt_size) ;
			vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "PATH_INFO", r->uri, &pkt_size) ;
		}
	}


	headers = apr_table_elts(r->headers_in);
	h = (apr_table_entry_t *) headers->elts;

	// check for max vars (a bit ugly)
	cnt = headers->nelts ;
	if (cnt + 11 > MAX_VARS) {
		cnt = MAX_VARS -11;
	}

	for(i=0;i< cnt;i++) {
		if (h[i].key){
			if (!strcasecmp(h[i].key, "Content-Type")) {
				vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "CONTENT_TYPE", h[i].val, &pkt_size) ;
			}
			else if (!strcasecmp(h[i].key, "Content-Length")) {
				vecptr = uwsgi_add_var(uwsgi_vars, vecptr, "CONTENT_LENGTH", h[i].val, &pkt_size) ;
			}
			else {
				penv = apr_pstrcat(r->pool, "HTTP_", h[i].key, NULL);
				for(cp = penv+5; *cp !=0; cp++) {
					if (*cp == '-') {
						*cp = '_';
					}
					else {
						*cp = toupper(*cp);
					}
				}
				vecptr = uwsgi_add_var(uwsgi_vars, vecptr, penv, h[i].val, &pkt_size) ;
			}
		}
	}

	/* environment variables */
	headers = apr_table_elts(r->subprocess_env);
	h = (apr_table_entry_t*) headers->elts;
	for (i = 0; i < headers->nelts; ++i) {
		vecptr = uwsgi_add_var(uwsgi_vars, vecptr, h[i].key, h[i].val, &pkt_size) ;
	}	
	

	uwsgi_vars[0].iov_base = pkt_header;
	uwsgi_vars[0].iov_len = 4;

	pkt_header[0] = c->modifier1 ;
#if APR_IS_BIGENDIAN
	pkt_size = uwsgi_swap16(pkt_size);
	memcpy(pkt_header+1, &pkt_size, 2);
	pkt_size = uwsgi_swap16(pkt_size);
#else
	memcpy(pkt_header+1, &pkt_size, 2);
#endif
	pkt_header[3] = c->modifier2 ;

	cnt = writev( uwsgi_poll.fd, uwsgi_vars, vecptr );
	if (cnt < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: writev() %s", strerror(errno));
		close(uwsgi_poll.fd);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	else if (cnt != pkt_size+4) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: writev() returned wrong size");
		close(uwsgi_poll.fd);
		return HTTP_INTERNAL_SERVER_ERROR;
	}


	
	if (ap_should_client_block(r)) {
		while ((cnt = ap_get_client_block(r, buf, 4096)) > 0) {
			cnt = send( uwsgi_poll.fd, buf, cnt, 0);
			if (cnt < 0) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: read() client block failed !");
				close(uwsgi_poll.fd);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
	}


	if (!c->cgi_mode) {
		r->assbackwards = 1 ;
		uwsgi_http_status[12] = 0 ;
	}

	
	bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

	uwsgi_poll.events = POLLIN ;



	for(;;) {
		/* put -1 to disable timeout on zero */
		cnt = poll(&uwsgi_poll, 1, (c->socket_timeout*1000)-1) ;
		if (cnt == 0) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: recv() timeout");
			apr_brigade_destroy(bb);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		else if (cnt > 0) {
			if (uwsgi_poll.revents & POLLIN || uwsgi_poll.revents & POLLHUP) {
				cnt = recv(uwsgi_poll.fd, buf, 4096, 0) ;
				if (cnt < 0) {
					if (errno != ECONNRESET) {
						ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: recv() %s", strerror(errno));
						apr_brigade_destroy(bb);
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					else {
						break;
					}
				}
				else if (cnt > 0) {
					if (!c->cgi_mode && uwsgi_http_status_read < 12) {
	                        		if (uwsgi_http_status_read + cnt >= 12) {
                                        		memcpy(uwsgi_http_status+uwsgi_http_status_read, buf, 12-uwsgi_http_status_read);
                                                	r->status = atoi(uwsgi_http_status+8);
                					uwsgi_http_status_read+=cnt;
                                        	}
                                        	else {
	                                		memcpy(uwsgi_http_status+uwsgi_http_status_read, buf, cnt);
                                        		uwsgi_http_status_read+=cnt;
                                        	}
                                	}
					// check for client disconnect
					if (r->connection->aborted) { 
						close(uwsgi_poll.fd);
						apr_brigade_destroy(bb);
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					apr_brigade_write(bb, NULL, NULL, buf, cnt);
				}
				else {
					// EOF
					break;
				}
			}

			// error
			if (uwsgi_poll.revents & POLLERR || uwsgi_poll.revents & POLLNVAL) {
                                break;
                        }
		}
		else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "uwsgi: poll() %s", strerror(errno));
			close(uwsgi_poll.fd);
			apr_brigade_destroy(bb);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}


	close(uwsgi_poll.fd);


	b = apr_bucket_eos_create(r->connection->bucket_alloc);
    	APR_BRIGADE_INSERT_TAIL(bb, b);

	if (!c->cgi_mode) {
		if (uwsgi_http_status_read == 0) {
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}
	else {

		if (hret = ap_scan_script_header_err_brigade(r, bb, NULL)) {
			apr_brigade_destroy(bb);
			return hret;
		}
	}


	return ap_pass_brigade(r->output_filters, bb) ;
}

static const char * cmd_uwsgi_force_script_name(cmd_parms *cmd, void *cfg, const char *location) {
	uwsgi_cfg *c = cfg;

	if (strlen(location) <= 255 && location[0] == '/') {
		strcpy(c->script_name, location);
	}
	else {
		return "ignored uWSGIforceScriptName. Invalid location" ;
	}

	return NULL ;

}

static const char * cmd_uwsgi_force_wsgi_scheme(cmd_parms *cmd, void *cfg, const char *scheme) {
	uwsgi_cfg *c = cfg;

	if (strlen(scheme) < 9 & strlen(scheme) > 0) {
		strcpy(c->scheme, scheme);
	}
	else {
		return "ignored uWSGIforceWSGIscheme. Invalid size (max 8 chars)" ;
	}

	return NULL ;

}

static const char * cmd_uwsgi_modifier1(cmd_parms *cmd, void *cfg, const char *value) {

        uwsgi_cfg *c ;
	int val ;

        if (cfg) {
                c = cfg ;
        }
        else {
                c = ap_get_module_config(cmd->server->module_config, &uwsgi_module);
        }

	val = atoi(value);
	if (val < 0 || val > 255) {
		return "ignored uWSGImodifier1. Value must be between 0 and 255" ;
	}
	else {
		c->modifier1 = (uint8_t) val;
	}

	return NULL;
}

static const char * cmd_uwsgi_force_cgi_mode(cmd_parms *cmd, void *cfg, const char *value) {

	uwsgi_cfg *c ;

	if (cfg) {
                c = cfg ;
        }
        else {
                c = ap_get_module_config(cmd->server->module_config, &uwsgi_module);
        }

	if (!strcmp("yes", value) || !strcmp("on", value) || !strcmp("enable", value) || !strcmp("1", value)) {
		c->cgi_mode = 1 ;
	}

	return NULL ;

}

static const char * cmd_uwsgi_modifier2(cmd_parms *cmd, void *cfg, const char *value) {

        uwsgi_cfg *c ;
	int val ;

        if (cfg) {
                c = cfg ;
        }
        else {
                c = ap_get_module_config(cmd->server->module_config, &uwsgi_module);
        }

	val = atoi(value);
	if (val < 0 || val > 255) {
		return "ignored uWSGImodifier2. Value must be between 0 and 255" ;
	}
	else {
		c->modifier2 = (uint8_t) val;
	}

	return NULL;
}

static const char * cmd_uwsgi_socket2(cmd_parms *cmd, void *cfg, const char *path) {

        uwsgi_cfg *c ;
	char *tcp_port;

        if (cfg) {
                c = cfg ;
        }
        else {
                c = ap_get_module_config(cmd->server->module_config, &uwsgi_module);
        }

	if (tcp_port = strchr(path, ':')) {
                c->addr_size2 = sizeof(struct sockaddr_in);
                c->s_addr2.i_addr.sin_family = AF_INET;
                c->s_addr2.i_addr.sin_port = htons(atoi(tcp_port+1));
                tcp_port[0] = 0;
                c->s_addr2.i_addr.sin_addr.s_addr = inet_addr(path);
        }
        else if (strlen(path) < 104) {
                strcpy(c->s_addr2.u_addr.sun_path, path);
                c->addr_size2 = strlen(path) + ( (void *)&c->s_addr.u_addr.sun_path - (void *)&c->s_addr ) ;
                // abstract namespace ??
                if (path[0] == '@') {
                        c->s_addr2.u_addr.sun_path[0] = 0 ;
                }
                c->s_addr2.u_addr.sun_family = AF_UNIX;
        }

        return NULL ;
}


static const char * cmd_uwsgi_socket(cmd_parms *cmd, void *cfg, const char *path, const char *timeout) {

	uwsgi_cfg *c ;
	char *tcp_port;

	if (cfg) {
		c = cfg ;
	}
	else {
		c = ap_get_module_config(cmd->server->module_config, &uwsgi_module);
	}

	if (tcp_port = strchr(path, ':')) {
		c->addr_size = sizeof(struct sockaddr_in);
		c->s_addr.i_addr.sin_family = AF_INET;
		c->s_addr.i_addr.sin_port = htons(atoi(tcp_port+1));
		tcp_port[0] = 0;
		c->s_addr.i_addr.sin_addr.s_addr = inet_addr(path);
	}
	else if (strlen(path) < 104) {
		strcpy(c->s_addr.u_addr.sun_path, path);
		c->addr_size = strlen(path) + ( (void *)&c->s_addr.u_addr.sun_path - (void *)&c->s_addr ) ;
		// abstract namespace ??
		if (path[0] == '@') {
			c->s_addr.u_addr.sun_path[0] = 0 ;
		}
		c->s_addr.u_addr.sun_family = AF_UNIX;
	}

	if (timeout) {
		c->socket_timeout = atoi(timeout);
	}


	return NULL ;
}

static const command_rec uwsgi_cmds[] = {
	AP_INIT_TAKE12("uWSGIsocket", cmd_uwsgi_socket, NULL, RSRC_CONF|ACCESS_CONF, "Absolute path and optional timeout in seconds of uwsgi server socket"),	
	AP_INIT_TAKE1("uWSGIsocket2", cmd_uwsgi_socket2, NULL, RSRC_CONF|ACCESS_CONF, "Absolute path of failover uwsgi server socket"),	
	AP_INIT_TAKE1("uWSGImodifier1", cmd_uwsgi_modifier1, NULL, RSRC_CONF|ACCESS_CONF, "Set uWSGI modifier1"),	
	AP_INIT_TAKE1("uWSGImodifier2", cmd_uwsgi_modifier2, NULL, RSRC_CONF|ACCESS_CONF, "Set uWSGI modifier2"),	
	AP_INIT_TAKE1("uWSGIforceScriptName", cmd_uwsgi_force_script_name, NULL, ACCESS_CONF, "Fix for PATH_INFO/SCRIPT_NAME when the location has filesystem correspondence"),	
	AP_INIT_TAKE1("uWSGIforceCGImode", cmd_uwsgi_force_cgi_mode, NULL, ACCESS_CONF, "Force uWSGI CGI mode for perfect integration with apache filter"),	
	AP_INIT_TAKE1("uWSGIforceWSGIscheme", cmd_uwsgi_force_wsgi_scheme, NULL, ACCESS_CONF, "Force the WSGI scheme var (set by default to \"http\")"),	
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
