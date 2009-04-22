// apxs2 -i -c mod_uwsgi.c

#include "ap_config.h"
#include "apr_version.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"
#include "util_script.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#define UWSGI_SOCK "/tmp/uwsgi.sock"
#define MAX_VARS 64

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


static int uwsgi_handler(request_rec *r) {
	struct sockaddr_un s_addr ;
        int uwsgi_socket ;

	struct iovec uwsgi_vars[(MAX_VARS*4)+1] ;
	int vecptr = 1 ;
	char pkt_header[4];
	unsigned short pkt_size = 0;
	char buf[4096] ;
	int cnt;

	apr_bucket_brigade *bb;
	
	memset(&s_addr, 0, sizeof(struct sockaddr_un)) ;

        s_addr.sun_family = AF_UNIX;
        strcpy(s_addr.sun_path, UWSGI_SOCK);

        uwsgi_socket = socket(AF_UNIX, SOCK_STREAM, 0);


	connect(uwsgi_socket, (struct sockaddr *) &s_addr, strlen(UWSGI_SOCK) + ( (void *)&s_addr.sun_path - (void *)&s_addr) ) ;

		
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
		//ap_log_rerror(APLOG_MARK, APLOG_ERR, 404, r, "uwsgi: %s", r->path_info);
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

	writev( uwsgi_socket, uwsgi_vars, vecptr );

	r->assbackwards = 1 ;

	bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	
	while(cnt = recv(uwsgi_socket, buf, 4096, 0)) {
		apr_brigade_write(bb, NULL, NULL, buf, cnt);
	}

	close(uwsgi_socket);
	
	return ap_pass_brigade(r->output_filters, bb);;
}

static const command_rec uwsgi_cmds[] = {
    {NULL}
};

static void register_hooks(apr_pool_t *p) {
    ap_hook_handler(uwsgi_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA uwsgi_module = {

    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    uwsgi_cmds,
    register_hooks
};
