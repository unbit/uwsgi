/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

/* Cherokee
 *
 * Authors:
 *      Alvaro Lopez Ortega <alvaro@alobbs.com>
 *
 * Copyright (C) 2001-2009 Alvaro Lopez Ortega
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */ 

#include "common-internal.h"
#include "handler_uwsgi.h"

#include "connection.h"
#include "source_interpreter.h"
#include "thread.h"
#include "util.h"
#include "connection-protected.h"
#include "bogotime.h"

#define ENTRIES "handler,cgi"

/* Plug-in initialization
 */
CGI_LIB_INIT (uwsgi, http_all_methods);

/* Methods implementation
 */
static ret_t 
props_free (cherokee_handler_uwsgi_props_t *props)
{
	if (props->balancer)
		cherokee_balancer_free (props->balancer);

	return cherokee_handler_cgi_base_props_free (PROP_CGI_BASE(props));
}

ret_t 
cherokee_handler_uwsgi_configure (cherokee_config_node_t *conf, cherokee_server_t *srv, cherokee_module_props_t **_props)
{
	ret_t                          ret;
	cherokee_list_t               *i;
	cherokee_handler_uwsgi_props_t *props;
	
	/* Instance a new property object
	 */
	if (*_props == NULL) {
		CHEROKEE_NEW_STRUCT (n, handler_uwsgi_props);

		cherokee_handler_cgi_base_props_init_base (PROP_CGI_BASE(n), 
							   MODULE_PROPS_FREE(props_free));

		n->balancer = NULL;

		*_props = MODULE_PROPS(n);
	}

	props = PROP_UWSGI(*_props);	

	/* Parse the configuration tree
	 */
	cherokee_config_node_foreach (i, conf) {
		cherokee_config_node_t *subconf = CONFIG_NODE(i);

		if (equal_buf_str (&subconf->key, "balancer")) {
			ret = cherokee_balancer_instance (&subconf->val, subconf, srv, &props->balancer); 
			if (ret != ret_ok) return ret;
		}
	}

	/* Init base class
	 */
	ret = cherokee_handler_cgi_base_configure (conf, srv, _props);
	if (ret != ret_ok) return ret;

	/* Final checks
	 */
	if (props->balancer == NULL) {
		LOG_CRITICAL_S ("ERROR: UWSGI handler needs a balancer\n");
		return ret_error;
	}

	return ret_ok;
}


static void 
add_env_pair (cherokee_handler_cgi_base_t *cgi_base, 
	      const char *key, int key_len, 
	      const char *val, int val_len)
{
	cherokee_handler_uwsgi_t *uwsgi = HDL_UWSGI(cgi_base);
	unsigned short u_key_len = (unsigned short) key_len ;
	unsigned short u_val_len = (unsigned short) val_len ;


	/* 2 bytes for every string (16 bit le) */
	cherokee_buffer_ensure_size (&uwsgi->header, uwsgi->header.len + key_len + val_len + 4);

	/* TODO: force to le if cherokee is big-endian */

	cherokee_buffer_add (&uwsgi->header, (const char *) &u_key_len, 2);
	cherokee_buffer_add (&uwsgi->header, key, key_len);
	cherokee_buffer_add (&uwsgi->header, (const char *) &u_val_len, 2);
	cherokee_buffer_add (&uwsgi->header, val, val_len);
}


static ret_t
read_from_uwsgi (cherokee_handler_cgi_base_t *cgi_base, cherokee_buffer_t *buffer)
{
	ret_t                    ret;
	size_t                   read = 0;
	cherokee_handler_uwsgi_t *uwsgi = HDL_UWSGI(cgi_base);
	
	ret = cherokee_socket_bufread (&uwsgi->socket, buffer, 4096, &read);

	switch (ret) {
	case ret_eagain:
		cherokee_thread_deactive_to_polling (HANDLER_THREAD(cgi_base), HANDLER_CONN(cgi_base), 
						     uwsgi->socket.socket, 0, false);
		return ret_eagain;

	case ret_ok:
		TRACE (ENTRIES, "%d bytes read\n", read);
		return ret_ok;

	case ret_eof:
	case ret_error:
		cgi_base->got_eof = true;
		return ret;

	default:
		RET_UNKNOWN(ret);
	}

	SHOULDNT_HAPPEN;
	return ret_error;	
}


ret_t 
cherokee_handler_uwsgi_new (cherokee_handler_t **hdl, void *cnt, cherokee_module_props_t *props)
{
	CHEROKEE_NEW_STRUCT (n, handler_uwsgi);
	
	/* Init the base class
	 */
	cherokee_handler_cgi_base_init (
			HDL_CGI_BASE(n), cnt,
			PLUGIN_INFO_HANDLER_PTR(uwsgi), 
			HANDLER_PROPS(props),
			add_env_pair, read_from_uwsgi);

	/* Virtual methods
	 */
	MODULE(n)->init         = (handler_func_init_t) cherokee_handler_uwsgi_init;
	MODULE(n)->free         = (module_func_free_t) cherokee_handler_uwsgi_free;

	/* Virtual methods: implemented by handler_cgi_base
	 */
	HANDLER(n)->step        = (handler_func_step_t) cherokee_handler_cgi_base_step;
	HANDLER(n)->add_headers = (handler_func_add_headers_t) cherokee_handler_cgi_base_add_headers;

	/* Properties
	 */
	n->post_len = 0;
	n->src_ref  = NULL;

	cherokee_buffer_init (&n->header);
	cherokee_socket_init (&n->socket);

	/* Return the object
	 */
	*hdl = HANDLER(n);
	return ret_ok;	   
}


ret_t 
cherokee_handler_uwsgi_free (cherokee_handler_uwsgi_t *hdl)
{
	/* Free the rest of the handler CGI memory
	 */
	cherokee_handler_cgi_base_free (HDL_CGI_BASE(hdl));

	/* UWSGI stuff
	 */
	cherokee_socket_close (&hdl->socket);
	cherokee_socket_mrproper (&hdl->socket);

	cherokee_buffer_mrproper (&hdl->header);

	return ret_ok;
}


static ret_t
uwsgi_fix_packet (cherokee_buffer_t *buf)
{

	uwsgi_header uh;

	uh.arg1 = 0 ;
	uh.arg2 = 0 ;
	uh.env_size = (unsigned short) buf->len ;

	/* TODO: check endianess */

	cherokee_buffer_ensure_size (buf, buf->len + 4);
	cherokee_buffer_prepend (buf, (const char * )&uh, 4);

	return ret_ok;
}


static ret_t
build_header (cherokee_handler_uwsgi_t *hdl)
{

	cuint_t len;
        char    tmp[64];

        len = snprintf (tmp, sizeof(tmp), FMT_OFFSET, (CST_OFFSET)hdl->post_len);

        add_env_pair(HDL_CGI_BASE(hdl), "CONTENT_LENGTH", 14, tmp, len);

	cherokee_handler_cgi_base_build_envp (HDL_CGI_BASE(hdl), HANDLER_CONN(hdl));       	

	return uwsgi_fix_packet (&hdl->header);
}



static ret_t 
connect_to_server (cherokee_handler_uwsgi_t *hdl)
{
	ret_t                          ret;
	cherokee_connection_t         *conn  = HANDLER_CONN(hdl);
	cherokee_handler_uwsgi_props_t *props = HANDLER_UWSGI_PROPS(hdl);

	/* Get a reference to the target host
	 */
	if (hdl->src_ref == NULL) {
		ret = cherokee_balancer_dispatch (props->balancer, conn, &hdl->src_ref);
		if (ret != ret_ok)
			return ret;
	}

	/* Try to connect
	 */
	if (hdl->src_ref->type == source_host) {
		ret = cherokee_source_connect_polling (hdl->src_ref, &hdl->socket, conn);
		if ((ret == ret_deny) || (ret == ret_error))
		{
			cherokee_balancer_report_fail (props->balancer, conn, hdl->src_ref);
		}
	} else {
		ret = cherokee_source_interpreter_connect_polling (SOURCE_INT(hdl->src_ref),
								   &hdl->socket, conn);
	}

	return ret;
}


static ret_t
send_header (cherokee_handler_uwsgi_t *hdl)
{
	ret_t                  ret;
	size_t                 written = 0;
	cherokee_connection_t *conn    = HANDLER_CONN(hdl);
	
	ret = cherokee_socket_bufwrite (&hdl->socket, &hdl->header, &written);
	if (ret != ret_ok) {
		conn->error_code = http_bad_gateway;
		return ret;
	}

#if 0	
	cherokee_buffer_print_debug (&hdl->header, -1);
#endif
	cherokee_buffer_move_to_begin (&hdl->header, written);

	TRACE (ENTRIES, "sent remaining=%d\n", hdl->header.len);

	if (! cherokee_buffer_is_empty (&hdl->header))
		return ret_eagain;
	
	return ret_ok;
}


static ret_t
send_post (cherokee_handler_uwsgi_t *hdl)
{
	ret_t                  ret;
	int                    e_fd = -1;
	int                    mode =  0;
	cherokee_connection_t *conn = HANDLER_CONN(hdl);
	
	ret = cherokee_post_walk_to_fd (&conn->post, hdl->socket.socket, &e_fd, &mode);
	
	switch (ret) {
	case ret_ok:
		break;
	case ret_eagain:
		if (e_fd != -1)
			cherokee_thread_deactive_to_polling (HANDLER_THREAD(hdl), conn, e_fd, mode, false);
		return ret_eagain;
	default:
		conn->error_code = http_bad_gateway;
		return ret;
	}

	return ret_ok;
}


ret_t 
cherokee_handler_uwsgi_init (cherokee_handler_uwsgi_t *hdl)
{
	ret_t                  ret;
	cherokee_connection_t *conn = HANDLER_CONN(hdl);

	switch (HDL_CGI_BASE(hdl)->init_phase) {
	case hcgi_phase_build_headers:
		TRACE (ENTRIES, "Init: %s\n", "begins");

		/* Extracts PATH_INFO and filename from request uri 
		 */
		ret = cherokee_handler_cgi_base_extract_path (HDL_CGI_BASE(hdl), false);
		if (unlikely (ret < ret_ok)) {
			conn->error_code = http_internal_error;
			return ret_error;
		}
		
		/* Prepare Post
		 */
		if (! cherokee_post_is_empty (&conn->post)) {
			cherokee_post_walk_reset (&conn->post);
			cherokee_post_get_len (&conn->post, &hdl->post_len);
		}

		/* Build the headers
		 */
		ret = build_header (hdl);
		if (unlikely (ret != ret_ok)) {
			conn->error_code = http_internal_error;
			return ret_error;
		}

		HDL_CGI_BASE(hdl)->init_phase = hcgi_phase_connect;

	case hcgi_phase_connect:
		TRACE (ENTRIES, "Init: %s\n", "connect");

		/* Connect	
		 */
		ret = connect_to_server (hdl);
		switch (ret) {
		case ret_ok:
			break;
		case ret_eagain:
			return ret_eagain;
		case ret_deny:
			conn->error_code = http_gateway_timeout;
			return ret_error;
		default:
			conn->error_code = http_service_unavailable;
			return ret_error;
		}
		
		HDL_CGI_BASE(hdl)->init_phase = hcgi_phase_send_headers;

	case hcgi_phase_send_headers:
		TRACE (ENTRIES, "Init: %s\n", "send_headers");

		/* Send the header
		 */
		ret = send_header (hdl);
		if (ret != ret_ok) 
			return ret;

		HDL_CGI_BASE(hdl)->init_phase = hcgi_phase_send_post;

	case hcgi_phase_send_post:
		/* Send the Post
		 */
		if (hdl->post_len > 0) {
			return send_post (hdl);
		}
		break;
	}

	return ret_ok;
}
