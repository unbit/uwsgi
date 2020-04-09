#include "psgi.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_plugin psgi_plugin;
extern struct uwsgi_perl uperl;

XS(XS_async_sleep) {

        dXSARGS;
        int timeout ;

        psgi_check_args(1);

        struct wsgi_request *wsgi_req = current_wsgi_req();

        timeout = SvIV(ST(0));

        if (timeout >= 0) {
		async_add_timeout(wsgi_req, timeout);
        }

	wsgi_req->async_force_again = 1;

	XSRETURN_UNDEF;
}



XS(XS_wait_fd_read) {

	dXSARGS;
        int fd, timeout = 0;

	psgi_check_args(1);

        struct wsgi_request *wsgi_req = current_wsgi_req();

	fd = SvIV(ST(0));
	if (items > 1) {
		timeout = SvIV(ST(1));
	} 

        if (async_add_fd_read(wsgi_req, fd, timeout)) {
		croak("unable to add fd %d to the event queue", fd);
	}

	wsgi_req->async_force_again = 1;

	XSRETURN_UNDEF;
}


XS(XS_wait_fd_write) {

        dXSARGS;
        int fd, timeout = 0;

        psgi_check_args(1);

        struct wsgi_request *wsgi_req = current_wsgi_req();

        fd = SvIV(ST(0));
        if (items > 1) {
                timeout = SvIV(ST(1));
        }

        if (async_add_fd_write(wsgi_req, fd, timeout)) {
		croak("unable to add fd %d to the event queue", fd);
        }

	wsgi_req->async_force_again = 1;

	XSRETURN_UNDEF;
}

XS(XS_signal) {
	dXSARGS;

	psgi_check_args(1);

	uwsgi_signal_send(uwsgi.signal_socket, SvIV(ST(0)));

	XSRETURN_UNDEF;
}

XS(XS_set_user_harakiri) {
        dXSARGS;

        psgi_check_args(1);

	set_user_harakiri( SvIV(ST(0)) );

        XSRETURN_UNDEF;
}

XS(XS_reload) {
    dXSARGS;

    psgi_check_args(0);

    if (kill(uwsgi.workers[0].pid, SIGHUP)) {
    	uwsgi_error("kill()");
        XSRETURN_NO;
    }
    XSRETURN_YES;
}

XS(XS_cache_set) {
	dXSARGS;

	char *key, *val;
	STRLEN keylen;
	STRLEN vallen;
	uint64_t expires = 0;
	char *cache = NULL;

	psgi_check_args(2);

	key = SvPV(ST(0), keylen);
	val = SvPV(ST(1), vallen);

	if (items > 2) {
		expires = SvIV(ST(2));
		if (items > 3) {
			cache = SvPV_nolen(ST(3));
		}
	}

	if (!uwsgi_cache_magic_set(key, (uint16_t) keylen, val, (uint64_t) vallen, expires, 0, cache)) {
		XSRETURN_YES;
	}
	XSRETURN_UNDEF;
}

XS(XS_cache_get) {
	dXSARGS;

	char *key;
	char *cache = NULL;
	STRLEN keylen;
	uint64_t vallen = 0;

	psgi_check_args(1);

	key = SvPV(ST(0), keylen);

	if (items > 1) {
		cache = SvPV_nolen(ST(1));
	}

	char *value = uwsgi_cache_magic_get(key, (uint16_t) keylen, &vallen, NULL, cache);
	if (value) {
		ST(0) = newSVpv(value, vallen);
		free(value);
		sv_2mortal(ST(0));
		XSRETURN(1);
	}

	XSRETURN_UNDEF;
}

XS(XS_cache_exists) {
        dXSARGS;

        char *key;
        char *cache = NULL;
        STRLEN keylen;

        psgi_check_args(1);

        key = SvPV(ST(0), keylen);

        if (items > 1) {
                cache = SvPV_nolen(ST(1));
        }

        if (uwsgi_cache_magic_exists(key, (uint16_t) keylen, cache)) {
                XSRETURN_YES;
        }

        XSRETURN_UNDEF;

}

XS(XS_cache_del) {
        dXSARGS;

        char *key;
        char *cache = NULL;
        STRLEN keylen;

        psgi_check_args(1);

        key = SvPV(ST(0), keylen);

        if (items > 1) {
                cache = SvPV_nolen(ST(1));
        }

        if (!uwsgi_cache_magic_del(key, (uint16_t) keylen, cache)) {
                XSRETURN_YES;
        }

        XSRETURN_UNDEF;

}

XS(XS_cache_clear) {
        dXSARGS;

        char *cache = NULL;
        psgi_check_args(1);

        cache = SvPV_nolen(ST(0));

        if (!uwsgi_cache_magic_clear(cache)) {
                XSRETURN_YES;
        }

        XSRETURN_UNDEF;

}




XS(XS_register_signal) {
	dXSARGS;

	if (!uwsgi.master_process) {
		XSRETURN_NO;
	}

	psgi_check_args(3);

	uint8_t signum = SvIV(ST(0));
	STRLEN kindlen;
	char *kind = SvPV(ST(1), kindlen);

	if (uwsgi_register_signal(signum, kind, (void *) newRV_inc(ST(2)), psgi_plugin.modifier1)) {
		XSRETURN_NO;
        }

	XSRETURN_YES;
	
}

XS(XS_spooler) {
	dXSARGS;
	psgi_check_args(1);
	uperl.spooler = (CV *) newRV_inc(ST(0));
	XSRETURN_YES;
}

XS(XS_register_rpc) {
        dXSARGS;

        psgi_check_args(2);

        char *name = SvPV_nolen(ST(0));

	if (uwsgi_register_rpc(name, &psgi_plugin, 0, (void *) newRV_inc(ST(1)))) {
                XSRETURN_NO;
        }

        XSRETURN_YES;
}


XS(XS_postfork) {
        dXSARGS;

        psgi_check_args(1);

	uperl.postfork = newRV_inc(ST(0));

        XSRETURN_YES;
}

XS(XS_atexit) {
        dXSARGS;

        psgi_check_args(1);

        uperl.atexit = newRV_inc(ST(0));

        XSRETURN_YES;
}



XS(XS_log) {

	dXSARGS;

	psgi_check_args(1);

	uwsgi_log("%s", SvPV_nolen(ST(0)));

	XSRETURN_UNDEF;
}

XS(XS_alarm) {

        dXSARGS;

	char *alarm;
	char *msg;
	STRLEN msg_len;

        psgi_check_args(2);

	alarm = SvPV_nolen(ST(0));
	msg = SvPV(ST(1), msg_len);

	uwsgi_alarm_trigger(alarm, msg, msg_len);

        XSRETURN_UNDEF;
}

XS(XS_worker_id) {
	dXSARGS;
        psgi_check_args(0);
	ST(0) = newSViv(uwsgi.mywid);	
	XSRETURN(1);
}

XS(XS_async_connect) {

	dXSARGS;
	psgi_check_args(1);

	ST(0) = newSViv(uwsgi_connect(SvPV_nolen(ST(0)), 0, 1));

	XSRETURN(1);
}

XS(XS_ready_fd) {
	dXSARGS;
        psgi_check_args(0);
	struct wsgi_request *wsgi_req = current_wsgi_req();	
	ST(0) = newSViv(uwsgi_ready_fd(wsgi_req));
	XSRETURN(1);
}

XS(XS_call) {

	dXSARGS;

        char *func;
        uint64_t size = 0;
        int i;
        char *argv[256];
        uint16_t argvs[256];
	STRLEN arg_len;

	psgi_check_args(1);

        func = SvPV_nolen(ST(0));

        for(i=0;i<(items-1);i++) {
                argv[i] = SvPV(ST(i+1), arg_len);
		argvs[i] = arg_len;
        }

	// response must be always freed
        char *response = uwsgi_do_rpc(NULL, func, items-1, argv, argvs, &size);
        if (response) {
		ST(0) = newSVpv(response, size);
        	sv_2mortal(ST(0));
		free(response);
        	XSRETURN(1);
        }

	XSRETURN_UNDEF;
}

XS(XS_rpc) {

        dXSARGS;

	char *node;
        char *func;
        uint64_t size = 0;
        int i;
        char *argv[256];
        uint16_t argvs[256];
        STRLEN arg_len;

        psgi_check_args(2);

	node = SvPV_nolen(ST(0));
        func = SvPV_nolen(ST(1));

        for(i=0;i<(items-2);i++) {
                argv[i] = SvPV(ST(i+2), arg_len);
                argvs[i] = arg_len;
        }

        // response must be always freed
        char *response = uwsgi_do_rpc(node, func, items-2, argv, argvs, &size);
        if (response) {
                ST(0) = newSVpv(response, size);
                sv_2mortal(ST(0));
                free(response);
                XSRETURN(1);
        }

        XSRETURN_UNDEF;
}



XS(XS_suspend) {

	dXSARGS;
	psgi_check_args(0);

	struct wsgi_request *wsgi_req = current_wsgi_req();

	wsgi_req->async_force_again = 0;

        if (uwsgi.schedule_to_main) uwsgi.schedule_to_main(wsgi_req);

	XSRETURN_UNDEF;
}

XS(XS_signal_wait) {

	dXSARGS;

	psgi_check_args(0);

        struct wsgi_request *wsgi_req = current_wsgi_req();
        int received_signal = -1;

        wsgi_req->signal_received = -1;

	if (items > 0) {
                received_signal = uwsgi_signal_wait(SvIV(ST(0)));
        }
        else {
                received_signal = uwsgi_signal_wait(-1);
        }

        if (received_signal < 0) {
		XSRETURN_NO;
        }

        wsgi_req->signal_received = received_signal;
	XSRETURN_YES;
}

#ifdef UWSGI_SSL
XS(XS_i_am_the_lord) {

	dXSARGS;

        psgi_check_args(1);

	if (uwsgi_legion_i_am_the_lord(SvPV_nolen(ST(0)))) {
        	XSRETURN_YES;
	}
        XSRETURN_NO;
}
#endif

XS(XS_connection_fd) {
	dXSARGS;

	psgi_check_args(0);	

	struct wsgi_request *wsgi_req = current_wsgi_req();

	ST(0) = newSViv(wsgi_req->fd);
        sv_2mortal(ST(0));
        XSRETURN(1);	
}

XS(XS_websocket_handshake) {

	dXSARGS;

        char *key = NULL;
	STRLEN key_len = 0;

        char *origin = NULL;
	STRLEN origin_len = 0;

	char *proto = NULL;
	STRLEN proto_len = 0;

	psgi_check_args(0);
	
	if (items > 0) {
		key = SvPV(ST(0), key_len);
		if (items > 1) {
			origin = SvPV(ST(1), origin_len);
			if (items > 2) {
				proto = SvPV(ST(2), proto_len);
			}
		}
		
	}
        struct wsgi_request *wsgi_req = current_wsgi_req();

        if (uwsgi_websocket_handshake(wsgi_req, key, key_len, origin, origin_len, proto, proto_len)) {
                croak("unable to complete websocket handshake");
	}

	XSRETURN_UNDEF;
}

XS(XS_websocket_send) {
	dXSARGS;

        char *message = NULL;
        STRLEN message_len = 0;

	psgi_check_args(1);

	message = SvPV(ST(0), message_len);

        struct wsgi_request *wsgi_req = current_wsgi_req();

        if (uwsgi_websocket_send(wsgi_req, message, message_len)) {
                croak("unable to send websocket message");
        }

	XSRETURN_UNDEF;
}

XS(XS_websocket_send_from_sharedarea) {
        dXSARGS;

        psgi_check_args(2);
	int id = SvIV(ST(0));
        uint64_t pos = SvIV(ST(1));
	uint64_t len = 0;

	if (items > 2) {
		len = SvIV(ST(2));
	}
	
        struct wsgi_request *wsgi_req = current_wsgi_req();

        if (uwsgi_websocket_send_from_sharedarea(wsgi_req, id, pos, len)) {
                croak("unable to send websocket message from sharedarea");
        }

        XSRETURN_UNDEF;
}


XS(XS_websocket_send_binary) {
        dXSARGS;

        char *message = NULL;
        STRLEN message_len = 0;

        psgi_check_args(1);

        message = SvPV(ST(0), message_len);

        struct wsgi_request *wsgi_req = current_wsgi_req();

        if (uwsgi_websocket_send_binary(wsgi_req, message, message_len)) {
                croak("unable to send websocket binary message");
        }

        XSRETURN_UNDEF;
}

XS(XS_websocket_send_binary_from_sharedarea) {
        dXSARGS;

        psgi_check_args(2);
        int id = SvIV(ST(0));
        uint64_t pos = SvIV(ST(1));
        uint64_t len = 0;

        if (items > 2) {
                len = SvIV(ST(2));
        }

        struct wsgi_request *wsgi_req = current_wsgi_req();

        if (uwsgi_websocket_send_binary_from_sharedarea(wsgi_req, id, pos, len)) {
                croak("unable to send websocket binary message from sharedarea");
        }

        XSRETURN_UNDEF;
}



XS(XS_websocket_recv) {
	dXSARGS;

	psgi_check_args(0);

        struct wsgi_request *wsgi_req = current_wsgi_req();
        struct uwsgi_buffer *ub = uwsgi_websocket_recv(wsgi_req);
        if (!ub) {
        	croak("unable to receive websocket message");
		XSRETURN_UNDEF;
        }

	ST(0) = newSVpv(ub->buf, ub->pos);
	uwsgi_buffer_destroy(ub);
        sv_2mortal(ST(0));

        XSRETURN(1);
}

XS(XS_websocket_recv_nb) {
        dXSARGS;

        psgi_check_args(0);

        struct wsgi_request *wsgi_req = current_wsgi_req();
        struct uwsgi_buffer *ub = uwsgi_websocket_recv_nb(wsgi_req);
        if (!ub) {
                croak("unable to receive websocket message");
                XSRETURN_UNDEF;
        }

        ST(0) = newSVpv(ub->buf, ub->pos);
        uwsgi_buffer_destroy(ub);
        sv_2mortal(ST(0));

        XSRETURN(1);
}

XS(XS_add_timer) {

	dXSARGS;

	psgi_check_args(2);

        uint8_t uwsgi_signal = SvIV(ST(0));
        int seconds = SvIV(ST(1));

        if (uwsgi_add_timer(uwsgi_signal, seconds)) {
		croak("unable to register timer");
		XSRETURN_UNDEF;
        }

        XSRETURN(1);
}

XS(XS_add_rb_timer) {

        dXSARGS;

        psgi_check_args(2);

        uint8_t uwsgi_signal = SvIV(ST(0));
        int seconds = SvIV(ST(1));

        if (uwsgi_signal_add_rb_timer(uwsgi_signal, seconds, 0)) {
                croak("unable to register rb timer");
                XSRETURN_UNDEF;
        }

        XSRETURN(1);
}

XS(XS_metric_inc) {
        dXSARGS;
        char *metric = NULL;
        STRLEN metric_len = 0;
	int64_t value = 1;
        psgi_check_args(1);
        metric = SvPV(ST(0), metric_len);
	if (items > 1) {
		value = (int64_t) SvIV(ST(1));
	}
        if (uwsgi_metric_inc(metric, NULL, value)) {
                croak("unable to update metric");
                XSRETURN_UNDEF;
        }
        XSRETURN_YES;
}

XS(XS_metric_dec) {
        dXSARGS;
        char *metric = NULL;
        STRLEN metric_len = 0;
        int64_t value = 1;
        psgi_check_args(1);
        metric = SvPV(ST(0), metric_len);
        if (items > 1) {
                value = (int64_t) SvIV(ST(1));
        }
        if (uwsgi_metric_dec(metric, NULL, value)) {
                croak("unable to update metric");
                XSRETURN_UNDEF;
        }
        XSRETURN_YES;
}

XS(XS_metric_mul) {
        dXSARGS;
        char *metric = NULL;
        STRLEN metric_len = 0;
        int64_t value = 1;
        psgi_check_args(1);
        metric = SvPV(ST(0), metric_len);
        if (items > 1) {
                value = (int64_t) SvIV(ST(1));
        }
        if (uwsgi_metric_mul(metric, NULL, value)) {
                croak("unable to update metric");
                XSRETURN_UNDEF;
        }
        XSRETURN_YES;
}

XS(XS_metric_div) {
        dXSARGS;
        char *metric = NULL;
        STRLEN metric_len = 0;
        int64_t value = 1;
        psgi_check_args(1);
        metric = SvPV(ST(0), metric_len);
        if (items > 1) {
                value = (int64_t) SvIV(ST(1));
        }
        if (uwsgi_metric_div(metric, NULL, value)) {
                croak("unable to update metric");
                XSRETURN_UNDEF;
        }
        XSRETURN_YES;
}      

XS(XS_metric_set) {
        dXSARGS;
        char *metric = NULL;
        STRLEN metric_len = 0;
        int64_t value = 0;
        psgi_check_args(2);
        metric = SvPV(ST(0), metric_len);
        value = (int64_t) SvIV(ST(1));
        if (uwsgi_metric_set(metric, NULL, value)) {
                croak("unable to update metric");
                XSRETURN_UNDEF;
        }
        XSRETURN_YES;
}

XS(XS_metric_get) {
        dXSARGS;

        char *metric = NULL;
        STRLEN metric_len = 0;

        psgi_check_args(1);

        metric = SvPV(ST(0), metric_len);

	ST(0) = newSViv(uwsgi_metric_get(metric, NULL));
        sv_2mortal(ST(0));
        XSRETURN(1);
}

XS(XS_sharedarea_wait) {
        dXSARGS;
        int id;
	int freq = 0;
	int timeout = 0;

	psgi_check_args(1);
	
	id = SvIV(ST(0));
	if (items > 1) {
		freq = SvIV(ST(1));
		if (items > 2) {
			timeout = SvIV(ST(2));
		}
	}

	if (uwsgi_sharedarea_wait(id, freq, timeout)) {
                croak("unable to wait for sharedarea %d", id);
                XSRETURN_UNDEF;
        }
	XSRETURN_YES;
}

XS(XS_sharedarea_read) {
	dXSARGS;
	int id;
	uint64_t pos;
	uint64_t len = 0;
	psgi_check_args(2);	

	id = SvIV(ST(0));
	pos = SvIV(ST(1));

	if (items > 2) {
		len = SvIV(ST(2));	
	}
	else {
		struct uwsgi_sharedarea *sa = uwsgi_sharedarea_get_by_id(id, pos);
		if (!sa) {
			croak("unable to read from sharedarea %d", id);
                	XSRETURN_UNDEF;
		}
		len = (sa->max_pos+1)-pos;
	}

	char *buf = uwsgi_malloc(len);
	int64_t rlen = uwsgi_sharedarea_read(id, pos, buf, len);
	if (rlen < 0) {
		free(buf);
		croak("unable to read from sharedarea %d", id);
                XSRETURN_UNDEF;
	}

	ST(0) = sv_newmortal();
     	sv_usepvn(ST(0), buf, rlen);
        XSRETURN(1);
}

XS(XS_sharedarea_readfast) {
        dXSARGS;
        int id;
        uint64_t pos;
        uint64_t len = 0;
        psgi_check_args(3);

        id = SvIV(ST(0));
        pos = SvIV(ST(1));
	char *buf = SvPV_nolen(ST(2));

        if (items > 3) {
                len = SvIV(ST(3));
        }

        if (uwsgi_sharedarea_read(id, pos, buf, len)) {
                croak("unable to (fast) read from sharedarea %d", id);
                XSRETURN_UNDEF;
        }

	XSRETURN_YES;
}


XS(XS_sharedarea_write) {
        dXSARGS;
        int id;
        uint64_t pos;
        STRLEN vallen;

        psgi_check_args(3);

        id = SvIV(ST(0));
        pos = SvIV(ST(1));
        char *value = SvPV(ST(2), vallen);

        if (uwsgi_sharedarea_write(id, pos, value, vallen)) {
                croak("unable to write to sharedarea %d", id);
                XSRETURN_UNDEF;
        }

	XSRETURN_YES;
}


XS(XS_chunked_read) {
	dXSARGS;
        int timeout = 0;
	size_t len = 0;

	psgi_check_args(0);
	if (items > 0) {
        	timeout = SvIV(ST(0));
        }
        struct wsgi_request *wsgi_req = current_wsgi_req();
        char *chunk = uwsgi_chunked_read(wsgi_req, &len, timeout, 0);
        if (!chunk) {
		croak("unable to receive chunked part");
		XSRETURN_UNDEF;
        }

	ST(0) = newSVpvn(chunk, len);
        sv_2mortal(ST(0));
        XSRETURN(1);
}

XS(XS_chunked_read_nb) {
        dXSARGS;
        size_t len = 0;

        psgi_check_args(0);

        struct wsgi_request *wsgi_req = current_wsgi_req();
        char *chunk = uwsgi_chunked_read(wsgi_req, &len, 0, 1);
        if (!chunk) {
		if (uwsgi_is_again()) XSRETURN_UNDEF;
                croak("unable to receive chunked part");
                XSRETURN_UNDEF;
        }

        ST(0) = newSVpvn(chunk, len);
        sv_2mortal(ST(0));
        XSRETURN(1);
}

XS(XS_spool) {

	dXSARGS;
	psgi_check_args(1);

	SV *arg = ST(0);
	HV *env = NULL;

	char *body = NULL;
	STRLEN body_len = 0;

	if (SvROK(arg)) {
		env = (HV *) SvRV(arg);
	}
	else {
		croak("spool argument must be a hashref");
		XSRETURN_UNDEF;
	}

	if (SvTYPE(env) != SVt_PVHV) {
		croak("spool argument must be a hashref");
                XSRETURN_UNDEF;
	}

	if (hv_exists(env, "body", 4)) {
		SV **body_sv = hv_fetch(env, "body", 4, 0);
		body = SvPV(*body_sv, body_len);
		(void)hv_delete(env, "body", 4, 0);
	}	

	struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);
	
	HE *he;
	hv_iterinit(env);
        while((he = hv_iternext(env))) {
		I32 klen;
		STRLEN vlen;
		char *key = hv_iterkey(he, &klen);
                char *value = SvPV(hv_iterval(env, he), vlen);
		if (uwsgi_buffer_append_keyval(ub, key, klen, value, vlen)) {
			croak("unable to serialize hash to spool file");
			uwsgi_buffer_destroy(ub);
			XSRETURN_UNDEF;
		}
        }

	char *filename = uwsgi_spool_request(NULL, ub->buf, ub->pos, body, body_len);
	uwsgi_buffer_destroy(ub);
	if (filename) {
		ST(0) = newSVpv(filename, strlen(filename));
		free(filename);
		XSRETURN(1);
	}

	croak("unable to spool request");
	XSRETURN_UNDEF;
}

XS(XS_add_var) {
	dXSARGS;
        psgi_check_args(2);

	struct wsgi_request *wsgi_req = current_wsgi_req();

	STRLEN keylen;
	char *key = SvPV(ST(0), keylen);

	STRLEN vallen;
	char *val = SvPV(ST(1), vallen);

	if (!uwsgi_req_append(wsgi_req, key, keylen, val, vallen)) {
		croak("unable to add request var, check your buffer size");
		XSRETURN_UNDEF;
	}

	XSRETURN_YES;
	
}

void init_perl_embedded_module() {
	psgi_xs(reload);

	psgi_xs(cache_get);
	psgi_xs(cache_exists);
	psgi_xs(cache_set);
	psgi_xs(cache_del);
	psgi_xs(cache_clear);

	psgi_xs(call);
	psgi_xs(rpc);
	psgi_xs(wait_fd_read);
	psgi_xs(wait_fd_write);
	psgi_xs(async_sleep);
	psgi_xs(ready_fd);
	psgi_xs(log);
	psgi_xs(async_connect);
	psgi_xs(suspend);
	psgi_xs(signal);
	psgi_xs(register_signal);
	psgi_xs(register_rpc);
	psgi_xs(signal_wait);
#ifdef UWSGI_SSL
	psgi_xs(i_am_the_lord);
#endif

	psgi_xs(connection_fd);

	psgi_xs(alarm);
	psgi_xs(websocket_handshake);
	psgi_xs(websocket_recv);
	psgi_xs(websocket_recv_nb);
	psgi_xs(websocket_send);
	psgi_xs(websocket_send_from_sharedarea);
	psgi_xs(websocket_send_binary);
	psgi_xs(websocket_send_binary_from_sharedarea);
	psgi_xs(postfork);
	psgi_xs(atexit);

	psgi_xs(add_timer);
	psgi_xs(add_rb_timer);

	psgi_xs(set_user_harakiri);

	psgi_xs(metric_inc);
	psgi_xs(metric_dec);
	psgi_xs(metric_mul);
	psgi_xs(metric_div);
	psgi_xs(metric_get);
	psgi_xs(metric_set);

	psgi_xs(chunked_read);
	psgi_xs(chunked_read_nb);

	psgi_xs(sharedarea_read);
	psgi_xs(sharedarea_readfast);
	psgi_xs(sharedarea_write);
	psgi_xs(sharedarea_wait);

	psgi_xs(spooler);
	psgi_xs(spool);

	psgi_xs(add_var);
	psgi_xs(worker_id);
	
}
