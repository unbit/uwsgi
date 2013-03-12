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
			cache = SvPV_nolen(ST(1));
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

	char *value = uwsgi_cache_magic_get(key, (uint16_t) keylen, &vallen, cache);
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

        cache = SvPV_nolen(ST(1));

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

XS(XS_async_connect) {

	dXSARGS;
	psgi_check_args(1);

	ST(0) = newSViv(uwsgi_connect(SvPV_nolen(ST(0)), 0, 1));

	XSRETURN(1);
}

XS(XS_call) {

	dXSARGS;

        char *func;
        uint16_t size = 0;
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

XS(XS_websocket_handshake) {

	dXSARGS;

        char *key = NULL;
	STRLEN key_len = 0;

        char *origin = NULL;
	STRLEN origin_len = 0;

	psgi_check_args(1);
	
	key = SvPV(ST(0), key_len);

	if (items > 1) {
		origin = SvPV(ST(0), origin_len);
	}
        struct wsgi_request *wsgi_req = current_wsgi_req();

        if (uwsgi_websocket_handshake(wsgi_req, key, key_len, origin, origin_len)) {
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



void init_perl_embedded_module() {
	psgi_xs(reload);

	psgi_xs(cache_get);
	psgi_xs(cache_exists);
	psgi_xs(cache_set);
	psgi_xs(cache_del);
	psgi_xs(cache_clear);

	psgi_xs(call);
	psgi_xs(wait_fd_read);
	psgi_xs(wait_fd_write);
	psgi_xs(async_sleep);
	psgi_xs(log);
	psgi_xs(async_connect);
	psgi_xs(suspend);
	psgi_xs(signal);
	psgi_xs(register_signal);
	psgi_xs(signal_wait);
#ifdef UWSGI_SSL
	psgi_xs(i_am_the_lord);
#endif
	psgi_xs(alarm);
	psgi_xs(websocket_handshake);
	psgi_xs(websocket_recv);
	psgi_xs(websocket_recv_nb);
	psgi_xs(websocket_send);
	psgi_xs(postfork);
	psgi_xs(atexit);

	psgi_xs(add_timer);
	psgi_xs(add_rb_timer);
}

