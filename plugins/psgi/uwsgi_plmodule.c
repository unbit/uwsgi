#include "psgi.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_plugin psgi_plugin;

#ifdef UWSGI_ASYNC


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

        if (fd >= 0) {
                async_add_fd_read(wsgi_req, fd, timeout);
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

        if (fd >= 0) {
                async_add_fd_write(wsgi_req, fd, timeout);
        }

	wsgi_req->async_force_again = 1;

	XSRETURN_UNDEF;
}

#endif

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

	if (uwsgi.cache_max_items == 0) goto clear;
	
	psgi_check_args(2);

	key = SvPV(ST(0), keylen);
	val = SvPV(ST(1), vallen);

	uwsgi_wlock(uwsgi.cache_lock);
	uwsgi_cache_set(key, (uint16_t) keylen, val, (uint64_t) vallen, 0, 0);
	uwsgi_rwunlock(uwsgi.cache_lock);

clear:
	XSRETURN_UNDEF;
}

XS(XS_cache_get) {
	dXSARGS;

	char *key, *val;
	STRLEN keylen;
	uint64_t vallen;

	if (uwsgi.cache_max_items == 0) goto clear;
	
	psgi_check_args(1);

	key = SvPV(ST(0), keylen);

	uwsgi_rlock(uwsgi.cache_lock);
	val = uwsgi_cache_get(key, (uint16_t) keylen, &vallen);

	if (!val)
		uwsgi_rwunlock(uwsgi.cache_lock);
clear:
		XSRETURN_UNDEF;

	ST(0) = newSVpv(val, vallen);
	uwsgi_rwunlock(uwsgi.cache_lock);
	sv_2mortal(ST(0));
	
	XSRETURN(1);
	
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

XS(XS_log) {

	dXSARGS;

	psgi_check_args(1);

	uwsgi_log("%s", SvPV_nolen(ST(0)));

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

        if (size > 0) {
		ST(0) = newSVpv(response, size);
        	sv_2mortal(ST(0));
		free(response);
        	XSRETURN(1);
        }
	free(response);

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


void init_perl_embedded_module() {
	psgi_xs(reload);
	psgi_xs(cache_set);
	psgi_xs(cache_get);
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
}

