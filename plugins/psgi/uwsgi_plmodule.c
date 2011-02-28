#include "psgi.h"

extern struct uwsgi_server uwsgi;

#define psgi_xs(func) newXS("uwsgi::" #func, XS_##func, "uwsgi")
#define psgi_check_args(x) if (items < x) Perl_croak(aTHX_ "Usage: uwsgi::%s takes %d arguments", __FUNCTION__ + 3, x)

XS(XS_reload) {
    dXSARGS;
    items = 0;

    uwsgi_log("SENDING HUP TO %d\n", (int) uwsgi.workers[0].pid);
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
	
	psgi_check_args(2);

	key = SvPV(ST(0), keylen);
	val = SvPV(ST(1), vallen);

	uwsgi_cache_set(key, (uint16_t) keylen, val, (uint64_t) vallen, 0, 0);

	XSRETURN_UNDEF;
}

XS(XS_cache_get) {
	dXSARGS;

	char *key, *val;
	STRLEN keylen;
	uint64_t vallen;
	
	psgi_check_args(1);

	key = SvPV(ST(0), keylen);

	val = uwsgi_cache_get(key, (uint16_t) keylen, &vallen);

	if (!val)
		XSRETURN_UNDEF;

	ST(0) = newSVpv(val, vallen);
	sv_2mortal(ST(0));
	
	XSRETURN(1);
	
}

XS(XS_call) {

	dXSARGS;

	char buffer[0xffff];
        char *func;
        uint16_t size = 0;
        int i;
        char *argv[0xff];

	psgi_check_args(1);

        func = SvPV_nolen(ST(0));

        for(i=0;i<(items-1);i++) {
                argv[i] = SvPV_nolen(ST(i+1));
        }

        size = uwsgi_rpc(func, items-1, argv, buffer);

        if (size > 0) {
		ST(0) = newSVpv(buffer, size);
        	sv_2mortal(ST(0));

        	XSRETURN(1);
        }

	XSRETURN_UNDEF;
}



void init_perl_embedded_module() {
	psgi_xs(reload);
	psgi_xs(cache_set);
	psgi_xs(cache_get);
	psgi_xs(call);
}

